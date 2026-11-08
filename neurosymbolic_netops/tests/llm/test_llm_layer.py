"""LLM layer tests. All provider calls are MOCKED at the SDK boundary: these tests prove the
interface logic (tool loop, validation, retries, labelling), NOT that a live provider works.
The live smoke test is marked ``live`` and skipped unless explicitly selected with a key."""

import json
import os
from types import SimpleNamespace

import pytest

from agent.contracts import LLMDiagnosisOutput
from agent.llm.base import ChatResult, LLMError, LLMProvider, RetryableLLMError, ToolSpec, extract_json, redact_text, run_structured
from agent.llm.replay import RecordingProvider, ReplayProvider


class Scripted(LLMProvider):
    def __init__(self, replies, **kw):
        super().__init__(provider="mock", model="scripted", log_path=None, **kw)
        self.replies = list(replies)
        self.seen = []

    def _chat_once(self, system, messages, tools, json_mode):
        self.seen.append((system, [dict(m) for m in messages], [t.name for t in tools or []], json_mode))
        r = self.replies.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def reply(text="", calls=None):
    return ChatResult(text=text, tool_calls=calls or [], prompt_tokens=100, completion_tokens=20, total_tokens=120)


GOOD = json.dumps({"hypotheses": [{"device": "Leaf-1", "category": "BGP", "fault_type": "bgp_remote_as_mismatch",
                                   "location": "10.0.1.1", "statement": "wrong AS", "evidence": ["E-1"]}],
                   "reasoning_summary": "x"})


def test_tool_loop_then_validated_output():
    p = Scripted([reply(calls=[{"id": "1", "name": "bgp_summary", "args": {"device": "Leaf-1"}}]), reply(GOOD)])
    called = []
    out, usage, msgs = run_structured(p, "sys", "user", LLMDiagnosisOutput, tools=[ToolSpec("bgp_summary", "d", {})],
                                      execute_tool=lambda n, a: called.append((n, a)) or {"ok": True})
    assert called == [("bgp_summary", {"device": "Leaf-1"})]
    assert out.hypotheses[0].fault_type == "bgp_remote_as_mismatch"
    assert (usage.calls, usage.prompt_tokens, usage.total_tokens, usage.source) == (2, 200, 240, "provider_reported")
    assert [m["role"] for m in msgs] == ["user", "assistant", "tool"]


def test_invalid_json_is_fed_back_then_accepted():
    p = Scripted([reply("not json"), reply('{"hypotheses": [], "reasoning_summary": "x"}'), reply(GOOD)])
    out, usage, _ = run_structured(p, "s", "u", LLMDiagnosisOutput)
    assert usage.invalid_responses == 2 and out.hypotheses[0].device == "Leaf-1"
    assert "did not validate" in p.seen[1][1][-1]["content"]


def test_persistently_invalid_output_raises():
    p = Scripted([reply("nope")] * 3)
    with pytest.raises(LLMError, match="invalid structured output"):
        run_structured(p, "s", "u", LLMDiagnosisOutput, max_invalid=2)


def test_retry_on_rate_limit_then_success(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
    p = Scripted([RetryableLLMError("429"), RetryableLLMError("503"), reply(GOOD)])
    out, usage, _ = run_structured(p, "s", "u", LLMDiagnosisOutput)
    assert usage.retries == 2 and out.hypotheses


def test_gives_up_after_max_retries(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
    p = Scripted([RetryableLLMError("timeout")] * 10, max_retries=2)
    with pytest.raises(LLMError, match="giving up"):
        run_structured(p, "s", "u", LLMDiagnosisOutput)


def test_missing_api_key_fails_loudly(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    from agent.llm.gemini import GeminiProvider
    from agent.llm.openai_provider import OpenAIProvider
    with pytest.raises(LLMError, match="GEMINI_API_KEY"):
        GeminiProvider()
    with pytest.raises(LLMError, match="OPENAI_API_KEY"):
        OpenAIProvider()


def test_record_then_replay_is_labelled_and_misses_raise(tmp_path):
    inner = Scripted([reply(GOOD)])
    rec = RecordingProvider(inner=inner, cassette=tmp_path / "c.json", log_path=None)
    run_structured(rec, "s", "u", LLMDiagnosisOutput)
    rp = ReplayProvider(provider="mock", model="scripted", cassette=tmp_path / "c.json", log_path=None)
    out, usage, _ = run_structured(rp, "s", "u", LLMDiagnosisOutput)
    assert usage.source == "replay" and out.hypotheses
    with pytest.raises(LLMError, match="replay miss"):
        run_structured(rp, "s", "different prompt", LLMDiagnosisOutput)


def test_gemini_adapter_converts_function_calls_and_usage():
    from agent.llm.gemini import GeminiProvider
    fc = SimpleNamespace(id="c1", name="bgp_summary", args={"device": "Leaf-1"})
    resp = SimpleNamespace(function_calls=[fc], text="", candidates=[SimpleNamespace(content="RAW")],
                           usage_metadata=SimpleNamespace(prompt_token_count=50, candidates_token_count=5,
                                                          thoughts_token_count=7, total_token_count=62))
    captured = {}

    def gen(model, contents, config):
        captured.update(model=model, n=len(contents), tools=config.tools)
        return resp
    p = GeminiProvider(client=SimpleNamespace(models=SimpleNamespace(generate_content=gen)), log_path=None)
    r = p._chat_once("sys", [{"role": "user", "content": "hi"}], [ToolSpec("bgp_summary", "d", {"type": "object"})], False)
    assert r.tool_calls == [{"id": "c1", "name": "bgp_summary", "args": {"device": "Leaf-1"}}]
    assert (r.prompt_tokens, r.completion_tokens, r.total_tokens, r.raw_message) == (50, 12, 62, "RAW")
    assert captured["tools"][0].function_declarations[0].name == "bgp_summary"


def test_openai_adapter_converts_tool_calls():
    from agent.llm.openai_provider import OpenAIProvider
    tc = SimpleNamespace(id="t1", function=SimpleNamespace(name="inspect_acl", arguments='{"device": "Leaf-2"}'))
    resp = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=None, tool_calls=[tc]))],
                           usage=SimpleNamespace(prompt_tokens=30, completion_tokens=4, total_tokens=34))
    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=lambda **kw: resp)))
    p = OpenAIProvider(client=client, log_path=None)
    r = p._chat_once("s", [{"role": "user", "content": "x"}], [ToolSpec("inspect_acl", "d", {})], False)
    assert r.tool_calls == [{"id": "t1", "name": "inspect_acl", "args": {"device": "Leaf-2"}}] and r.total_tokens == 34


def test_redaction_and_json_extraction():
    assert "S3cr3t" not in redact_text("neighbor 1.1.1.1 password S3cr3t")
    assert "AIza" not in redact_text("key AIzaSyA1234567890abcdefghijklmnop")
    assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}


@pytest.mark.live
def test_live_provider_smoke():
    """Real provider call. Run with: pytest -m live tests/llm (requires a key; costs tokens)."""
    from agent.llm.base import provider_from_env
    p = provider_from_env("llm")
    out, usage, _ = run_structured(p, "Answer in JSON.", 'Return {"hypotheses":[{"device":"Leaf-1","category":"LINK",'
                                   '"fault_type":"interface_admin_down","location":"eth1","statement":"test"}],'
                                   '"reasoning_summary":"smoke"}', LLMDiagnosisOutput)
    assert usage.calls >= 1 and usage.total_tokens > 0


def test_provider_rejected_output_is_fed_back_as_invalid_response():
    from agent.llm.base import InvalidModelOutputError
    p = Scripted([InvalidModelOutputError("Tool choice is none, but model called a tool"), reply(GOOD)])
    out, usage, _ = run_structured(p, "s", "u", LLMDiagnosisOutput)
    assert usage.invalid_responses == 1 and out.hypotheses
    assert "Do not call any tool" in p.seen[1][1][-1]["content"]
