"""Provider-neutral LLM interface: chat with tool calling, retries, structured output, usage.

Messages use a neutral format: {"role": "user"|"assistant"|"tool", "content": str,
"tool_calls": [{"id","name","args"}], "tool_call_id", "name", "_raw": provider object}.
``run_structured`` drives the tool loop and validates the final JSON with Pydantic; invalid
responses are fed back with the validation error and counted. Nothing here falls back to a
rule engine: failures raise ``LLMError``.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Type

from pydantic import BaseModel, ValidationError

from agent.contracts import LLMUsage

LOG_PATH = Path(__file__).resolve().parents[2] / "runtime" / "llm_calls.jsonl"


class LLMError(RuntimeError):
    pass


class RetryableLLMError(LLMError):
    pass


@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: Dict[str, Any]


@dataclass
class ChatResult:
    text: str
    tool_calls: List[Dict[str, Any]]
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    raw_message: Any = None
    latency_ms: float = 0.0


@dataclass
class LLMProvider:
    provider: str = "abstract"
    model: str = ""
    timeout_s: float = 60.0
    max_retries: int = 4
    temperature: Optional[float] = 0.2
    source: str = "provider_reported"
    log_path: Optional[Path] = field(default=LOG_PATH)

    def _chat_once(self, system: str, messages: List[dict], tools: Optional[List[ToolSpec]],
                   json_mode: bool) -> ChatResult:  # pragma: no cover - implemented by subclasses
        raise NotImplementedError

    def chat(self, system: str, messages: List[dict], tools: Optional[List[ToolSpec]] = None,
             json_mode: bool = False, usage: Optional[LLMUsage] = None) -> ChatResult:
        attempt = 0
        while True:
            t0 = time.perf_counter()
            try:
                res = self._chat_once(system, messages, tools, json_mode)
                res.latency_ms = round((time.perf_counter() - t0) * 1000, 1)
                if usage is not None:
                    usage.add(LLMUsage(provider=self.provider, model=self.model, calls=1, prompt_tokens=res.prompt_tokens,
                                       completion_tokens=res.completion_tokens, total_tokens=res.total_tokens,
                                       latency_ms=res.latency_ms, source=self.source))
                self._log(system, messages, tools, res, None)
                return res
            except RetryableLLMError as exc:
                attempt += 1
                self._log(system, messages, tools, None, f"retryable: {exc}")
                if attempt > self.max_retries:
                    raise LLMError(f"{self.provider}: giving up after {attempt} attempts: {exc}") from exc
                if usage is not None:
                    usage.retries += 1
                time.sleep(min(30.0, (2 ** attempt) * 0.5 + random.random()))

    def _log(self, system, messages, tools, res: Optional[ChatResult], error: Optional[str]) -> None:
        if not self.log_path:
            return
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            entry = {"ts": time.time(), "provider": self.provider, "model": self.model,
                     "n_messages": len(messages), "tools": [t.name for t in tools or []],
                     "last_message": redact_text(str(messages[-1].get("content", ""))[:2000]) if messages else "",
                     "response": redact_text(res.text[:4000]) if res else None,
                     "tool_calls": res.tool_calls if res else None,
                     "usage": {"prompt": res.prompt_tokens, "completion": res.completion_tokens} if res else None,
                     "error": error}
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
        except OSError:
            pass


_SECRET_RX = [re.compile(r"(?i)(api[_-]?key|authorization|bearer)\s*[:=]?\s*\S+"),
              re.compile(r"(password\s+)(?!<redacted)\S+"), re.compile(r"AIza[0-9A-Za-z_\-]{20,}"),
              re.compile(r"sk-[0-9A-Za-z_\-]{20,}")]


def redact_text(s: str) -> str:
    for rx in _SECRET_RX:
        s = rx.sub(lambda m: (m.group(1) + "<redacted>") if m.lastindex else "<redacted>", s)
    return s


def extract_json(text: str) -> Any:
    t = text.strip()
    m = re.search(r"```(?:json)?\s*(.*?)```", t, re.S)
    if m:
        t = m.group(1)
    start = min([i for i in (t.find("{"), t.find("[")) if i >= 0], default=-1)
    if start < 0:
        raise ValueError("no JSON object in response")
    return json.loads(t[start:])


def run_structured(provider: LLMProvider, system: str, user: str, schema: Type[BaseModel],
                   tools: Optional[List[ToolSpec]] = None, execute_tool: Optional[Callable[[str, dict], dict]] = None,
                   max_tool_rounds: int = 10, max_invalid: int = 2) -> tuple[BaseModel, LLMUsage, List[dict]]:
    """Tool loop + validated structured output. Returns (parsed, usage, transcript)."""
    usage = LLMUsage(provider=provider.provider, model=provider.model, source=provider.source)
    schema_txt = json.dumps(schema.model_json_schema())
    sys_full = (system + "\n\nWhen you are finished, reply with ONLY a JSON object that validates against this "
                f"JSON Schema (no prose, no markdown):\n{schema_txt}")
    msgs: List[dict] = [{"role": "user", "content": user}]
    rounds = invalid = 0
    while True:
        use_tools = tools if (tools and rounds < max_tool_rounds) else None
        res = provider.chat(sys_full, msgs, use_tools, json_mode=use_tools is None, usage=usage)
        if res.tool_calls and use_tools:
            rounds += 1
            msgs.append({"role": "assistant", "content": res.text, "tool_calls": res.tool_calls, "_raw": res.raw_message})
            for tc in res.tool_calls:
                out = execute_tool(tc["name"], tc.get("args") or {}) if execute_tool else {"error": "tools disabled"}
                msgs.append({"role": "tool", "tool_call_id": tc.get("id"), "name": tc["name"],
                             "content": json.dumps(out, default=str)[:12000]})
            continue
        try:
            parsed = schema.model_validate(extract_json(res.text))
            return parsed, usage, msgs
        except (ValueError, ValidationError) as exc:
            invalid += 1
            usage.invalid_responses += 1
            if invalid > max_invalid:
                raise LLMError(f"invalid structured output after {invalid} attempts: {str(exc)[:500]}") from exc
            msgs.append({"role": "assistant", "content": res.text, "_raw": res.raw_message})
            msgs.append({"role": "user", "content": f"Your reply did not validate: {str(exc)[:1500]}\n"
                                                     "Reply again with ONLY the corrected JSON object."})


def cassette_key(provider: str, model: str, system: str, messages: List[dict], tools, json_mode: bool) -> str:
    clean = [{k: v for k, v in m.items() if k != "_raw"} for m in messages]
    payload = json.dumps([provider, model, system, clean, [t.name for t in tools or []], json_mode], sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


def provider_from_env(mode: Optional[str] = None) -> LLMProvider:
    """Construct the provider selected by NETOPS_LLM_* variables. Raises if the key is missing."""
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parents[2] / ".env")
    name = os.environ.get("NETOPS_LLM_PROVIDER", "gemini")
    common = dict(timeout_s=float(os.environ.get("NETOPS_LLM_TIMEOUT_S", 60)),
                  max_retries=int(os.environ.get("NETOPS_LLM_MAX_RETRIES", 4)),
                  temperature=float(os.environ["NETOPS_LLM_TEMPERATURE"]) if os.environ.get("NETOPS_LLM_TEMPERATURE") else 0.2)
    model = os.environ.get("NETOPS_LLM_MODEL") or ("gemini-3.6-flash" if name == "gemini" else "gpt-4.1-mini")
    if (mode or os.environ.get("NETOPS_LLM_MODE")) == "offline":
        from agent.llm.replay import ReplayProvider
        return ReplayProvider(provider=name, model=model)
    if name == "gemini":
        from agent.llm.gemini import GeminiProvider
        return GeminiProvider(model=model, **common)
    if name == "openai":
        from agent.llm.openai_provider import OpenAIProvider
        return OpenAIProvider(model=model, **common)
    raise LLMError(f"unknown NETOPS_LLM_PROVIDER {name!r}")
