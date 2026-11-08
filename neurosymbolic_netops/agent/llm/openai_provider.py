"""OpenAI provider (Chat Completions API). Requires OPENAI_API_KEY."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Optional

from agent.llm.base import ChatResult, LLMError, LLMProvider, RetryableLLMError


@dataclass
class OpenAIProvider(LLMProvider):
    provider: str = "openai"
    model: str = "gpt-4.1-mini"
    api_key: Optional[str] = None
    client: object = None

    def __post_init__(self):
        if self.client is None:
            key = self.api_key or os.environ.get("OPENAI_API_KEY")
            if not key:
                raise LLMError("OPENAI_API_KEY is not set; choose NETOPS_LLM_MODE=rule_based or offline explicitly")
            import openai
            self.client = openai.OpenAI(api_key=key, timeout=self.timeout_s, max_retries=0)

    def _chat_once(self, system, messages, tools, json_mode) -> ChatResult:
        import openai
        msgs = [{"role": "system", "content": system}]
        for m in messages:
            if m["role"] == "assistant":
                d = {"role": "assistant", "content": m.get("content") or None}
                if m.get("tool_calls"):
                    d["tool_calls"] = [{"id": tc["id"], "type": "function",
                                        "function": {"name": tc["name"], "arguments": json.dumps(tc.get("args") or {})}}
                                       for tc in m["tool_calls"]]
                msgs.append(d)
            elif m["role"] == "tool":
                msgs.append({"role": "tool", "tool_call_id": m["tool_call_id"], "content": m["content"]})
            else:
                msgs.append({"role": "user", "content": m["content"]})
        kw = dict(model=self.model, messages=msgs)
        if self.temperature is not None:
            kw["temperature"] = self.temperature
        if tools:
            kw["tools"] = [{"type": "function", "function": {"name": t.name, "description": t.description,
                                                             "parameters": t.parameters}} for t in tools]
        elif json_mode:
            kw["response_format"] = {"type": "json_object"}
        try:
            r = self.client.chat.completions.create(**kw)
        except (openai.RateLimitError, openai.APITimeoutError, openai.APIConnectionError, openai.InternalServerError) as exc:
            raise RetryableLLMError(f"{type(exc).__name__}: {exc}") from exc
        except openai.APIError as exc:
            raise LLMError(f"OpenAI API error: {exc}") from exc
        msg = r.choices[0].message
        calls = []
        for tc in msg.tool_calls or []:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except ValueError:
                args = {"_unparseable_arguments": tc.function.arguments}
            calls.append({"id": tc.id, "name": tc.function.name, "args": args})
        u = r.usage
        return ChatResult(text=msg.content or "", tool_calls=calls, prompt_tokens=u.prompt_tokens if u else 0,
                          completion_tokens=u.completion_tokens if u else 0, total_tokens=u.total_tokens if u else 0)
