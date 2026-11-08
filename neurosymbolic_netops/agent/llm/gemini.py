"""Google Gemini provider (google-genai SDK). Requires GEMINI_API_KEY (or GOOGLE_API_KEY)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List, Optional

from agent.llm.base import ChatResult, LLMError, LLMProvider, RetryableLLMError, ToolSpec


@dataclass
class GeminiProvider(LLMProvider):
    provider: str = "gemini"
    model: str = "gemini-2.5-flash"
    api_key: Optional[str] = None
    client: object = None  # injectable for tests

    def __post_init__(self):
        if self.client is None:
            key = self.api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
            if not key:
                raise LLMError("GEMINI_API_KEY is not set; choose NETOPS_LLM_MODE=rule_based or offline explicitly")
            from google import genai
            from google.genai import types
            self.client = genai.Client(api_key=key, http_options=types.HttpOptions(timeout=int(self.timeout_s * 1000)))

    def _contents(self, messages: List[dict]):
        from google.genai import types
        out = []
        for m in messages:
            if m["role"] == "user":
                out.append(types.Content(role="user", parts=[types.Part.from_text(text=m["content"])]))
            elif m["role"] == "assistant":
                if m.get("_raw") is not None:  # preserves thought signatures / function-call parts
                    out.append(m["_raw"])
                else:
                    parts = [types.Part.from_function_call(name=tc["name"], args=tc.get("args") or {}) for tc in m.get("tool_calls") or []]
                    if m.get("content"):
                        parts.insert(0, types.Part.from_text(text=m["content"]))
                    out.append(types.Content(role="model", parts=parts))
            elif m["role"] == "tool":
                import json
                try:
                    resp = json.loads(m["content"])
                except ValueError:
                    resp = {"result": m["content"]}
                part = types.Part.from_function_response(name=m["name"], response=resp if isinstance(resp, dict) else {"result": resp})
                if out and out[-1].role == "user" and all(p.function_response for p in out[-1].parts):
                    out[-1].parts.append(part)
                else:
                    out.append(types.Content(role="user", parts=[part]))
        return out

    def _chat_once(self, system, messages, tools, json_mode) -> ChatResult:
        from google.genai import errors, types
        cfg = dict(system_instruction=system,
                   automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True))
        if self.temperature is not None:
            cfg["temperature"] = self.temperature
        if tools:
            cfg["tools"] = [types.Tool(function_declarations=[
                types.FunctionDeclaration(name=t.name, description=t.description, parameters_json_schema=t.parameters)
                for t in tools])]
        elif json_mode:
            cfg["response_mime_type"] = "application/json"
        try:
            resp = self.client.models.generate_content(model=self.model, contents=self._contents(messages),
                                                       config=types.GenerateContentConfig(**cfg))
        except errors.APIError as exc:
            code = getattr(exc, "code", None)
            if code in (408, 429, 500, 502, 503, 504):
                raise RetryableLLMError(f"HTTP {code}: {exc}") from exc
            raise LLMError(f"Gemini API error {code}: {exc}") from exc
        except (TimeoutError, ConnectionError) as exc:
            raise RetryableLLMError(str(exc)) from exc
        calls = [{"id": getattr(fc, "id", None) or f"g{k}", "name": fc.name, "args": dict(fc.args or {})}
                 for k, fc in enumerate(resp.function_calls or [])]
        text = ""
        try:
            text = resp.text or ""
        except (ValueError, AttributeError):
            text = ""
        um = resp.usage_metadata
        pt = (um.prompt_token_count or 0) if um else 0
        ct = ((um.candidates_token_count or 0) + (um.thoughts_token_count or 0)) if um else 0
        raw = resp.candidates[0].content if resp.candidates else None
        return ChatResult(text=text, tool_calls=calls, prompt_tokens=pt, completion_tokens=ct,
                          total_tokens=(um.total_token_count or pt + ct) if um else pt + ct, raw_message=raw)
