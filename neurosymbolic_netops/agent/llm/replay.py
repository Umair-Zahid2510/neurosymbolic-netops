"""Record / replay of LLM exchanges (mode ``offline``).

``RecordingProvider`` wraps a live provider and stores every exchange in a cassette.
``ReplayProvider`` serves exchanges from the cassette by exact request hash and raises on a
miss. Replayed results are labelled ``source="replay"`` everywhere and must never be reported
as live provider runs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

from agent.llm.base import ChatResult, LLMError, LLMProvider, cassette_key

DEFAULT_CASSETTE = Path(__file__).resolve().parents[2] / "runtime" / "llm_cassette.json"


def _load(path: Path) -> Dict[str, dict]:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


@dataclass
class RecordingProvider(LLMProvider):
    inner: Optional[LLMProvider] = None
    cassette: Path = DEFAULT_CASSETTE

    def __post_init__(self):
        self.provider, self.model, self.source = self.inner.provider, self.inner.model, self.inner.source

    def _chat_once(self, system, messages, tools, json_mode) -> ChatResult:
        res = self.inner._chat_once(system, messages, tools, json_mode)
        data = _load(self.cassette)
        data[cassette_key(self.provider, self.model, system, messages, tools, json_mode)] = {
            "text": res.text, "tool_calls": res.tool_calls, "prompt_tokens": res.prompt_tokens,
            "completion_tokens": res.completion_tokens, "total_tokens": res.total_tokens}
        self.cassette.parent.mkdir(parents=True, exist_ok=True)
        self.cassette.write_text(json.dumps(data, indent=1), encoding="utf-8")
        return res


@dataclass
class ReplayProvider(LLMProvider):
    provider: str = "gemini"
    model: str = "gemini-2.5-flash"
    cassette: Path = DEFAULT_CASSETTE
    source: str = "replay"
    _data: Dict[str, dict] = field(default_factory=dict)

    def __post_init__(self):
        self._data = _load(self.cassette)

    def _chat_once(self, system, messages, tools, json_mode) -> ChatResult:
        k = cassette_key(self.provider, self.model, system, messages, tools, json_mode)
        if k not in self._data:
            raise LLMError("replay miss: this request was never recorded (offline mode cannot call a live model)")
        d = self._data[k]
        return ChatResult(text=d["text"], tool_calls=d["tool_calls"], prompt_tokens=d["prompt_tokens"],
                          completion_tokens=d["completion_tokens"], total_tokens=d["total_tokens"])
