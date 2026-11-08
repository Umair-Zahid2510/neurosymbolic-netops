"""Append-only, HMAC-SHA256 hash-chained audit log.

Each entry stores ``prev`` (the previous entry's MAC) and ``mac = HMAC(key, prev || canonical
JSON of the entry)``. Any edit, deletion or reordering breaks verification. This provides
tamper *evidence* with a shared secret key; it is not PKI non-repudiation (see LIMITATIONS.md).
Secrets in payloads are redacted before writing.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_SECRET_KEYS = re.compile(r"(password|secret|api[_-]?key|token|authorization)", re.I)
GENESIS = "0" * 64


def redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: ("<redacted>" if _SECRET_KEYS.search(str(k)) and v is not None else redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    if isinstance(obj, str):
        return re.sub(r"(password\s+)\S+", r"\1<redacted>", obj)
    return obj


class AuditLog:
    def __init__(self, path: Optional[Path] = None, key: Optional[bytes] = None):
        self.path = Path(path) if path else None
        from core.settings import is_ephemeral, secret_key
        self._key = key or secret_key("NETOPS_AUDIT_HMAC_KEY")
        # no hardcoded fallback: without the variable a random per-process key is used, so a log
        # written to disk can only be verified later if NETOPS_AUDIT_HMAC_KEY is set
        self.ephemeral_key = key is None and is_ephemeral("NETOPS_AUDIT_HMAC_KEY")
        self._lock = threading.Lock()
        self.entries: List[Dict[str, Any]] = []
        if self.path and self.path.exists():
            self.entries = [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def _mac(self, prev: str, body: Dict[str, Any]) -> str:
        msg = prev.encode() + json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(self._key, msg, hashlib.sha256).hexdigest()

    def append(self, actor: str, action: str, **payload: Any) -> Dict[str, Any]:
        with self._lock:
            prev = self.entries[-1]["mac"] if self.entries else GENESIS
            body = {"seq": len(self.entries), "ts": datetime.now(timezone.utc).isoformat(), "actor": actor,
                    "action": action, "payload": redact(payload), "prev": prev}
            entry = dict(body, mac=self._mac(prev, body))
            self.entries.append(entry)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, sort_keys=True) + "\n")
            return entry

    def verify(self, entries: Optional[List[Dict[str, Any]]] = None) -> Tuple[bool, Optional[int]]:
        """Return (ok, first_bad_seq)."""
        prev = GENESIS
        for k, e in enumerate(entries if entries is not None else self.entries):
            body = {x: e[x] for x in ("seq", "ts", "actor", "action", "payload", "prev")}
            if e["prev"] != prev or e["seq"] != k or not hmac.compare_digest(e["mac"], self._mac(prev, body)):
                return False, k
            prev = e["mac"]
        return True, None
