"""Central configuration loading and secret-key handling.

* ``load_env()`` loads ``neurosymbolic_netops/.env`` once (existing environment variables win).
* ``secret_key(var)`` returns the HMAC key from ``var``. There is no hardcoded fallback: if the
  variable is unset, a random per-process key is generated and ``is_ephemeral(var)`` reports it.
  Tokens and audit chains signed with an ephemeral key are valid only inside that process, so
  persistent audit logs and cross-process approval require the variable to be set.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Dict

ROOT = Path(__file__).resolve().parent.parent
_loaded = False
_ephemeral: Dict[str, bytes] = {}


def load_env() -> None:
    global _loaded
    if _loaded:
        return
    try:
        from dotenv import load_dotenv
        load_dotenv(ROOT / ".env", override=False)
    except ImportError:  # pragma: no cover
        pass
    _loaded = True


def secret_key(var: str) -> bytes:
    load_env()
    val = os.environ.get(var)
    if val:
        if len(val) < 16:
            raise ValueError(f"{var} must be at least 16 characters")
        return val.encode()
    if var not in _ephemeral:
        _ephemeral[var] = secrets.token_bytes(32)
    return _ephemeral[var]


def is_ephemeral(var: str) -> bool:
    load_env()
    return not os.environ.get(var)
