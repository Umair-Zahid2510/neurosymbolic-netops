"""Compatibility facade (pre-audit module name).

The old contents (a regex checker presented as Batfish, with ``loop_free = True`` hardcoded) were
removed. Use ``core.verification.make_verifier("batfish" | "local", topology)``:
* ``core/verification/batfish_backend.py``  real pybatfish backend (label ``batfish``)
* ``core/verification/local_symbolic.py``   local model (labels ``local_symbolic`` / ``ir_static``)
"""
from core.verification import CompositeVerifier, make_verifier  # noqa: F401
from core.verification.batfish_backend import BatfishBackend, BatfishUnavailable, batfish_reachable  # noqa: F401
from core.verification.base import VerificationReport  # noqa: F401
