"""Compatibility facade (pre-audit module name).

The old regex config editor and dict-swap "two-phase commit" were removed. See
``core/actuation/transaction.py`` (prepare/commit with compensating rollback),
``core/actuation/adapters.py`` (fault-injectable SIMULATED adapter) and ``core/patch_ops.py``.
"""
from core.actuation.adapters import FaultInjection, InMemoryAdapter  # noqa: F401
from core.actuation.transaction import TransactionEngine, TransactionRecord  # noqa: F401
from core.patch_ops import PatchPlan, apply_plan  # noqa: F401
