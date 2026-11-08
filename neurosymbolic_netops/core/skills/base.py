"""Typed skill framework: registry, permission tags, input validation, timeouts, call logging.

Every skill call produces a ``SkillCall`` record with an ``evidence_id`` that hypotheses and
reports can cite. Skills are read-only by construction (they receive no writable handle to
the network); write-side operations live in ``core/actuation`` behind approval tokens.
"""

from __future__ import annotations

import concurrent.futures as cf
import hashlib
import itertools
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Literal, Optional, Type

from pydantic import BaseModel, ValidationError

from core.causal_topology import TopologyGraph
from core.config_ir import Network
from core.network_model import NetworkState, compute_state
from core.telemetry.schema import IncidentDigest, TelemetryEvent

Permission = Literal["read"]
_EXEC = cf.ThreadPoolExecutor(max_workers=4, thread_name_prefix="skill")


class SkillCall(BaseModel):
    call_id: str
    evidence_id: str
    skill: str
    caller: str
    args: Dict[str, Any]
    ok: bool
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    duration_ms: float
    data_source: str


@dataclass
class SkillContext:
    """Read-only view of the (observed) network handed to skills.

    ``data_source`` labels where observations come from: ``local_simulation`` (state computed by
    core.network_model from the running configuration) or ``frr_emulator`` (live device output).
    """
    network: Network
    topology: TopologyGraph
    events: List[TelemetryEvent] = field(default_factory=list)
    digest: Optional[IncidentDigest] = None
    data_source: str = "local_simulation"
    call_log: List[SkillCall] = field(default_factory=list)
    _state: Optional[NetworkState] = None

    @property
    def state(self) -> NetworkState:
        if self._state is None:
            self._state = compute_state(self.network, self.topology)
        return self._state


@dataclass
class Skill:
    name: str
    description: str
    input_model: Type[BaseModel]
    func: Callable[[SkillContext, Any], Dict[str, Any]]
    permission: Permission = "read"
    timeout_s: float = 5.0
    category: str = "general"

    def json_schema(self) -> Dict[str, Any]:
        s = self.input_model.model_json_schema()
        s.pop("title", None)
        return s


class SkillRegistry:
    def __init__(self) -> None:
        self._skills: Dict[str, Skill] = {}
        self.planned: Dict[str, str] = {}
        self._ids = itertools.count(1)

    def register(self, skill: Skill) -> Skill:
        if skill.permission != "read":
            raise ValueError("diagnostic skills must be read-only")
        self._skills[skill.name] = skill
        return skill

    def plan(self, name: str, reason: str) -> None:
        self.planned[name] = reason

    def get(self, name: str) -> Skill:
        return self._skills[name]

    def names(self) -> List[str]:
        return sorted(self._skills)

    def specs(self) -> List[Skill]:
        return [self._skills[n] for n in self.names()]

    def invoke(self, name: str, args: Dict[str, Any], ctx: SkillContext, caller: str = "unknown") -> SkillCall:
        n = next(self._ids)
        call_id = f"C{n:03d}"
        t0 = time.perf_counter()

        def done(ok: bool, result=None, error=None) -> SkillCall:
            payload = repr((name, sorted(args.items()), result, error))
            call = SkillCall(call_id=call_id, evidence_id="E-" + hashlib.sha1(payload.encode()).hexdigest()[:8],
                             skill=name, caller=caller, args=args, ok=ok, result=result, error=error,
                             duration_ms=round((time.perf_counter() - t0) * 1000, 3), data_source=ctx.data_source)
            ctx.call_log.append(call)
            return call

        if name not in self._skills:
            hint = f" (planned: {self.planned[name]})" if name in self.planned else ""
            return done(False, error=f"unknown skill {name!r}{hint}")
        skill = self._skills[name]
        try:
            parsed = skill.input_model.model_validate(args or {})
        except ValidationError as exc:
            return done(False, error=f"invalid arguments: {exc.errors(include_url=False)}")
        fut = _EXEC.submit(skill.func, ctx, parsed)
        try:
            return done(True, result=fut.result(timeout=skill.timeout_s))
        except cf.TimeoutError:
            return done(False, error=f"timeout after {skill.timeout_s}s")
        except (KeyError, ValueError, LookupError) as exc:
            return done(False, error=f"{type(exc).__name__}: {exc}")


def redact_secret(value: Optional[str]) -> Optional[str]:
    """Replace a secret with a short digest so equality can be compared without disclosure."""
    if value is None:
        return None
    return "<redacted sha256:" + hashlib.sha256(value.encode()).hexdigest()[:8] + ">"
