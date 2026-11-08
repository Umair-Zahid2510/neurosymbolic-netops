"""Backend-independent verification contracts.

Every verifier backend returns a ``VerificationReport`` with one ``CheckResult`` per intent.
Each result names the backend that produced it, so a report can never present a local
simulation result as a Batfish result.
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, Protocol

from pydantic import BaseModel, Field

from core.config_ir import Network
from core.intent_schema import IntentSet

BackendName = Literal["batfish", "local_symbolic", "ir_static", "mock"]


class Counterexample(BaseModel):
    intent_id: str
    summary: str
    flow: Optional[str] = None
    path: List[str] = Field(default_factory=list)
    disposition: Optional[str] = None
    device: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class CheckResult(BaseModel):
    intent_id: str
    intent_kind: str
    backend: BackendName
    passed: Optional[bool]  # None = this backend cannot evaluate the intent
    counterexamples: List[Counterexample] = Field(default_factory=list)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    note: str = ""


class VerificationReport(BaseModel):
    backends: List[BackendName]
    passed: bool
    checks: List[CheckResult]
    parse_issues: List[str] = Field(default_factory=list)
    unevaluated_intents: List[str] = Field(default_factory=list)
    network_fingerprint: str
    duration_ms: float

    def violated(self) -> List[str]:
        return sorted({c.intent_id for c in self.checks if c.passed is False})

    def counterexamples(self) -> List[Counterexample]:
        return [ce for c in self.checks for ce in c.counterexamples]

    def summary_lines(self, limit: int = 20) -> List[str]:
        lines = [f"[{c.backend}] {c.intent_id}: {ce.summary}" for c in self.checks if c.passed is False
                 for ce in c.counterexamples]
        return lines[:limit]


class VerifierBackend(Protocol):
    name: BackendName

    def verify(self, network: Network, intents: IntentSet) -> VerificationReport: ...


def combine(reports: List[VerificationReport], fingerprint: str) -> VerificationReport:
    """Merge reports from several backends. An intent passes only if no backend reports a
    violation and at least one backend evaluated it."""
    checks = [c for r in reports for c in r.checks]
    by_id: Dict[str, List[CheckResult]] = {}
    for c in checks:
        by_id.setdefault(c.intent_id, []).append(c)
    unevaluated = sorted(i for i, cs in by_id.items() if all(c.passed is None for c in cs))
    failed = any(c.passed is False for c in checks)
    issues = [p for r in reports for p in r.parse_issues]
    return VerificationReport(
        backends=[b for r in reports for b in r.backends], passed=(not failed and not unevaluated and not issues),
        checks=checks, parse_issues=issues, unevaluated_intents=unevaluated,
        network_fingerprint=fingerprint, duration_ms=round(sum(r.duration_ms for r in reports), 2))
