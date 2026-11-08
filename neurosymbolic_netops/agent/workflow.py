"""Incident workflow state machine and the traceable incident record."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from agent.contracts import DiagnosisReport, Hypothesis, LLMUsage
from core.actuation.approval import ApprovalToken
from core.actuation.transaction import TransactionRecord
from core.patch_ops import PatchPlan
from core.skills.base import SkillCall


class State(str, Enum):
    DETECTED = "DETECTED"
    DIAGNOSING = "DIAGNOSING"
    ROOT_CAUSE_IDENTIFIED = "ROOT_CAUSE_IDENTIFIED"
    PLANNING = "PLANNING"
    VERIFYING = "VERIFYING"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    POST_CHECK = "POST_CHECK"
    COMPLETED = "COMPLETED"
    ROLLBACK = "ROLLBACK"
    FAILED = "FAILED"


ALLOWED = {
    State.DETECTED: {State.DIAGNOSING, State.FAILED},
    State.DIAGNOSING: {State.ROOT_CAUSE_IDENTIFIED, State.FAILED},
    State.ROOT_CAUSE_IDENTIFIED: {State.PLANNING, State.COMPLETED, State.FAILED},
    State.PLANNING: {State.VERIFYING, State.PLANNING, State.DIAGNOSING, State.FAILED},
    State.VERIFYING: {State.PLANNING, State.DIAGNOSING, State.APPROVED, State.COMPLETED, State.FAILED},
    State.APPROVED: {State.EXECUTING, State.FAILED},
    State.EXECUTING: {State.POST_CHECK, State.ROLLBACK, State.FAILED},
    State.POST_CHECK: {State.COMPLETED, State.ROLLBACK},
    State.ROLLBACK: {State.FAILED},
    State.COMPLETED: set(),
    State.FAILED: set(),
}


class IllegalTransition(RuntimeError):
    pass


class Transition(BaseModel):
    frm: State
    to: State
    at: str
    reason: str = ""


class PlanAttempt(BaseModel):
    attempt: int
    strategy: str
    plan: Optional[PatchPlan]
    plan_error: Optional[str] = None
    verification_passed: Optional[bool] = None
    verification_backends: List[str] = Field(default_factory=list)
    violated_before: List[str] = Field(default_factory=list)
    violated_after: List[str] = Field(default_factory=list)
    new_violations: List[str] = Field(default_factory=list)
    counterexamples: List[str] = Field(default_factory=list)
    disposition: str = ""  # accepted | adopted_partial_progress | rejected
    verify_ms: float = 0.0


class IncidentRecord(BaseModel):
    incident_id: str
    modes: Dict[str, str]
    state: State = State.DETECTED
    transitions: List[Transition] = Field(default_factory=list)
    digest: Dict[str, Any] = Field(default_factory=dict)
    candidates: List[Dict[str, Any]] = Field(default_factory=list)
    initially_violated: List[str] = Field(default_factory=list)
    diagnoses: List[DiagnosisReport] = Field(default_factory=list)
    final_hypotheses: List[Hypothesis] = Field(default_factory=list)
    tool_calls: List[SkillCall] = Field(default_factory=list)
    attempts: List[PlanAttempt] = Field(default_factory=list)
    final_plan: Optional[PatchPlan] = None
    final_verification: Dict[str, Any] = Field(default_factory=dict)
    approval: Optional[ApprovalToken] = None
    approval_decision: str = ""
    transaction: Optional[TransactionRecord] = None
    outcome: str = "in_progress"
    timings_ms: Dict[str, float] = Field(default_factory=dict)
    llm_usage: Optional[LLMUsage] = None

    def go(self, to: State, reason: str = "") -> None:
        if to not in ALLOWED[self.state]:
            raise IllegalTransition(f"{self.state.value} -> {to.value} not allowed")
        self.transitions.append(Transition(frm=self.state, to=to, at=datetime.now(timezone.utc).isoformat(), reason=reason))
        self.state = to

    def add_usage(self, u: Optional[LLMUsage]) -> None:
        if u is None:
            return
        if self.llm_usage is None:
            self.llm_usage = u.model_copy()
        else:
            self.llm_usage.add(u)
