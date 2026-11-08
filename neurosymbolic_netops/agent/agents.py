"""The five Tier-2 agents. Responsibilities and tool access are deliberately disjoint:

=================  =====================================  ======================================
Agent              Responsibility                          Tool access
=================  =====================================  ======================================
DiagnosticAgent    evidence -> ranked fault hypotheses     read-only skills
PlanningAgent      hypotheses (+counterexamples) -> plan   read-only skills; emits typed PatchOps
VerificationAgent  plan -> verdict + counterexamples       verifier backends only; never an LLM
ExecutionAgent     approved plan -> transaction            transaction engine (write side)
Supervisor         state machine, budgets, approval,       orchestrates the others
                   reflection policy, incident record
=================  =====================================  ======================================

Diagnostic and planning *strategies* are pluggable: ``rule_based`` (deterministic) or an LLM
strategy from ``agent/llm_agents.py``. The verification and execution agents are identical
across modes, so experimental conditions differ only in the reasoning strategy.
"""

from __future__ import annotations

from typing import List, Optional, Protocol

from agent.contracts import DiagnosisReport, Hypothesis, PlanProposal
from core.actuation.approval import ApprovalToken
from core.actuation.transaction import TransactionEngine, TransactionRecord
from core.config_ir import Network
from core.intent_schema import IntentSet
from core.patch_ops import PatchPlan
from core.skills.base import SkillContext
from core.verification.base import VerificationReport


class DiagnosisStrategy(Protocol):
    strategy: str

    def diagnose(self, ctx: SkillContext, candidates: List[str], feedback: Optional[List[str]] = None) -> DiagnosisReport: ...


class PlanningStrategy(Protocol):
    strategy: str

    def plan(self, ctx: SkillContext, hypotheses: List[Hypothesis], feedback: Optional[List[str]] = None,
             exclude: Optional[set] = None) -> PlanProposal: ...


class DiagnosticAgent:
    role = "diagnostic_agent"

    def __init__(self, strategy: DiagnosisStrategy):
        self.strategy = strategy

    def run(self, ctx: SkillContext, candidates: List[str], feedback: Optional[List[str]] = None) -> DiagnosisReport:
        return self.strategy.diagnose(ctx, candidates, feedback)


class PlanningAgent:
    role = "planning_agent"

    def __init__(self, strategy: PlanningStrategy):
        self.strategy = strategy

    def run(self, ctx: SkillContext, hypotheses: List[Hypothesis], feedback: Optional[List[str]] = None,
            exclude: Optional[set] = None) -> PlanProposal:
        return self.strategy.plan(ctx, hypotheses, feedback, exclude)


class VerificationAgent:
    role = "verification_agent"

    def __init__(self, verifier, intents: IntentSet):
        self.verifier = verifier
        self.intents = intents

    @property
    def backend(self) -> str:
        return getattr(self.verifier, "name", "unknown")

    def run(self, network: Network) -> VerificationReport:
        return self.verifier.verify(network, self.intents)


class ExecutionAgent:
    role = "execution_agent"

    def __init__(self, engine: TransactionEngine):
        self.engine = engine

    def run(self, plan: PatchPlan, token: Optional[ApprovalToken]) -> TransactionRecord:
        return self.engine.execute(plan, token, actor=self.role)
