"""Typed message contracts between the Tier-2 agents."""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field

from core.patch_ops import PatchPlan

Category = Literal["LINK", "BGP", "ACL", "ROUTING", "OTHER"]
FaultType = Literal[
    "interface_admin_down", "speed_mismatch", "duplex_mismatch", "mtu_mismatch",
    "bgp_remote_as_mismatch", "bgp_auth_mismatch", "bgp_af_not_activated", "bgp_peer_missing_neighbor",
    "bgp_export_policy_blocks", "bgp_import_policy_blocks", "missing_prefix_advertisement",
    "acl_blocks_intended_traffic", "acl_blocks_control_plane", "other",
]


class LLMUsage(BaseModel):
    provider: str
    model: str
    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_ms: float = 0.0
    invalid_responses: int = 0
    retries: int = 0
    source: Literal["provider_reported", "replay"] = "provider_reported"

    def add(self, other: "LLMUsage") -> "LLMUsage":
        for k in ("calls", "prompt_tokens", "completion_tokens", "total_tokens", "invalid_responses", "retries"):
            setattr(self, k, getattr(self, k) + getattr(other, k))
        self.latency_ms = round(self.latency_ms + other.latency_ms, 1)
        return self


class Hypothesis(BaseModel):
    id: str = ""
    device: str
    category: Category
    fault_type: FaultType
    location: str = Field(description="interface, neighbor IP, ACL name or prefix the fault is located at")
    statement: str
    evidence: List[str] = Field(default_factory=list, description="evidence_ids of skill calls / anomaly ids")
    self_reported_confidence: Optional[float] = Field(
        default=None, ge=0, le=1, description="LLM self-assessment; uncalibrated, never used for gating")


class DiagnosisReport(BaseModel):
    strategy: str  # "rule_based" | "llm:<provider>/<model>" | "replay:<provider>/<model>"
    hypotheses: List[Hypothesis]
    reasoning_summary: str = ""
    skill_call_ids: List[str] = Field(default_factory=list)
    usage: Optional[LLMUsage] = None


class PlanProposal(BaseModel):
    strategy: str
    plan: Optional[PatchPlan] = None
    notes: str = ""
    usage: Optional[LLMUsage] = None


class LLMDiagnosisOutput(BaseModel):
    """Schema the LLM must return for diagnosis (validated with Pydantic)."""
    hypotheses: List[Hypothesis] = Field(min_length=1, max_length=6)
    reasoning_summary: str


class LLMPlanOutput(BaseModel):
    """Schema the LLM must return for planning."""
    plan: PatchPlan
    notes: str = ""
