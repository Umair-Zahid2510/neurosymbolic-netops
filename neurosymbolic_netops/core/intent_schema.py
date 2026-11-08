"""Pydantic declarative intent schemas conforming to YANG/OpenConfig-style abstractions."""

from typing import Literal
from pydantic import BaseModel, Field


class ConfigurationPatch(BaseModel):
    target_device: str
    subsystem: Literal["INTERFACE", "BGP", "ROUTING", "ACL"]
    command_block: str
    rollback_command_block: str
    justification: str


class AgentDiagnosticOutput(BaseModel):
    identified_culprit_device: str
    failure_category: Literal["LINK", "BGP", "ACL", "COMPOUND"]
    root_cause_analysis: str
    confidence_score: float = Field(ge=0.0, le=1.0)
    proposed_patch: ConfigurationPatch
