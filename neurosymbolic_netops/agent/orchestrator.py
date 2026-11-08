"""End-to-end orchestration: Tier 1 (telemetry -> digest) through Tier 4 (transaction).

``build_system`` wires the agents for one experimental condition; ``run_incident`` executes a
scenario (a faulty network plus generated telemetry) through the full pipeline. Every result
carries the labels of the components that produced it.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from agent.agents import DiagnosticAgent, ExecutionAgent, PlanningAgent, VerificationAgent
from agent.rule_based_diagnoser import RuleBasedDiagnoser, RuleBasedPlanner
from agent.supervisor import Supervisor, SupervisorConfig
from agent.workflow import IncidentRecord
from core.actuation.adapters import FaultInjection, InMemoryAdapter
from core.actuation.approval import ApprovalAuthority, AutoApproveVerifiedPolicy
from core.actuation.audit import AuditLog
from core.actuation.transaction import TransactionEngine
from core.config_ir import Network
from core.inventory import Testbed
from core.skills.library import build_registry
from core.telemetry.anomaly import EdgeDetector, load_or_train
from core.telemetry.generator import GeneratorOptions, generate
from core.telemetry.normalize import Normalizer
from core.verification import make_verifier


@dataclass
class SystemConfig:
    reasoning: str = "rule_based"          # rule_based | llm | offline
    llm_tools: bool = True                 # LLM may call read-only skills
    verifier: str = "local"                # local | batfish | none
    max_attempts: int = 4
    allow_partial_progress: bool = True
    execute: bool = True
    adapter_faults: FaultInjection = field(default_factory=FaultInjection)
    llm_provider: Optional[object] = None  # an agent.llm.base.LLMProvider for reasoning in (llm, offline)
    audit_path: Optional[Path] = None


@dataclass
class IncidentRun:
    record: IncidentRecord
    detection_ms: float
    digest_bytes: int
    raw_bytes: int
    audit_ok: bool
    audit_entries: int
    final_network: Optional[Network] = None


def build_supervisor(tb: Testbed, observed: Network, cfg: SystemConfig, audit: AuditLog) -> Supervisor:
    reg = build_registry()
    if cfg.reasoning == "rule_based":
        dstrat, pstrat = RuleBasedDiagnoser(reg, tb.intents), RuleBasedPlanner(reg)
    elif cfg.reasoning in ("llm", "offline"):
        from agent.llm_agents import LLMDiagnoser, LLMPlanner
        if cfg.llm_provider is None:
            raise ValueError("reasoning=llm/offline requires an explicit llm_provider (no silent fallback)")
        dstrat = LLMDiagnoser(cfg.llm_provider, reg, tb.intents, use_tools=cfg.llm_tools)
        pstrat = LLMPlanner(cfg.llm_provider, reg, tb.intents)
    else:
        raise ValueError(f"unknown reasoning mode {cfg.reasoning!r}")
    gate = cfg.verifier != "none"
    verifier = make_verifier(cfg.verifier if gate else "local", tb.topology)
    post_verifier = make_verifier("local", tb.topology)  # evaluates the adapter's observed state
    authority = ApprovalAuthority()
    engine = TransactionEngine(InMemoryAdapter(observed, cfg.adapter_faults), verifier if gate else None,
                               post_verifier, tb.intents, authority, audit)
    return Supervisor(tb.topology, DiagnosticAgent(dstrat), PlanningAgent(pstrat), VerificationAgent(verifier, tb.intents),
                      ExecutionAgent(engine), AutoApproveVerifiedPolicy(), authority,
                      SupervisorConfig(max_attempts=cfg.max_attempts, allow_partial_progress=cfg.allow_partial_progress,
                                       execute=cfg.execute, use_verification_gate=gate))


def run_incident(tb: Testbed, incident_id: str, faulty: Network, cfg: SystemConfig,
                 telemetry: Optional[GeneratorOptions] = None, detector: Optional[EdgeDetector] = None) -> IncidentRun:
    gen = generate(tb.network, faulty, tb.topology, tb.intents, telemetry or GeneratorOptions())
    raw_bytes = sum(len(json.dumps(r)) for r in gen.records)
    t0 = time.perf_counter()
    events = Normalizer(lambda ip: tb.topology.owner_of_ip(ip, tb.network)).normalize(gen.records)
    digest = (detector or EdgeDetector(load_or_train())).detect(incident_id, events, raw_bytes, tb.topology.devices)
    detection_ms = (time.perf_counter() - t0) * 1000
    audit = AuditLog(cfg.audit_path)
    sup = build_supervisor(tb, faulty, cfg, audit)
    rec = sup.handle(incident_id, faulty, digest, events)
    ok, _ = audit.verify()
    return IncidentRun(record=rec, detection_ms=round(detection_ms, 2), digest_bytes=digest.digest_bytes,
                       raw_bytes=raw_bytes, audit_ok=ok, audit_entries=len(audit.entries),
                       final_network=sup.exe.engine.adapter.observed_network() if sup.exe else None)
