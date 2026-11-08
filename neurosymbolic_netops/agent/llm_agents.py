"""LLM diagnostic and planning strategies (modes ``llm`` / ``offline``).

The model sees the Tier-1 digest, ranked candidates, declared intents and (with tools) may
call the read-only skills; without tools ("LLM-only" condition) it gets the candidate devices'
running configurations in the prompt instead. Output is validated against Pydantic schemas.
The model never verifies or deploys anything: verification and execution are separate agents.
"""

from __future__ import annotations

import json
from typing import List, Optional

from agent.contracts import DiagnosisReport, Hypothesis, LLMDiagnosisOutput, LLMPlanOutput, PlanProposal
from agent.llm.base import LLMError, LLMProvider, ToolSpec, run_structured
from core.intent_schema import IntentSet
from core.skills.base import SkillContext, SkillRegistry

DIAG_SYSTEM = """You are the Diagnostic Agent of a network operations system for a data-center fabric.
Goal: identify the configuration faults (root causes) that explain the incident.
Rules:
- You only have READ-ONLY tools. Use them to gather evidence; do not guess what you can check.
- Base every hypothesis on evidence; put the evidence_id values returned by tools (or anomaly ids like A01) in "evidence".
- A symptom on one device is often caused by the configuration of its link or BGP peer: check both ends.
- Several independent faults may be present at once; report each as a separate hypothesis (most likely first).
- Use canonical interface names (eth1, eth2, eth10, eth20), exact device names and exact neighbor IPs.
- "location" is the interface (e.g. eth1), the BGP neighbor IP, "<ACL name>#<rule index>" for ACL rules, or the prefix.
- self_reported_confidence is optional and is treated as uncalibrated."""

PLAN_SYSTEM = """You are the Planning Agent. Convert fault hypotheses into a minimal repair plan made only of the typed
operations allowed by the JSON schema (never raw CLI). Each op names a device and an exact target that exists.
Rules:
- Change as little as possible; never weaken declared isolation/security intents (e.g. do not remove or unbind a
  security ACL unless you re-establish the same protection).
- Fill "addresses_hypotheses" with the hypothesis ids your plan fixes.
- If verification rejected a previous plan, read the counterexamples carefully and propose a DIFFERENT plan that
  removes the violation without introducing new ones. Inspect configuration with the tools if needed."""


def _tools(reg: SkillRegistry) -> List[ToolSpec]:
    return [ToolSpec(name=s.name, description=s.description, parameters=s.json_schema()) for s in reg.specs()]


def _intent_summary(intents: IntentSet) -> str:
    return "\n".join(f"- {i.id} ({i.kind}): {i.description}" for i in intents.intents)


def _executor(reg: SkillRegistry, ctx: SkillContext, caller: str):
    def run(name: str, args: dict) -> dict:
        c = reg.invoke(name, args, ctx, caller)
        return {"evidence_id": c.evidence_id, "ok": c.ok, "result": c.result} if c.ok else \
               {"evidence_id": c.evidence_id, "ok": False, "error": c.error}
    return run


class LLMDiagnoser:
    def __init__(self, provider: LLMProvider, registry: SkillRegistry, intents: IntentSet, use_tools: bool = True):
        self.p, self.reg, self.intents, self.use_tools = provider, registry, intents, use_tools
        label = "replay" if provider.source == "replay" else "llm"
        self.strategy = f"{label}:{provider.provider}/{provider.model}" + ("" if use_tools else " (no tools)")

    def diagnose(self, ctx: SkillContext, candidates: List[str], feedback: Optional[List[str]] = None) -> DiagnosisReport:
        start = len(ctx.call_log)
        digest = [a.model_dump(mode="json", include={"anomaly_id", "kind", "device", "interface", "peer_ip", "flow", "count", "summary"})
                  for a in (ctx.digest.anomalies if ctx.digest else [])]
        parts = [f"INCIDENT ANOMALY DIGEST (Tier-1 edge detectors):\n{json.dumps(digest, indent=1)}",
                 f"MISSING TELEMETRY: {ctx.digest.missing_data if ctx.digest else []}",
                 f"TOPOLOGY-RANKED CANDIDATE DEVICES (most suspicious first): {candidates}",
                 f"DECLARED INTENTS:\n{_intent_summary(self.intents)}"]
        if feedback:
            parts.append("VERIFICATION FEEDBACK FROM PREVIOUS ITERATION:\n" + "\n".join(feedback))
        if not self.use_tools:
            from core.skills.library import DeviceArg, get_running_config
            cfgs = [get_running_config(ctx, DeviceArg(device=d))["config"] for d in (candidates or sorted(ctx.network))]
            parts.append("RUNNING CONFIGURATIONS:\n" + "\n\n".join(cfgs))
        try:
            out, usage, _ = run_structured(self.p, DIAG_SYSTEM, "\n\n".join(parts), LLMDiagnosisOutput,
                                           tools=_tools(self.reg) if self.use_tools else None,
                                           execute_tool=_executor(self.reg, ctx, "diagnostic_agent[llm]"))
        except LLMError as exc:
            return DiagnosisReport(strategy=self.strategy, hypotheses=[], reasoning_summary=f"LLM ERROR: {exc}",
                                   skill_call_ids=[c.call_id for c in ctx.call_log[start:]])
        hyps = [h for h in out.hypotheses if h.device in ctx.network]
        for k, h in enumerate(hyps, 1):
            h.id = f"H{k}"
        return DiagnosisReport(strategy=self.strategy, hypotheses=hyps, reasoning_summary=out.reasoning_summary,
                               skill_call_ids=[c.call_id for c in ctx.call_log[start:]], usage=usage)


class LLMPlanner:
    def __init__(self, provider: LLMProvider, registry: SkillRegistry, intents: IntentSet):
        self.p, self.reg, self.intents = provider, registry, intents
        self.strategy = ("replay" if provider.source == "replay" else "llm") + f":{provider.provider}/{provider.model}"

    def plan(self, ctx: SkillContext, hypotheses: List[Hypothesis], feedback: Optional[List[str]] = None,
             exclude: Optional[set] = None) -> PlanProposal:
        from core.skills.library import DeviceArg, get_running_config
        devs = sorted({h.device for h in hypotheses})
        parts = [f"HYPOTHESES:\n{json.dumps([h.model_dump() for h in hypotheses], indent=1)}",
                 f"DECLARED INTENTS:\n{_intent_summary(self.intents)}",
                 "RUNNING CONFIGURATION OF AFFECTED DEVICES (IOS rendering; canonical names: GigabitEthernet0/N = ethN):\n"
                 + "\n\n".join(get_running_config(ctx, DeviceArg(device=d))["config"] for d in devs)]
        if feedback:
            parts.append("FEEDBACK:\n" + "\n".join(feedback))
        try:
            out, usage, _ = run_structured(self.p, PLAN_SYSTEM, "\n\n".join(parts), LLMPlanOutput, tools=_tools(self.reg),
                                           execute_tool=_executor(self.reg, ctx, "planning_agent[llm]"), max_tool_rounds=6)
        except LLMError as exc:
            return PlanProposal(strategy=self.strategy, plan=None, notes=f"LLM ERROR: {exc}")
        return PlanProposal(strategy=self.strategy, plan=out.plan, notes=out.notes, usage=usage)
