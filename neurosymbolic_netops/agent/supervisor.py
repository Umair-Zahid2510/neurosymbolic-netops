"""Supervisor agent: drives the incident state machine and the bounded reflection loop.

Reflection loop (survey sections 2.3 / 5.2; Cornetto-style "accept iff verified"):
  diagnose -> plan -> verify -> (pass) approve -> execute -> post-check
                         |
                         +-- (fail) counterexamples go back to the planner (and, after partial
                             progress, to the diagnostic agent) until ``max_attempts``.

Partial-progress policy (explicit, recorded per attempt): a plan that fails verification may be
*adopted into the working candidate* (never deployed on its own) only if it strictly reduces
the set of violated intents and introduces no new violation. The final deployed plan must
still pass verification as a whole against the original network.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import List, Optional

from agent.agents import DiagnosticAgent, ExecutionAgent, PlanningAgent, VerificationAgent
from agent.workflow import IncidentRecord, PlanAttempt, State
from core.actuation.approval import ApprovalAuthority
from core.causal_topology import TopologyGraph
from core.config_ir import Network, network_fingerprint
from core.patch_ops import PatchError, PatchPlan, apply_plan
from core.skills.base import SkillContext
from core.telemetry.schema import IncidentDigest, TelemetryEvent


@dataclass
class SupervisorConfig:
    max_attempts: int = 4
    allow_partial_progress: bool = True
    execute: bool = True
    keep_hops: int = 1
    use_verification_gate: bool = True   # False = "unverified" ablation (plan goes straight to approval)


class Supervisor:
    role = "supervisor"

    def __init__(self, topology: TopologyGraph, diagnostic: DiagnosticAgent, planning: PlanningAgent,
                 verification: VerificationAgent, execution: Optional[ExecutionAgent], approval_policy,
                 authority: ApprovalAuthority, config: Optional[SupervisorConfig] = None):
        self.topology = topology
        self.diag, self.plan, self.verify, self.exe = diagnostic, planning, verification, execution
        self.policy = approval_policy
        self.authority = authority
        self.cfg = config or SupervisorConfig()

    def handle(self, incident_id: str, observed: Network, digest: IncidentDigest,
               events: Optional[List[TelemetryEvent]] = None, data_source: str = "local_simulation") -> IncidentRecord:
        t_all = time.perf_counter()
        rec = IncidentRecord(incident_id=incident_id, modes={
            "diagnosis": self.diag.strategy.strategy, "planning": self.plan.strategy.strategy,
            "verifier": self.verify.backend if self.cfg.use_verification_gate else "NONE (ablation)",
            "actuation": (self.exe.engine.adapter.name + "/" + self.exe.engine.adapter.label) if self.exe and self.cfg.execute else "none",
            "approval": getattr(self.policy, "name", "unknown"), "telemetry": data_source})
        rec.digest = {"anomalies": [a.model_dump(mode="json") for a in digest.anomalies],
                      "missing_data": digest.missing_data, "raw_bytes": digest.raw_bytes, "digest_bytes": digest.digest_bytes}
        timings = {"diagnose": 0.0, "plan": 0.0, "verify": 0.0, "execute": 0.0}

        ranked = self.topology.rank_candidates(digest.anomalies, observed)
        rec.candidates = [c.model_dump() for c in ranked]
        kept = self.topology.prune(ranked, keep_hops=self.cfg.keep_hops)
        order = [c.device for c in ranked] + [d for d in kept if d not in {c.device for c in ranked}]
        candidates = [d for d in order if d in kept]

        t0 = time.perf_counter()
        base = self.verify.run(observed)
        timings["verify"] += (time.perf_counter() - t0) * 1000
        rec.initially_violated = base.violated()

        ctx = SkillContext(network=observed, topology=self.topology, events=events or [], digest=digest, data_source=data_source)
        rec.go(State.DIAGNOSING, f"{len(digest.anomalies)} anomalies; violated intents {base.violated()}")
        working, adopted = observed, []
        violated_now = base.violated()
        feedback: List[str] = []
        exclude: set = set()
        need_diag = True
        diag = None
        accepted: Optional[PatchPlan] = None

        for attempt in range(1, self.cfg.max_attempts + 1):
            if need_diag:
                if rec.state != State.DIAGNOSING:
                    rec.go(State.DIAGNOSING, "re-diagnose after partial progress" if adopted else "re-diagnose")
                ctx = SkillContext(network=working, topology=self.topology, events=events or [], digest=digest,
                                   data_source=data_source, call_log=ctx.call_log)
                t0 = time.perf_counter()
                diag = self.diag.run(ctx, candidates, feedback or None)
                timings["diagnose"] += (time.perf_counter() - t0) * 1000
                rec.diagnoses.append(diag)
                rec.add_usage(diag.usage)
                if not diag.hypotheses:
                    rec.go(State.FAILED, "no hypothesis produced")
                    rec.outcome = "no_hypothesis"
                    break
                if not violated_now and not adopted:
                    rec.go(State.ROOT_CAUSE_IDENTIFIED, "hypotheses found but no intent is violated")
                    rec.final_hypotheses = diag.hypotheses
                    rec.go(State.COMPLETED, "advisory only: no intent violation to repair")
                    rec.outcome = "no_violation"
                    break
                rec.go(State.ROOT_CAUSE_IDENTIFIED, f"{len(diag.hypotheses)} hypotheses")
                rec.go(State.PLANNING)
                need_diag = False
            else:
                rec.go(State.PLANNING, "revise plan using counterexamples")
            t0 = time.perf_counter()
            prop = self.plan.run(ctx, diag.hypotheses, feedback or None, exclude)
            timings["plan"] += (time.perf_counter() - t0) * 1000
            rec.add_usage(prop.usage)
            att = PlanAttempt(attempt=attempt, strategy=prop.strategy, plan=prop.plan, violated_before=list(violated_now))
            rec.attempts.append(att)
            if prop.plan is None:
                att.disposition = "no_plan"
                att.plan_error = prop.notes
                rec.go(State.FAILED, f"planner produced no plan: {prop.notes}")
                rec.outcome = "no_plan"
                break
            try:
                candidate = apply_plan(working, prop.plan)
            except PatchError as exc:
                att.plan_error, att.disposition = str(exc), "invalid_plan"
                feedback = [f"PLAN INVALID: {exc}"]
                continue
            if not self.cfg.use_verification_gate:
                att.disposition = "accepted_unverified"
                accepted = PatchPlan(ops=[o for p in adopted for o in p.ops] + list(prop.plan.ops),
                                     rationale=prop.plan.rationale, addresses_hypotheses=prop.plan.addresses_hypotheses)
                rec.go(State.VERIFYING, "verification gate disabled (ablation)")
                break
            rec.go(State.VERIFYING)
            t0 = time.perf_counter()
            rep = self.verify.run(candidate)
            att.verify_ms = round((time.perf_counter() - t0) * 1000, 2)
            timings["verify"] += att.verify_ms
            att.verification_passed, att.verification_backends = rep.passed, list(rep.backends)
            att.violated_after = rep.violated()
            att.new_violations = sorted(set(rep.violated()) - set(violated_now))
            att.counterexamples = rep.summary_lines()
            if rep.passed:
                att.disposition = "accepted"
                accepted = PatchPlan(ops=[o for p in adopted for o in p.ops] + list(prop.plan.ops),
                                     rationale=" | ".join([p.rationale for p in adopted] + [prop.plan.rationale]),
                                     addresses_hypotheses=[h for p in adopted for h in p.addresses_hypotheses] + prop.plan.addresses_hypotheses)
                break
            progressed = (self.cfg.allow_partial_progress and not att.new_violations
                          and len(rep.violated()) < len(violated_now))
            if progressed:
                att.disposition = "adopted_partial_progress"
                working, violated_now = candidate, rep.violated()
                adopted.append(prop.plan)
                feedback = ["Previous changes were kept (partial progress). Remaining violations:"] + rep.summary_lines()
                need_diag = True
            else:
                att.disposition = "rejected"
                feedback = (["REJECTED by verification. Violations after applying your plan:"] + rep.summary_lines()
                            + ([f"NEW violations introduced by your plan: {att.new_violations}"] if att.new_violations else []))
                bad_devs = {ce.device for c in rep.checks if c.intent_id in att.new_violations for ce in c.counterexamples if ce.device}
                bad_devs |= {ce.details.get("acl_hit", {}).get("device") for c in rep.checks if c.intent_id in att.new_violations
                             for ce in c.counterexamples} - {None}
                hyp_by_id = {h.id: h for h in diag.hypotheses}
                for hid in prop.plan.addresses_hypotheses:
                    h = hyp_by_id.get(hid)
                    if h and (not bad_devs or h.device in bad_devs):
                        exclude.add((h.device, h.fault_type, h.location))
                if not att.new_violations:
                    need_diag = True

        rec.tool_calls = list(ctx.call_log)
        rec.final_hypotheses = diag.hypotheses if diag else []
        if rec.state in (State.FAILED, State.COMPLETED):
            return self._finish(rec, timings, t_all)
        if accepted is None:
            rec.go(State.FAILED, f"no verified plan within {self.cfg.max_attempts} attempts")
            rec.outcome = "rejected_unverified"
            return self._finish(rec, timings, t_all)

        rec.final_plan = accepted
        final_net = apply_plan(observed, accepted)
        fp = network_fingerprint(final_net)
        if self.cfg.use_verification_gate:
            t0 = time.perf_counter()
            final_rep = self.verify.run(final_net)
            timings["verify"] += (time.perf_counter() - t0) * 1000
            rec.final_verification = {"passed": final_rep.passed, "backends": final_rep.backends,
                                      "violated": final_rep.violated(), "fingerprint": fp}
            ok = final_rep.passed
        else:
            rec.final_verification = {"passed": None, "backends": [], "note": "verification gate disabled"}
            ok = True
        approve, why = self.policy.decide(accepted, ok, f"Incident {incident_id}: plan {accepted.plan_hash()[:12]}")
        rec.approval_decision = why
        if not approve:
            rec.go(State.FAILED, f"approval denied: {why}")
            rec.outcome = "approval_denied"
            return self._finish(rec, timings, t_all)
        rec.approval = self.authority.issue(accepted, fp, approver=getattr(self.policy, "name", "unknown"),
                                            policy=getattr(self.policy, "name", "unknown"))
        rec.go(State.APPROVED, why)
        if not (self.exe and self.cfg.execute):
            rec.outcome = "approved_not_executed"
            return self._finish(rec, timings, t_all)
        rec.go(State.EXECUTING)
        t0 = time.perf_counter()
        tx = self.exe.run(accepted, rec.approval)
        timings["execute"] += (time.perf_counter() - t0) * 1000
        rec.transaction = tx
        if tx.status == "COMMITTED":
            rec.go(State.POST_CHECK, "post-check passed on observed state")
            rec.go(State.COMPLETED, "committed")
            rec.outcome = "repaired"
        elif tx.status in ("ROLLED_BACK", "ROLLBACK_FAILED"):
            if any(s.step == "post_check" for s in tx.steps):
                rec.go(State.POST_CHECK, "post-check failed")
            rec.go(State.ROLLBACK, tx.failure or "")
            rec.go(State.FAILED, "rolled back" if tx.status == "ROLLED_BACK" else "ROLLBACK FAILED - manual intervention")
            rec.outcome = "rolled_back" if tx.status == "ROLLED_BACK" else "rollback_failed"
        else:
            rec.go(State.FAILED, f"transaction aborted: {tx.failure}")
            rec.outcome = "tx_aborted"
        return self._finish(rec, timings, t_all)

    @staticmethod
    def _finish(rec: IncidentRecord, timings, t_all) -> IncidentRecord:
        rec.timings_ms = {k: round(v, 2) for k, v in timings.items()}
        rec.timings_ms["total"] = round((time.perf_counter() - t_all) * 1000, 2)
        return rec
