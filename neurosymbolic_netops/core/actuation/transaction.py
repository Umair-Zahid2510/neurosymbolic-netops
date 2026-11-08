"""Tier-4 transactional actuation: prepare / authorize / apply / post-check / commit or roll back.

This is a **prepare-commit workflow with compensating rollback**, not a true two-phase commit:
devices are changed one at a time and, on any failure, every already-changed device is
restored to the configuration captured before the transaction. True 2PC would require device
support for candidate datastores and confirmed commit (NETCONF ``:confirmed-commit``), which
the available adapters do not provide.

Lifecycle (each step is written to the audit log):
  1 capture running configs          6 authorize (one-time token bound to plan + candidate)
  2 build candidate from typed ops   7 apply device by device
  3 syntax check (render->parse)     8 post-check on *observed* live state (adapter view)
  4 intent / symbolic verification   9 commit, or
  5 prepare (diff, adapter reachable) 10 compensating rollback + restore verification
"""

from __future__ import annotations

import time
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field

from core.actuation.adapters import AdapterError, AdapterTimeout, DeviceAdapter
from core.actuation.approval import ApprovalAuthority, ApprovalToken
from core.actuation.audit import AuditLog
from core.config_ir import Network, network_fingerprint
from core.intent_schema import IntentSet
from core.parsers.ios import parse_ios
from core.patch_ops import PatchError, PatchPlan, apply_plan, render_diff
from core.renderers.ios import render_ios

TxStatus = Literal["COMMITTED", "ROLLED_BACK", "ROLLBACK_FAILED", "ABORTED"]


class StepRecord(BaseModel):
    step: str
    ok: bool
    detail: str = ""
    ms: float = 0.0


class TransactionRecord(BaseModel):
    tx_id: str
    adapter: str
    adapter_label: str
    plan_hash: str
    devices: List[str]
    status: TxStatus = "ABORTED"
    steps: List[StepRecord] = Field(default_factory=list)
    applied_devices: List[str] = Field(default_factory=list)
    rolled_back_devices: List[str] = Field(default_factory=list)
    failure: Optional[str] = None
    post_check_violations: List[str] = Field(default_factory=list)
    restore_verified: Optional[bool] = None
    diff: str = ""
    duration_ms: float = 0.0


class TransactionEngine:
    def __init__(self, adapter: DeviceAdapter, pre_verifier, post_verifier, intents: IntentSet,
                 authority: ApprovalAuthority, audit: AuditLog):
        self.adapter = adapter
        self.pre_verifier = pre_verifier     # symbolic gate (local or batfish)
        self.post_verifier = post_verifier   # evaluates the adapter's observed live state
        self.intents = intents
        self.authority = authority
        self.audit = audit
        self._n = 0

    def capture(self) -> Network:
        return {d: self.adapter.get_config(d) for d in self.adapter.devices()}

    def execute(self, plan: PatchPlan, token: Optional[ApprovalToken], actor: str = "execution_agent") -> TransactionRecord:
        self._n += 1
        t_start = time.perf_counter()
        rec = TransactionRecord(tx_id=f"TX{self._n:04d}-{plan.plan_hash()[:8]}", adapter=self.adapter.name,
                                adapter_label=getattr(self.adapter, "label", "UNKNOWN"), plan_hash=plan.plan_hash(),
                                devices=plan.devices())

        def step(name: str, ok: bool, detail: str = "", t0: Optional[float] = None) -> bool:
            ms = round((time.perf_counter() - t0) * 1000, 2) if t0 else 0.0
            rec.steps.append(StepRecord(step=name, ok=ok, detail=detail, ms=ms))
            self.audit.append(actor, f"tx.{name}", tx_id=rec.tx_id, ok=ok, detail=detail)
            return ok

        def finish(status: TxStatus, failure: Optional[str] = None) -> TransactionRecord:
            rec.status, rec.failure = status, failure
            rec.duration_ms = round((time.perf_counter() - t_start) * 1000, 2)
            self.audit.append(actor, "tx.end", tx_id=rec.tx_id, status=status, failure=failure,
                              applied=rec.applied_devices, rolled_back=rec.rolled_back_devices)
            return rec

        self.audit.append(actor, "tx.begin", tx_id=rec.tx_id, plan_hash=rec.plan_hash, ops=plan.describe(),
                          adapter=rec.adapter, adapter_label=rec.adapter_label)
        # 1 capture
        t0 = time.perf_counter()
        try:
            captured = self.capture()
        except AdapterError as exc:
            step("capture", False, str(exc), t0)
            return finish("ABORTED", f"capture failed: {exc}")
        step("capture", True, f"fingerprint {network_fingerprint(captured)[:12]}", t0)
        # 2 candidate
        t0 = time.perf_counter()
        try:
            candidate = apply_plan(captured, plan)
        except PatchError as exc:
            step("build_candidate", False, str(exc), t0)
            return finish("ABORTED", f"plan not applicable to running config: {exc}")
        rec.diff = render_diff(captured, candidate)
        step("build_candidate", True, f"{len(plan.ops)} ops on {plan.devices()}", t0)
        # 3 syntax: every changed device must render and re-parse to the identical IR
        t0 = time.perf_counter()
        bad = [d for d in plan.devices() if parse_ios(render_ios(candidate[d]), d) != candidate[d]]
        if not step("syntax_check", not bad, f"round-trip mismatch on {bad}" if bad else "render/parse round-trip OK", t0):
            return finish("ABORTED", "syntax check failed")
        # 4 symbolic verification (None only in the explicitly labelled "no gate" ablation)
        t0 = time.perf_counter()
        if self.pre_verifier is None:
            step("symbolic_verification", True, "SKIPPED (ablation: no pre-deployment verification)", t0)
        else:
            report = self.pre_verifier.verify(candidate, self.intents)
            if not step("symbolic_verification", report.passed,
                        f"backends={report.backends} violated={report.violated()}", t0):
                return finish("ABORTED", f"candidate violates intents {report.violated()}")
        fp = network_fingerprint(candidate)
        # 5 prepare
        t0 = time.perf_counter()
        step("prepare", True, f"devices to change: {plan.devices()}", t0)
        # 6 authorize
        reason = self.authority.check(token, plan, fp)
        if not step("authorize", reason is None, reason or f"token from {token.approver} ({token.policy})"):
            return finish("ABORTED", f"authorization failed: {reason}")
        # 7 apply
        for dev in plan.devices():
            t0 = time.perf_counter()
            try:
                self.adapter.push_config(dev, candidate[dev])
                rec.applied_devices.append(dev)
                step(f"apply:{dev}", True, "", t0)
            except AdapterTimeout as exc:
                step(f"apply:{dev}", False, f"timeout: {exc}", t0)
                return self._rollback(rec, captured, step, finish, f"apply timeout on {dev}", include=dev)
            except AdapterError as exc:
                step(f"apply:{dev}", False, str(exc), t0)
                return self._rollback(rec, captured, step, finish, f"apply failed on {dev}", include=dev)
        # 8 post-check on observed live state
        t0 = time.perf_counter()
        live = self.adapter.observed_network()
        post = self.post_verifier.verify(live, self.intents)
        rec.post_check_violations = post.violated()
        if not step("post_check", post.passed, f"observed state violated={post.violated()}", t0):
            return self._rollback(rec, captured, step, finish, f"post-check failed: {post.violated()}")
        # 9 commit
        step("commit", True, "change confirmed")
        return finish("COMMITTED")

    def _rollback(self, rec, captured, step, finish, why: str, include: Optional[str] = None):
        """Compensating rollback: restore the captured config on every touched device (a device whose
        push timed out may have been partially changed, so it is restored too)."""
        targets = list(rec.applied_devices) + ([include] if include and include not in rec.applied_devices else [])
        if hasattr(self.adapter, "begin_restore"):
            self.adapter.begin_restore()
        failed = []
        for dev in targets:
            t0 = time.perf_counter()
            try:
                self.adapter.push_config(dev, captured[dev])
                rec.rolled_back_devices.append(dev)
                step(f"rollback:{dev}", True, "restored captured configuration", t0)
            except AdapterError as exc:
                failed.append(dev)
                step(f"rollback:{dev}", False, str(exc), t0)
        restored = all(self.adapter.get_config(d) == captured[d] for d in targets if d not in failed)
        rec.restore_verified = restored and not failed
        step("restore_verification", rec.restore_verified,
             "all touched devices match captured config" if rec.restore_verified else f"not restored: {failed}")
        if failed:
            return finish("ROLLBACK_FAILED", f"{why}; rollback failed on {failed} (manual intervention required)")
        return finish("ROLLED_BACK", why)
