"""Write-side authorization: one-time approval tokens bound to an exact plan and candidate state.

A token is ``HMAC(key, plan_hash || candidate_fingerprint || approver || nonce)``. The
transaction engine refuses to apply anything without a valid, unused token whose plan hash and
fingerprint match what is about to be deployed, so a plan changed after approval (or a token
replayed for a second deployment) is rejected.

Approval *policies* decide whether to issue a token:
* ``HumanApprovalPolicy``   asks on the console (interactive demos);
* ``AutoApproveVerifiedPolicy`` issues a token only for plans whose verification passed - used
  by the benchmark and labelled ``auto_policy`` in every record (it simulates a human approver);
* ``DenyAllPolicy``         read-only operation (BiAn-style advisor mode).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timezone
from typing import Optional, Set

from pydantic import BaseModel

from core.patch_ops import PatchPlan


class ApprovalToken(BaseModel):
    plan_hash: str
    candidate_fingerprint: str
    approver: str
    policy: str
    issued_at: str
    nonce: str
    mac: str


class ApprovalAuthority:
    def __init__(self, key: Optional[bytes] = None):
        self._key = key or (os.environ.get("NETOPS_APPROVAL_HMAC_KEY") or "netops-dev-approval-key").encode()
        self._used: Set[str] = set()

    def _mac(self, plan_hash: str, fp: str, approver: str, nonce: str) -> str:
        return hmac.new(self._key, f"{plan_hash}|{fp}|{approver}|{nonce}".encode(), hashlib.sha256).hexdigest()

    def issue(self, plan: PatchPlan, candidate_fingerprint: str, approver: str, policy: str) -> ApprovalToken:
        nonce = secrets.token_hex(8)
        return ApprovalToken(plan_hash=plan.plan_hash(), candidate_fingerprint=candidate_fingerprint, approver=approver,
                             policy=policy, issued_at=datetime.now(timezone.utc).isoformat(), nonce=nonce,
                             mac=self._mac(plan.plan_hash(), candidate_fingerprint, approver, nonce))

    def check(self, token: Optional[ApprovalToken], plan: PatchPlan, candidate_fingerprint: str) -> Optional[str]:
        """Return None if valid (and consume it), else the reason for rejection."""
        if token is None:
            return "no approval token"
        if token.nonce in self._used:
            return "approval token already used (replay)"
        if token.plan_hash != plan.plan_hash():
            return "plan changed after approval"
        if token.candidate_fingerprint != candidate_fingerprint:
            return "candidate configuration differs from the approved one"
        if not hmac.compare_digest(token.mac, self._mac(token.plan_hash, token.candidate_fingerprint, token.approver, token.nonce)):
            return "invalid token signature"
        self._used.add(token.nonce)
        return None


class AutoApproveVerifiedPolicy:
    name = "auto_policy"

    def decide(self, plan: PatchPlan, verification_passed: bool, summary: str) -> tuple[bool, str]:
        return (True, "auto-approved: verification passed") if verification_passed else (False, "verification failed")


class DenyAllPolicy:
    name = "deny_all"

    def decide(self, plan, verification_passed, summary):
        return False, "read-only mode: no write-side changes are approved"


class HumanApprovalPolicy:
    name = "human"

    def __init__(self, input_fn=input, print_fn=print):
        self.input_fn, self.print_fn = input_fn, print_fn

    def decide(self, plan: PatchPlan, verification_passed: bool, summary: str) -> tuple[bool, str]:
        self.print_fn("\n=== APPROVAL REQUIRED ===\n" + summary + "\nOperations:\n  " + "\n  ".join(plan.describe()))
        if not verification_passed:
            self.print_fn("Verification did NOT pass; approval is not possible.")
            return False, "verification failed"
        ans = self.input_fn("Approve deployment? [y/N] ").strip().lower()
        return (ans == "y"), ("approved by operator" if ans == "y" else "rejected by operator")
