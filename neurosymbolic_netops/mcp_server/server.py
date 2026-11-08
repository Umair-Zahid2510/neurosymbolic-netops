"""Model Context Protocol server exposing NetOps tools with privilege separation (mcp 2.x SDK).

Roles (least privilege, enforced at *registration*: a role never even sees tools above it):
  read      -> read-only diagnostic tools
  verify    -> read + verification tools
  operator  -> read + verify + write tools (prepare/apply/rollback)

Write tools additionally require a one-time approval token bound to the exact plan hash and
candidate fingerprint (issued out-of-band by an approver, never by the server or the model).
Every call is appended to the HMAC-chained audit log with redacted arguments. Inputs are
validated from the function signatures (Pydantic). The network behind the server is the
in-memory SIMULATED adapter unless another adapter is supplied.

Run (stdio):  python -m mcp_server.server --role read
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Literal, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mcp.server.mcpserver import MCPServer  # noqa: E402

from core.actuation.adapters import InMemoryAdapter  # noqa: E402
from core.actuation.approval import ApprovalAuthority, ApprovalToken  # noqa: E402
from core.actuation.audit import AuditLog  # noqa: E402
from core.actuation.transaction import TransactionEngine  # noqa: E402
from core.config_ir import Network, network_fingerprint  # noqa: E402
from core.inventory import Testbed, load_testbed  # noqa: E402
from core.patch_ops import PatchError, PatchPlan, apply_plan  # noqa: E402
from core.skills.base import SkillContext  # noqa: E402
from core.skills.library import build_registry  # noqa: E402
from core.verification import make_verifier  # noqa: E402

Role = Literal["read", "verify", "operator"]
RANK = {"read": 0, "verify": 1, "operator": 2}


class NetOpsService:
    def __init__(self, tb: Testbed, network: Optional[Network] = None, authority: Optional[ApprovalAuthority] = None,
                 audit: Optional[AuditLog] = None, verifier_kind: str = "local"):
        self.tb = tb
        self.adapter = InMemoryAdapter(network or tb.network)
        self.authority = authority or ApprovalAuthority()
        self.audit = audit or AuditLog()
        self.verifier = make_verifier(verifier_kind, tb.topology)
        self.engine = TransactionEngine(self.adapter, self.verifier, make_verifier("local", tb.topology), tb.intents,
                                        self.authority, self.audit)
        self.registry = build_registry()
        self.captured = {}

    def ctx(self) -> SkillContext:
        net = {d: self.adapter.get_config(d) for d in self.adapter.devices()}
        return SkillContext(network=net, topology=self.tb.topology, data_source=f"{self.adapter.name}/{self.adapter.label}")


def build_server(role: Role, service: NetOpsService) -> MCPServer:
    srv = MCPServer("netops", instructions=f"NetOps tools (role={role}). Network backend: {service.adapter.label}.")
    audit = service.audit

    def skill(name: str, **args):
        audit.append(f"mcp:{role}", f"tool.{name}", args=args)
        c = service.registry.invoke(name, {k: v for k, v in args.items() if v is not None}, service.ctx(), f"mcp:{role}")
        return {"evidence_id": c.evidence_id, "ok": c.ok, "result": c.result, "error": c.error, "data_source": c.data_source}

    # ---------------- read
    def list_devices() -> dict:
        """List devices, roles, ASNs and fabric links."""
        return skill("list_devices")

    def inspect_interface(device: str, interface: str) -> dict:
        """Interface status, addressing, MTU/speed/duplex and ACL bindings."""
        return skill("inspect_interface", device=device, interface=interface)

    def bgp_summary(device: str) -> dict:
        """BGP neighbors with state and last reset reason."""
        return skill("bgp_summary", device=device)

    def routing_table(device: str, prefix: Optional[str] = None) -> dict:
        """Routing table, optionally filtered by prefix."""
        return skill("routing_table", device=device, prefix=prefix)

    def inspect_acl(device: str, acl: Optional[str] = None) -> dict:
        """ACL rules, bindings and hit counters."""
        return skill("inspect_acl", device=device, acl=acl)

    def query_topology() -> dict:
        """Physical links of the fabric."""
        audit.append(f"mcp:{role}", "tool.query_topology")
        return {"links": [l.model_dump() for l in service.tb.topology.links]}

    def traceroute(device: str, destination_ip: str, source_ip: Optional[str] = None, protocol: str = "ip",
                   dst_port: Optional[int] = None) -> dict:
        """Simulated forwarding trace (every ECMP branch)."""
        return skill("traceroute", device=device, destination_ip=destination_ip, source_ip=source_ip,
                     protocol=protocol, dst_port=dst_port)

    for fn in (list_devices, inspect_interface, bgp_summary, routing_table, inspect_acl, query_topology, traceroute):
        srv.add_tool(fn, name=fn.__name__, description="[read] " + (fn.__doc__ or ""))

    # ---------------- verify
    if RANK[role] >= RANK["verify"]:
        def verify_intents() -> dict:
            """Verify the running network against all declared intents."""
            audit.append(f"mcp:{role}", "tool.verify_intents")
            r = service.verifier.verify(service.ctx().network, service.tb.intents)
            return {"passed": r.passed, "backends": r.backends, "violated": r.violated(), "counterexamples": r.summary_lines()}

        def verify_plan(plan_json: str) -> dict:
            """Apply a typed PatchPlan (JSON) to a copy of the running network and verify it. Changes nothing."""
            audit.append(f"mcp:{role}", "tool.verify_plan", plan=plan_json[:4000])
            try:
                plan = PatchPlan.model_validate_json(plan_json)
                cand = apply_plan(service.ctx().network, plan)
            except (ValueError, PatchError) as exc:
                return {"valid": False, "error": str(exc)}
            r = service.verifier.verify(cand, service.tb.intents)
            return {"valid": True, "passed": r.passed, "backends": r.backends, "violated": r.violated(),
                    "counterexamples": r.summary_lines(), "plan_hash": plan.plan_hash(),
                    "candidate_fingerprint": network_fingerprint(cand)}

        def check_reachability(device: str, src_ip: str, dst_ip: str, protocol: str = "ip",
                               dst_port: Optional[int] = None, ingress_interface: Optional[str] = None) -> dict:
            """Is a flow delivered on every path?"""
            r = skill("traceroute", device=device, destination_ip=dst_ip, source_ip=src_ip, protocol=protocol,
                      dst_port=dst_port, ingress_interface=ingress_interface)
            if r["ok"]:
                r["delivered_on_all_paths"] = all(t["disposition"] == "DELIVERED" for t in r["result"]["traces"])
            return r

        def acl_packet_test(device: str, acl: str, src_ip: str, dst_ip: str, protocol: str = "ip",
                            dst_port: Optional[int] = None) -> dict:
            """Security-policy analysis: which ACL rule matches a packet."""
            return skill("acl_packet_test", device=device, acl=acl, src_ip=src_ip, dst_ip=dst_ip, protocol=protocol, dst_port=dst_port)

        for fn in (verify_intents, verify_plan, check_reachability, acl_packet_test):
            srv.add_tool(fn, name=fn.__name__, description="[verify] " + (fn.__doc__ or ""))

    # ---------------- write
    if RANK[role] >= RANK["operator"]:
        def prepare_change(plan_json: str) -> dict:
            """Validate and verify a plan; returns plan_hash and candidate_fingerprint for the approver. Changes nothing."""
            audit.append(f"mcp:{role}", "tool.prepare_change", plan=plan_json[:4000])
            try:
                plan = PatchPlan.model_validate_json(plan_json)
                cand = apply_plan(service.ctx().network, plan)
            except (ValueError, PatchError) as exc:
                return {"prepared": False, "error": str(exc)}
            r = service.verifier.verify(cand, service.tb.intents)
            return {"prepared": r.passed, "violated": r.violated(), "plan_hash": plan.plan_hash(),
                    "candidate_fingerprint": network_fingerprint(cand), "ops": plan.describe(),
                    "next_step": "obtain an approval token from an authorised approver, then call apply_change"}

        def apply_change(plan_json: str, approval_token_json: str) -> dict:
            """Apply an approved plan transactionally (verify, authorise, apply, post-check, commit or roll back)."""
            audit.append(f"mcp:{role}", "tool.apply_change", plan=plan_json[:4000])
            try:
                plan = PatchPlan.model_validate_json(plan_json)
                token = ApprovalToken.model_validate_json(approval_token_json)
            except ValueError as exc:
                return {"status": "REJECTED", "error": f"invalid input: {exc}"}
            before = service.engine.capture()
            tx = service.engine.execute(plan, token, actor=f"mcp:{role}")
            if tx.status == "COMMITTED":
                service.captured[tx.tx_id] = before
            return {"tx_id": tx.tx_id, "status": tx.status, "failure": tx.failure,
                    "steps": [s.model_dump() for s in tx.steps], "adapter": tx.adapter_label}

        def rollback_change(tx_id: str) -> dict:
            """Restore the configuration captured before a committed transaction."""
            audit.append(f"mcp:{role}", "tool.rollback_change", tx_id=tx_id)
            if tx_id not in service.captured:
                return {"status": "REJECTED", "error": f"unknown or non-committed transaction {tx_id}"}
            before = service.captured.pop(tx_id)
            for d, cfg in before.items():
                service.adapter.push_config(d, cfg)
            ok = all(service.adapter.get_config(d) == c for d, c in before.items())
            audit.append(f"mcp:{role}", "tx.manual_rollback", tx_id=tx_id, restored=ok)
            return {"status": "ROLLED_BACK" if ok else "ROLLBACK_FAILED", "tx_id": tx_id}

        for fn in (prepare_change, apply_change, rollback_change):
            srv.add_tool(fn, name=fn.__name__, description="[write] " + (fn.__doc__ or ""))
    return srv


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--role", choices=["read", "verify", "operator"], default="read")
    ap.add_argument("--verifier", choices=["local", "batfish"], default="local")
    args = ap.parse_args()
    svc = NetOpsService(load_testbed(), audit=AuditLog(ROOT / "runtime" / "mcp_audit.jsonl"), verifier_kind=args.verifier)
    build_server(args.role, svc).run()  # stdio transport


if __name__ == "__main__":
    main()
