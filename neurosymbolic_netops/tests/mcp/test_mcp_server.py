"""MCP server tests: real MCP protocol exchange between the mcp 2.x Client and our server,
connected in-process (no network). Backend network is the SIMULATED in-memory adapter."""

import asyncio
import json

from mcp.client.client import Client

from benchmark.faults import TEMPLATES
from core.config_ir import network_fingerprint
from core.patch_ops import PatchPlan, SetInterfaceEnabled, apply_plan
from mcp_server.server import NetOpsService, build_server

READ = {"list_devices", "inspect_interface", "bgp_summary", "routing_table", "inspect_acl", "query_topology", "traceroute"}
VERIFY = {"verify_intents", "verify_plan", "check_reachability", "acl_packet_test"}
WRITE = {"prepare_change", "apply_change", "rollback_change"}


def run(coro):
    return asyncio.run(coro)


def payload(res):
    return json.loads(res.content[0].text)


def broken_service(tb):
    net = apply_plan(tb.network, TEMPLATES["iface_shutdown"](tb.network, tb.topology, dev="Leaf-1", intf="eth2").inject)
    return NetOpsService(tb, net)


def test_tool_discovery_respects_roles(testbed):
    async def names(role):
        async with Client(build_server(role, NetOpsService(testbed))) as c:
            return {t.name for t in (await c.list_tools()).tools}
    assert run(names("read")) == READ
    assert run(names("verify")) == READ | VERIFY
    assert run(names("operator")) == READ | VERIFY | WRITE


def test_read_role_cannot_invoke_write_tools(testbed):
    async def go():
        async with Client(build_server("read", NetOpsService(testbed))) as c:
            r = await c.call_tool("apply_change", {"plan_json": "{}", "approval_token_json": "{}"})
            return r
    r = run(go())
    assert r.is_error


def test_read_tool_invocation_and_input_validation(testbed):
    async def go():
        async with Client(build_server("read", broken_service(testbed))) as c:
            ok = payload(await c.call_tool("bgp_summary", {"device": "Leaf-1"}))
            bad = await c.call_tool("inspect_interface", {"device": "Leaf-1"})
            return ok, bad
    ok, bad = run(go())
    assert ok["ok"] and ok["data_source"] == "inmemory/SIMULATED"
    assert any(n["state"] == "Idle" for n in ok["result"]["neighbors"])
    assert bad.is_error


def test_write_requires_valid_approval_token_and_audits(testbed):
    svc = broken_service(testbed)
    plan = PatchPlan(ops=[SetInterfaceEnabled(device="Leaf-1", interface="eth2", enabled=True)])

    async def go():
        async with Client(build_server("operator", svc)) as c:
            prep = payload(await c.call_tool("prepare_change", {"plan_json": plan.model_dump_json()}))
            forged = payload(await c.call_tool("apply_change", {"plan_json": plan.model_dump_json(),
                     "approval_token_json": json.dumps({"plan_hash": prep["plan_hash"], "candidate_fingerprint": prep["candidate_fingerprint"],
                                                        "approver": "llm", "policy": "x", "issued_at": "now", "nonce": "1", "mac": "00"})}))
            tok = svc.authority.issue(plan, prep["candidate_fingerprint"], approver="human-operator", policy="human")
            ok = payload(await c.call_tool("apply_change", {"plan_json": plan.model_dump_json(), "approval_token_json": tok.model_dump_json()}))
            replay = payload(await c.call_tool("apply_change", {"plan_json": plan.model_dump_json(), "approval_token_json": tok.model_dump_json()}))
            rb = payload(await c.call_tool("rollback_change", {"tx_id": ok["tx_id"]}))
            return prep, forged, ok, replay, rb
    prep, forged, ok, replay, rb = run(go())
    assert prep["prepared"] and prep["violated"] == []
    assert forged["status"] == "ABORTED" and "invalid token signature" in forged["failure"]
    assert ok["status"] == "COMMITTED"
    assert replay["status"] == "ABORTED"
    assert rb["status"] == "ROLLED_BACK" and not svc.adapter.get_config("Leaf-1").interfaces["eth2"].enabled
    assert svc.audit.verify()[0] and any(e["action"] == "tool.apply_change" for e in svc.audit.entries)
