import json

import pytest

from agent.llm.base import ChatResult, LLMProvider
from agent.orchestrator import SystemConfig, run_incident
from agent.workflow import ALLOWED, IllegalTransition, IncidentRecord, State
from benchmark.faults import TEMPLATES
from core.actuation.adapters import FaultInjection, InMemoryAdapter
from core.actuation.approval import ApprovalAuthority
from core.actuation.audit import AuditLog
from core.actuation.transaction import TransactionEngine
from core.patch_ops import PatchPlan, SetInterfaceEnabled, apply_plan
from core.verification import make_verifier


def fault(tb, name, **kw):
    return apply_plan(tb.network, TEMPLATES[name](tb.network, tb.topology, **kw).inject)


# ------------------------------------------------------------------ workflow
def test_illegal_transition_rejected():
    r = IncidentRecord(incident_id="x", modes={})
    with pytest.raises(IllegalTransition):
        r.go(State.EXECUTING)
    assert State.EXECUTING not in ALLOWED[State.DETECTED]


def test_no_incident_ids_in_agent_or_core_code():
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    import re
    rx = re.compile(r"(FAULT|STRESS)_[A-Z]+_\d{3}")
    for p in list((root / "agent").rglob("*.py")) + list((root / "core").rglob("*.py")):
        assert not rx.search(p.read_text(encoding="utf-8")), p


# ------------------------------------------------------------------ transactions (fault injection)
def engine(tb, net, faults=None, audit=None):
    v = make_verifier("local", tb.topology)
    return TransactionEngine(InMemoryAdapter(net, faults), v, v, tb.intents, ApprovalAuthority(), audit or AuditLog())


def fix_plan():
    return PatchPlan(ops=[SetInterfaceEnabled(device="Leaf-1", interface="eth2", enabled=True)])


@pytest.fixture
def broken(testbed):
    return fault(testbed, "iface_shutdown", dev="Leaf-1", intf="eth2")


def token(eng, net, plan):
    from core.config_ir import network_fingerprint
    return eng.authority.issue(plan, network_fingerprint(apply_plan(net, plan)), "test", "test")


def test_commit_success_and_audit_chain(testbed, broken):
    eng = engine(testbed, broken); p = fix_plan()
    rec = eng.execute(p, token(eng, broken, p))
    assert rec.status == "COMMITTED" and rec.applied_devices == ["Leaf-1"]
    assert eng.adapter.get_config("Leaf-1").interfaces["eth2"].enabled
    ok, _ = eng.audit.verify()
    assert ok and eng.audit.entries[-1]["action"] == "tx.end"


def test_missing_or_replayed_or_mismatched_token_rejected(testbed, broken):
    eng = engine(testbed, broken); p = fix_plan()
    assert eng.execute(p, None).failure.startswith("authorization failed: no approval token")
    t = token(eng, broken, p)
    assert eng.execute(p, t).status == "COMMITTED"
    eng2 = engine(testbed, broken)
    eng2.authority = eng.authority
    assert "already used" in eng2.execute(p, t).failure
    from core.patch_ops import SetInterfaceMtu
    other = PatchPlan(ops=list(p.ops) + [SetInterfaceMtu(device="Leaf-1", interface="eth2", mtu=1500)])
    eng3 = engine(testbed, broken)
    assert "plan changed after approval" in eng3.execute(other, token(eng3, broken, p)).failure


def test_unverified_candidate_is_never_applied(testbed):
    net = testbed.network
    eng = engine(testbed, net)
    bad = PatchPlan(ops=[SetInterfaceEnabled(device="Spine-1", interface="eth1", enabled=False)])
    rec = eng.execute(bad, token(eng, net, bad))
    assert rec.status == "ABORTED" and rec.applied_devices == [] and "violates intents" in rec.failure


@pytest.mark.parametrize("faults,expected", [
    (FaultInjection(fail_apply_on={"Leaf-1"}), "ROLLED_BACK"),
    (FaultInjection(timeout_on={"Leaf-1"}), "ROLLED_BACK"),
    (FaultInjection(runtime_effect=PatchPlan(ops=[SetInterfaceEnabled(device="Leaf-1", interface="eth2", enabled=False)])), "ROLLED_BACK"),
    (FaultInjection(runtime_effect=PatchPlan(ops=[SetInterfaceEnabled(device="Leaf-1", interface="eth2", enabled=False)]),
                    fail_rollback_on={"Leaf-1"}), "ROLLBACK_FAILED"),
])
def test_fault_injection_paths(testbed, broken, faults, expected):
    eng = engine(testbed, broken, faults); p = fix_plan()
    rec = eng.execute(p, token(eng, broken, p))
    assert rec.status == expected
    if expected == "ROLLED_BACK":
        assert rec.restore_verified and eng.adapter.get_config("Leaf-1") == broken["Leaf-1"]
    else:
        assert rec.restore_verified is False and "manual intervention" in rec.failure


def test_partial_multi_device_deployment_is_compensated(testbed):
    net = fault(testbed, "iface_shutdown", dev="Leaf-1", intf="eth2")
    net = apply_plan(net, TEMPLATES["iface_shutdown"](net, testbed.topology, dev="Spine-1", intf="eth2").inject)
    p = PatchPlan(ops=[SetInterfaceEnabled(device="Leaf-1", interface="eth2", enabled=True),
                       SetInterfaceEnabled(device="Spine-1", interface="eth2", enabled=True)])
    eng = engine(testbed, net, FaultInjection(fail_apply_on={"Spine-1"}))
    rec = eng.execute(p, token(eng, net, p))
    assert rec.status == "ROLLED_BACK" and rec.applied_devices == ["Leaf-1"]
    assert set(rec.rolled_back_devices) == {"Leaf-1", "Spine-1"}
    assert eng.adapter.get_config("Leaf-1") == net["Leaf-1"]


def test_audit_tamper_detected(testbed, broken):
    eng = engine(testbed, broken); p = fix_plan()
    eng.execute(p, token(eng, broken, p))
    entries = [dict(e) for e in eng.audit.entries]
    entries[2]["payload"] = {"forged": True}
    assert eng.audit.verify(entries) == (False, 2)


# ------------------------------------------------------------------ end-to-end (rule based)
def test_e2e_single_fault_repaired(testbed):
    run = run_incident(testbed, "e2e-1", fault(testbed, "remote_as_mismatch", dev="Leaf-1", nbr="10.0.1.1"), SystemConfig())
    r = run.record
    assert r.outcome == "repaired" and r.state == State.COMPLETED and run.audit_ok
    assert [t.to for t in r.transitions][-3:] == [State.EXECUTING, State.POST_CHECK, State.COMPLETED]
    assert r.final_hypotheses[0].device == "Leaf-1" and r.tool_calls


def test_e2e_unsafe_repair_is_blocked_by_gate_but_deployed_without_it(testbed):
    net = fault(testbed, "acl_block_bgp", dev="Leaf-2", intf="eth2")
    gated = run_incident(testbed, "g", net, SystemConfig()).record
    assert gated.outcome in ("no_plan", "rejected_unverified") and gated.transaction is None
    assert any(a.disposition == "rejected" and "isolate-admin-lan20" in a.new_violations for a in gated.attempts)
    ungated = run_incident(testbed, "u", net, SystemConfig(verifier="none")).record
    assert ungated.transaction.applied_devices == ["Leaf-2"]           # the unsafe change reached the device
    assert ungated.outcome == "rolled_back" and "isolate-admin-lan20" in ungated.transaction.post_check_violations


# ------------------------------------------------------------------ LLM strategy with scripted (mock) provider
class ScriptedLLM(LLMProvider):
    """Mock provider (NOT a real model): returns a fixed sequence of replies."""
    def __init__(self, replies):
        super().__init__(provider="mock", model="scripted", log_path=None)
        self.replies = list(replies)

    def _chat_once(self, system, messages, tools, json_mode):
        return ChatResult(text=self.replies.pop(0), tool_calls=[], prompt_tokens=10, completion_tokens=5, total_tokens=15)


def test_e2e_llm_strategy_reflection_on_counterexample(testbed):
    net = fault(testbed, "acl_block_bgp", dev="Leaf-2", intf="eth2")
    diag = json.dumps({"hypotheses": [{"device": "Leaf-2", "category": "ACL", "fault_type": "acl_blocks_control_plane",
                                       "location": "eth2", "statement": "wrong ACL bound on eth2"}], "reasoning_summary": "r"})
    unsafe = json.dumps({"plan": {"ops": [{"op": "bind_acl", "device": "Leaf-2", "interface": "eth2", "direction": "in",
                                           "acl": None}], "rationale": "unbind", "addresses_hypotheses": ["H1"]}})
    safe = json.dumps({"plan": {"ops": [{"op": "bind_acl", "device": "Leaf-2", "interface": "eth2", "direction": "in",
                                         "acl": "PERIMETER_SECURITY_POLICY"}], "rationale": "restore perimeter ACL",
                                "addresses_hypotheses": ["H1"]}})
    p = ScriptedLLM([diag, unsafe, safe])
    r = run_incident(testbed, "llm", net, SystemConfig(reasoning="llm", llm_provider=p, llm_tools=False)).record
    assert [a.disposition for a in r.attempts] == ["rejected", "accepted"]
    assert r.attempts[0].new_violations == ["isolate-admin-lan20"]
    assert r.outcome == "repaired" and r.llm_usage.calls == 3 and r.modes["diagnosis"].startswith("llm:mock")


def test_llm_mode_without_provider_fails_loudly(testbed):
    with pytest.raises(ValueError, match="no silent fallback"):
        run_incident(testbed, "x", testbed.network, SystemConfig(reasoning="llm"))
