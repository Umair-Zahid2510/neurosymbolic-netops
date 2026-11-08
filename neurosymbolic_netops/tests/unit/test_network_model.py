from core.network_model import compute_state, traceroute
from core.patch_ops import PatchPlan, SetBgpNeighborRemoteAs, SetInterfaceEnabled, apply_plan
from core.telemetry.schema import FlowSpec

LAN10, LAN20 = "10.1.10.10", "10.1.20.10"


def test_base_fabric_all_sessions_established_and_ecmp(testbed):
    st = compute_state(testbed.network, testbed.topology)
    assert all(s.state == "ESTABLISHED" for s in st.sessions) and len(st.sessions) == 8
    r = st.ribs["Leaf-1"]["10.1.20.0/24"]
    assert r.protocol == "bgp" and len(r.next_hops) == 2 and r.as_path == [65000, 65002]
    traces = traceroute(testbed.network, testbed.topology, st, "Leaf-1", FlowSpec(src_ip=LAN10, dst_ip=LAN20), "eth10")
    assert sorted(t.path() for t in traces) == [["Leaf-1", "Spine-1", "Leaf-2"], ["Leaf-1", "Spine-2", "Leaf-2"]]
    assert all(t.disposition == "DELIVERED" for t in traces)


def test_as_loop_prevention_spines_do_not_transit_each_other(testbed):
    st = compute_state(testbed.network, testbed.topology)
    for spine in ("Spine-1", "Spine-2"):
        for r in st.ribs[spine].values():
            assert 65000 not in r.as_path


def test_remote_as_mismatch_breaks_only_that_session(testbed):
    net = apply_plan(testbed.network, PatchPlan(ops=[SetBgpNeighborRemoteAs(device="Leaf-1", neighbor="10.0.1.1", remote_as=65099)]))
    st = compute_state(net, testbed.topology)
    bad = {(s.device, s.neighbor_ip) for s in st.sessions if s.state != "ESTABLISHED"}
    assert bad == {("Leaf-1", "10.0.1.1"), ("Spine-1", "10.0.1.2")}
    assert "expects remote-as 65099" in " ".join(st.session("Leaf-1", "10.0.1.1").reasons)


def test_isolation_flow_denied_by_perimeter_acl(testbed):
    st = compute_state(testbed.network, testbed.topology)
    t = traceroute(testbed.network, testbed.topology, st, "Spine-1", FlowSpec(src_ip="192.168.99.5", dst_ip=LAN10))
    assert [x.disposition for x in t] == ["DENIED_IN"] and t[0].acl_hit.acl == "PERIMETER_SECURITY_POLICY"


def test_link_down_removes_one_ecmp_path(testbed):
    net = apply_plan(testbed.network, PatchPlan(ops=[SetInterfaceEnabled(device="Spine-2", interface="eth2", enabled=False)]))
    st = compute_state(net, testbed.topology)
    traces = traceroute(net, testbed.topology, st, "Leaf-1", FlowSpec(src_ip=LAN10, dst_ip=LAN20), "eth10")
    assert [t.path() for t in traces] == [["Leaf-1", "Spine-1", "Leaf-2"]]
