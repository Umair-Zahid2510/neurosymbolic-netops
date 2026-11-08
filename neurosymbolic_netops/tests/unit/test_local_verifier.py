import pytest

from benchmark.faults import TEMPLATES
from core.config_ir import AclRule, copy_network
from core.patch_ops import apply_plan
from core.verification import make_verifier


@pytest.fixture(scope="module")
def verifier(testbed):
    return make_verifier("local", testbed.topology)


def test_base_network_satisfies_all_intents(testbed, verifier):
    r = verifier.verify(testbed.network, testbed.intents)
    assert r.passed and r.violated() == [] and r.unevaluated_intents == []
    assert set(r.backends) == {"local_symbolic", "ir_static"}


def test_audit_p4a_supernet_deny_is_rejected(testbed, verifier):
    net = copy_network(testbed.network)
    net["Leaf-1"].acls["PERIMETER_SECURITY_POLICY"].rules.insert(1, AclRule(action="deny", src="10.1.0.0/16"))
    assert "reach-lan20-lan10" in verifier.verify(net, testbed.intents).violated()


def test_audit_p4b_shadowed_security_rule_is_rejected(testbed, verifier):
    net = copy_network(testbed.network)
    net["Leaf-1"].acls["PERIMETER_SECURITY_POLICY"].rules.reverse()
    r = verifier.verify(net, testbed.intents)
    assert r.violated() == ["isolate-admin-lan10"]
    assert "ISOLATION BREACH" in r.counterexamples()[0].summary


@pytest.mark.parametrize("template,kw,expected", [
    ("iface_shutdown", dict(dev="Leaf-1", intf="eth1"), {"bgp-all-sessions", "redundancy-lan10-lan20", "redundancy-lan20-lan10"}),
    ("mtu_mismatch", dict(dev="Leaf-2", intf="eth1"), {"link-consistency"}),
    ("missing_network", dict(dev="Leaf-1"), {"reach-lan20-lan10"}),
    ("acl_deny_service", dict(dev="Leaf-2", port=443), {"svc-https-lan10-lan20"}),
    ("route_map_drop", dict(dev="Spine-1", nbr="10.0.2.2"), {"redundancy-lan20-lan10"}),
])
def test_faults_violate_expected_intents(testbed, verifier, template, kw, expected):
    f = TEMPLATES[template](testbed.network, testbed.topology, **kw)
    v = set(verifier.verify(apply_plan(testbed.network, f.inject), testbed.intents).violated())
    assert expected <= v


def test_unparsed_config_cannot_pass(testbed, verifier):
    net = copy_network(testbed.network)
    net["Leaf-1"].unsupported_lines = ["L99: ip ospf cost 5"]
    r = verifier.verify(net, testbed.intents)
    assert not r.passed and r.parse_issues
