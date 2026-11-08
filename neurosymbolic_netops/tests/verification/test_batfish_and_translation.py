import pytest

from benchmark.faults import TEMPLATES
from core.patch_ops import apply_plan
from core.renderers.vendors import render_eos, render_junos
from core.vendor_translator import TranslationError, translate
from core.verification.batfish_backend import batfish_reachable

needs_batfish = pytest.mark.skipif(not batfish_reachable(), reason="Batfish service not running on localhost:9996")


def test_translation_goes_through_ir_and_preserves_values(testbed):
    from core.renderers.ios import render_ios
    ios = render_ios(testbed.network["Leaf-1"])
    junos = translate(ios, "juniper_junos")
    eos = translate(ios, "arista_eos")
    assert "set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.2/30" in junos
    assert "set interfaces ge-0/0/1 unit 0 family inet mtu 1500" in junos
    assert "set protocols bgp group FABRIC neighbor 10.0.1.1 peer-as 65000" in junos
    assert "from source-address 192.168.99.0/24" in junos and "then discard" in junos
    assert "interface Ethernet1" in eos and "ip address 10.0.1.2/30" in eos and "maximum-paths 2" in eos


def test_translation_refuses_unparsed_input():
    with pytest.raises(TranslationError):
        translate("hostname X\nrouter ospf 1\n network 10.0.0.0 0.0.0.255 area 0\n", "arista_eos")


def test_shutdown_and_deactivation_rendered(testbed):
    net = apply_plan(testbed.network, TEMPLATES["iface_shutdown"](testbed.network, testbed.topology, dev="Leaf-1", intf="eth1").inject)
    assert "set interfaces ge-0/0/1 disable" in render_junos(net["Leaf-1"])
    assert "   shutdown" in render_eos(net["Leaf-1"])


def test_causal_discovery_pc_runs_and_beats_correlation_when_confounder_observed(testbed):
    from core.causal_discovery import evaluate
    r = evaluate(testbed.topology, testbed.network, testbed.intents, n=400, seed=1, observe_confounder=True)
    assert r["pc_skeleton_precision"] > r["correlation_precision"]
    assert r["spurious_cpu_edges_by_pc"] <= r["spurious_cpu_associations_by_correlation"]


@pytest.mark.batfish
@needs_batfish
def test_batfish_base_network_passes_with_no_parse_warnings(testbed):
    from core.verification import make_verifier
    r = make_verifier("batfish", testbed.topology).verify(testbed.network, testbed.intents)
    assert r.passed and not r.parse_issues and "batfish" in r.backends
    assert r.checks[0].evidence["parse_warnings"] == []


@pytest.mark.batfish
@needs_batfish
@pytest.mark.parametrize("template,kw,intent", [
    ("remote_as_mismatch", dict(dev="Leaf-1", nbr="10.0.1.1"), "bgp-all-sessions"),
    ("acl_deny_lan", dict(dev="Leaf-2"), "reach-lan10-lan20"),
    ("md5_unilateral", dict(dev="Leaf-2", nbr="10.0.2.1"), "bgp-peer-consistency"),  # caught by ir_static, not Batfish
])
def test_batfish_composite_detects_faults(testbed, template, kw, intent):
    from core.verification import make_verifier
    net = apply_plan(testbed.network, TEMPLATES[template](testbed.network, testbed.topology, **kw).inject)
    r = make_verifier("batfish", testbed.topology).verify(net, testbed.intents)
    assert intent in r.violated()


def test_dashboard_loads():
    from streamlit.testing.v1 import AppTest
    from tests.conftest import ROOT
    at = AppTest.from_file(str(ROOT / "dashboard" / "app.py"), default_timeout=120).run()
    assert not at.exception
    at.button[0].click().run()  # run a full incident (rule-based, local verifier) from the UI
    assert not at.exception and at.metric[0].value == "repaired"
    for view in ("Topology", "Training results", "Benchmark results"):
        at.sidebar.radio[0].set_value(view).run()
        assert not at.exception, view
