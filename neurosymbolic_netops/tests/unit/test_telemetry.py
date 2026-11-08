from benchmark.faults import TEMPLATES
from core.patch_ops import apply_plan
from core.telemetry.anomaly import EdgeDetector, build_corpus, load_or_train
from core.telemetry.generator import GeneratorOptions, generate
from core.telemetry.normalize import Normalizer


def test_normalizer_formats_and_quality_flags():
    n = Normalizer()
    ev = n.normalize([
        {"type": "syslog", "line": "<189>Nov 08 10:00:01.123 UTC Leaf-1: %LINK-3-UPDOWN: Interface GigabitEthernet0/2, changed state to down"},
        {"type": "syslog", "line": "Spine-1: %BGP-5-ADJCHANGE: neighbor 10.0.1.2 Down Interface flap"},
        {"type": "syslog", "line": "Spine-1: %BGP-5-ADJCHANGE: neighbor 10.0.1.2 Down Interface flap"},
        {"type": "syslog", "line": "garbage"},
    ])
    assert len(ev) == 2 and n.duplicates_dropped == 1 and n.unparsed == ["garbage"]
    assert ev[0].device == "Leaf-1" and ev[0].interface == "eth2" and ev[0].timestamp.tzinfo is not None
    assert ev[1].peer_ip == "10.0.1.2" and "missing_timestamp" in ev[1].quality


def test_generator_is_deterministic_and_healthy_network_is_quiet(testbed):
    a = generate(testbed.network, testbed.network, testbed.topology, testbed.intents, GeneratorOptions(seed=1))
    b = generate(testbed.network, testbed.network, testbed.topology, testbed.intents, GeneratorOptions(seed=1))
    assert a.records == b.records
    ev = Normalizer().normalize(a.records)
    dg = EdgeDetector(load_or_train()).detect("x", ev, 0, testbed.topology.devices)
    assert [x.kind for x in dg.anomalies] == []


def test_dropout_reported_as_missing_data(testbed):
    f = TEMPLATES["iface_shutdown"](testbed.network, testbed.topology, dev="Leaf-1", intf="eth1")
    g = generate(testbed.network, apply_plan(testbed.network, f.inject), testbed.topology, testbed.intents,
                 GeneratorOptions(seed=2, dropout_devices=["Spine-2"]))
    dg = EdgeDetector(load_or_train()).detect("x", Normalizer().normalize(g.records), 0, testbed.topology.devices)
    assert dg.missing_data == ["no telemetry from Spine-2"]
    assert any(a.kind == "link_down" and a.device == "Leaf-1" for a in dg.anomalies)


def test_acl_fault_without_log_keyword_detected_from_counters(testbed):
    f = TEMPLATES["acl_deny_lan"](testbed.network, testbed.topology, dev="Leaf-2")
    g = generate(testbed.network, apply_plan(testbed.network, f.inject), testbed.topology, testbed.intents,
                 GeneratorOptions(seed=4))
    dg = EdgeDetector(load_or_train()).detect("x", Normalizer().normalize(g.records), 0, testbed.topology.devices)
    assert any(a.kind == "acl_drops" and a.device == "Leaf-2" for a in dg.anomalies)
    ranked = testbed.topology.rank_candidates(dg.anomalies, testbed.network)
    assert ranked[0].device == "Leaf-2"


def test_classifier_heldout_metrics_are_recorded():
    clf = load_or_train()
    m = clf.metrics
    assert {"heldout_phrasing", "heldout_phrasing_message_only", "model_bytes"} <= set(m)
    X, y = build_corpus(99, 5, held_out=True)
    assert clf.evaluate(X, y)["accuracy"] >= 0.9
