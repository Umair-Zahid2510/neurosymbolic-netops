import numpy as np

from benchmark.faults import TEMPLATES
from core.patch_ops import apply_plan
from core.telemetry.anomaly import EdgeDetector, load_or_train
from core.telemetry.generator import GeneratorOptions, generate
from core.telemetry.normalize import Normalizer
from core.telemetry.ranker import LearnedRanker, feature_names, featurize, ranking_metrics


def _digest(tb, net, seed):
    g = generate(tb.network, net, tb.topology, tb.intents, GeneratorOptions(seed=seed))
    return EdgeDetector(load_or_train()).detect("x", Normalizer().normalize(g.records), 0, tb.topology.devices)


def test_featurize_shape_and_no_ground_truth(testbed):
    f = TEMPLATES["acl_deny_lan"](testbed.network, testbed.topology, dev="Leaf-2")
    net = apply_plan(testbed.network, f.inject)
    devs, X = featurize(_digest(testbed, net, 1).anomalies, testbed.topology, net)
    assert devs == sorted(testbed.network) and X.shape == (4, len(feature_names()))
    assert np.isfinite(X).all()


def test_ranker_learns_and_ranks(testbed):
    X, y = [], []
    for k, (dev, intf) in enumerate([("Leaf-1", "eth1"), ("Spine-2", "eth2"), ("Leaf-2", "eth1"), ("Spine-1", "eth1")]):
        net = apply_plan(testbed.network, TEMPLATES["iface_shutdown"](testbed.network, testbed.topology, dev=dev, intf=intf).inject)
        devs, F = featurize(_digest(testbed, net, k).anomalies, testbed.topology, net)
        X.append(F); y += [1 if d == dev else 0 for d in devs]
    m = LearnedRanker().fit(np.vstack(X), np.asarray(y))
    ranked = m.rank(devs, F)
    assert len(ranked) == 4 and all(0.0 <= p <= 1.0 for _, p in ranked)


def test_ranking_metrics():
    m = ranking_metrics([["A", "B", "C"], ["B", "A", "C"]], [{"A"}, {"A"}])
    assert m == {"n": 2, "top1": 0.5, "top3": 1.0, "mrr": 0.75, "recall_at_2": 1.0}
