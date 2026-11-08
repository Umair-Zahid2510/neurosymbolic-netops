"""Learned root-cause candidate ranker (trained component).

Problem: given an incident's Tier-1 anomaly digest, rank the network devices by the probability
that their configuration is the root cause.

Features per (incident, device) - all derived from the digest and topology, never from ground truth:
  * the hand-tuned topology heuristic score (``TopologyGraph.rank_candidates``) and its rank
  * counts of each anomaly kind observed ON the device
  * counts of each anomaly kind observed on the far end of a link of the device
  * number of anomalies naming one of the device's IPs as BGP peer
  * number of failed flows whose expected path includes the device
  * device role (spine/leaf) and degree
Model: gradient-boosted trees (scikit-learn ``HistGradientBoostingClassifier``), binary target
"device is a ground-truth culprit". Trained on the ``dev`` split only; evaluated on ``test`` and
``legacy``. Baseline for comparison: the heuristic ranking alone.
"""

from __future__ import annotations

import pickle
from typing import Dict, List, Tuple

import numpy as np

from core.causal_topology import TopologyGraph
from core.config_ir import Network
from core.telemetry.schema import AnomalyEvent

KINDS = ["link_down", "interface_errors", "bgp_session_down", "bgp_session_flap", "bgp_auth_failure",
         "bgp_peer_mismatch", "acl_drops", "probe_failure", "route_missing", "resource_pressure", "log_anomaly"]


def feature_names() -> List[str]:
    return (["heuristic_score", "heuristic_rank", "heuristic_score_share"]
            + [f"on_{k}" for k in KINDS] + [f"peer_{k}" for k in KINDS]
            + ["named_as_bgp_peer", "on_failed_flow_path", "is_spine", "degree", "n_anomalies_total"])


def featurize(anoms: List[AnomalyEvent], topo: TopologyGraph, network: Network) -> Tuple[List[str], np.ndarray]:
    ranked = topo.rank_candidates(anoms, network)
    score = {c.device: c.score for c in ranked}
    rank = {c.device: k + 1 for k, c in enumerate(ranked)}
    total = sum(score.values()) or 1.0
    devices = sorted(topo.devices)
    rows = []
    for d in devices:
        on = {k: 0 for k in KINDS}
        peer = {k: 0 for k in KINDS}
        named = flow = 0
        for a in anoms:
            if a.device == d:
                on[a.kind] = on.get(a.kind, 0) + 1
            if a.device and a.interface:
                l = topo.link_for(a.device, a.interface)
                if l and l.other(a.device)[0] == d:
                    peer[a.kind] = peer.get(a.kind, 0) + 1
            if a.peer_ip:
                o = topo.owner_of_ip(a.peer_ip, network)
                if o and o[0] == d:
                    named += 1
            if a.flow:
                s = topo.owner_of_ip(a.flow.src_ip, network)
                t = topo.owner_of_ip(a.flow.dst_ip, network)
                if s and t and d in topo.devices_on_shortest_paths(s[0], t[0]):
                    flow += 1
        role = topo.metadata["nodes"].get(d, {}).get("role")
        rows.append([score.get(d, 0.0), rank.get(d, len(devices) + 1), score.get(d, 0.0) / total]
                    + [on[k] for k in KINDS] + [peer[k] for k in KINDS]
                    + [named, flow, 1.0 if role == "spine" else 0.0, len(topo.link_peers(d)), len(anoms)])
    return devices, np.asarray(rows, dtype=float)


class LearnedRanker:
    def __init__(self, seed: int = 0):
        from sklearn.ensemble import HistGradientBoostingClassifier
        self.model = HistGradientBoostingClassifier(max_iter=200, learning_rate=0.05, max_leaf_nodes=15,
                                                    l2_regularization=1.0, random_state=seed)

    def fit(self, X: np.ndarray, y: np.ndarray) -> "LearnedRanker":
        self.model.fit(X, y)
        return self

    def rank(self, devices: List[str], X: np.ndarray) -> List[Tuple[str, float]]:
        p = self.model.predict_proba(X)[:, 1]
        return sorted(zip(devices, p), key=lambda t: (-t[1], t[0]))

    def save(self, path) -> int:
        import sklearn
        blob = pickle.dumps({"model": self.model, "sklearn_version": sklearn.__version__, "features": feature_names()})
        path.write_bytes(blob)
        return len(blob)


def ranking_metrics(ranked_lists: List[List[str]], truths: List[set]) -> Dict[str, float]:
    """top-1, top-3, mean reciprocal rank of the first culprit, and culprit recall@2."""
    t1 = t3 = mrr = r2 = 0.0
    for r, t in zip(ranked_lists, truths):
        pos = [k for k, d in enumerate(r) if d in t]
        t1 += bool(pos and pos[0] == 0)
        t3 += bool(pos and pos[0] < 3)
        mrr += 1.0 / (pos[0] + 1) if pos else 0.0
        r2 += len(set(r[:2]) & t) / len(t)
    n = max(1, len(truths))
    return {"n": len(truths), "top1": round(t1 / n, 4), "top3": round(t3 / n, 4), "mrr": round(mrr / n, 4),
            "recall_at_2": round(r2 / n, 4)}
