"""Causal discovery on telemetry time series with the PC algorithm (causal-learn).

What this is: the PC constraint-based algorithm (Fisher-z conditional independence tests)
applied to multivariate telemetry, scored against a KNOWN ground-truth causal graph.

Where the data comes from (label: SYNTHETIC): a linear-Gaussian structural causal model whose
graph is derived from the topology: physical-link error rate -> BGP session instability on that
link -> loss of every flow whose ECMP paths use that link; per-device CPU series are independent
distractors that are *correlated in time* (shared diurnal trend) but causally unrelated, so
correlation-based association would wrongly link them. Real per-sample device telemetry would be
needed to make claims about production networks; none is available here.

Three kinds of relation are reported separately:
  topological  - edges of the topology graph (structure, not inference)
  statistical  - pairwise |Pearson r| above a threshold (association only)
  causal       - PC output (directed where PC could orient; undirected otherwise)
"""

from __future__ import annotations

import random
from typing import Dict, List, Tuple

import numpy as np

from core.causal_topology import TopologyGraph
from core.config_ir import Network
from core.intent_schema import IntentSet, ReachabilityIntent
from core.network_model import compute_state, traceroute


def build_scm(topo: TopologyGraph, network: Network, intents: IntentSet) -> Tuple[List[str], List[Tuple[str, str]]]:
    links = [f"{l.a_dev}:{l.a_intf}~{l.b_dev}:{l.b_intf}" for l in topo.links]
    st = compute_state(network, topo)
    vars_, edges = [], []
    for l in links:
        vars_ += [f"err[{l}]", f"bgp_instab[{l}]"]
        edges.append((f"err[{l}]", f"bgp_instab[{l}]"))
    seen = set()
    for i in intents.intents:
        if isinstance(i, ReachabilityIntent) and i.flow.protocol == "ip":
            v = f"loss[{i.flow.src_prefix}->{i.flow.dst_prefix}]"
            if v in seen:
                continue
            seen.add(v)
            vars_.append(v)
            for t in traceroute(network, topo, st, i.source.device, i.flow.representative(), i.source.interface):
                p = t.path()
                for a, b in zip(p, p[1:]):
                    for l, lab in zip(topo.links, links):
                        if {l.a_dev, l.b_dev} == {a, b} and (f"bgp_instab[{lab}]", v) not in edges:
                            edges.append((f"bgp_instab[{lab}]", v))
    vars_ += [f"cpu[{d}]" for d in sorted(network)]
    return vars_, edges


def simulate(vars_: List[str], edges: List[Tuple[str, str]], n: int = 600, seed: int = 0) -> np.ndarray:
    rng = np.random.default_rng(seed)
    idx = {v: k for k, v in enumerate(vars_)}
    X = np.zeros((n, len(vars_)))
    parents: Dict[str, List[str]] = {v: [] for v in vars_}
    for a, b in edges:
        parents[b].append(a)
    trend = np.sin(np.linspace(0, 6 * np.pi, n))  # shared diurnal trend (confounds only cpu series)
    order = [v for v in vars_ if not parents[v]] + [v for v in vars_ if parents[v] and v.startswith("bgp")] + \
            [v for v in vars_ if v.startswith("loss")]
    for v in order:
        col = rng.normal(0, 1, n)
        if v.startswith("cpu"):
            col += 2.0 * trend
        for p in parents[v]:
            col += rng.uniform(0.8, 1.5) * X[:, idx[p]]
        X[:, idx[v]] = col
    return X


def run_pc(X: np.ndarray, vars_: List[str], alpha: float = 0.01):
    from causallearn.search.ConstraintBased.PC import pc
    cg = pc(X, alpha=alpha, indep_test="fisherz", show_progress=False)
    G = cg.G.graph
    directed, undirected = [], []
    for i in range(len(vars_)):
        for j in range(len(vars_)):
            if G[i, j] == -1 and G[j, i] == 1:
                directed.append((vars_[i], vars_[j]))
            elif i < j and G[i, j] == -1 and G[j, i] == -1:
                undirected.append((vars_[i], vars_[j]))
    return directed, undirected


def evaluate(topo: TopologyGraph, network: Network, intents: IntentSet, n: int = 600, seed: int = 0,
             alpha: float = 0.01, corr_threshold: float = 0.3, observe_confounder: bool = False) -> Dict:
    """observe_confounder=True adds the shared time-of-day trend as a measured variable, which
    restores PC's causal-sufficiency assumption for the CPU series."""
    vars_, truth = build_scm(topo, network, intents)
    X = simulate(vars_, truth, n, seed)
    if observe_confounder:
        X = np.column_stack([X, np.sin(np.linspace(0, 6 * np.pi, n))])
        vars_ = vars_ + ["time_of_day"]
        truth = truth + [("time_of_day", v) for v in vars_ if v.startswith("cpu")]
    directed, undirected = run_pc(X, vars_, alpha)
    est_skel = {frozenset(e) for e in directed + undirected}
    true_skel = {frozenset(e) for e in truth}
    tp = len(est_skel & true_skel)
    corr = np.corrcoef(X.T)
    assoc = {frozenset((vars_[i], vars_[j])) for i in range(len(vars_)) for j in range(i + 1, len(vars_))
             if abs(corr[i, j]) > corr_threshold}
    spurious_assoc = [sorted(e) for e in assoc - true_skel if any(v.startswith("cpu") for v in e)]
    oriented_correct = sum(1 for e in directed if e in set(truth))
    return {
        "data": "SYNTHETIC linear-Gaussian SCM derived from topology", "observe_confounder": observe_confounder, "n_samples": n, "n_variables": len(vars_),
        "true_edges": len(truth),
        "pc_skeleton_precision": round(tp / len(est_skel), 4) if est_skel else None,
        "pc_skeleton_recall": round(tp / len(true_skel), 4),
        "pc_directed_edges": len(directed), "pc_directed_correct": oriented_correct,
        "pc_undirected_edges": len(undirected),
        "shd_skeleton": len(est_skel ^ true_skel),
        "correlation_edges": len(assoc), "correlation_precision": round(len(assoc & true_skel) / len(assoc), 4) if assoc else None,
        "spurious_cpu_associations_by_correlation": len(spurious_assoc),
        "spurious_cpu_edges_by_pc": sum(1 for e in est_skel if any(v.startswith("cpu") for v in e) and e not in true_skel),
    }
