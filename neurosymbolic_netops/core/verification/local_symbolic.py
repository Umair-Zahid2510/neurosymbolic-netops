"""Local symbolic verification backends (labels: ``local_symbolic`` and ``ir_static``).

``LocalSymbolicBackend`` evaluates intents with the deterministic model in
``core/network_model.py``. It is NOT Batfish. Its modelling assumptions are listed in that
module and in LIMITATIONS.md.

``IrStaticBackend`` evaluates configuration invariants that need no forwarding model (link
parameter consistency). It is combined with whichever forwarding backend is in use.
"""

from __future__ import annotations

import time
from typing import List

from core.causal_topology import TopologyGraph
from core.config_ir import Network, network_fingerprint
from core.intent_schema import (BgpSessionsIntent, IntentSet, IsolationIntent, LinkConsistencyIntent,
                                NoForwardingLoopsIntent, ReachabilityIntent, RedundancyIntent)
from core.network_model import NetworkState, Trace, compute_state, traceroute
from core.verification.base import CheckResult, Counterexample, VerificationReport


def _trace_ce(intent_id: str, flow_label: str, t: Trace, summary: str) -> Counterexample:
    details = {"detail": t.detail}
    if t.acl_hit:
        details["acl_hit"] = t.acl_hit.model_dump()
    return Counterexample(intent_id=intent_id, summary=summary, flow=flow_label, path=t.path(),
                          disposition=t.disposition, device=t.hops[-1].device if t.hops else None,
                          details=details)


class LocalSymbolicBackend:
    name = "local_symbolic"

    def __init__(self, topology: TopologyGraph):
        self.topology = topology

    def _check(self, intent, network: Network, state: NetworkState) -> CheckResult:
        topo = self.topology
        res = CheckResult(intent_id=intent.id, intent_kind=intent.kind, backend="local_symbolic", passed=True)
        ces = res.counterexamples
        if isinstance(intent, BgpSessionsIntent):
            wanted = set(intent.sessions) if intent.sessions else None
            for s in state.sessions:
                key = f"{s.device}:{s.neighbor_ip}"
                if wanted is not None and key not in wanted:
                    continue
                if s.state != "ESTABLISHED":
                    ces.append(Counterexample(intent_id=intent.id, device=s.device, disposition=s.state,
                                              summary=f"BGP {key} -> {s.peer_device}: {s.state}: " + "; ".join(s.reasons),
                                              details={"reasons": s.reasons, "peer": s.peer_device}))
            res.evidence = {"sessions": {f"{s.device}:{s.neighbor_ip}": s.state for s in state.sessions}}
        elif isinstance(intent, ReachabilityIntent):
            flow = intent.flow.representative()
            traces = traceroute(network, topo, state, intent.source.device, flow, intent.source.interface)
            for t in traces:
                if not t.success:
                    ces.append(_trace_ce(intent.id, intent.flow.label(), t,
                                         f"{intent.flow.label()} from {intent.source.label()}: {t.disposition} at "
                                         f"{t.hops[-1].device} ({t.detail}) via {'>'.join(t.path())}"))
            if not traces:
                ces.append(Counterexample(intent_id=intent.id, summary="no trace produced", flow=intent.flow.label()))
            res.evidence = {"traces": [{"path": t.path(), "disposition": t.disposition} for t in traces]}
        elif isinstance(intent, RedundancyIntent):
            flow = intent.flow.representative()
            traces = traceroute(network, topo, state, intent.source.device, flow, intent.source.interface)
            ok_paths = {tuple(t.path()[1:-1]) for t in traces if t.success}
            transit = set().union(*[set(p) for p in ok_paths]) if ok_paths else set()
            used: set = set()
            disjoint = 0
            for p in sorted(ok_paths, key=lambda x: (len(x), x)):  # greedy transit-disjoint path count
                if not used & set(p):
                    disjoint += 1
                    used |= set(p)
            if disjoint < intent.min_paths:
                ces.append(Counterexample(intent_id=intent.id, flow=intent.flow.label(),
                                          summary=f"{intent.flow.label()}: only {disjoint} disjoint delivering path(s) "
                                                  f"(need {intent.min_paths}); transit devices {sorted(transit)}",
                                          details={"delivering_paths": [list(p) for p in ok_paths]}))
            res.evidence = {"delivering_paths": [list(p) for p in ok_paths]}
        elif isinstance(intent, IsolationIntent):
            flow = intent.flow.representative()
            for loc in intent.ingress:
                for t in traceroute(network, topo, state, loc.device, flow, loc.interface):
                    if t.success:
                        ces.append(_trace_ce(intent.id, intent.flow.label(), t,
                                             f"ISOLATION BREACH: {intent.flow.label()} entering at {loc.label()} is "
                                             f"DELIVERED via {'>'.join(t.path())}"))
        elif isinstance(intent, NoForwardingLoopsIntent):
            from core.intent_schema import FlowSelector
            for sp in intent.prefixes:
                for dp in intent.prefixes:
                    if sp == dp:
                        continue
                    f = FlowSelector(src_prefix=sp, dst_prefix=dp)
                    src = topo.owner_of_ip(f.representative().src_ip, network)
                    starts = [d for d in network] if src is None else [src[0]]
                    for d in starts:
                        for t in traceroute(network, topo, state, d, f.representative()):
                            if t.disposition in ("LOOP", "MAX_HOPS"):
                                ces.append(_trace_ce(intent.id, f.label(), t, f"forwarding loop for {f.label()}: {'>'.join(t.path())}"))
        elif isinstance(intent, LinkConsistencyIntent):
            res.passed = None
            res.note = "configuration invariant; evaluated by ir_static"
            return res
        else:  # pragma: no cover
            res.passed = None
            res.note = f"unsupported intent kind {intent.kind}"
            return res
        res.passed = not ces
        return res

    def verify(self, network: Network, intents: IntentSet) -> VerificationReport:
        t0 = time.perf_counter()
        issues = [f"{d}: {l}" for d, cfg in network.items() for l in cfg.unsupported_lines]
        state = compute_state(network, self.topology)
        checks: List[CheckResult] = [self._check(i, network, state) for i in intents.intents]
        failed = any(c.passed is False for c in checks)
        return VerificationReport(backends=["local_symbolic"], passed=not failed and not issues, checks=checks,
                                  parse_issues=issues, network_fingerprint=network_fingerprint(network),
                                  duration_ms=round((time.perf_counter() - t0) * 1000, 3))


class IrStaticBackend:
    name = "ir_static"

    def __init__(self, topology: TopologyGraph):
        self.topology = topology

    def verify(self, network: Network, intents: IntentSet) -> VerificationReport:
        t0 = time.perf_counter()
        checks = []
        for intent in intents.intents:
            if not isinstance(intent, LinkConsistencyIntent):
                continue
            res = CheckResult(intent_id=intent.id, intent_kind=intent.kind, backend="ir_static", passed=True)
            for l in self.topology.links:
                a = network.get(l.a_dev); b = network.get(l.b_dev)
                ia = a.interfaces.get(l.a_intf) if a else None
                ib = b.interfaces.get(l.b_intf) if b else None
                if ia is None or ib is None:
                    res.counterexamples.append(Counterexample(intent_id=intent.id,
                                               summary=f"link {l.a_dev}:{l.a_intf}-{l.b_dev}:{l.b_intf} missing interface"))
                    continue
                for attr in ("mtu", "speed", "duplex"):
                    va, vb = getattr(ia, attr), getattr(ib, attr)
                    if va != vb:
                        res.counterexamples.append(Counterexample(
                            intent_id=intent.id, device=l.a_dev,
                            summary=f"{attr} mismatch on link {l.a_dev}:{l.a_intf}={va} vs {l.b_dev}:{l.b_intf}={vb}",
                            details={"attribute": attr, l.a_dev: va, l.b_dev: vb}))
            res.passed = not res.counterexamples
            checks.append(res)
        return VerificationReport(backends=["ir_static"], passed=all(c.passed for c in checks), checks=checks,
                                  network_fingerprint=network_fingerprint(network),
                                  duration_ms=round((time.perf_counter() - t0) * 1000, 3))
