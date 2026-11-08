"""Batfish verification backend (label: ``batfish``).

Talks to a running Batfish service (``docker run -d -p 9996:9996 batfish/allinone``) through
pybatfish. For every verification it:

1. renders each device in the IR to canonical Cisco IOS (``core.renderers.ios``),
2. initialises a Batfish snapshot (cached by configuration fingerprint),
3. refuses to verify if any file fails to parse (``fileParseStatus``),
4. answers intents with Batfish questions and maps the answers onto ``CheckResult``s:

   * ``bgp_sessions``        -> ``bgpSessionStatus`` (+ ``bgpSessionCompatibility`` for reasons)
   * ``reachability``        -> ``traceroute`` from ``@enter(node[iface])``; every trace must succeed
   * ``redundancy``          -> ``traceroute``; count transit-disjoint successful traces
   * ``isolation``           -> ``traceroute`` from each ingress; no trace may succeed
   * ``no_forwarding_loops`` -> ``detectLoops``
   * ``link_consistency``    -> not evaluated here (``ir_static``)

Raw answer rows are kept in ``CheckResult.evidence`` so results can be audited. If the service
is unreachable, ``verify`` raises ``BatfishUnavailable``; it never falls back silently.
"""

from __future__ import annotations

import socket
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.causal_topology import TopologyGraph
from core.config_ir import Network, network_fingerprint
from core.intent_schema import (BgpSessionsIntent, IntentSet, IsolationIntent, LinkConsistencyIntent,
                                NoForwardingLoopsIntent, ReachabilityIntent, RedundancyIntent)
from core.renderers.ios import ios_interface_name, render_ios
from core.verification.base import CheckResult, Counterexample, VerificationReport

SUCCESS = {"ACCEPTED", "DELIVERED_TO_SUBNET", "EXITS_NETWORK"}


class BatfishUnavailable(RuntimeError):
    pass


def batfish_reachable(host: str = "localhost", port: int = 9996, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class BatfishBackend:
    name = "batfish"

    def __init__(self, topology: TopologyGraph, host: str = "localhost", network_name: str = "netops",
                 workdir: Optional[Path] = None):
        self.topology = topology
        self.host = host
        self.network_name = network_name
        self.workdir = Path(workdir or tempfile.gettempdir()) / "netops_batfish_snapshots"
        self._bf = None
        self.last_snapshot: Optional[str] = None

    # ------------------------------------------------------------- session/snapshot
    def _session(self):
        if self._bf is None:
            if not batfish_reachable(self.host):
                raise BatfishUnavailable(f"Batfish service not reachable at {self.host}:9996")
            from pybatfish.client.session import Session
            bf = Session(host=self.host)
            bf.set_network(self.network_name)
            self._bf = bf
        return self._bf

    def load_snapshot(self, network: Network) -> str:
        bf = self._session()
        name = "s_" + network_fingerprint(network)[:16]
        if name in bf.list_snapshots():
            bf.set_snapshot(name)
        else:
            d = self.workdir / name / "configs"
            d.mkdir(parents=True, exist_ok=True)
            for dev, cfg in network.items():
                (d / f"{dev}.cfg").write_text(render_ios(cfg), encoding="utf-8")
            bf.init_snapshot(str(d.parent), name=name, overwrite=True)
        self.last_snapshot = name
        return name

    def _node(self, dev: str) -> str:
        return dev.lower()  # Batfish lower-cases hostnames

    def _dev(self, node: str, network: Network) -> str:
        for d in network:
            if d.lower() == str(node).lower():
                return d
        return str(node)

    # ------------------------------------------------------------- questions
    def parse_status(self) -> List[Dict[str, Any]]:
        bf = self._session()
        return bf.q.fileParseStatus().answer().frame().to_dict("records")

    def parse_warnings(self) -> List[Dict[str, Any]]:
        bf = self._session()
        return [{k: str(v) for k, v in r.items()} for r in bf.q.parseWarning().answer().frame().to_dict("records")]

    def _traceroute(self, start: str, flow) -> List[Any]:
        from pybatfish.datamodel.flow import HeaderConstraints
        bf = self._session()
        hc = dict(srcIps=flow.src_ip, dstIps=flow.dst_ip)
        if flow.protocol != "ip":
            hc["ipProtocols"] = [flow.protocol.upper()]
        if flow.dst_port is not None:
            hc["dstPorts"] = str(flow.dst_port)
        if flow.src_port is not None:
            hc["srcPorts"] = str(flow.src_port)
        frame = bf.q.traceroute(startLocation=start, headers=HeaderConstraints(**hc)).answer().frame()
        traces = []
        for _, row in frame.iterrows():
            traces.extend(row["Traces"])
        return traces

    def _start(self, device: str, interface: Optional[str]) -> str:
        if interface:
            return f"@enter({self._node(device)}[{ios_interface_name(interface)}])"
        return self._node(device)

    @staticmethod
    def _trace_nodes(trace) -> List[str]:
        return [h.node for h in trace.hops]

    def _check(self, intent, network: Network) -> CheckResult:
        bf = self._session()
        res = CheckResult(intent_id=intent.id, intent_kind=intent.kind, backend="batfish", passed=True)
        ces = res.counterexamples
        if isinstance(intent, BgpSessionsIntent):
            status = bf.q.bgpSessionStatus().answer().frame()
            compat = bf.q.bgpSessionCompatibility().answer().frame()
            reasons = {(str(r["Node"]), str(r["Remote_IP"])): str(r["Configured_Status"]) for _, r in compat.iterrows()}
            wanted = set(intent.sessions) if intent.sessions else None
            rows = []
            for _, r in status.iterrows():
                dev = self._dev(r["Node"], network)
                key = f"{dev}:{r['Remote_IP']}"
                st = str(r["Established_Status"])
                rows.append({"session": key, "status": st, "remote_node": str(r["Remote_Node"])})
                if wanted is not None and key not in wanted:
                    continue
                if st != "ESTABLISHED":
                    why = reasons.get((str(r["Node"]), str(r["Remote_IP"])), "")
                    ces.append(Counterexample(intent_id=intent.id, device=dev, disposition=st,
                                              summary=f"BGP {key}: {st} (Batfish configured status: {why})",
                                              details={"configured_status": why}))
            res.evidence = {"bgpSessionStatus": rows}
        elif isinstance(intent, (ReachabilityIntent, RedundancyIntent)):
            flow = intent.flow.representative()
            traces = self._traceroute(self._start(intent.source.device, intent.source.interface), flow)
            res.evidence = {"traces": [{"nodes": self._trace_nodes(t), "disposition": str(t.disposition)} for t in traces]}
            if isinstance(intent, ReachabilityIntent):
                for t in traces:
                    if str(t.disposition) not in SUCCESS:
                        nodes = [self._dev(n, network) for n in self._trace_nodes(t)]
                        ces.append(Counterexample(intent_id=intent.id, flow=intent.flow.label(), path=nodes,
                                                  disposition=str(t.disposition), device=nodes[-1] if nodes else None,
                                                  summary=f"{intent.flow.label()} from {intent.source.label()}: "
                                                          f"{t.disposition} via {'>'.join(nodes)}"))
                if not traces:
                    ces.append(Counterexample(intent_id=intent.id, summary="Batfish returned no traces"))
            else:
                ok = {tuple(self._trace_nodes(t)[1:-1]) for t in traces if str(t.disposition) in SUCCESS}
                used: set = set(); disjoint = 0
                for p in sorted(ok, key=lambda x: (len(x), x)):
                    if not used & set(p):
                        disjoint += 1; used |= set(p)
                if disjoint < intent.min_paths:
                    ces.append(Counterexample(intent_id=intent.id, flow=intent.flow.label(),
                                              summary=f"{intent.flow.label()}: {disjoint} transit-disjoint delivering "
                                                      f"path(s) per Batfish traceroute (need {intent.min_paths})"))
        elif isinstance(intent, IsolationIntent):
            flow = intent.flow.representative()
            for loc in intent.ingress:
                for t in self._traceroute(self._start(loc.device, loc.interface), flow):
                    if str(t.disposition) in SUCCESS:
                        nodes = [self._dev(n, network) for n in self._trace_nodes(t)]
                        ces.append(Counterexample(intent_id=intent.id, flow=intent.flow.label(), path=nodes,
                                                  disposition=str(t.disposition),
                                                  summary=f"ISOLATION BREACH (Batfish): {intent.flow.label()} entering "
                                                          f"at {loc.label()} {t.disposition} via {'>'.join(nodes)}"))
        elif isinstance(intent, NoForwardingLoopsIntent):
            frame = bf.q.detectLoops().answer().frame()
            for _, r in frame.iterrows():
                ces.append(Counterexample(intent_id=intent.id, summary=f"Batfish detectLoops: {r['Flow']}"))
            res.evidence = {"detectLoops_rows": len(frame)}
        elif isinstance(intent, LinkConsistencyIntent):
            res.passed = None
            res.note = "configuration invariant; evaluated by ir_static"
            return res
        res.passed = not ces
        return res

    def verify(self, network: Network, intents: IntentSet) -> VerificationReport:
        t0 = time.perf_counter()
        snap = self.load_snapshot(network)
        issues = [f"{r.get('File_Name')}: parse status {r.get('Status')}" for r in self.parse_status()
                  if str(r.get("Status")) != "PASSED"]
        checks = [] if issues else [self._check(i, network) for i in intents.intents]
        if checks:
            checks[0].evidence["snapshot"] = snap
            checks[0].evidence["parse_warnings"] = self.parse_warnings()
        failed = any(c.passed is False for c in checks)
        return VerificationReport(backends=["batfish"], passed=not failed and not issues, checks=checks,
                                  parse_issues=issues, network_fingerprint=network_fingerprint(network),
                                  duration_ms=round((time.perf_counter() - t0) * 1000, 1))
