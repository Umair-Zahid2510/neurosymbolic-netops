"""Tier-1 topology graph and topology-aware root-cause candidate ranking.

Terminology (kept deliberately separate, see LIMITATIONS.md):

* **Topological relationships** - physical links, BGP sessions, subnet attachment. Built here
  from topology metadata *and verified against the parsed device configurations*.
* **Statistical dependencies** / **inferred causal relationships** - computed from telemetry
  time series in ``core/causal_discovery.py`` (PC algorithm). Nothing in this module performs
  causal discovery, despite the historical module name, which is kept for compatibility.

Candidate ranking is a transparent heuristic: anomaly evidence is attributed to the device it
was observed on, and partially to topological neighbours that could be the true cause (the far
end of a link, the owner of a peer IP, devices on the expected path of a failed flow).
"""

from __future__ import annotations

import ipaddress
import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

import networkx as nx
from pydantic import BaseModel

from core.config_ir import Network
from core.telemetry.schema import AnomalyEvent


class Link(BaseModel):
    a_dev: str
    a_intf: str
    b_dev: str
    b_intf: str

    def other(self, dev: str) -> Tuple[str, str]:
        return (self.b_dev, self.b_intf) if dev == self.a_dev else (self.a_dev, self.a_intf)

    def endpoint(self, dev: str) -> str:
        return self.a_intf if dev == self.a_dev else self.b_intf


class CandidateScore(BaseModel):
    device: str
    score: float
    reasons: List[str]


# Relative weight of the share of an anomaly attributed to each related device.
SAME_DEVICE = 1.0
LINK_PEER = 0.6
PEER_IP_OWNER = 0.8
ON_FLOW_PATH = 0.3


class TopologyGraph:
    def __init__(self, metadata: dict, network: Optional[Network] = None):
        self.metadata = metadata
        self.devices: List[str] = sorted(metadata.get("nodes", {}))
        self.links: List[Link] = []
        self.graph = nx.Graph()
        self.warnings: List[str] = []
        self._build(network)

    @classmethod
    def from_file(cls, path: Path, network: Optional[Network] = None) -> "TopologyGraph":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")), network)

    # ------------------------------------------------------------------ build
    def _build(self, network: Optional[Network]) -> None:
        seen = set()
        for dev, info in self.metadata.get("nodes", {}).items():
            self.graph.add_node(dev, kind="device", role=info.get("role"), asn=info.get("asn"))
            for intf, iinfo in info.get("interfaces", {}).items():
                iid = f"{dev}:{intf}"
                self.graph.add_node(iid, kind="interface", device=dev)
                self.graph.add_edge(dev, iid, relation="contains")
                if iinfo.get("subnet"):
                    self.graph.add_node(iinfo["subnet"], kind="subnet")
                    self.graph.add_edge(iid, iinfo["subnet"], relation="attached_subnet")
                pn, pi = iinfo.get("peer_node"), iinfo.get("peer_intf")
                if pn and pi:
                    key = tuple(sorted([(dev, intf), (pn, pi)]))
                    if key not in seen:
                        seen.add(key)
                        (ad, ai), (bd, bi) = key
                        self.links.append(Link(a_dev=ad, a_intf=ai, b_dev=bd, b_intf=bi))
                        self.graph.add_edge(f"{ad}:{ai}", f"{bd}:{bi}", relation="link")
        if network is not None:
            self._verify_against_configs(network)
            self._add_bgp_sessions(network)

    def _verify_against_configs(self, network: Network) -> None:
        for l in self.links:
            a = network.get(l.a_dev); b = network.get(l.b_dev)
            if not a or not b or l.a_intf not in a.interfaces or l.b_intf not in b.interfaces:
                self.warnings.append(f"link {l.a_dev}:{l.a_intf}-{l.b_dev}:{l.b_intf} missing in configs")
                continue
            na, nb = a.interfaces[l.a_intf].network, b.interfaces[l.b_intf].network
            if na != nb:
                self.warnings.append(f"link {l.a_dev}:{l.a_intf}-{l.b_dev}:{l.b_intf} subnet mismatch {na} vs {nb}")
        for dev, cfg in network.items():
            for intf in cfg.interfaces.values():
                if intf.network and self.link_for(dev, intf.name) is None:
                    self.graph.add_node(intf.network, kind="subnet")
                    self.graph.add_edge(f"{dev}:{intf.name}", intf.network, relation="attached_subnet")

    def _add_bgp_sessions(self, network: Network) -> None:
        for dev, cfg in network.items():
            if not cfg.bgp:
                continue
            for ip in cfg.bgp.neighbors:
                owner = self.owner_of_ip(ip, network)
                if owner:
                    self.graph.add_edge(dev, owner[0], relation="bgp_session_configured")

    # ------------------------------------------------------------------ queries
    def owner_of_ip(self, ip: str, network: Network) -> Optional[Tuple[str, str]]:
        """Device/interface that *owns* ``ip`` exactly, else the one whose subnet contains it."""
        for dev, cfg in network.items():
            i = cfg.interface_owning(ip)
            if i:
                return dev, i.name
        for dev, cfg in network.items():
            i = cfg.interface_on_subnet(ip)
            if i and self.link_for(dev, i.name) is None:
                return dev, i.name
        return None

    def link_peers(self, dev: str) -> List[Tuple[str, str, str]]:
        """[(local_intf, peer_dev, peer_intf)]"""
        out = []
        for l in self.links:
            if dev in (l.a_dev, l.b_dev):
                pd, pi = l.other(dev)
                out.append((l.endpoint(dev), pd, pi))
        return out

    def link_for(self, dev: str, intf: str) -> Optional[Link]:
        for l in self.links:
            if (l.a_dev, l.a_intf) == (dev, intf) or (l.b_dev, l.b_intf) == (dev, intf):
                return l
        return None

    def device_graph(self) -> nx.Graph:
        g = nx.Graph()
        g.add_nodes_from(self.devices)
        for l in self.links:
            g.add_edge(l.a_dev, l.b_dev)
        return g

    def devices_on_shortest_paths(self, src_dev: str, dst_dev: str) -> Set[str]:
        g = self.device_graph()
        try:
            return {d for p in nx.all_shortest_paths(g, src_dev, dst_dev) for d in p}
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return set()

    def k_hop(self, seeds: Iterable[str], k: int) -> Set[str]:
        g = self.device_graph()
        out: Set[str] = set()
        for s in seeds:
            if s in g:
                out |= set(nx.single_source_shortest_path_length(g, s, cutoff=k))
        return out

    # ------------------------------------------------------------------ ranking
    def rank_candidates(self, anomalies: List[AnomalyEvent], network: Network) -> List[CandidateScore]:
        scores: Dict[str, float] = defaultdict(float)
        reasons: Dict[str, List[str]] = defaultdict(list)

        def credit(dev: Optional[str], w: float, why: str) -> None:
            if dev and dev in self.devices:
                scores[dev] += w
                reasons[dev].append(why)

        for a in anomalies:
            w = a.severity
            credit(a.device, w * SAME_DEVICE, f"{a.kind} observed on device ({a.anomaly_id})")
            if a.device and a.interface:
                l = self.link_for(a.device, a.interface)
                if l:
                    pd, pi = l.other(a.device)
                    credit(pd, w * LINK_PEER, f"far end {pi} of link with {a.kind} on {a.device}:{a.interface}")
            if a.peer_ip:
                owner = self.owner_of_ip(a.peer_ip, network)
                if owner and owner[0] != a.device:
                    credit(owner[0], w * PEER_IP_OWNER, f"owns peer {a.peer_ip} named in {a.kind}")
            if a.flow:
                s = self.owner_of_ip(a.flow.src_ip, network)
                d = self.owner_of_ip(a.flow.dst_ip, network)
                if s and d:
                    for dev in self.devices_on_shortest_paths(s[0], d[0]):
                        credit(dev, w * ON_FLOW_PATH, f"on expected path of failed flow {a.flow.src_ip}->{a.flow.dst_ip}")
        ranked = [CandidateScore(device=d, score=round(scores[d], 4), reasons=reasons[d]) for d in scores]
        ranked.sort(key=lambda c: (-c.score, c.device))
        return ranked

    def prune(self, ranked: List[CandidateScore], keep_hops: int = 0, min_score_ratio: float = 0.0) -> List[str]:
        """Devices kept for diagnosis: every device with a positive score at or above
        ``min_score_ratio * top_score``, expanded by ``keep_hops`` link hops.
        Falls back to all devices when there is no evidence."""
        if not ranked:
            return list(self.devices)
        top = ranked[0].score
        seeds = [c.device for c in ranked if c.score > 0 and c.score >= min_score_ratio * top]
        kept = self.k_hop(seeds, keep_hops) if keep_hops else set(seeds)
        return sorted(kept)

