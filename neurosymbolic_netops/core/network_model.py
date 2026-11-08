"""Local control-plane / data-plane model of an IR network (label: ``local_symbolic``).

This is a deterministic *simulation*, not Batfish and not a device. It computes:

1. Link state from interface admin state and physical parameters.
2. eBGP session state from configuration on both ends (peer ownership, connected subnet,
   link state, remote-as on both sides, MD5 password equality, IPv4-unicast activation,
   TCP/179 admitted by interface ACLs in at least one initiation direction, physical
   degradation).
3. Per-device RIBs: connected, static, and eBGP routes propagated to a fixed point with
   AS-path loop prevention, outbound/inbound route-maps, shortest-AS-path best path, and
   ``maximum-paths`` ECMP.
4. Packet traces (``traceroute``) through ingress/egress ACLs and longest-prefix-match
   forwarding, enumerating every ECMP branch, with LOOP / NO_ROUTE / DENIED dispositions.

Documented modelling assumptions (also in LIMITATIONS.md):

* Single-hop eBGP only; no iBGP, OSPF, VRFs, NAT or policy routing.
* Forced speed mismatch -> link down. Duplex or MTU mismatch -> link up but "degraded";
  BGP sessions over a degraded link are reported FLAPPING and carry no routes (conservative).
* An undefined ACL bound to an interface permits everything (IOS behaviour). An undefined
  route-map applied to a BGP neighbor denies every route.
* A route-map entry matching a non-existent prefix-list matches nothing.
* Timers, convergence transients, and hardware failures are out of scope.
"""

from __future__ import annotations

import ipaddress
from typing import Dict, List, Literal, Optional, Tuple

from pydantic import BaseModel, Field

from core.causal_topology import Link, TopologyGraph
from core.config_ir import DeviceConfig, Network
from core.telemetry.schema import FlowSpec

EPHEMERAL_PORT = 49152
ADMIN_DISTANCE = {"connected": 0, "static": 1, "bgp": 20}


class LinkState(BaseModel):
    a_dev: str
    a_intf: str
    b_dev: str
    b_intf: str
    up: bool
    down_reasons: List[str] = Field(default_factory=list)
    degraded: List[str] = Field(default_factory=list)


class BgpSessionState(BaseModel):
    device: str
    neighbor_ip: str
    peer_device: Optional[str] = None
    local_interface: Optional[str] = None
    state: Literal["ESTABLISHED", "NOT_ESTABLISHED", "FLAPPING", "NO_PEER"]
    reasons: List[str] = Field(default_factory=list)
    routes_received: int = 0


class NextHop(BaseModel):
    ip: Optional[str] = None  # None = directly connected
    interface: str


class Route(BaseModel):
    prefix: str
    protocol: Literal["connected", "static", "bgp"]
    next_hops: List[NextHop]
    as_path: List[int] = Field(default_factory=list)
    learned_from: List[str] = Field(default_factory=list)


class Hop(BaseModel):
    device: str
    ingress: Optional[str] = None
    egress: Optional[str] = None
    note: str = ""


class AclHit(BaseModel):
    device: str
    interface: str
    direction: Literal["in", "out"]
    acl: str
    rule_index: Optional[int]  # None = implicit deny
    rule: str


class Trace(BaseModel):
    hops: List[Hop]
    disposition: Literal["DELIVERED", "DENIED_IN", "DENIED_OUT", "NO_ROUTE", "LOOP", "MAX_HOPS", "LINK_DOWN"]
    detail: str = ""
    acl_hit: Optional[AclHit] = None

    @property
    def success(self) -> bool:
        return self.disposition == "DELIVERED"

    def path(self) -> List[str]:
        return [h.device for h in self.hops]


class NetworkState(BaseModel):
    links: List[LinkState]
    sessions: List[BgpSessionState]
    ribs: Dict[str, Dict[str, Route]]

    def session(self, device: str, neighbor_ip: str) -> Optional[BgpSessionState]:
        for s in self.sessions:
            if s.device == device and s.neighbor_ip == neighbor_ip:
                return s
        return None

    def link_state(self, dev: str, intf: str) -> Optional[LinkState]:
        for l in self.links:
            if (l.a_dev, l.a_intf) == (dev, intf) or (l.b_dev, l.b_intf) == (dev, intf):
                return l
        return None


# ------------------------------------------------------------------ helpers
def acl_check(cfg: DeviceConfig, intf_name: str, direction: str, flow: FlowSpec) -> Optional[AclHit]:
    """Return an AclHit if the interface ACL in ``direction`` denies ``flow``, else None."""
    intf = cfg.interfaces.get(intf_name)
    if not intf:
        return None
    name = intf.acl_in if direction == "in" else intf.acl_out
    if not name or name not in cfg.acls:
        return None  # unbound or undefined ACL -> permit (IOS semantics)
    action, idx = cfg.acls[name].evaluate(flow.protocol, flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port)
    if action == "deny":
        rule = cfg.acls[name].rules[idx].key() if idx is not None else "implicit deny"
        return AclHit(device=cfg.hostname, interface=intf_name, direction=direction, acl=name,
                      rule_index=idx, rule=rule)
    return None


def route_map_permits(cfg: DeviceConfig, name: Optional[str], prefix: str) -> bool:
    if name is None:
        return True
    entries = cfg.route_maps.get(name)
    if entries is None:
        return False
    for e in sorted(entries, key=lambda x: x.seq):
        if e.match_prefix_list is None:
            return e.action == "permit"
        pl = cfg.prefix_lists.get(e.match_prefix_list)
        if pl is not None and pl.permits(prefix):
            return e.action == "permit"
    return False


def _speed_conflict(a: Optional[str], b: Optional[str]) -> bool:
    return bool(a and b and "auto" not in (a, b) and a != b)


# ------------------------------------------------------------------ state computation
def compute_links(network: Network, topo: TopologyGraph) -> List[LinkState]:
    out = []
    for l in topo.links:
        a = network.get(l.a_dev); b = network.get(l.b_dev)
        ia = a.interfaces.get(l.a_intf) if a else None
        ib = b.interfaces.get(l.b_intf) if b else None
        reasons, degraded = [], []
        if ia is None or ib is None:
            reasons.append("interface missing from configuration")
        else:
            if not ia.enabled:
                reasons.append(f"{l.a_dev}:{l.a_intf} administratively down")
            if not ib.enabled:
                reasons.append(f"{l.b_dev}:{l.b_intf} administratively down")
            if _speed_conflict(ia.speed, ib.speed):
                reasons.append(f"speed mismatch {l.a_dev}:{l.a_intf}={ia.speed} vs {l.b_dev}:{l.b_intf}={ib.speed}")
            if ia.duplex and ib.duplex and "auto" not in (ia.duplex, ib.duplex) and ia.duplex != ib.duplex:
                degraded.append(f"duplex mismatch {l.a_dev}:{l.a_intf}={ia.duplex} vs {l.b_dev}:{l.b_intf}={ib.duplex}")
            if ia.mtu != ib.mtu:
                degraded.append(f"MTU mismatch {l.a_dev}:{l.a_intf}={ia.mtu} vs {l.b_dev}:{l.b_intf}={ib.mtu}")
        out.append(LinkState(a_dev=l.a_dev, a_intf=l.a_intf, b_dev=l.b_dev, b_intf=l.b_intf,
                             up=not reasons, down_reasons=reasons, degraded=degraded))
    return out


def _tcp179_admitted(a: DeviceConfig, ai: str, a_ip: str, b: DeviceConfig, bi: str, b_ip: str) -> Tuple[bool, List[str]]:
    """Can a TCP/179 session form with either side initiating? Returns (ok, blocking reasons)."""
    blocks: List[str] = []
    for (ini, ini_i, ini_ip, rsp, rsp_i, rsp_ip) in ((a, ai, a_ip, b, bi, b_ip), (b, bi, b_ip, a, ai, a_ip)):
        syn = FlowSpec(src_ip=ini_ip, dst_ip=rsp_ip, protocol="tcp", src_port=EPHEMERAL_PORT, dst_port=179)
        ack = FlowSpec(src_ip=rsp_ip, dst_ip=ini_ip, protocol="tcp", src_port=179, dst_port=EPHEMERAL_PORT)
        hits = [h for h in (acl_check(ini, ini_i, "out", syn), acl_check(rsp, rsp_i, "in", syn),
                            acl_check(rsp, rsp_i, "out", ack), acl_check(ini, ini_i, "in", ack)) if h]
        if not hits:
            return True, []
        blocks += [f"{h.device} {h.interface} ACL {h.acl} ({h.direction}) '{h.rule}' blocks TCP/179" for h in hits]
    return False, sorted(set(blocks))


def compute_sessions(network: Network, topo: TopologyGraph, links: List[LinkState]) -> List[BgpSessionState]:
    lmap = {}
    for ls in links:
        lmap[(ls.a_dev, ls.a_intf)] = ls
        lmap[(ls.b_dev, ls.b_intf)] = ls
    out = []
    for dev, cfg in sorted(network.items()):
        if not cfg.bgp:
            continue
        for ip, nbr in sorted(cfg.bgp.neighbors.items()):
            owner = topo.owner_of_ip(ip, network)
            if not owner or network[owner[0]].interface_owning(ip) is None:
                out.append(BgpSessionState(device=dev, neighbor_ip=ip, state="NO_PEER",
                                           reasons=[f"no device owns {ip}"]))
                continue
            pdev, pintf = owner
            peer = network[pdev]
            local = cfg.interface_on_subnet(ip)
            st = BgpSessionState(device=dev, neighbor_ip=ip, peer_device=pdev,
                                 local_interface=local.name if local else None, state="ESTABLISHED")
            r = st.reasons
            if local is None:
                r.append(f"{dev} has no connected interface to {ip} (multihop not modelled)")
            else:
                ls = lmap.get((dev, local.name))
                if ls is None or (ls.b_dev, ls.a_dev).count(pdev) == 0:
                    r.append(f"no physical link between {dev}:{local.name} and {pdev}:{pintf}")
                elif not ls.up:
                    r += ls.down_reasons
            local_ip = local.ip if local else None
            pbgp = peer.bgp
            pnbr = pbgp.neighbors.get(local_ip) if (pbgp and local_ip) else None
            if not pbgp:
                r.append(f"{pdev} has no BGP process")
            elif pnbr is None:
                r.append(f"{pdev} has no neighbor statement for {local_ip}")
            else:
                if nbr.remote_as != pbgp.asn:
                    r.append(f"{dev} expects remote-as {nbr.remote_as} for {ip} but {pdev} is AS {pbgp.asn}")
                if pnbr.remote_as != cfg.bgp.asn:
                    r.append(f"{pdev} expects remote-as {pnbr.remote_as} for {local_ip} but {dev} is AS {cfg.bgp.asn}")
                if (nbr.password or None) != (pnbr.password or None):
                    r.append(f"MD5 authentication mismatch between {dev} and {pdev}")
                if not nbr.activated:
                    r.append(f"{dev}: neighbor {ip} not activated for IPv4 unicast")
                if not pnbr.activated:
                    r.append(f"{pdev}: neighbor {local_ip} not activated for IPv4 unicast")
            if local is not None and local_ip:
                ok, blocks = _tcp179_admitted(cfg, local.name, local_ip, peer, pintf, ip)
                if not ok:
                    r += blocks
            if r:
                st.state = "NOT_ESTABLISHED"
            elif local is not None and lmap.get((dev, local.name)) and lmap[(dev, local.name)].degraded:
                st.state = "FLAPPING"
                r += lmap[(dev, local.name)].degraded
            out.append(st)
    return out


def compute_ribs(network: Network, topo: TopologyGraph, links: List[LinkState],
                 sessions: List[BgpSessionState]) -> Dict[str, Dict[str, Route]]:
    up_by_if = {}
    for ls in links:
        up_by_if[(ls.a_dev, ls.a_intf)] = ls.up
        up_by_if[(ls.b_dev, ls.b_intf)] = ls.up
    ribs: Dict[str, Dict[str, Route]] = {}
    for dev, cfg in network.items():
        rib: Dict[str, Route] = {}
        for intf in cfg.interfaces.values():
            if not intf.enabled or not intf.network:
                continue
            if not up_by_if.get((dev, intf.name), True):
                continue
            rib[intf.network] = Route(prefix=intf.network, protocol="connected",
                                      next_hops=[NextHop(interface=intf.name)])
        for sr in cfg.static_routes:
            out_if = cfg.interface_on_subnet(sr.next_hop)
            if out_if and out_if.network in rib and sr.prefix not in rib:
                rib[sr.prefix] = Route(prefix=sr.prefix, protocol="static",
                                       next_hops=[NextHop(ip=sr.next_hop, interface=out_if.name)])
        ribs[dev] = rib

    # BGP: adj-RIB-in candidates, fixed-point propagation
    est = {(s.device, s.neighbor_ip): s for s in sessions if s.state == "ESTABLISHED"}
    # bgp_best[dev][prefix] = list of (as_path, next_hop_ip, interface, from_device)
    bgp_best: Dict[str, Dict[str, List[Tuple[Tuple[int, ...], Optional[str], Optional[str], Optional[str]]]]] = {}
    for dev, cfg in network.items():
        bgp_best[dev] = {}
        if cfg.bgp:
            for p in cfg.bgp.networks:
                if p in ribs[dev] and ribs[dev][p].protocol in ("connected", "static"):
                    bgp_best[dev][p] = [((), None, None, None)]
    for _round in range(32):
        changed = False
        cand: Dict[str, Dict[str, list]] = {d: {} for d in network}
        for (dev, nip), s in est.items():
            cfg = network[dev]
            pdev = s.peer_device
            peer = network[pdev]
            nbr = cfg.bgp.neighbors[nip]
            local_ip = cfg.interfaces[s.local_interface].ip
            if (pdev, local_ip) not in est:
                continue
            pnbr = peer.bgp.neighbors[local_ip]
            # routes advertised by pdev to dev
            for prefix, paths in bgp_best[pdev].items():
                path = paths[0][0]
                if not route_map_permits(peer, pnbr.route_map_out, prefix):
                    continue
                new_path = (peer.bgp.asn,) + path
                if cfg.bgp.asn in new_path:
                    continue
                if not route_map_permits(cfg, nbr.route_map_in, prefix):
                    continue
                cand[dev].setdefault(prefix, []).append((new_path, nip, s.local_interface, pdev))
        new_best: Dict[str, Dict[str, list]] = {}
        for dev, cfg in network.items():
            nb: Dict[str, list] = {}
            for p, paths in bgp_best[dev].items():
                if paths and paths[0][1] is None:
                    nb[p] = paths  # locally originated always wins
            for p, paths in cand[dev].items():
                if p in nb:
                    continue
                shortest = min(len(x[0]) for x in paths)
                best = sorted([x for x in paths if len(x[0]) == shortest],
                              key=lambda x: ipaddress.ip_address(x[1]))
                maxp = cfg.bgp.maximum_paths if cfg.bgp else 1
                nb[p] = best[:maxp]
            new_best[dev] = nb
        if new_best != bgp_best:
            changed = True
            bgp_best = new_best
        if not changed:
            break
    for dev, table in bgp_best.items():
        for p, paths in table.items():
            if paths[0][1] is None:
                continue
            if p in ribs[dev] and ADMIN_DISTANCE[ribs[dev][p].protocol] < ADMIN_DISTANCE["bgp"]:
                continue
            ribs[dev][p] = Route(prefix=p, protocol="bgp",
                                 next_hops=[NextHop(ip=x[1], interface=x[2]) for x in paths],
                                 as_path=list(paths[0][0]), learned_from=[x[3] for x in paths])
    return ribs


def compute_state(network: Network, topo: TopologyGraph) -> NetworkState:
    links = compute_links(network, topo)
    sessions = compute_sessions(network, topo, links)
    ribs = compute_ribs(network, topo, links, sessions)
    counts: Dict[Tuple[str, str], int] = {}
    for dev, rib in ribs.items():
        for r in rib.values():
            for src in r.learned_from:
                counts[(dev, src)] = counts.get((dev, src), 0) + 1
    for s in sessions:
        if s.peer_device:
            s.routes_received = counts.get((s.device, s.peer_device), 0)
    return NetworkState(links=links, sessions=sessions, ribs=ribs)


# ------------------------------------------------------------------ forwarding
def lpm(rib: Dict[str, Route], dst_ip: str) -> Optional[Route]:
    addr = ipaddress.ip_address(dst_ip)
    best, best_len = None, -1
    for p, r in rib.items():
        net = ipaddress.ip_network(p)
        if addr in net and net.prefixlen > best_len:
            best, best_len = r, net.prefixlen
    return best


def traceroute(network: Network, topo: TopologyGraph, state: NetworkState, start_device: str,
               flow: FlowSpec, ingress_interface: Optional[str] = None, max_hops: int = 16) -> List[Trace]:
    """Enumerate every forwarding path of ``flow`` entering ``start_device`` (optionally through
    ``ingress_interface``, whose inbound ACL is applied)."""
    traces: List[Trace] = []

    def walk(dev: str, ingress: Optional[str], hops: List[Hop], visited: Tuple[str, ...]) -> None:
        cfg = network[dev]
        hop = Hop(device=dev, ingress=ingress)
        hops = hops + [hop]
        if ingress:
            hit = acl_check(cfg, ingress, "in", flow)
            if hit:
                traces.append(Trace(hops=hops, disposition="DENIED_IN", acl_hit=hit,
                                    detail=f"{dev} {ingress} ACL {hit.acl} '{hit.rule}'"))
                return
        if cfg.interface_owning(flow.dst_ip):
            hop.note = "destination is a local interface address"
            traces.append(Trace(hops=hops, disposition="DELIVERED", detail=f"accepted by {dev}"))
            return
        if len(hops) > max_hops:
            traces.append(Trace(hops=hops, disposition="MAX_HOPS"))
            return
        route = lpm(state.ribs.get(dev, {}), flow.dst_ip)
        if route is None:
            traces.append(Trace(hops=hops, disposition="NO_ROUTE", detail=f"{dev} has no route to {flow.dst_ip}"))
            return
        for nh in route.next_hops:
            branch = [h.model_copy() for h in hops]
            branch[-1].egress = nh.interface
            hit = acl_check(cfg, nh.interface, "out", flow)
            if hit:
                traces.append(Trace(hops=branch, disposition="DENIED_OUT", acl_hit=hit,
                                    detail=f"{dev} {nh.interface} ACL {hit.acl} '{hit.rule}'"))
                continue
            link = topo.link_for(dev, nh.interface)
            if nh.ip is None and link is None:
                branch[-1].note = f"delivered to connected subnet {route.prefix}"
                traces.append(Trace(hops=branch, disposition="DELIVERED", detail=f"delivered to {route.prefix} on {dev}"))
                continue
            if link is None:
                traces.append(Trace(hops=branch, disposition="NO_ROUTE", detail=f"no link behind {dev}:{nh.interface}"))
                continue
            ls = state.link_state(dev, nh.interface)
            if ls is not None and not ls.up:
                traces.append(Trace(hops=branch, disposition="LINK_DOWN", detail="; ".join(ls.down_reasons)))
                continue
            pdev, pintf = link.other(dev)
            if pdev in visited:
                traces.append(Trace(hops=branch + [Hop(device=pdev, ingress=pintf)], disposition="LOOP",
                                    detail=f"forwarding loop revisits {pdev}"))
                continue
            walk(pdev, pintf, branch, visited + (pdev,))

    walk(start_device, ingress_interface, [], (start_device,))
    return traces
