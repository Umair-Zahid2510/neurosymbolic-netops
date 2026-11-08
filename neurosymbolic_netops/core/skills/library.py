"""Read-only diagnostic skills (SADE-style decomposition).

Observations are limited to what an operator could obtain from the device or the telemetry
store (e.g. BGP state and last-reset text, not the simulator's internal root-cause reasons).
State-derived skills report ``data_source`` (``local_simulation`` unless an emulator adapter
supplies live state).
"""

from __future__ import annotations

import ipaddress
import statistics
from collections import defaultdict
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field

from core.network_model import BgpSessionState, lpm, route_map_permits, traceroute
from core.renderers.ios import render_acl_rule, render_ios
from core.skills.base import Skill, SkillContext, SkillRegistry, redact_secret
from core.telemetry.schema import FlowSpec


# ------------------------------------------------------------------ input models
class NoArgs(BaseModel):
    pass


class DeviceArg(BaseModel):
    device: str


class InterfaceArg(BaseModel):
    device: str
    interface: str = Field(description="canonical name, e.g. eth1 or eth10")


class OptInterfaceArg(BaseModel):
    device: str
    interface: Optional[str] = None


class NeighborArg(BaseModel):
    device: str
    neighbor_ip: str


class PrefixArg(BaseModel):
    device: str
    prefix: Optional[str] = Field(default=None, description="CIDR filter; omit for the full table")


class IpArg(BaseModel):
    device: str
    destination_ip: str


class AclArg(BaseModel):
    device: str
    acl: Optional[str] = None


class PacketTestArg(BaseModel):
    device: str
    acl: str
    src_ip: str
    dst_ip: str
    protocol: Literal["ip", "tcp", "udp", "icmp"] = "ip"
    dst_port: Optional[int] = None
    src_port: Optional[int] = None


class RoutePolicyArg(BaseModel):
    device: str
    route_map: str
    prefix: Optional[str] = None


class TraceArg(BaseModel):
    device: str
    destination_ip: str
    source_ip: Optional[str] = None
    protocol: Literal["ip", "tcp", "udp", "icmp"] = "ip"
    dst_port: Optional[int] = None
    ingress_interface: Optional[str] = None


class LogSearchArg(BaseModel):
    device: Optional[str] = None
    contains: Optional[str] = None
    mnemonic_prefix: Optional[str] = None
    limit: int = Field(default=20, ge=1, le=200)


# ------------------------------------------------------------------ helpers
def _dev(ctx: SkillContext, name: str):
    if name not in ctx.network:
        raise KeyError(f"unknown device {name}; known: {sorted(ctx.network)}")
    return ctx.network[name]


def observable_bgp(s: BgpSessionState) -> Dict[str, Optional[str]]:
    """Map simulated session state to what `show bgp neighbor` would display."""
    r = " ".join(s.reasons)
    if s.state == "ESTABLISHED":
        return {"state": "Established", "last_reset": None}
    if s.state == "FLAPPING":
        return {"state": "Established (flapping)", "last_reset": "BGP Notification sent, hold time expired"}
    if s.state == "NO_PEER":
        return {"state": "Active", "last_reset": "No route to peer / connection refused"}
    if "administratively down" in r or "speed mismatch" in r or "link" in r and "no physical" not in r:
        return {"state": "Idle", "last_reset": "Interface flap"}
    if "expects remote-as" in r:
        return {"state": "Idle", "last_reset": "BGP Notification sent/received, peer in wrong AS"}
    if "not activated" in r:
        return {"state": "Idle", "last_reset": "No address family negotiated"}
    if "has no neighbor statement" in r:
        return {"state": "Active", "last_reset": "Connection refused by peer"}
    return {"state": "Active", "last_reset": None}  # auth / filtered TCP: connection never completes


def _fleet_mode(ctx: SkillContext, attr: str):
    vals = [getattr(ctx.network[d].interfaces[i], attr) for l in ctx.topology.links
            for d, i in ((l.a_dev, l.a_intf), (l.b_dev, l.b_intf)) if i in ctx.network[d].interfaces]
    try:
        return statistics.mode(vals)
    except statistics.StatisticsError:
        return None


# ------------------------------------------------------------------ skills
def list_devices(ctx: SkillContext, a: NoArgs):
    out = []
    for d, cfg in sorted(ctx.network.items()):
        out.append({"device": d, "role": ctx.topology.metadata["nodes"].get(d, {}).get("role"),
                    "bgp_asn": cfg.bgp.asn if cfg.bgp else None,
                    "interfaces": sorted(cfg.interfaces),
                    "links": [{"local": li, "peer": pd, "peer_interface": pi} for li, pd, pi in ctx.topology.link_peers(d)]})
    return {"devices": out}


def inspect_interface(ctx: SkillContext, a: InterfaceArg):
    cfg = _dev(ctx, a.device)
    i = cfg.interfaces.get(a.interface)
    if i is None:
        raise KeyError(f"{a.device} has no interface {a.interface}; has {sorted(cfg.interfaces)}")
    ls = ctx.state.link_state(a.device, a.interface)
    oper = "up" if i.enabled and (ls is None or ls.up) else "down"
    return {"device": a.device, "interface": a.interface, "admin_status": "up" if i.enabled else "administratively down",
            "oper_status": oper, "ipv4": i.ipv4, "mtu": i.mtu, "speed": i.speed, "duplex": i.duplex,
            "acl_in": i.acl_in, "acl_out": i.acl_out, "description": i.description}


def check_link(ctx: SkillContext, a: InterfaceArg):
    l = ctx.topology.link_for(a.device, a.interface)
    if l is None:
        raise KeyError(f"{a.device}:{a.interface} is not a fabric link")
    pd, pi = l.other(a.device)
    local = inspect_interface(ctx, InterfaceArg(device=a.device, interface=a.interface))
    peer = inspect_interface(ctx, InterfaceArg(device=pd, interface=pi))
    diffs = [k for k in ("mtu", "speed", "duplex") if local[k] != peer[k]]
    return {"local": local, "peer": peer, "parameter_mismatches": diffs,
            "fleet_typical": {k: _fleet_mode(ctx, k) for k in ("mtu", "speed", "duplex")}}


def interface_counters(ctx: SkillContext, a: OptInterfaceArg):
    series: Dict[tuple, List[float]] = defaultdict(list)
    for e in ctx.events:
        if e.source == "interface_counter" and e.device == a.device and (a.interface is None or e.interface == a.interface):
            series[(e.interface, e.metric)].append(e.value)
    out = []
    for (intf, metric), vals in sorted(series.items(), key=lambda x: (str(x[0][0]), x[0][1])):
        if metric in ("cpu_util_pct", "mem_util_pct", "rib_routes", "oper_status") or max(vals) > 5:
            out.append({"interface": intf, "metric": metric, "first": vals[0], "last": vals[-1],
                        "max": max(vals), "median": statistics.median(vals), "samples": len(vals)})
    return {"device": a.device, "counters": out, "note": "only series with notable values are listed"}


def bgp_summary(ctx: SkillContext, a: DeviceArg):
    cfg = _dev(ctx, a.device)
    if not cfg.bgp:
        return {"device": a.device, "bgp": None}
    rows = []
    for s in ctx.state.sessions:
        if s.device == a.device:
            obs = observable_bgp(s)
            rows.append({"neighbor": s.neighbor_ip, "remote_as_configured": cfg.bgp.neighbors[s.neighbor_ip].remote_as,
                         "state": obs["state"], "last_reset": obs["last_reset"], "prefixes_received": s.routes_received})
    return {"device": a.device, "local_as": cfg.bgp.asn, "router_id": cfg.bgp.router_id, "neighbors": rows}


def bgp_neighbor(ctx: SkillContext, a: NeighborArg):
    cfg = _dev(ctx, a.device)
    if not cfg.bgp or a.neighbor_ip not in cfg.bgp.neighbors:
        raise KeyError(f"{a.device} has no BGP neighbor {a.neighbor_ip}")
    n = cfg.bgp.neighbors[a.neighbor_ip]
    s = ctx.state.session(a.device, a.neighbor_ip)
    owner = ctx.topology.owner_of_ip(a.neighbor_ip, ctx.network)
    return {"device": a.device, "local_as": cfg.bgp.asn, "neighbor": a.neighbor_ip,
            "peer_device_per_topology": owner[0] if owner else None,
            "remote_as_configured": n.remote_as, "password": redact_secret(n.password),
            "ipv4_unicast_activated": n.activated, "route_map_in": n.route_map_in, "route_map_out": n.route_map_out,
            **(observable_bgp(s) if s else {"state": "unknown"}),
            "prefixes_received": s.routes_received if s else 0,
            "advertised_networks": cfg.bgp.networks}


def routing_table(ctx: SkillContext, a: PrefixArg):
    _dev(ctx, a.device)
    rib = ctx.state.ribs.get(a.device, {})
    rows = []
    for p, r in sorted(rib.items(), key=lambda x: ipaddress.ip_network(x[0])):
        if a.prefix and not ipaddress.ip_network(p).overlaps(ipaddress.ip_network(a.prefix, strict=False)):
            continue
        rows.append({"prefix": p, "protocol": r.protocol, "next_hops": [nh.model_dump() for nh in r.next_hops],
                     "as_path": r.as_path})
    return {"device": a.device, "routes": rows, "count": len(rows)}


def route_lookup(ctx: SkillContext, a: IpArg):
    _dev(ctx, a.device)
    r = lpm(ctx.state.ribs.get(a.device, {}), a.destination_ip)
    return {"device": a.device, "destination": a.destination_ip,
            "match": None if r is None else {"prefix": r.prefix, "protocol": r.protocol,
                                             "next_hops": [nh.model_dump() for nh in r.next_hops], "as_path": r.as_path}}


def inspect_acl(ctx: SkillContext, a: AclArg):
    cfg = _dev(ctx, a.device)
    names = [a.acl] if a.acl else sorted(cfg.acls)
    hits: Dict[str, float] = defaultdict(float)
    for e in ctx.events:
        if e.source == "interface_counter" and e.device == a.device and (e.metric or "").startswith("acl_deny_delta:"):
            hits[e.metric.split(":", 1)[1]] += e.value
    out = []
    for n in names:
        if n not in cfg.acls:
            raise KeyError(f"{a.device} has no ACL {n}; has {sorted(cfg.acls)}")
        bound = [{"interface": i.name, "direction": d} for i in cfg.interfaces.values()
                 for d, v in (("in", i.acl_in), ("out", i.acl_out)) if v == n]
        out.append({"acl": n, "rules": [{"index": k, "rule": render_acl_rule(r), "key": r.key()}
                                         for k, r in enumerate(cfg.acls[n].rules)],
                    "bound_to": bound, "deny_hits_in_window": hits.get(n, 0.0)})
    return {"device": a.device, "acls": out}


def acl_packet_test(ctx: SkillContext, a: PacketTestArg):
    cfg = _dev(ctx, a.device)
    if a.acl not in cfg.acls:
        raise KeyError(f"{a.device} has no ACL {a.acl}")
    action, idx = cfg.acls[a.acl].evaluate(a.protocol, a.src_ip, a.dst_ip, a.src_port, a.dst_port)
    return {"device": a.device, "acl": a.acl, "action": action, "matched_rule_index": idx,
            "matched_rule": render_acl_rule(cfg.acls[a.acl].rules[idx]) if idx is not None else "implicit deny"}


def inspect_route_policy(ctx: SkillContext, a: RoutePolicyArg):
    cfg = _dev(ctx, a.device)
    entries = cfg.route_maps.get(a.route_map)
    users = [{"neighbor": ip, "direction": d} for ip, n in (cfg.bgp.neighbors.items() if cfg.bgp else [])
             for d, v in (("in", n.route_map_in), ("out", n.route_map_out)) if v == a.route_map]
    res = {"device": a.device, "route_map": a.route_map, "defined": entries is not None,
           "entries": [e.model_dump() for e in entries] if entries else [], "applied_to": users}
    if a.prefix:
        res["prefix_evaluated"] = a.prefix
        res["permits_prefix"] = route_map_permits(cfg, a.route_map, str(ipaddress.ip_network(a.prefix, strict=False)))
    return res


def trace_route(ctx: SkillContext, a: TraceArg):
    _dev(ctx, a.device)
    src = a.source_ip or (ctx.network[a.device].interfaces[a.ingress_interface].ip if a.ingress_interface else "10.255.255.1")
    flow = FlowSpec(src_ip=src, dst_ip=a.destination_ip, protocol=a.protocol, dst_port=a.dst_port,
                    src_port=49152 if a.protocol in ("tcp", "udp") else None)
    traces = traceroute(ctx.network, ctx.topology, ctx.state, a.device, flow, a.ingress_interface)
    return {"flow": flow.model_dump(), "traces": [{"path": t.path(), "disposition": t.disposition, "detail": t.detail}
                                                  for t in traces],
            "note": "path computed from configuration (simulated traceroute)"}


def search_logs(ctx: SkillContext, a: LogSearchArg):
    out = []
    for e in ctx.events:
        if e.source != "syslog":
            continue
        if a.device and e.device != a.device:
            continue
        if a.mnemonic_prefix and not (e.mnemonic or "").startswith(a.mnemonic_prefix):
            continue
        if a.contains and a.contains.lower() not in (e.message or "").lower():
            continue
        out.append({"event_id": e.event_id, "time": e.timestamp.isoformat() if e.timestamp else None,
                    "device": e.device, "mnemonic": e.mnemonic, "message": e.message})
    return {"matches": out[: a.limit], "total": len(out)}


def probe_status(ctx: SkillContext, a: NoArgs):
    agg: Dict[str, Dict] = {}
    for e in ctx.events:
        if e.source != "probe":
            continue
        k = f"{e.flow.src_ip}->{e.flow.dst_ip}"
        d = agg.setdefault(k, {"flow": k, "agent": e.device, "samples": 0, "max_loss_pct": 0.0, "rtt_ms": []})
        d["samples"] += 1
        d["max_loss_pct"] = max(d["max_loss_pct"], e.value or 0.0)
        rtt = (e.message or "").split("=")[-1]
        if rtt not in ("None", ""):
            d["rtt_ms"].append(float(rtt))
    for d in agg.values():
        d["median_rtt_ms"] = statistics.median(d["rtt_ms"]) if d["rtt_ms"] else None
        del d["rtt_ms"]
    return {"probes": list(agg.values())}


def get_running_config(ctx: SkillContext, a: DeviceArg):
    cfg = _dev(ctx, a.device)
    text = render_ios(cfg)
    lines = []
    for line in text.splitlines():
        if " password " in line:
            head, secret = line.rsplit(" password ", 1)
            line = f"{head} password {redact_secret(secret)}"
        lines.append(line)
    return {"device": a.device, "config": "\n".join(lines)}


def anomaly_digest(ctx: SkillContext, a: NoArgs):
    if ctx.digest is None:
        return {"anomalies": []}
    return {"anomalies": [x.model_dump(mode="json", exclude={"evidence_event_ids"}) for x in ctx.digest.anomalies],
            "missing_data": ctx.digest.missing_data}


def build_registry() -> SkillRegistry:
    reg = SkillRegistry()
    for name, fn, model, cat, desc in [
        ("list_devices", list_devices, NoArgs, "topology", "List devices, roles, ASNs, interfaces and fabric links."),
        ("inspect_interface", inspect_interface, InterfaceArg, "interface", "Admin/oper status, IP, MTU, speed, duplex and ACL bindings of one interface."),
        ("check_link", check_link, InterfaceArg, "interface", "Compare both ends of a fabric link (MTU/speed/duplex/status) and fleet-typical values."),
        ("interface_counters", interface_counters, OptInterfaceArg, "telemetry", "Error/collision/giant/ACL counters and device gauges from the telemetry window."),
        ("bgp_summary", bgp_summary, DeviceArg, "bgp", "BGP neighbors with state, last reset reason and prefixes received."),
        ("bgp_neighbor", bgp_neighbor, NeighborArg, "bgp", "Configuration and state of one BGP neighbor (password shown as a digest)."),
        ("routing_table", routing_table, PrefixArg, "routing", "Routing table (optionally filtered by prefix)."),
        ("route_lookup", route_lookup, IpArg, "routing", "Longest-prefix-match lookup for a destination IP."),
        ("inspect_acl", inspect_acl, AclArg, "acl", "ACL rules with indices, interface bindings and deny-hit counters."),
        ("acl_packet_test", acl_packet_test, PacketTestArg, "acl", "Evaluate a packet against an ACL (first match, implicit deny)."),
        ("inspect_route_policy", inspect_route_policy, RoutePolicyArg, "bgp", "Route-map entries, where it is applied, and whether it permits a prefix."),
        ("traceroute", trace_route, TraceArg, "routing", "Simulated forwarding trace with every ECMP branch and its disposition."),
        ("search_logs", search_logs, LogSearchArg, "telemetry", "Search normalised syslog by device, mnemonic prefix or substring."),
        ("probe_status", probe_status, NoArgs, "telemetry", "Packet loss and latency of synthetic end-to-end probes."),
        ("get_running_config", get_running_config, DeviceArg, "config", "Running configuration (IOS rendering, secrets redacted)."),
        ("anomaly_digest", anomaly_digest, NoArgs, "telemetry", "Tier-1 anomaly digest for the incident."),
    ]:
        reg.register(Skill(name=name, description=desc, input_model=model, func=fn, category=cat))
    for name, why in {"ospf_neighbors": "no OSPF in the IR or testbed", "arp_table": "no L2/ARP state is modelled",
                      "vlan_inspection": "host LANs are routed ports; no VLAN state", "dns_check": "no DNS service in the testbed",
                      "firewall_session_table": "no stateful firewall; ACL skills cover packet filtering"}.items():
        reg.plan(name, why)
    return reg
