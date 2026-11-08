"""IR -> Juniper Junos (set format) and Arista EOS renderers.

Translation goes through the vendor-neutral IR (parse IOS -> IR -> render target), never by
text substitution. Semantic notes:
* Junos ``family inet mtu`` is the IP MTU (same meaning as IOS ``mtu`` on routed ports).
* IOS ``network`` statements become a Junos export policy that accepts the exact direct routes
  plus BGP-learned routes (IOS re-advertises best BGP paths by default).
* An IOS neighbor not activated for IPv4 unicast is rendered as a deactivated Junos neighbor.
* Interface speed/duplex are rendered (``speed``, ``link-mode``) but are platform dependent.
Behavioural equivalence is *checked*, not assumed: see ``core/vendor_translator.py``.
"""

from __future__ import annotations

import ipaddress
import re
from typing import List

from core.config_ir import AclRule, DeviceConfig


def junos_ifname(name: str) -> str:
    m = re.fullmatch(r"eth(\d+)", name)
    return f"ge-0/0/{m.group(1)}" if m else name


def eos_ifname(name: str) -> str:
    m = re.fullmatch(r"eth(\d+)", name)
    return f"Ethernet{m.group(1)}" if m else name


def _junos_term(acl: str, k: int, r: AclRule) -> List[str]:
    base = f"set firewall family inet filter {acl} term t{k}"
    out = []
    if r.src != "0.0.0.0/0":
        out.append(f"{base} from source-address {r.src}")
    if r.dst != "0.0.0.0/0":
        out.append(f"{base} from destination-address {r.dst}")
    if r.protocol != "ip":
        out.append(f"{base} from protocol {r.protocol}")
    if r.src_port is not None:
        out.append(f"{base} from source-port {r.src_port}")
    if r.dst_port is not None:
        out.append(f"{base} from destination-port {r.dst_port}")
    out.append(f"{base} then {'accept' if r.action == 'permit' else 'discard'}")
    return out


def render_junos(dev: DeviceConfig) -> str:
    o = ["#RANCID-CONTENT-TYPE: juniper", f"set system host-name {dev.hostname}"]
    for name, i in sorted(dev.interfaces.items()):
        jn = junos_ifname(name)
        if i.description:
            o.append(f'set interfaces {jn} description "{i.description}"')
        if not i.enabled:
            o.append(f"set interfaces {jn} disable")
        if i.speed and i.speed != "auto":
            o.append(f"set interfaces {jn} speed {i.speed}m")
        if i.duplex and i.duplex != "auto":
            o.append(f"set interfaces {jn} link-mode {i.duplex}-duplex")
        if i.ipv4:
            o.append(f"set interfaces {jn} unit 0 family inet address {i.ipv4}")
        o.append(f"set interfaces {jn} unit 0 family inet mtu {i.mtu}")
        if i.acl_in:
            o.append(f"set interfaces {jn} unit 0 family inet filter input {i.acl_in}")
        if i.acl_out:
            o.append(f"set interfaces {jn} unit 0 family inet filter output {i.acl_out}")
    for name, acl in sorted(dev.acls.items()):
        for k, r in enumerate(acl.rules):
            o += _junos_term(name, k, r)
        o.append(f"set firewall family inet filter {name} term implicit-deny then discard")
    for name, pl in sorted(dev.prefix_lists.items()):
        for e in sorted(pl.entries, key=lambda x: x.seq):
            o.append(f"set policy-options prefix-list {name} {e.prefix}")
    for name, entries in sorted(dev.route_maps.items()):
        for e in entries:
            t = f"set policy-options policy-statement {name} term s{e.seq}"
            if e.match_prefix_list:
                o.append(f"{t} from prefix-list {e.match_prefix_list}")
            o.append(f"{t} then {'accept' if e.action == 'permit' else 'reject'}")
        o.append(f"set policy-options policy-statement {name} term implicit then reject")
    if dev.bgp:
        b = dev.bgp
        o.append(f"set routing-options autonomous-system {b.asn}")
        if b.router_id:
            o.append(f"set routing-options router-id {b.router_id}")
        exp = "EXPORT_IOS_EQUIV"
        for k, n in enumerate(sorted(b.networks)):
            o.append(f"set policy-options policy-statement {exp} term net{k} from protocol direct")
            o.append(f"set policy-options policy-statement {exp} term net{k} from route-filter {n} exact")
            o.append(f"set policy-options policy-statement {exp} term net{k} then accept")
        o.append(f"set policy-options policy-statement {exp} term bgp from protocol bgp")
        o.append(f"set policy-options policy-statement {exp} term bgp then accept")
        o.append(f"set policy-options policy-statement {exp} term rest then reject")
        g = "set protocols bgp group FABRIC"
        o += [f"{g} type external", f"{g} export {exp}"]
        if b.maximum_paths > 1:
            o.append(f"{g} multipath")
        for ip, n in sorted(b.neighbors.items()):
            nb = f"{g} neighbor {ip}"
            o.append(f"{nb} peer-as {n.remote_as}")
            if n.description:
                o.append(f'{nb} description "{n.description}"')
            if n.password:
                o.append(f'{nb} authentication-key "{n.password}"')
            if n.route_map_in:
                o.append(f"{nb} import {n.route_map_in}")
            if n.route_map_out:
                o.append(f"{nb} export {n.route_map_out}")
                o.append(f"{nb} export {exp}")
            if not n.activated:
                o.append(f"deactivate protocols bgp group FABRIC neighbor {ip}")
    for r in dev.static_routes:
        o.append(f"set routing-options static route {r.prefix} next-hop {r.next_hop}")
    return "\n".join(o) + "\n"


def _eos_addr(p: str) -> str:
    return "any" if p == "0.0.0.0/0" else (f"host {ipaddress.ip_network(p).network_address}" if p.endswith("/32") else p)


def render_eos(dev: DeviceConfig) -> str:
    o = ["! device: (EOS)", "!RANCID-CONTENT-TYPE: arista", f"hostname {dev.hostname}", "!", "ip routing", "!"]
    for name, acl in sorted(dev.acls.items()):
        o.append(f"ip access-list {name}")
        for k, r in enumerate(acl.rules, 1):
            parts = [str(k * 10), r.action, r.protocol, _eos_addr(r.src)]
            if r.src_port is not None:
                parts += ["eq", str(r.src_port)]
            parts.append(_eos_addr(r.dst))
            if r.dst_port is not None:
                parts += ["eq", str(r.dst_port)]
            o.append("   " + " ".join(parts))
        o.append("!")
    for name, pl in sorted(dev.prefix_lists.items()):
        for e in sorted(pl.entries, key=lambda x: x.seq):
            o.append(f"ip prefix-list {name} seq {e.seq} {e.action} {e.prefix}")
    for name, i in sorted(dev.interfaces.items()):
        o.append(f"interface {eos_ifname(name)}")
        if i.description:
            o.append(f"   description {i.description}")
        o.append("   no switchport")
        if i.ipv4:
            o.append(f"   ip address {i.ipv4}")
        o.append(f"   mtu {i.mtu}")
        if i.speed and i.speed != "auto":
            o.append(f"   speed forced {i.speed}{'full' if i.duplex != 'half' else 'half'}")
        if i.acl_in:
            o.append(f"   ip access-group {i.acl_in} in")
        if i.acl_out:
            o.append(f"   ip access-group {i.acl_out} out")
        o.append("   shutdown" if not i.enabled else "   no shutdown")
        o.append("!")
    for name, entries in sorted(dev.route_maps.items()):
        for e in entries:
            o.append(f"route-map {name} {e.action} {e.seq}")
            if e.match_prefix_list:
                o.append(f"   match ip address prefix-list {e.match_prefix_list}")
            o.append("!")
    if dev.bgp:
        b = dev.bgp
        o.append(f"router bgp {b.asn}")
        if b.router_id:
            o.append(f"   router-id {b.router_id}")
        o.append("   no bgp default ipv4-unicast")
        if b.maximum_paths > 1:
            o.append(f"   maximum-paths {b.maximum_paths}")
        for ip, n in sorted(b.neighbors.items()):
            o.append(f"   neighbor {ip} remote-as {n.remote_as}")
            if n.password:
                o.append(f"   neighbor {ip} password {n.password}")
            if n.route_map_in:
                o.append(f"   neighbor {ip} route-map {n.route_map_in} in")
            if n.route_map_out:
                o.append(f"   neighbor {ip} route-map {n.route_map_out} out")
        o.append("   address-family ipv4")
        for ip, n in sorted(b.neighbors.items()):
            if n.activated:
                o.append(f"      neighbor {ip} activate")
        for net in sorted(b.networks):
            o.append(f"      network {net}")
        o.append("!")
    for r in dev.static_routes:
        o.append(f"ip route {r.prefix} {r.next_hop}")
    o.append("end")
    return "\n".join(o) + "\n"
