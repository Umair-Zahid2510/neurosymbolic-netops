"""Render IR to canonical Cisco IOS configuration text.

The output is the dialect fed to Batfish and shown to operators. ``parse_ios(render_ios(x))``
is required (and tested) to reproduce ``x`` exactly for every supported feature.
"""

from __future__ import annotations

import ipaddress
import re
from typing import List

from core.config_ir import AclRule, DeviceConfig

#: Canonical-name -> IOS-name mapping rules. Host-facing LANs are canonical ``vlanN``.
def ios_interface_name(canonical: str) -> str:
    m = re.fullmatch(r"eth(\d+)", canonical)
    if m:
        return f"GigabitEthernet0/{m.group(1)}"
    m = re.fullmatch(r"vlan(\d+)", canonical)
    if m:
        return f"Vlan{m.group(1)}"
    m = re.fullmatch(r"lo(\d+)", canonical)
    if m:
        return f"Loopback{m.group(1)}"
    return canonical


def _addr(prefix: str) -> str:
    net = ipaddress.ip_network(prefix)
    if net.prefixlen == 0:
        return "any"
    if net.prefixlen == 32:
        return f"host {net.network_address}"
    return f"{net.network_address} {net.hostmask}"


def render_acl_rule(rule: AclRule) -> str:
    parts = [rule.action, rule.protocol, _addr(rule.src)]
    if rule.src_port is not None:
        parts += ["eq", str(rule.src_port)]
    parts.append(_addr(rule.dst))
    if rule.dst_port is not None:
        parts += ["eq", str(rule.dst_port)]
    if rule.log:
        parts.append("log")
    return " ".join(parts)


def render_ios(dev: DeviceConfig) -> str:
    out: List[str] = [f"! Rendered from IR by core.renderers.ios", f"hostname {dev.hostname}", "!",
                      "ip routing", "!"]
    for name in sorted(dev.acls):
        out.append(f"ip access-list extended {name}")
        out += [f" {render_acl_rule(r)}" for r in dev.acls[name].rules]
        out.append("!")
    for name in sorted(dev.prefix_lists):
        for e in sorted(dev.prefix_lists[name].entries, key=lambda x: x.seq):
            line = f"ip prefix-list {name} seq {e.seq} {e.action} {e.prefix}"
            if e.ge is not None:
                line += f" ge {e.ge}"
            if e.le is not None:
                line += f" le {e.le}"
            out.append(line)
        out.append("!")
    for name in sorted(dev.interfaces, key=_intf_sort_key):
        i = dev.interfaces[name]
        out.append(f"interface {ios_interface_name(name)}")
        if i.description:
            out.append(f" description {i.description}")
        if i.ipv4:
            itf = ipaddress.ip_interface(i.ipv4)
            out.append(f" ip address {itf.ip} {itf.netmask}")
        if i.acl_in:
            out.append(f" ip access-group {i.acl_in} in")
        if i.acl_out:
            out.append(f" ip access-group {i.acl_out} out")
        out.append(f" mtu {i.mtu}")
        if i.speed:
            out.append(f" speed {i.speed}")
        if i.duplex:
            out.append(f" duplex {i.duplex}")
        out.append(" no shutdown" if i.enabled else " shutdown")
        out.append("!")
    for name in sorted(dev.route_maps):
        for e in dev.route_maps[name]:
            out.append(f"route-map {name} {e.action} {e.seq}")
            if e.match_prefix_list:
                out.append(f" match ip address prefix-list {e.match_prefix_list}")
            out.append("!")
    if dev.bgp:
        b = dev.bgp
        out.append(f"router bgp {b.asn}")
        if b.router_id:
            out.append(f" bgp router-id {b.router_id}")
        out.append(" bgp log-neighbor-changes")
        out.append(" no bgp default ipv4-unicast")
        for ip in sorted(b.neighbors, key=ipaddress.ip_address):
            n = b.neighbors[ip]
            out.append(f" neighbor {ip} remote-as {n.remote_as}")
            if n.description:
                out.append(f" neighbor {ip} description {n.description}")
            if n.password:
                out.append(f" neighbor {ip} password {n.password}")
        out.append(" !")
        out.append(" address-family ipv4 unicast")
        for net in sorted(b.networks, key=ipaddress.ip_network):
            nw = ipaddress.ip_network(net)
            out.append(f"  network {nw.network_address} mask {nw.netmask}")
        if b.maximum_paths != 1:
            out.append(f"  maximum-paths {b.maximum_paths}")
        for ip in sorted(b.neighbors, key=ipaddress.ip_address):
            n = b.neighbors[ip]
            if n.activated:
                out.append(f"  neighbor {ip} activate")
            if n.route_map_in:
                out.append(f"  neighbor {ip} route-map {n.route_map_in} in")
            if n.route_map_out:
                out.append(f"  neighbor {ip} route-map {n.route_map_out} out")
        out.append(" exit-address-family")
        out.append("!")
    for r in dev.static_routes:
        nw = ipaddress.ip_network(r.prefix)
        out.append(f"ip route {nw.network_address} {nw.netmask} {r.next_hop}")
    out.append("end")
    return "\n".join(out) + "\n"


def _intf_sort_key(name: str):
    m = re.fullmatch(r"([a-z]+)(\d+)", name)
    return (m.group(1), int(m.group(2))) if m else (name, 0)
