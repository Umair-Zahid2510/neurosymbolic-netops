"""Cisco IOS-subset parser producing the vendor-neutral IR.

The parser is deliberately strict about what it understands: every non-comment line that
does not map onto the IR is appended to ``DeviceConfig.unsupported_lines`` with its line
number. Callers (verification, the benchmark loader) can then refuse to reason about a
configuration whose meaning was only partially captured.

It also accepts the pre-audit "legacy" dialect used by the original dataset (``interface
eth1``, BGP ``network``/``activate`` statements outside an address-family block, and
``no neighbor X activate``), so the original 25 scenarios can be migrated losslessly.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Dict, List, Optional, Tuple

from core.config_ir import (
    Acl, AclRule, BgpNeighbor, BgpProcess, DeviceConfig, Interface, PrefixList,
    PrefixListEntry, RouteMapEntry, StaticRoute,
)

PORT_NAMES = {"bgp": 179, "www": 80, "http": 80, "https": 443, "domain": 53, "ssh": 22,
              "telnet": 23, "snmp": 161, "ntp": 123, "syslog": 514}


class ParseError(ValueError):
    pass


def canonical_interface_name(name: str) -> str:
    """Map vendor interface names to canonical IR names (eth<N>, vlan<N>, lo<N>)."""
    n = name.strip()
    m = re.fullmatch(r"(?i)(?:GigabitEthernet|GigE|Gi|TenGigabitEthernet|Te)\d+/(\d+)", n)
    if m:
        return f"eth{int(m.group(1))}"
    m = re.fullmatch(r"(?i)(?:Ethernet|eth)(\d+)", n)
    if m:
        return f"eth{int(m.group(1))}"
    m = re.fullmatch(r"(?i)vlan(\d+)", n)
    if m:
        return f"vlan{int(m.group(1))}"
    m = re.fullmatch(r"(?i)(?:Loopback|lo)(\d+)", n)
    if m:
        return f"lo{int(m.group(1))}"
    return n.lower()


def _wildcard_to_prefixlen(wildcard: str) -> int:
    inv = int(ipaddress.IPv4Address(wildcard))
    mask = (~inv) & 0xFFFFFFFF
    bits = bin(mask).count("1")
    if mask != ((0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF):
        raise ParseError(f"non-contiguous wildcard {wildcard} is not supported")
    return bits


def _mask_to_prefixlen(mask: str) -> int:
    return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen


def _parse_addr_spec(tokens: List[str], i: int) -> Tuple[str, int]:
    tok = tokens[i]
    if tok == "any":
        return "0.0.0.0/0", i + 1
    if tok == "host":
        return f"{tokens[i + 1]}/32", i + 2
    if "/" in tok:
        return str(ipaddress.ip_network(tok, strict=False)), i + 1
    plen = _wildcard_to_prefixlen(tokens[i + 1])
    return str(ipaddress.ip_network(f"{tok}/{plen}", strict=False)), i + 2


def _parse_port(tokens: List[str], i: int) -> Tuple[Optional[int], int]:
    if i < len(tokens) and tokens[i] == "eq":
        val = tokens[i + 1]
        port = int(val) if val.isdigit() else PORT_NAMES.get(val)
        if port is None:
            raise ParseError(f"unknown port name {val}")
        return port, i + 2
    if i < len(tokens) and tokens[i] in ("gt", "lt", "range", "neq"):
        raise ParseError(f"port operator '{tokens[i]}' is not supported")
    return None, i


def parse_acl_rule(text: str) -> AclRule:
    tokens = text.split()
    if tokens and tokens[0].isdigit():
        tokens = tokens[1:]
    if not tokens or tokens[0] not in ("permit", "deny"):
        raise ParseError(f"not an ACL rule: {text!r}")
    action, proto = tokens[0], tokens[1]
    if proto not in ("ip", "tcp", "udp", "icmp"):
        raise ParseError(f"unsupported protocol {proto}")
    i = 2
    src, i = _parse_addr_spec(tokens, i)
    sport, i = _parse_port(tokens, i)
    dst, i = _parse_addr_spec(tokens, i)
    dport, i = _parse_port(tokens, i)
    log = False
    if i < len(tokens) and tokens[i] in ("log", "log-input"):
        log, i = True, i + 1
    if i != len(tokens):
        raise ParseError(f"trailing tokens {tokens[i:]} in {text!r}")
    return AclRule(action=action, protocol=proto, src=src, dst=dst,
                   src_port=sport, dst_port=dport, log=log)


def parse_ios(text: str, hostname_hint: Optional[str] = None) -> DeviceConfig:
    dev = DeviceConfig(hostname=hostname_hint or "unknown")
    unsupported: List[str] = []
    ctx: Optional[str] = None
    ctx_obj = None
    bgp_explicit_activate: Dict[str, bool] = {}
    no_default_ipv4 = False

    def unsup(lineno: int, line: str, why: str = "") -> None:
        unsupported.append(f"L{lineno}: {line.strip()}" + (f"  [{why}]" if why else ""))

    def neighbor(ip: str) -> BgpNeighbor:
        assert dev.bgp is not None
        if ip not in dev.bgp.neighbors:
            dev.bgp.neighbors[ip] = BgpNeighbor(ip=ip, remote_as=0)
        return dev.bgp.neighbors[ip]

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("!"):
            continue
        indented = line[:1] in (" ", "\t")
        if not indented:
            ctx, ctx_obj = None, None
            toks = stripped.split()
            try:
                if toks[0] == "hostname":
                    dev.hostname = toks[1]
                elif stripped in ("end", "ip routing", "no ip domain-lookup"):
                    pass
                elif toks[0] == "interface":
                    name = canonical_interface_name(" ".join(toks[1:]))
                    ctx = "interface"
                    ctx_obj = dev.interfaces.setdefault(name, Interface(name=name))
                elif toks[:3] == ["ip", "access-list", "extended"]:
                    ctx = "acl"
                    ctx_obj = dev.acls.setdefault(toks[3], Acl(name=toks[3]))
                elif toks[0] == "route-map":
                    ctx = "route-map"
                    entry = RouteMapEntry(seq=int(toks[3]) if len(toks) > 3 else 10, action=toks[2])
                    dev.route_maps.setdefault(toks[1], []).append(entry)
                    ctx_obj = entry
                elif toks[:2] == ["ip", "prefix-list"]:
                    name = toks[2]
                    rest = toks[3:]
                    seq = int(rest[1]) if rest[0] == "seq" else (len(dev.prefix_lists.get(name, PrefixList(name=name)).entries) + 1) * 5
                    if rest[0] == "seq":
                        rest = rest[2:]
                    kw = dict(zip(rest[2::2], rest[3::2]))
                    pl = dev.prefix_lists.setdefault(name, PrefixList(name=name))
                    pl.entries.append(PrefixListEntry(seq=seq, action=rest[0], prefix=rest[1],
                                                      ge=int(kw["ge"]) if "ge" in kw else None,
                                                      le=int(kw["le"]) if "le" in kw else None))
                elif toks[:2] == ["router", "bgp"]:
                    ctx = "bgp"
                    dev.bgp = dev.bgp or BgpProcess(asn=int(toks[2]))
                elif toks[:2] == ["ip", "route"]:
                    plen = _mask_to_prefixlen(toks[3])
                    dev.static_routes.append(StaticRoute(prefix=f"{toks[2]}/{plen}", next_hop=toks[4]))
                else:
                    unsup(lineno, line)
            except (IndexError, ValueError) as exc:
                unsup(lineno, line, str(exc))
            continue

        # ---- indented lines: belong to the current context ----
        toks = stripped.split()
        try:
            if ctx == "interface":
                intf: Interface = ctx_obj
                if toks[0] == "description":
                    intf.description = stripped[len("description"):].strip()
                elif toks[:2] == ["ip", "address"]:
                    intf.ipv4 = f"{toks[2]}/{_mask_to_prefixlen(toks[3])}"
                elif toks[:2] == ["ip", "access-group"]:
                    if toks[3] == "in":
                        intf.acl_in = toks[2]
                    else:
                        intf.acl_out = toks[2]
                elif toks[0] == "mtu":
                    intf.mtu = int(toks[1])
                elif toks[0] == "speed":
                    intf.speed = toks[1]
                elif toks[0] == "duplex":
                    intf.duplex = toks[1]
                elif stripped == "shutdown":
                    intf.enabled = False
                elif stripped == "no shutdown":
                    intf.enabled = True
                elif stripped in ("no switchport",):
                    pass
                else:
                    unsup(lineno, line)
            elif ctx == "acl":
                if toks[0] == "remark":
                    continue
                ctx_obj.rules.append(parse_acl_rule(stripped))
            elif ctx == "route-map":
                if toks[:4] == ["match", "ip", "address", "prefix-list"]:
                    ctx_obj.match_prefix_list = toks[4]
                else:
                    unsup(lineno, line)
            elif ctx == "bgp":
                if toks[:2] == ["bgp", "router-id"]:
                    dev.bgp.router_id = toks[2]
                elif stripped == "no bgp default ipv4-unicast":
                    no_default_ipv4 = True
                elif stripped in ("bgp log-neighbor-changes",) or toks[0] in ("exit-address-family",) \
                        or toks[:2] == ["address-family", "ipv4"]:
                    pass
                elif toks[0] == "maximum-paths":
                    dev.bgp.maximum_paths = int(toks[1])
                elif toks[0] == "network":
                    if len(toks) >= 4 and toks[2] == "mask":
                        dev.bgp.networks.append(f"{toks[1]}/{_mask_to_prefixlen(toks[3])}")
                    else:
                        dev.bgp.networks.append(str(ipaddress.ip_network(toks[1], strict=False)))
                elif toks[:1] == ["no"] and len(toks) == 4 and toks[1] == "neighbor" and toks[3] == "activate":
                    neighbor(toks[2])
                    bgp_explicit_activate[toks[2]] = False
                elif toks[0] == "neighbor":
                    ip, kw = toks[1], toks[2]
                    n = neighbor(ip)
                    if kw == "remote-as":
                        n.remote_as = int(toks[3])
                    elif kw == "description":
                        n.description = " ".join(toks[3:])
                    elif kw == "password":
                        n.password = " ".join(toks[3:])
                    elif kw == "activate":
                        bgp_explicit_activate[ip] = True
                    elif kw == "route-map":
                        if toks[4] == "in":
                            n.route_map_in = toks[3]
                        else:
                            n.route_map_out = toks[3]
                    else:
                        unsup(lineno, line)
                else:
                    unsup(lineno, line)
            else:
                unsup(lineno, line, "indented line outside a known block")
        except (IndexError, ValueError) as exc:
            unsup(lineno, line, str(exc))

    if dev.bgp:
        for ip, n in dev.bgp.neighbors.items():
            n.activated = bgp_explicit_activate.get(ip, not no_default_ipv4)
            if n.remote_as == 0:
                unsupported.append(f"neighbor {ip} has no remote-as")
        for entries in dev.route_maps.values():
            entries.sort(key=lambda e: e.seq)
    dev.unsupported_lines = unsupported
    return dev
