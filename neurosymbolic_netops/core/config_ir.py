"""Vendor-neutral configuration intermediate representation (IR).

Every component that reads or changes device configuration (parsers, renderers, patch
operations, verification, diagnostic skills, actuation, vendor translation) works on these
models instead of on raw CLI text.

Interface names are canonical short names (``eth1``, ``eth10``, ``lo0``). Renderers map them
to vendor names (for example ``GigabitEthernet0/1`` on Cisco IOS).

Scope: the IR covers the subset of features used by the testbed (interfaces, extended ACLs,
route-maps with optional prefix-list matching, prefix-lists, eBGP with one IPv4 unicast
address family, static routes). Anything outside that subset is recorded in
``DeviceConfig.unsupported_lines`` by the parser rather than silently discarded.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator

Action = Literal["permit", "deny"]
Protocol = Literal["ip", "tcp", "udp", "icmp"]
Direction = Literal["in", "out"]

ANY = "0.0.0.0/0"


def _canon_net(value: str) -> str:
    return str(ipaddress.ip_network(value, strict=False))


class AclRule(BaseModel):
    """One extended-ACL entry. Prefixes are stored in CIDR form."""

    action: Action
    protocol: Protocol = "ip"
    src: str = ANY
    dst: str = ANY
    src_port: Optional[int] = Field(default=None, ge=0, le=65535)
    dst_port: Optional[int] = Field(default=None, ge=0, le=65535)
    log: bool = False

    @field_validator("src", "dst")
    @classmethod
    def _cidr(cls, v: str) -> str:
        return _canon_net(v)

    def matches(self, protocol: str, src_ip: str, dst_ip: str,
                src_port: Optional[int] = None, dst_port: Optional[int] = None) -> bool:
        if self.protocol != "ip" and self.protocol != protocol:
            return False
        if ipaddress.ip_address(src_ip) not in ipaddress.ip_network(self.src):
            return False
        if ipaddress.ip_address(dst_ip) not in ipaddress.ip_network(self.dst):
            return False
        if self.src_port is not None and self.src_port != src_port:
            return False
        if self.dst_port is not None and self.dst_port != dst_port:
            return False
        return True

    def key(self) -> str:
        """Stable human-readable identity used to reference a rule in patches and evidence."""
        parts = [self.action, self.protocol, self.src, self.dst]
        if self.src_port is not None:
            parts.append(f"sport={self.src_port}")
        if self.dst_port is not None:
            parts.append(f"dport={self.dst_port}")
        return " ".join(parts)


class Acl(BaseModel):
    name: str
    rules: List[AclRule] = Field(default_factory=list)

    def evaluate(self, protocol: str, src_ip: str, dst_ip: str,
                 src_port: Optional[int] = None, dst_port: Optional[int] = None):
        """First-match semantics with implicit deny. Returns (action, rule_index or None)."""
        for idx, rule in enumerate(self.rules):
            if rule.matches(protocol, src_ip, dst_ip, src_port, dst_port):
                return rule.action, idx
        return "deny", None


class PrefixListEntry(BaseModel):
    seq: int
    action: Action
    prefix: str
    ge: Optional[int] = None
    le: Optional[int] = None

    @field_validator("prefix")
    @classmethod
    def _cidr(cls, v: str) -> str:
        return _canon_net(v)

    def matches(self, prefix: str) -> bool:
        net = ipaddress.ip_network(prefix)
        base = ipaddress.ip_network(self.prefix)
        if self.ge is None and self.le is None:
            return net == base
        if not net.subnet_of(base):
            return False
        lo = self.ge if self.ge is not None else base.prefixlen
        hi = self.le if self.le is not None else 32
        return lo <= net.prefixlen <= hi


class PrefixList(BaseModel):
    name: str
    entries: List[PrefixListEntry] = Field(default_factory=list)

    def permits(self, prefix: str) -> bool:
        for e in sorted(self.entries, key=lambda x: x.seq):
            if e.matches(prefix):
                return e.action == "permit"
        return False


class RouteMapEntry(BaseModel):
    seq: int
    action: Action
    match_prefix_list: Optional[str] = None  # None = match every route


class Interface(BaseModel):
    name: str
    description: Optional[str] = None
    ipv4: Optional[str] = None  # "10.0.1.2/30"
    enabled: bool = True
    mtu: int = Field(default=1500, ge=576, le=9216)
    speed: Optional[str] = None  # "1000", "100", "auto"
    duplex: Optional[Literal["full", "half", "auto"]] = None
    acl_in: Optional[str] = None
    acl_out: Optional[str] = None

    @field_validator("ipv4")
    @classmethod
    def _ifaddr(cls, v: Optional[str]) -> Optional[str]:
        return str(ipaddress.ip_interface(v)) if v else None

    @property
    def ip(self) -> Optional[str]:
        return str(ipaddress.ip_interface(self.ipv4).ip) if self.ipv4 else None

    @property
    def network(self) -> Optional[str]:
        return str(ipaddress.ip_interface(self.ipv4).network) if self.ipv4 else None


class BgpNeighbor(BaseModel):
    ip: str
    remote_as: int
    description: Optional[str] = None
    password: Optional[str] = None
    activated: bool = True
    route_map_in: Optional[str] = None
    route_map_out: Optional[str] = None


class BgpProcess(BaseModel):
    asn: int
    router_id: Optional[str] = None
    networks: List[str] = Field(default_factory=list)
    maximum_paths: int = Field(default=1, ge=1, le=64)  # eBGP multipath (IOS default 1)
    neighbors: Dict[str, BgpNeighbor] = Field(default_factory=dict)

    @field_validator("networks")
    @classmethod
    def _nets(cls, v: List[str]) -> List[str]:
        return [_canon_net(n) for n in v]


class StaticRoute(BaseModel):
    prefix: str
    next_hop: str

    @field_validator("prefix")
    @classmethod
    def _cidr(cls, v: str) -> str:
        return _canon_net(v)


class DeviceConfig(BaseModel):
    hostname: str
    interfaces: Dict[str, Interface] = Field(default_factory=dict)
    acls: Dict[str, Acl] = Field(default_factory=dict)
    prefix_lists: Dict[str, PrefixList] = Field(default_factory=dict)
    route_maps: Dict[str, List[RouteMapEntry]] = Field(default_factory=dict)
    bgp: Optional[BgpProcess] = None
    static_routes: List[StaticRoute] = Field(default_factory=list)
    unsupported_lines: List[str] = Field(default_factory=list)

    def interface_owning(self, ip: str) -> Optional[Interface]:
        for intf in self.interfaces.values():
            if intf.ip == ip:
                return intf
        return None

    def interface_on_subnet(self, ip: str) -> Optional[Interface]:
        addr = ipaddress.ip_address(ip)
        for intf in self.interfaces.values():
            if intf.ipv4 and addr in ipaddress.ip_interface(intf.ipv4).network:
                return intf
        return None


Network = Dict[str, DeviceConfig]


def copy_network(net: Network) -> Network:
    return {k: v.model_copy(deep=True) for k, v in net.items()}


def network_fingerprint(net: Network) -> str:
    """Deterministic hash of a network's configuration state."""
    payload = json.dumps({k: net[k].model_dump(mode="json") for k in sorted(net)}, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()
