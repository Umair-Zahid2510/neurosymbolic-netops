"""Declarative, vendor-neutral network intent.

Intents say *what must hold*, never *how* to configure it. They are loaded from
``configs/intents.yaml`` and evaluated by every verification backend. No OpenConfig/YANG
compliance is claimed: this is a project-specific intermediate representation validated with
Pydantic (see LIMITATIONS.md).
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Annotated, List, Literal, Optional, Union

import yaml
from pydantic import BaseModel, Field, field_validator

from core.telemetry.schema import FlowSpec


class FlowSelector(BaseModel):
    """A class of traffic. Verification uses one representative host address per prefix."""
    src_prefix: str
    dst_prefix: str
    protocol: Literal["ip", "tcp", "udp", "icmp"] = "ip"
    dst_port: Optional[int] = None

    @field_validator("src_prefix", "dst_prefix")
    @classmethod
    def _cidr(cls, v: str) -> str:
        return str(ipaddress.ip_network(v, strict=False))

    @staticmethod
    def _host(prefix: str) -> str:
        net = ipaddress.ip_network(prefix)
        offset = 10 if net.num_addresses > 16 else 1
        return str(net.network_address + min(offset, net.num_addresses - 1))

    def representative(self) -> FlowSpec:
        return FlowSpec(src_ip=self._host(self.src_prefix), dst_ip=self._host(self.dst_prefix),
                        protocol=self.protocol, dst_port=self.dst_port,
                        src_port=49152 if self.protocol in ("tcp", "udp") else None)

    def label(self) -> str:
        p = self.protocol + (f"/{self.dst_port}" if self.dst_port else "")
        return f"{self.src_prefix} -> {self.dst_prefix} ({p})"


class Location(BaseModel):
    device: str
    interface: Optional[str] = None  # ingress interface whose inbound ACL applies

    def label(self) -> str:
        return f"{self.device}[{self.interface}]" if self.interface else self.device


class _Intent(BaseModel):
    id: str
    description: str = ""


class ReachabilityIntent(_Intent):
    """Every forwarding path of ``flow`` from ``source`` must deliver (no partial blackholes)."""
    kind: Literal["reachability"] = "reachability"
    flow: FlowSelector
    source: Location


class IsolationIntent(_Intent):
    """``flow`` entering at any of ``ingress`` must never be delivered."""
    kind: Literal["isolation"] = "isolation"
    flow: FlowSelector
    ingress: List[Location] = Field(min_length=1)


class RedundancyIntent(_Intent):
    """``flow`` must be delivered over at least ``min_paths`` paths with distinct transit devices."""
    kind: Literal["redundancy"] = "redundancy"
    flow: FlowSelector
    source: Location
    min_paths: int = Field(default=2, ge=2)


class BgpSessionsIntent(_Intent):
    """All configured eBGP sessions (or the listed ones) must be ESTABLISHED and stable."""
    kind: Literal["bgp_sessions"] = "bgp_sessions"
    sessions: Optional[List[str]] = None  # "Device:neighbor_ip"; None = every configured session


class NoForwardingLoopsIntent(_Intent):
    """No probe between the listed prefixes may loop."""
    kind: Literal["no_forwarding_loops"] = "no_forwarding_loops"
    prefixes: List[str] = Field(min_length=1)


class LinkConsistencyIntent(_Intent):
    """Both ends of every physical link agree on MTU, speed and duplex (configuration invariant)."""
    kind: Literal["link_consistency"] = "link_consistency"


class BgpPeerConsistencyIntent(_Intent):
    """Both ends of every configured eBGP peering agree on remote-AS, MD5 password and IPv4
    activation (configuration invariant; Batfish does not model MD5 or AF activation)."""
    kind: Literal["bgp_peer_consistency"] = "bgp_peer_consistency"


Intent = Annotated[Union[ReachabilityIntent, IsolationIntent, RedundancyIntent, BgpSessionsIntent,
                         NoForwardingLoopsIntent, LinkConsistencyIntent, BgpPeerConsistencyIntent],
                   Field(discriminator="kind")]


class IntentSet(BaseModel):
    name: str
    intents: List[Intent]

    @classmethod
    def load(cls, path: Path) -> "IntentSet":
        return cls.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")))

    def by_id(self, intent_id: str):
        for i in self.intents:
            if i.id == intent_id:
                return i
        raise KeyError(intent_id)
