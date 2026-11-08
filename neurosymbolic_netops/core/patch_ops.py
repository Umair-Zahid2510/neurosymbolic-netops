"""Typed, vendor-neutral configuration change operations.

Agents never emit raw CLI. A repair is a ``PatchPlan``: an ordered list of the operations
below. Each operation is validated against the network it is applied to and raises
``PatchError`` if its target does not exist or the change is a no-op that indicates a
misunderstanding (for example removing an ACL rule that is not present). Application is
pure: ``apply_plan`` returns a new network and never mutates its input.

The same operations are used by the benchmark to *inject* faults, so every injected fault
has an exact, machine-checkable inverse.
"""

from __future__ import annotations

import difflib
import hashlib
import json
from typing import Annotated, List, Literal, Optional, Union

from pydantic import BaseModel, Field

from core.config_ir import AclRule, Network, RouteMapEntry, copy_network


class PatchError(ValueError):
    pass


class _Op(BaseModel):
    device: str

    def _dev(self, net: Network):
        if self.device not in net:
            raise PatchError(f"unknown device {self.device!r}")
        return net[self.device]

    def _intf(self, net: Network, name: str):
        dev = self._dev(net)
        if name not in dev.interfaces:
            raise PatchError(f"{self.device}: unknown interface {name!r}")
        return dev.interfaces[name]

    def _nbr(self, net: Network, ip: str):
        dev = self._dev(net)
        if not dev.bgp or ip not in dev.bgp.neighbors:
            raise PatchError(f"{self.device}: no BGP neighbor {ip}")
        return dev.bgp.neighbors[ip]

    def describe(self) -> str:  # pragma: no cover - overridden
        return self.__class__.__name__


class SetInterfaceEnabled(_Op):
    op: Literal["set_interface_enabled"] = "set_interface_enabled"
    interface: str
    enabled: bool

    def apply(self, net: Network) -> None:
        self._intf(net, self.interface).enabled = self.enabled

    def describe(self) -> str:
        return f"{self.device} {self.interface}: {'no shutdown' if self.enabled else 'shutdown'}"


class SetInterfaceMtu(_Op):
    op: Literal["set_interface_mtu"] = "set_interface_mtu"
    interface: str
    mtu: int = Field(ge=576, le=9216)

    def apply(self, net: Network) -> None:
        self._intf(net, self.interface).mtu = self.mtu

    def describe(self) -> str:
        return f"{self.device} {self.interface}: mtu {self.mtu}"


class SetInterfaceSpeedDuplex(_Op):
    op: Literal["set_interface_speed_duplex"] = "set_interface_speed_duplex"
    interface: str
    speed: Optional[str] = None
    duplex: Optional[Literal["full", "half", "auto"]] = None

    def apply(self, net: Network) -> None:
        if self.speed is None and self.duplex is None:
            raise PatchError("speed and duplex both unset")
        i = self._intf(net, self.interface)
        if self.speed is not None:
            i.speed = self.speed
        if self.duplex is not None:
            i.duplex = self.duplex

    def describe(self) -> str:
        return f"{self.device} {self.interface}: speed {self.speed} duplex {self.duplex}"


class BindAcl(_Op):
    """Bind (acl=name) or unbind (acl=None) an ACL on an interface direction."""
    op: Literal["bind_acl"] = "bind_acl"
    interface: str
    direction: Literal["in", "out"]
    acl: Optional[str] = None

    def apply(self, net: Network) -> None:
        dev = self._dev(net)
        i = self._intf(net, self.interface)
        if self.acl is not None and self.acl not in dev.acls:
            raise PatchError(f"{self.device}: ACL {self.acl!r} does not exist")
        current = i.acl_in if self.direction == "in" else i.acl_out
        if self.acl is None and current is None:
            raise PatchError(f"{self.device} {self.interface}: no ACL bound {self.direction}")
        if self.direction == "in":
            i.acl_in = self.acl
        else:
            i.acl_out = self.acl

    def describe(self) -> str:
        if self.acl is None:
            return f"{self.device} {self.interface}: remove ACL ({self.direction})"
        return f"{self.device} {self.interface}: bind ACL {self.acl} {self.direction}"


class RemoveAclRule(_Op):
    op: Literal["remove_acl_rule"] = "remove_acl_rule"
    acl: str
    rule: AclRule

    def apply(self, net: Network) -> None:
        dev = self._dev(net)
        if self.acl not in dev.acls:
            raise PatchError(f"{self.device}: ACL {self.acl!r} does not exist")
        rules = dev.acls[self.acl].rules
        idx = [k for k, r in enumerate(rules) if r.key() == self.rule.key()]
        if len(idx) != 1:
            raise PatchError(f"{self.device} ACL {self.acl}: rule '{self.rule.key()}' matched {len(idx)} entries")
        del rules[idx[0]]

    def describe(self) -> str:
        return f"{self.device} ACL {self.acl}: remove '{self.rule.key()}'"


class InsertAclRule(_Op):
    op: Literal["insert_acl_rule"] = "insert_acl_rule"
    acl: str
    position: int = Field(ge=0, description="0 = top of the ACL")
    rule: AclRule

    def apply(self, net: Network) -> None:
        dev = self._dev(net)
        if self.acl not in dev.acls:
            raise PatchError(f"{self.device}: ACL {self.acl!r} does not exist")
        rules = dev.acls[self.acl].rules
        if self.position > len(rules):
            raise PatchError(f"position {self.position} beyond end of ACL ({len(rules)} rules)")
        rules.insert(self.position, self.rule)

    def describe(self) -> str:
        return f"{self.device} ACL {self.acl}: insert '{self.rule.key()}' at {self.position}"


class CreateAcl(_Op):
    """Create a new ACL (rules=[...]) or delete an unbound one (delete=True)."""
    op: Literal["create_acl"] = "create_acl"
    acl: str
    rules: List[AclRule] = Field(default_factory=list)
    delete: bool = False

    def apply(self, net: Network) -> None:
        from core.config_ir import Acl
        dev = self._dev(net)
        if self.delete:
            if self.acl not in dev.acls:
                raise PatchError(f"{self.device}: ACL {self.acl!r} does not exist")
            bound = [i.name for i in dev.interfaces.values() if self.acl in (i.acl_in, i.acl_out)]
            if bound:
                raise PatchError(f"{self.device}: ACL {self.acl!r} still bound on {bound}")
            del dev.acls[self.acl]
            return
        if self.acl in dev.acls:
            raise PatchError(f"{self.device}: ACL {self.acl!r} already exists")
        if not self.rules:
            raise PatchError("a new ACL needs at least one rule")
        dev.acls[self.acl] = Acl(name=self.acl, rules=list(self.rules))

    def describe(self) -> str:
        if self.delete:
            return f"{self.device}: delete ACL {self.acl}"
        return f"{self.device}: create ACL {self.acl} ({len(self.rules)} rules)"


class SetBgpNeighborRemoteAs(_Op):
    op: Literal["set_bgp_neighbor_remote_as"] = "set_bgp_neighbor_remote_as"
    neighbor: str
    remote_as: int = Field(ge=1, le=4294967295)

    def apply(self, net: Network) -> None:
        self._nbr(net, self.neighbor).remote_as = self.remote_as

    def describe(self) -> str:
        return f"{self.device} BGP neighbor {self.neighbor}: remote-as {self.remote_as}"


class SetBgpNeighborPassword(_Op):
    """password=None removes authentication."""
    op: Literal["set_bgp_neighbor_password"] = "set_bgp_neighbor_password"
    neighbor: str
    password: Optional[str] = None

    def apply(self, net: Network) -> None:
        n = self._nbr(net, self.neighbor)
        if self.password is None and n.password is None:
            raise PatchError(f"{self.device} neighbor {self.neighbor}: no password configured")
        n.password = self.password

    def describe(self) -> str:
        return f"{self.device} BGP neighbor {self.neighbor}: " + (
            "remove password" if self.password is None else "set password <redacted>")


class SetBgpNeighborActivated(_Op):
    op: Literal["set_bgp_neighbor_activated"] = "set_bgp_neighbor_activated"
    neighbor: str
    activated: bool

    def apply(self, net: Network) -> None:
        self._nbr(net, self.neighbor).activated = self.activated

    def describe(self) -> str:
        return f"{self.device} BGP neighbor {self.neighbor}: {'activate' if self.activated else 'deactivate'} ipv4 unicast"


class SetBgpNeighborRouteMap(_Op):
    """route_map=None removes the binding."""
    op: Literal["set_bgp_neighbor_route_map"] = "set_bgp_neighbor_route_map"
    neighbor: str
    direction: Literal["in", "out"]
    route_map: Optional[str] = None

    def apply(self, net: Network) -> None:
        dev = self._dev(net)
        n = self._nbr(net, self.neighbor)
        if self.route_map is not None and self.route_map not in dev.route_maps:
            raise PatchError(f"{self.device}: route-map {self.route_map!r} does not exist")
        current = n.route_map_in if self.direction == "in" else n.route_map_out
        if self.route_map is None and current is None:
            raise PatchError(f"{self.device} neighbor {self.neighbor}: no route-map {self.direction}")
        if self.direction == "in":
            n.route_map_in = self.route_map
        else:
            n.route_map_out = self.route_map

    def describe(self) -> str:
        return f"{self.device} BGP neighbor {self.neighbor}: route-map {self.direction} -> {self.route_map}"


class SetRouteMapEntry(_Op):
    """Create or replace one route-map stanza; action=None deletes the stanza."""
    op: Literal["set_route_map_entry"] = "set_route_map_entry"
    route_map: str
    seq: int = Field(ge=1)
    action: Optional[Literal["permit", "deny"]] = None
    match_prefix_list: Optional[str] = None

    def apply(self, net: Network) -> None:
        dev = self._dev(net)
        entries = dev.route_maps.setdefault(self.route_map, [])
        existing = [e for e in entries if e.seq == self.seq]
        if self.action is None:
            if not existing:
                raise PatchError(f"route-map {self.route_map} seq {self.seq} does not exist")
            entries.remove(existing[0])
            return
        if self.match_prefix_list and self.match_prefix_list not in dev.prefix_lists:
            raise PatchError(f"prefix-list {self.match_prefix_list!r} does not exist")
        if existing:
            entries.remove(existing[0])
        entries.append(RouteMapEntry(seq=self.seq, action=self.action, match_prefix_list=self.match_prefix_list))
        entries.sort(key=lambda e: e.seq)

    def describe(self) -> str:
        if self.action is None:
            return f"{self.device} route-map {self.route_map}: delete seq {self.seq}"
        return f"{self.device} route-map {self.route_map} {self.action} {self.seq}"


class SetPrefixListEntry(_Op):
    """Create or replace one prefix-list entry; action=None deletes it."""
    op: Literal["set_prefix_list_entry"] = "set_prefix_list_entry"
    prefix_list: str
    seq: int = Field(ge=1)
    action: Optional[Literal["permit", "deny"]] = None
    prefix: Optional[str] = None

    def apply(self, net: Network) -> None:
        from core.config_ir import PrefixList, PrefixListEntry
        dev = self._dev(net)
        pl = dev.prefix_lists.setdefault(self.prefix_list, PrefixList(name=self.prefix_list))
        pl.entries = [e for e in pl.entries if e.seq != self.seq]
        if self.action is None:
            return
        if not self.prefix:
            raise PatchError("prefix required")
        pl.entries.append(PrefixListEntry(seq=self.seq, action=self.action, prefix=self.prefix))
        pl.entries.sort(key=lambda e: e.seq)

    def describe(self) -> str:
        return f"{self.device} prefix-list {self.prefix_list} seq {self.seq}: {self.action} {self.prefix}"


class SetBgpNetwork(_Op):
    op: Literal["set_bgp_network"] = "set_bgp_network"
    prefix: str
    present: bool = True

    def apply(self, net: Network) -> None:
        import ipaddress
        dev = self._dev(net)
        if not dev.bgp:
            raise PatchError(f"{self.device}: BGP not configured")
        p = str(ipaddress.ip_network(self.prefix, strict=False))
        if self.present:
            if p in dev.bgp.networks:
                raise PatchError(f"{self.device}: network {p} already advertised")
            dev.bgp.networks.append(p)
        else:
            if p not in dev.bgp.networks:
                raise PatchError(f"{self.device}: network {p} not configured")
            dev.bgp.networks.remove(p)

    def describe(self) -> str:
        return f"{self.device} BGP: {'advertise' if self.present else 'withdraw'} {self.prefix}"


PatchOp = Annotated[Union[
    SetInterfaceEnabled, SetInterfaceMtu, SetInterfaceSpeedDuplex, BindAcl, CreateAcl, RemoveAclRule,
    InsertAclRule, SetBgpNeighborRemoteAs, SetBgpNeighborPassword, SetBgpNeighborActivated,
    SetBgpNeighborRouteMap, SetRouteMapEntry, SetPrefixListEntry, SetBgpNetwork,
], Field(discriminator="op")]


class PatchPlan(BaseModel):
    ops: List[PatchOp] = Field(min_length=1)
    rationale: str = ""
    addresses_hypotheses: List[str] = Field(default_factory=list)

    def plan_hash(self) -> str:
        payload = json.dumps([o.model_dump(mode="json") for o in self.ops], sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()

    def devices(self) -> List[str]:
        return sorted({o.device for o in self.ops})

    def describe(self) -> List[str]:
        return [o.describe() for o in self.ops]


def apply_plan(net: Network, plan: PatchPlan) -> Network:
    """Apply all operations to a copy of ``net``. Raises PatchError on the first invalid op."""
    new = copy_network(net)
    for k, op in enumerate(plan.ops):
        try:
            op.apply(new)
        except PatchError as exc:
            raise PatchError(f"op[{k}] {op.op}: {exc}") from exc
    return new


def render_diff(before: Network, after: Network) -> str:
    """Unified diff of the rendered IOS configs of every changed device (for display/audit)."""
    from core.renderers.ios import render_ios
    chunks = []
    for dev in sorted(set(before) | set(after)):
        a = render_ios(before[dev]).splitlines() if dev in before else []
        b = render_ios(after[dev]).splitlines() if dev in after else []
        if a != b:
            chunks.extend(difflib.unified_diff(a, b, f"{dev} (before)", f"{dev} (after)", lineterm="", n=1))
    return "\n".join(chunks)
