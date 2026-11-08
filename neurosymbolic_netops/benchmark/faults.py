"""Parametric fault library.

Each fault template, given a location, returns the ``PatchOp``s that *inject* the fault plus
ground-truth metadata. Faults are injected into the canonical base network, so scenarios
are independent and every fault's effect is computed rather than asserted.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional

from pydantic import BaseModel

from core.causal_topology import TopologyGraph
from core.config_ir import AclRule, Network
from core.patch_ops import (BindAcl, CreateAcl, InsertAclRule, PatchPlan, SetBgpNeighborActivated, SetBgpNeighborPassword,
                            SetBgpNeighborRemoteAs, SetBgpNeighborRouteMap, SetBgpNetwork, SetInterfaceEnabled,
                            SetInterfaceMtu, SetInterfaceSpeedDuplex, SetRouteMapEntry)

PERIMETER = "PERIMETER_SECURITY_POLICY"


class FaultSpec(BaseModel):
    template: str
    category: str               # LINK | BGP | ACL | ROUTING
    culprit: str                # device whose configuration is wrong
    location: str               # human-readable location (device:interface / neighbor)
    description: str
    inject: PatchPlan
    log_acl: bool = False       # ACL faults: whether the deny rule carries the 'log' keyword


def _plan(*ops, why: str) -> PatchPlan:
    return PatchPlan(ops=list(ops), rationale=why)


def fabric_links(topo: TopologyGraph):
    return [(l.a_dev, l.a_intf, l.b_dev, l.b_intf) for l in topo.links]


def bgp_pairs(net: Network):
    return [(d, ip) for d, cfg in sorted(net.items()) if cfg.bgp for ip in sorted(cfg.bgp.neighbors)]


def lan_of(net: Network, topo: TopologyGraph, dev: str) -> Optional[str]:
    for name, i in net[dev].interfaces.items():
        if i.network and topo.link_for(dev, name) is None:
            return i.network
    return None


# ------------------------------------------------------------------ templates
def iface_shutdown(net, topo, dev, intf, **_):
    return FaultSpec(template="iface_shutdown", category="LINK", culprit=dev, location=f"{dev}:{intf}",
                     description=f"{dev} {intf} administratively shut down",
                     inject=_plan(SetInterfaceEnabled(device=dev, interface=intf, enabled=False), why="inject"))


def mtu_mismatch(net, topo, dev, intf, mtu=1400, **_):
    return FaultSpec(template="mtu_mismatch", category="LINK", culprit=dev, location=f"{dev}:{intf}",
                     description=f"{dev} {intf} MTU set to {mtu}",
                     inject=_plan(SetInterfaceMtu(device=dev, interface=intf, mtu=mtu), why="inject"))


def duplex_mismatch(net, topo, dev, intf, **_):
    return FaultSpec(template="duplex_mismatch", category="LINK", culprit=dev, location=f"{dev}:{intf}",
                     description=f"{dev} {intf} forced to half duplex",
                     inject=_plan(SetInterfaceSpeedDuplex(device=dev, interface=intf, duplex="half"), why="inject"))


def speed_mismatch(net, topo, dev, intf, **_):
    return FaultSpec(template="speed_mismatch", category="LINK", culprit=dev, location=f"{dev}:{intf}",
                     description=f"{dev} {intf} forced to speed 100",
                     inject=_plan(SetInterfaceSpeedDuplex(device=dev, interface=intf, speed="100"), why="inject"))


def remote_as_mismatch(net, topo, dev, nbr, wrong_as=65099, **_):
    return FaultSpec(template="remote_as_mismatch", category="BGP", culprit=dev, location=f"{dev}:{nbr}",
                     description=f"{dev} neighbor {nbr} remote-as {wrong_as}",
                     inject=_plan(SetBgpNeighborRemoteAs(device=dev, neighbor=nbr, remote_as=wrong_as), why="inject"))


def md5_unilateral(net, topo, dev, nbr, **_):
    return FaultSpec(template="md5_unilateral", category="BGP", culprit=dev, location=f"{dev}:{nbr}",
                     description=f"{dev} neighbor {nbr} has an MD5 password the peer lacks",
                     inject=_plan(SetBgpNeighborPassword(device=dev, neighbor=nbr, password="S3cr3tKey"), why="inject"))


def neighbor_deactivated(net, topo, dev, nbr, **_):
    return FaultSpec(template="neighbor_deactivated", category="BGP", culprit=dev, location=f"{dev}:{nbr}",
                     description=f"{dev} neighbor {nbr} not activated for IPv4 unicast",
                     inject=_plan(SetBgpNeighborActivated(device=dev, neighbor=nbr, activated=False), why="inject"))


def missing_network(net, topo, dev, **_):
    p = lan_of(net, topo, dev)
    return FaultSpec(template="missing_network", category="ROUTING", culprit=dev, location=f"{dev}:{p}",
                     description=f"{dev} no longer advertises {p}",
                     inject=_plan(SetBgpNetwork(device=dev, prefix=p, present=False), why="inject"))


def route_map_drop(net, topo, dev, nbr, **_):
    return FaultSpec(template="route_map_drop", category="BGP", culprit=dev, location=f"{dev}:{nbr}",
                     description=f"{dev} applies deny-all route-map outbound to {nbr}",
                     inject=_plan(SetRouteMapEntry(device=dev, route_map="RM_EXPORT_FILTER", seq=10, action="deny"),
                                  SetBgpNeighborRouteMap(device=dev, neighbor=nbr, direction="out", route_map="RM_EXPORT_FILTER"),
                                  why="inject"))


def acl_deny_lan(net, topo, dev, log=False, **_):
    other = [lan_of(net, topo, d) for d in sorted(net) if d != dev and lan_of(net, topo, d)][0]
    rule = AclRule(action="deny", protocol="ip", src=other, log=log)
    return FaultSpec(template="acl_deny_lan", category="ACL", culprit=dev, location=f"{dev}:{PERIMETER}",
                     description=f"{dev} perimeter ACL denies traffic from {other}", log_acl=log,
                     inject=_plan(InsertAclRule(device=dev, acl=PERIMETER, position=1, rule=rule), why="inject"))


def acl_deny_service(net, topo, dev, port=443, log=False, **_):
    rule = AclRule(action="deny", protocol="tcp", dst_port=port, log=log)
    return FaultSpec(template="acl_deny_service", category="ACL", culprit=dev, location=f"{dev}:{PERIMETER}",
                     description=f"{dev} perimeter ACL denies tcp/{port}", log_acl=log,
                     inject=_plan(InsertAclRule(device=dev, acl=PERIMETER, position=1, rule=rule), why="inject"))


def acl_supernet_deny(net, topo, dev, log=False, **_):
    rule = AclRule(action="deny", protocol="ip", src="10.1.0.0/16", log=log)
    return FaultSpec(template="acl_supernet_deny", category="ACL", culprit=dev, location=f"{dev}:{PERIMETER}",
                     description=f"{dev} perimeter ACL denies supernet 10.1.0.0/16", log_acl=log,
                     inject=_plan(InsertAclRule(device=dev, acl=PERIMETER, position=1, rule=rule), why="inject"))


def acl_block_bgp(net, topo, dev, intf, **_):
    acl = "CTRL_PLANE_FILTER"
    return FaultSpec(template="acl_block_bgp", category="ACL", culprit=dev, location=f"{dev}:{intf}",
                     description=f"{dev} {intf} inbound ACL blocks BGP (tcp/179 both directions)",
                     inject=_plan(*_new_acl_ops(dev, acl, [AclRule(action="deny", protocol="tcp", dst_port=179),
                                                           AclRule(action="deny", protocol="tcp", src_port=179),
                                                           AclRule(action="permit")]),
                                  BindAcl(device=dev, interface=intf, direction="in", acl=acl), why="inject"))


def acl_transit_deny(net, topo, dev, intf, **_):
    acl = "TRANSIT_FILTER"
    return FaultSpec(template="acl_transit_deny", category="ACL", culprit=dev, location=f"{dev}:{intf}",
                     description=f"{dev} {intf} inbound default-deny transit filter",
                     inject=_plan(*_new_acl_ops(dev, acl, [AclRule(action="deny")]),
                                  BindAcl(device=dev, interface=intf, direction="in", acl=acl), why="inject"))


def _new_acl_ops(dev: str, acl: str, rules: List[AclRule]):
    return [CreateAcl(device=dev, acl=acl, rules=rules)]


TEMPLATES: Dict[str, Callable[..., FaultSpec]] = {
    f.__name__: f for f in (iface_shutdown, mtu_mismatch, duplex_mismatch, speed_mismatch, remote_as_mismatch,
                            md5_unilateral, neighbor_deactivated, missing_network, route_map_drop, acl_deny_lan,
                            acl_deny_service, acl_supernet_deny, acl_block_bgp, acl_transit_deny)
}


# ---------------------------------------------------------------------------------------------
# NOVEL templates: added AFTER the rule-based baseline was frozen (git commit a9fd5c4) and used
# only in the held-out test split. They exercise outbound ACLs on spines and prefix-specific
# route filtering, which the rule author did not write dedicated rules for.
# ---------------------------------------------------------------------------------------------
def acl_out_deny_spine(net, topo, dev, intf, **_):
    peer_dev, _ = topo.link_for(dev, intf).other(dev)
    lan = lan_of(net, topo, peer_dev)
    other = [lan_of(net, topo, d) for d in sorted(net) if lan_of(net, topo, d) and lan_of(net, topo, d) != lan][0]
    return FaultSpec(template="acl_out_deny_spine", category="ACL", culprit=dev, location=f"{dev}:{intf}",
                     description=f"{dev} {intf} outbound ACL drops {other} -> {lan}",
                     inject=_plan(CreateAcl(device=dev, acl="EGRESS_GUARD", rules=[
                         AclRule(action="deny", protocol="ip", src=other, dst=lan), AclRule(action="permit")]),
                         BindAcl(device=dev, interface=intf, direction="out", acl="EGRESS_GUARD"), why="inject"))


def route_map_prefix_filter(net, topo, dev, nbr, **_):
    from core.patch_ops import SetPrefixListEntry
    owner = topo.owner_of_ip(nbr, net)[0]
    lan = lan_of(net, topo, owner) or lan_of(net, topo, [d for d in sorted(net) if lan_of(net, topo, d)][0])
    victim = [lan_of(net, topo, d) for d in sorted(net) if lan_of(net, topo, d)][0]
    return FaultSpec(template="route_map_prefix_filter", category="BGP", culprit=dev, location=f"{dev}:{nbr}",
                     description=f"{dev} import filter from {nbr} drops {victim} only",
                     inject=_plan(SetPrefixListEntry(device=dev, prefix_list="PL_BLOCK", seq=5, action="permit", prefix=victim),
                                  SetRouteMapEntry(device=dev, route_map="RM_IMPORT", seq=10, action="deny", match_prefix_list="PL_BLOCK"),
                                  SetRouteMapEntry(device=dev, route_map="RM_IMPORT", seq=20, action="permit"),
                                  SetBgpNeighborRouteMap(device=dev, neighbor=nbr, direction="in", route_map="RM_IMPORT"),
                                  why="inject"))


NOVEL_TEMPLATES = {"acl_out_deny_spine": acl_out_deny_spine, "route_map_prefix_filter": route_map_prefix_filter}
