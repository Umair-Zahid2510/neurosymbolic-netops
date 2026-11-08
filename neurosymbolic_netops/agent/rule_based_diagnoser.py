"""Deterministic baseline: rule-based Diagnostic and Planning strategies (mode ``rule_based``).

Generic over topology, configuration and declared intent; contains no scenario or incident
knowledge. It inspects the network only through the read-only skill registry, so its tool
calls are logged exactly like an LLM's. It resembles the NetAssistant end of the design space
in the survey: deterministic workflows that cannot explain fault classes outside its rules.

Rules (all derived, never hardcoded to devices or addresses):
* link parameters that deviate from the fleet-typical value are suspected on the deviating side;
* a BGP neighbor whose configured remote-as differs from the peer's actual local AS;
* a unilateral or differing MD5 password; an un-activated neighbor;
* a LAN prefix referenced by a reachability intent that its owner does not advertise;
* a route-map applied to a neighbor that denies an intent-relevant prefix;
* an explicit ACL rule that denies an intended flow (reachability intents, or TCP/179 between
  configured BGP peers) at an interface the flow traverses.
"""

from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional, Tuple

from agent.contracts import DiagnosisReport, Hypothesis, PlanProposal
from core.config_ir import AclRule, Network
from core.intent_schema import IntentSet, ReachabilityIntent, RedundancyIntent
from core.patch_ops import (BindAcl, PatchPlan, RemoveAclRule, SetBgpNeighborActivated, SetBgpNeighborPassword,
                            SetBgpNeighborRemoteAs, SetBgpNeighborRouteMap, SetBgpNetwork, SetInterfaceEnabled,
                            SetInterfaceMtu, SetInterfaceSpeedDuplex)
from core.skills.base import SkillContext, SkillRegistry
from core.parsers.ios import parse_acl_rule

CALLER = "diagnostic_agent[rule_based]"


class RuleBasedDiagnoser:
    strategy = "rule_based"

    def __init__(self, registry: SkillRegistry, intents: IntentSet):
        self.reg = registry
        self.intents = intents

    def _call(self, ctx, name, **args):
        c = self.reg.invoke(name, args, ctx, CALLER)
        return c.result if c.ok else None, c.evidence_id

    def diagnose(self, ctx: SkillContext, candidates: List[str], feedback: Optional[List[str]] = None) -> DiagnosisReport:
        start = len(ctx.call_log)
        hyps: List[Hypothesis] = []
        seen = set()

        def add(h: Hypothesis):
            key = (h.device, h.fault_type, h.location)
            if key not in seen:
                seen.add(key)
                hyps.append(h)

        devices = candidates or sorted(ctx.network)
        # --- link layer (every fabric link touching a candidate)
        links = sorted({(l.a_dev, l.a_intf) for l in ctx.topology.links if devices and (l.a_dev in devices or l.b_dev in devices)})
        for dev, intf in links:
            r, ev = self._call(ctx, "check_link", device=dev, interface=intf)
            if not r:
                continue
            for side in ("local", "peer"):
                s = r[side]
                if s["admin_status"] != "up":
                    add(Hypothesis(device=s["device"], category="LINK", fault_type="interface_admin_down",
                                   location=s["interface"], statement=f"{s['device']} {s['interface']} is administratively down",
                                   evidence=[ev]))
            for attr, ftype in (("speed", "speed_mismatch"), ("duplex", "duplex_mismatch"), ("mtu", "mtu_mismatch")):
                if attr in r["parameter_mismatches"]:
                    typical = r["fleet_typical"][attr]
                    for side in ("local", "peer"):
                        s = r[side]
                        if s[attr] != typical:
                            add(Hypothesis(device=s["device"], category="LINK", fault_type=ftype, location=s["interface"],
                                           statement=f"{s['device']} {s['interface']} {attr}={s[attr]} deviates from fleet-typical {typical}",
                                           evidence=[ev]))
        # --- BGP
        asn: Dict[str, int] = {}
        summaries = {}
        for dev in sorted(ctx.network):
            r, ev = self._call(ctx, "bgp_summary", device=dev)
            if r and r.get("local_as") is not None:
                asn[dev] = r["local_as"]; summaries[dev] = (r, ev)
        for dev in devices:
            if dev not in summaries:
                continue
            r, ev = summaries[dev]
            for n in r["neighbors"]:
                if n["state"] == "Established":
                    continue
                nb, ev2 = self._call(ctx, "bgp_neighbor", device=dev, neighbor_ip=n["neighbor"])
                if not nb:
                    continue
                peer = nb["peer_device_per_topology"]
                if peer in asn and nb["remote_as_configured"] != asn[peer]:
                    add(Hypothesis(device=dev, category="BGP", fault_type="bgp_remote_as_mismatch", location=n["neighbor"],
                                   statement=f"{dev} neighbor {n['neighbor']} remote-as {nb['remote_as_configured']} but {peer} is AS {asn[peer]}",
                                   evidence=[ev, ev2]))
                if not nb["ipv4_unicast_activated"]:
                    add(Hypothesis(device=dev, category="BGP", fault_type="bgp_af_not_activated", location=n["neighbor"],
                                   statement=f"{dev} neighbor {n['neighbor']} not activated for IPv4 unicast", evidence=[ev2]))
                if peer:
                    local_ip = self._local_ip(ctx, dev, n["neighbor"])
                    pn, ev3 = self._call(ctx, "bgp_neighbor", device=peer, neighbor_ip=local_ip) if local_ip else (None, None)
                    if pn is None and local_ip:
                        add(Hypothesis(device=peer, category="BGP", fault_type="bgp_peer_missing_neighbor", location=local_ip,
                                       statement=f"{peer} has no neighbor statement for {local_ip}", evidence=[ev2]))
                    elif pn and pn["password"] != nb["password"]:
                        culprits = [d for d, pw in ((dev, nb["password"]), (peer, pn["password"])) if pw is not None]
                        for d in culprits:
                            loc = n["neighbor"] if d == dev else local_ip
                            add(Hypothesis(device=d, category="BGP", fault_type="bgp_auth_mismatch", location=loc,
                                           statement=f"MD5 password on {d} for {loc} does not match its peer"
                                                     + (" (unilateral)" if len(culprits) == 1 else ""), evidence=[ev2, ev3]))
                # control-plane ACLs on the link carrying this session
                for d, ip_local, ip_peer in ((dev, local_ip, n["neighbor"]), (peer, n["neighbor"], local_ip)):
                    if d and ip_local and ip_peer:
                        self._acl_flow_check(ctx, d, add, ip_peer, ip_local, "tcp", 179, "acl_blocks_control_plane",
                                             f"BGP TCP/179 from {ip_peer}", src_port=49152)
                        self._acl_flow_check(ctx, d, add, ip_peer, ip_local, "tcp", 49152, "acl_blocks_control_plane",
                                             f"BGP TCP/179 replies from {ip_peer}", src_port=179)
        # --- prefixes, route policy, data-plane ACLs (per intended flow)
        flows = [i for i in self.intents.intents if isinstance(i, (ReachabilityIntent, RedundancyIntent))]
        prefixes = sorted({p for i in flows for p in (i.flow.src_prefix, i.flow.dst_prefix)})
        for p in prefixes:
            owner = ctx.topology.owner_of_ip(str(ipaddress.ip_network(p).network_address + 1), ctx.network)
            if not owner:
                continue
            od = owner[0]
            cfg = ctx.network[od]
            if cfg.bgp and p not in cfg.bgp.networks:
                nb_ev = self._call(ctx, "routing_table", device=od, prefix=p)[1]
                add(Hypothesis(device=od, category="ROUTING", fault_type="missing_prefix_advertisement", location=p,
                               statement=f"{od} owns {p} but does not advertise it into BGP", evidence=[nb_ev]))
            for dev in devices:
                dcfg = ctx.network[dev]
                if not dcfg.bgp:
                    continue
                for ip, nbr in dcfg.bgp.neighbors.items():
                    for direction, rm in (("out", nbr.route_map_out), ("in", nbr.route_map_in)):
                        if rm:
                            r, ev = self._call(ctx, "inspect_route_policy", device=dev, route_map=rm, prefix=p)
                            if r and not r.get("permits_prefix", True):
                                add(Hypothesis(device=dev, category="BGP",
                                               fault_type="bgp_export_policy_blocks" if direction == "out" else "bgp_import_policy_blocks",
                                               location=ip, statement=f"{dev} route-map {rm} ({direction}) toward {ip} denies {p}",
                                               evidence=[ev]))
        for i in flows:
            f = i.flow.representative()
            for dev in devices:
                self._acl_flow_check(ctx, dev, add, f.src_ip, f.dst_ip, f.protocol, f.dst_port,
                                     "acl_blocks_intended_traffic", f"intended flow {i.flow.label()} ({i.id})",
                                     src_port=f.src_port)
        hyps = self._rank(hyps, candidates)
        for k, h in enumerate(hyps, 1):
            h.id = f"H{k}"
        return DiagnosisReport(strategy=self.strategy, hypotheses=hyps,
                               reasoning_summary=f"{len(hyps)} rule-matched hypotheses over {len(devices)} candidate devices",
                               skill_call_ids=[c.call_id for c in ctx.call_log[start:]])

    @staticmethod
    def _local_ip(ctx, dev, neighbor_ip) -> Optional[str]:
        i = ctx.network[dev].interface_on_subnet(neighbor_ip)
        return i.ip if i else None

    def _acl_flow_check(self, ctx, dev, add, src, dst, proto, dport, ftype, what, src_port=None):
        cfg = ctx.network.get(dev)
        if not cfg:
            return
        for intf in cfg.interfaces.values():
            for direction, acl in (("in", intf.acl_in), ("out", intf.acl_out)):
                if not acl or acl not in cfg.acls:
                    continue
                if not self._flow_traverses(ctx, dev, intf.name, direction, src, dst):
                    continue
                r, ev = self._call(ctx, "acl_packet_test", device=dev, acl=acl, src_ip=src, dst_ip=dst, protocol=proto,
                                   dst_port=dport, src_port=src_port)
                if r and r["action"] == "deny":
                    loc = f"{acl}#{r['matched_rule_index']}" if r["matched_rule_index"] is not None else f"{acl}#implicit"
                    add(Hypothesis(device=dev, category="ACL", fault_type=ftype, location=loc,
                                   statement=f"{dev} {intf.name} {direction} ACL {acl} rule '{r['matched_rule']}' denies {what}",
                                   evidence=[ev]))

    @staticmethod
    def _flow_traverses(ctx, dev, intf, direction, src, dst) -> bool:
        """Would a packet src->dst plausibly cross ``dev:intf`` in ``direction``? Uses topology: the
        interface faces the source (in) or the destination (out), or connects directly to it."""
        cfg = ctx.network[dev]
        i = cfg.interfaces[intf]
        target = src if direction == "in" else dst
        if i.network and ipaddress.ip_address(target) in ipaddress.ip_network(i.network):
            return True
        link = ctx.topology.link_for(dev, intf)
        if link is None:
            return False
        pdev, _ = link.other(dev)
        owner = ctx.topology.owner_of_ip(target, ctx.network)
        if owner is None:
            return False
        return owner[0] == pdev or owner[0] not in (dev,) and pdev in ctx.topology.devices_on_shortest_paths(dev, owner[0])

    @staticmethod
    def _rank(hyps: List[Hypothesis], candidates: List[str]) -> List[Hypothesis]:
        order = {d: k for k, d in enumerate(candidates)}
        return sorted(hyps, key=lambda h: (order.get(h.device, len(order)), h.category, h.fault_type, h.location))


class RuleBasedPlanner:
    strategy = "rule_based"

    def __init__(self, registry: SkillRegistry):
        self.reg = registry

    def plan(self, ctx: SkillContext, hypotheses: List[Hypothesis], feedback: Optional[List[str]] = None,
             exclude: Optional[set] = None) -> PlanProposal:
        """One operation per hypothesis (deduplicated). ``exclude`` holds hypothesis keys whose
        repair was already rejected by verification, so a revision tries something else."""
        net = ctx.network
        ops, used, skipped = [], [], []
        typical = {}
        for attr in ("mtu", "speed", "duplex"):
            vals = [getattr(net[d].interfaces[i], attr) for l in ctx.topology.links
                    for d, i in ((l.a_dev, l.a_intf), (l.b_dev, l.b_intf))]
            typical[attr] = max(set(vals), key=vals.count) if vals else None
        for h in hypotheses:
            key = (h.device, h.fault_type, h.location)
            if exclude and key in exclude:
                skipped.append(h.id)
                continue
            op = self._op_for(ctx, h, typical)
            if op is None:
                skipped.append(h.id)
                continue
            if any(o.model_dump() == op.model_dump() for o in ops):
                continue
            ops.append(op); used.append(h.id)
        if not ops:
            return PlanProposal(strategy=self.strategy, plan=None, notes=f"no applicable repair (skipped {skipped})")
        return PlanProposal(strategy=self.strategy,
                            plan=PatchPlan(ops=ops, rationale="rule-based repair per hypothesis", addresses_hypotheses=used),
                            notes=f"skipped {skipped}" if skipped else "")

    def _op_for(self, ctx, h: Hypothesis, typical):
        net = ctx.network
        d = net.get(h.device)
        if d is None:
            return None
        ft = h.fault_type
        if ft == "interface_admin_down":
            return SetInterfaceEnabled(device=h.device, interface=h.location, enabled=True)
        if ft == "mtu_mismatch":
            return SetInterfaceMtu(device=h.device, interface=h.location, mtu=typical["mtu"])
        if ft in ("speed_mismatch", "duplex_mismatch"):
            attr = "speed" if ft == "speed_mismatch" else "duplex"
            return SetInterfaceSpeedDuplex(device=h.device, interface=h.location, **{attr: typical[attr]})
        if ft == "bgp_remote_as_mismatch":
            owner = ctx.topology.owner_of_ip(h.location, net)
            if owner and net[owner[0]].bgp:
                return SetBgpNeighborRemoteAs(device=h.device, neighbor=h.location, remote_as=net[owner[0]].bgp.asn)
        if ft == "bgp_auth_mismatch":
            return SetBgpNeighborPassword(device=h.device, neighbor=h.location, password=None)
        if ft == "bgp_af_not_activated":
            return SetBgpNeighborActivated(device=h.device, neighbor=h.location, activated=True)
        if ft in ("bgp_export_policy_blocks", "bgp_import_policy_blocks"):
            return SetBgpNeighborRouteMap(device=h.device, neighbor=h.location,
                                          direction="out" if ft == "bgp_export_policy_blocks" else "in", route_map=None)
        if ft == "missing_prefix_advertisement":
            return SetBgpNetwork(device=h.device, prefix=h.location, present=True)
        if ft in ("acl_blocks_intended_traffic", "acl_blocks_control_plane"):
            acl, idx = h.location.split("#")
            if acl not in d.acls:
                return None
            if idx == "implicit" or len(d.acls[acl].rules) == 1:
                # removing the only rule would leave an implicit deny-all: unbind instead
                for i in d.interfaces.values():
                    if i.acl_in == acl:
                        return BindAcl(device=h.device, interface=i.name, direction="in", acl=None)
                    if i.acl_out == acl:
                        return BindAcl(device=h.device, interface=i.name, direction="out", acl=None)
                return None
            return RemoveAclRule(device=h.device, acl=acl, rule=d.acls[acl].rules[int(idx)])
        return None
