"""Synthetic telemetry generator (label: SYNTHETIC).

Telemetry is *derived from simulated network state*, not hand-written per scenario:
the healthy base network is simulated for a pre-fault window, the faulty network after the
fault onset, and every observable difference (link state, BGP session state, RIB size,
probe loss, error counters, ACL hit counters) is emitted as raw syslog lines, counter
samples and probe results in the formats a collector would receive.

Realism features: device-perspective syslog (only the device that would log a message logs
it, so the culprit is often ambiguous from logs alone), multiple phrasings per message
(the last phrasing of each template is reserved for held-out evaluation of the syslog
classifier), benign background noise and decoys, per-device telemetry dropout, missing
timestamps, duplicated lines and counter jitter.

Limitations: this is not packet-level emulation; message timing is coarse (30 s samples);
see LIMITATIONS.md.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from core.causal_topology import TopologyGraph
from core.config_ir import Network
from core.intent_schema import IntentSet, ReachabilityIntent
from core.network_model import NetworkState, compute_state, traceroute
from core.renderers.ios import ios_interface_name

T0 = datetime(2026, 11, 8, 10, 0, 0, tzinfo=timezone.utc)
SAMPLE_S = 30

# category -> mnemonic -> list of message phrasings. The LAST phrasing is held out (test only).
TEMPLATES: Dict[str, Dict[str, List[str]]] = {
    "link": {
        "LINK-5-CHANGED": ["Interface {intf}, changed state to administratively down",
                           "Interface {intf} changed state to administratively down",
                           "Interface {intf}: state changed to admin-down"],
        "LINK-3-UPDOWN": ["Interface {intf}, changed state to down",
                          "Interface {intf} changed state to down",
                          "Link on {intf} went down"],
        "LINEPROTO-5-UPDOWN": ["Line protocol on Interface {intf}, changed state to down",
                               "Line protocol on {intf} changed state to down",
                               "Protocol on interface {intf} is now down"],
        "CDP-4-DUPLEX_MISMATCH": ["duplex mismatch discovered on {intf} ({duplex}), with {peer} {pintf} ({pduplex})",
                                  "Duplex mismatch on {intf} ({duplex}) with neighbor {peer} {pintf} ({pduplex})",
                                  "{intf} duplex {duplex} disagrees with {peer} {pintf} duplex {pduplex}"],
        "ETH-4-MTU_MISMATCH": ["Oversized frames (giants) received on {intf}, MTU {mtu}",
                               "Giant frames dropped on {intf} (mtu {mtu})",
                               "{intf} discarding frames larger than MTU {mtu}"],
    },
    "bgp": {
        "BGP-5-ADJCHANGE": ["neighbor {peer_ip} Down {reason}",
                            "neighbor {peer_ip} Down - {reason}",
                            "BGP peer {peer_ip} transitioned to Idle: {reason}"],
        "BGP-3-NOTIFICATION_SENT": ["sent to neighbor {peer_ip} 2/2 (peer in wrong AS) 2 bytes {asn_hex}",
                                    "sent to neighbor {peer_ip} 2/2 (bad remote AS) {asn_hex}",
                                    "notification 2/2 peer-in-wrong-AS transmitted to {peer_ip}"],
        "BGP-3-NOTIFICATION_RECV": ["received from neighbor {peer_ip} 2/2 (peer in wrong AS) 2 bytes {asn_hex}",
                                    "received from neighbor {peer_ip} 2/2 (bad remote AS)",
                                    "notification 2/2 peer-in-wrong-AS received from {peer_ip}"],
        "BGP-3-HOLDTIME": ["sent to neighbor {peer_ip} 4/0 (hold time expired) 0 bytes",
                           "hold time expired for neighbor {peer_ip}",
                           "keepalives from {peer_ip} missing, hold timer expired"],
        "TCP-6-BADAUTH": ["No MD5 digest from {peer_ip}(179) to {local_ip}({port})",
                          "Invalid MD5 digest from {peer_ip}(179) to {local_ip}({port}) (RST)",
                          "MD5 authentication failure for segment from {peer_ip}:179"],
        "BGP-4-AFI_NOT_NEGOTIATED": ["neighbor {peer_ip} ipv4 unicast not negotiated, no address family active",
                                     "neighbor {peer_ip}: IPv4 Unicast capability not exchanged",
                                     "no common address family with peer {peer_ip}"],
    },
    "acl": {
        "SEC-6-IPACCESSLOGP": ["list {acl} denied {proto} {src}({sport}) -> {dst}({dport}), {n} packets",
                               "list {acl} denied {proto} {src} -> {dst}, {n} packets",
                               "ACL {acl} dropped {n} {proto} packets {src} -> {dst}"],
    },
    "routing": {
        "ROUTING-4-PREFIX_WITHDRAWN": ["prefix {prefix} removed from RIB (no valid path)",
                                       "route {prefix} withdrawn, no remaining next hop",
                                       "RIB lost reachability to {prefix}"],
    },
    "benign": {
        "SYS-5-CONFIG_I": ["Configured from console by admin on vty0 ({ip})",
                           "Configured from console by netops on vty1 ({ip})",
                           "Configuration modified by automation via vty2 ({ip})"],
        "NTP-5-PEERSYNC": ["NTP synced to peer {ip}", "Synchronized to NTP server {ip}",
                           "clock synchronised with time source {ip}"],
        "NTP-4-PEERUNREACH": ["Peer {ip} is unreachable", "NTP peer {ip} unreachable",
                              "time source {ip} not responding"],
        "SYS-6-LOGGINGHOST_STARTSTOP": ["Logging to host {ip} port 514 started - CLI initiated",
                                        "Logging to host {ip} started",
                                        "remote syslog destination {ip} enabled"],
        "SNMP-3-AUTHFAIL": ["Authentication failure for SNMP req from host {ip}",
                            "SNMP authentication failure from {ip}",
                            "rejected SNMP request with bad community from {ip}"],
        "SEC_LOGIN-5-LOGIN_SUCCESS": ["Login Success [user: netops] [Source: {ip}] [localport: 22]",
                                      "Login Success [user: admin] [Source: {ip}]",
                                      "user netops authenticated from {ip} over ssh"],
    },
    "resource": {
        "SYS-2-MALLOCFAIL": ["Memory allocation of 65536 bytes failed, pool Processor",
                             "Memory allocation failure in pool Processor",
                             "processor pool exhausted, allocation of 65536 bytes failed"],
    },
}


@dataclass
class GeneratorOptions:
    seed: int = 0
    pre_samples: int = 6
    post_samples: int = 8
    noise_rate: float = 1.0          # expected benign lines per device per sample
    decoys: bool = False             # benign-looking-but-alarming lines on unrelated devices
    dropout_devices: List[str] = field(default_factory=list)  # devices sending NO telemetry
    line_drop_prob: float = 0.0      # random loss of individual records
    missing_ts_prob: float = 0.0
    duplicate_prob: float = 0.0
    held_out_phrasing: bool = False  # True: use only the held-out (last) phrasing
    probe_interval: int = 1          # probe every N samples


@dataclass
class GeneratedTelemetry:
    records: List[dict]
    labels: List[str]   # per-record ground-truth category (for classifier training/eval ONLY)
    fault_onset: datetime


def _phrase(rng: random.Random, cat: str, mnem: str, held_out: bool, **kw) -> str:
    variants = TEMPLATES[cat][mnem]
    v = variants[-1] if held_out else rng.choice(variants[:-1])
    return v.format(**kw)


class _Emitter:
    def __init__(self, opts: GeneratorOptions):
        self.o = opts
        self.rng = random.Random(opts.seed)
        self.records: List[dict] = []
        self.labels: List[str] = []

    def syslog(self, ts: datetime, device: str, cat: str, mnem: str, **kw) -> None:
        if device in self.o.dropout_devices or self.rng.random() < self.o.line_drop_prob:
            return
        sev = mnem.split("-")[1] if mnem.count("-") >= 2 else "5"
        mnem_out = mnem.replace("_SENT", "").replace("_RECV", "")
        msg = _phrase(self.rng, cat, mnem, self.o.held_out_phrasing, **kw)
        ts = ts + timedelta(milliseconds=self.rng.randint(0, 2500))
        if self.rng.random() < self.o.missing_ts_prob:
            line = f"{device}: %{mnem_out}: {msg}"
        else:
            pri = 184 + int(sev) if sev.isdigit() else 189
            line = f"<{pri}>{ts.strftime('%b %d %H:%M:%S.%f')[:-3]} UTC {device}: %{mnem_out}: {msg}"
        n = 2 if self.rng.random() < self.o.duplicate_prob else 1
        for _ in range(n):
            self.records.append({"type": "syslog", "line": line})
            self.labels.append(cat)

    def counter(self, ts: datetime, device: str, interface: Optional[str], metric: str, value: float) -> None:
        if device in self.o.dropout_devices or self.rng.random() < self.o.line_drop_prob:
            return
        self.records.append({"type": "counter", "ts": ts.isoformat(), "device": device,
                             "interface": interface, "metric": metric, "value": value})
        self.labels.append("metric")

    def probe(self, ts: datetime, agent: str, flow: dict, loss_pct: float, rtt_ms: Optional[float]) -> None:
        if agent in self.o.dropout_devices:
            return
        self.records.append({"type": "probe", "ts": ts.isoformat(), "agent": agent, "flow": flow,
                             "loss_pct": loss_pct, "rtt_ms": rtt_ms})
        self.labels.append("probe")


def _rand_ip(rng: random.Random) -> str:
    return f"172.16.{rng.randint(0, 20)}.{rng.randint(2, 250)}"


def generate(base: Network, faulty: Network, topo: TopologyGraph, intents: IntentSet,
             opts: Optional[GeneratorOptions] = None) -> GeneratedTelemetry:
    opts = opts or GeneratorOptions()
    em = _Emitter(opts)
    rng = em.rng
    s_base = compute_state(base, topo)
    s_fault = compute_state(faulty, topo)
    onset = T0 + timedelta(seconds=opts.pre_samples * SAMPLE_S)
    n_samples = opts.pre_samples + opts.post_samples

    # ---------------- event-driven syslog at fault onset (and repeats while broken)
    _link_events(em, onset, base, faulty, topo, s_base, s_fault)
    for k in range(opts.post_samples):
        ts = onset + timedelta(seconds=k * SAMPLE_S)
        _bgp_events(em, ts, faulty, topo, s_base, s_fault, first=(k == 0))
        _acl_log_events(em, ts, faulty, topo, s_fault, intents)
    _route_events(em, onset, s_base, s_fault)

    # ---------------- periodic counters, probes, noise
    acl_hits: Dict[Tuple[str, str], float] = {}
    for k in range(n_samples):
        ts = T0 + timedelta(seconds=k * SAMPLE_S)
        net, st = (base, s_base) if ts < onset else (faulty, s_fault)
        _counters(em, ts, net, topo, st, acl_hits, intents)
        if k % opts.probe_interval == 0:
            _probes(em, ts, net, topo, st, intents)
        for dev in net:
            for _ in range(_poisson(rng, opts.noise_rate)):
                mnem = rng.choice(list(TEMPLATES["benign"]))
                em.syslog(ts, dev, "benign", mnem, ip=_rand_ip(rng))
        if opts.decoys and k == opts.pre_samples + 1:
            dev = rng.choice(sorted(net))
            em.syslog(ts, dev, "benign", "SNMP-3-AUTHFAIL", ip=_rand_ip(rng))
            em.syslog(ts, dev, "benign", "SYS-5-CONFIG_I", ip=_rand_ip(rng))
    order = sorted(range(len(em.records)), key=lambda i: _record_ts(em.records[i]))
    return GeneratedTelemetry(records=[em.records[i] for i in order], labels=[em.labels[i] for i in order],
                              fault_onset=onset)


def _record_ts(r: dict) -> str:
    if r["type"] == "syslog":
        line = r["line"]
        try:
            stamp = line.split(">", 1)[1][:19]
            return datetime.strptime(f"2026 {stamp}", "%Y %b %d %H:%M:%S.%f").replace(tzinfo=timezone.utc).isoformat()
        except (IndexError, ValueError):
            return "9999"
    return r["ts"]


def _poisson(rng: random.Random, lam: float) -> int:
    import math
    L, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= L:
            return k
        k += 1


def _link_events(em, ts, base, faulty, topo, s_base, s_fault):
    for lb, lf in zip(s_base.links, s_fault.links):
        for dev, intf, pdev, pintf in ((lf.a_dev, lf.a_intf, lf.b_dev, lf.b_intf), (lf.b_dev, lf.b_intf, lf.a_dev, lf.a_intf)):
            i = faulty[dev].interfaces.get(intf)
            pi = faulty[pdev].interfaces.get(pintf)
            if lb.up and not lf.up:
                name = ios_interface_name(intf)
                if i is not None and not i.enabled:
                    em.syslog(ts, dev, "link", "LINK-5-CHANGED", intf=name)
                else:
                    em.syslog(ts, dev, "link", "LINK-3-UPDOWN", intf=name)
                    em.syslog(ts, dev, "link", "LINEPROTO-5-UPDOWN", intf=name)
            for d in lf.degraded:
                if d not in lb.degraded and i is not None and pi is not None:
                    if d.startswith("duplex") and i.duplex == "full":
                        em.syslog(ts, dev, "link", "CDP-4-DUPLEX_MISMATCH", intf=ios_interface_name(intf),
                                  duplex=i.duplex, peer=pdev, pintf=ios_interface_name(pintf), pduplex=pi.duplex)
                    if d.startswith("MTU") and i.mtu < pi.mtu:
                        em.syslog(ts, dev, "link", "ETH-4-MTU_MISMATCH", intf=ios_interface_name(intf), mtu=i.mtu)


def _bgp_events(em, ts, faulty, topo, s_base, s_fault, first: bool):
    for sb, sf in zip(s_base.sessions, s_fault.sessions):
        if sb.state != "ESTABLISHED" or sf.state == "ESTABLISHED":
            continue
        dev, pip = sf.device, sf.neighbor_ip
        cfg = faulty[dev]
        local_ip = cfg.interfaces[sf.local_interface].ip if sf.local_interface else "0.0.0.0"
        reasons = " ".join(sf.reasons)
        if sf.state == "FLAPPING":
            em.syslog(ts, dev, "bgp", "BGP-3-HOLDTIME", peer_ip=pip)
            em.syslog(ts, dev, "bgp", "BGP-5-ADJCHANGE", peer_ip=pip, reason="BGP Notification sent")
            continue
        if not first:
            continue
        if "administratively down" in reasons or "speed mismatch" in reasons:
            em.syslog(ts, dev, "bgp", "BGP-5-ADJCHANGE", peer_ip=pip, reason="Interface flap")
        elif "expects remote-as" in reasons:
            nbr = cfg.bgp.neighbors[pip]
            peer_asn = faulty[sf.peer_device].bgp.asn if sf.peer_device and faulty[sf.peer_device].bgp else 0
            if nbr.remote_as != peer_asn:  # this side detects the wrong AS in the OPEN it receives
                em.syslog(ts, dev, "bgp", "BGP-3-NOTIFICATION_SENT", peer_ip=pip, asn_hex=f"{peer_asn:04X}")
            else:
                em.syslog(ts, dev, "bgp", "BGP-3-NOTIFICATION_RECV", peer_ip=pip, asn_hex=f"{cfg.bgp.asn:04X}")
            em.syslog(ts, dev, "bgp", "BGP-5-ADJCHANGE", peer_ip=pip, reason="BGP Notification")
        elif "MD5" in reasons:
            if cfg.bgp.neighbors[pip].password:  # the side expecting a digest logs the failure
                em.syslog(ts, dev, "bgp", "TCP-6-BADAUTH", peer_ip=pip, local_ip=local_ip, port=em.rng.randint(30000, 60000))
        elif "not activated" in reasons:
            em.syslog(ts, dev, "bgp", "BGP-4-AFI_NOT_NEGOTIATED", peer_ip=pip)
            em.syslog(ts, dev, "bgp", "BGP-5-ADJCHANGE", peer_ip=pip, reason="Capability mismatch")
        elif "blocks TCP/179" in reasons:
            em.syslog(ts, dev, "bgp", "BGP-5-ADJCHANGE", peer_ip=pip, reason="Hold timer expired / connection timed out")
        else:
            em.syslog(ts, dev, "bgp", "BGP-5-ADJCHANGE", peer_ip=pip, reason="Peer closed the session")


def _acl_log_events(em, ts, faulty, topo, s_fault, intents):
    """ACL log lines appear only for rules configured with the ``log`` keyword (IOS behaviour)."""
    for intent in intents.intents:
        if not isinstance(intent, ReachabilityIntent):
            continue
        flow = intent.flow.representative()
        for t in traceroute(faulty, topo, s_fault, intent.source.device, flow, intent.source.interface):
            h = t.acl_hit
            if h and h.rule_index is not None:
                rule = faulty[h.device].acls[h.acl].rules[h.rule_index]
                if rule.log:
                    em.syslog(ts, h.device, "acl", "SEC-6-IPACCESSLOGP", acl=h.acl, proto=flow.protocol,
                              src=flow.src_ip, dst=flow.dst_ip, sport=flow.src_port or 0,
                              dport=flow.dst_port or 0, n=em.rng.randint(5, 200))


def _route_events(em, ts, s_base, s_fault):
    for dev, rib in s_base.ribs.items():
        for p in rib:
            if p not in s_fault.ribs.get(dev, {}):
                em.syslog(ts, dev, "routing", "ROUTING-4-PREFIX_WITHDRAWN", prefix=p)


def _counters(em, ts, net, topo, st: NetworkState, acl_hits, intents):
    rng = em.rng
    for dev, cfg in net.items():
        em.counter(ts, dev, None, "cpu_util_pct", round(max(1.0, rng.gauss(18, 4)), 1))
        em.counter(ts, dev, None, "mem_util_pct", round(max(5.0, rng.gauss(41, 2)), 1))
        em.counter(ts, dev, None, "rib_routes", float(len(st.ribs.get(dev, {}))))
        for name, intf in cfg.interfaces.items():
            ls = st.link_state(dev, name)
            oper_up = intf.enabled and (ls is None or ls.up)
            em.counter(ts, dev, name, "oper_status", 1.0 if oper_up else 0.0)
            errs = float(rng.choice([0, 0, 0, 1]))
            crc = late = giants = 0.0
            if ls is not None and ls.up:
                for d in ls.degraded:
                    if d.startswith("duplex"):
                        if intf.duplex == "half":
                            late = float(rng.randint(150, 900))
                        else:
                            crc = float(rng.randint(80, 600))
                    if d.startswith("MTU"):
                        pdev, pintf = topo.link_for(dev, name).other(dev)
                        if intf.mtu < net[pdev].interfaces[pintf].mtu:
                            giants = float(rng.randint(40, 400))
            em.counter(ts, dev, name, "in_errors_delta", errs + crc + giants)
            em.counter(ts, dev, name, "crc_errors_delta", crc)
            em.counter(ts, dev, name, "late_collisions_delta", late)
            em.counter(ts, dev, name, "giants_delta", giants)
    # ACL deny-hit counters for every bound ACL. Baseline: background hits on deny rules
    # (e.g. scanning from blocked subnets); plus hits for every intended flow that is dropped.
    deny: Dict[Tuple[str, str, str], float] = {}
    for dev, cfg in net.items():
        for name, intf in cfg.interfaces.items():
            for acl in (intf.acl_in, intf.acl_out):
                if acl and acl in cfg.acls and any(r.action == "deny" for r in cfg.acls[acl].rules):
                    deny[(dev, name, acl)] = float(rng.choice([0, 0, 1, 2, 3]))
    for intent in intents.intents:
        if not isinstance(intent, ReachabilityIntent):
            continue
        for t in traceroute(net, topo, st, intent.source.device, intent.flow.representative(), intent.source.interface):
            if t.acl_hit:
                h = t.acl_hit
                deny[(h.device, h.interface, h.acl)] = deny.get((h.device, h.interface, h.acl), 0.0) + float(rng.randint(50, 500))
    for (dev, name, acl), v in deny.items():
        em.counter(ts, dev, name, f"acl_deny_delta:{acl}", v)


def _probes(em, ts, net, topo, st, intents):
    rng = em.rng
    for intent in intents.intents:
        if not isinstance(intent, ReachabilityIntent) or intent.flow.protocol != "ip":
            continue
        flow = intent.flow.representative()
        traces = traceroute(net, topo, st, intent.source.device, flow, intent.source.interface)
        ok = [t for t in traces if t.success]
        loss = 100.0 if not traces else round(100.0 * (1 - len(ok) / len(traces)), 1)
        rtt = round(0.35 * len(ok[0].hops) + abs(rng.gauss(0, 0.08)), 3) if ok else None
        em.probe(ts, intent.source.device, flow.model_dump(), loss, rtt)
