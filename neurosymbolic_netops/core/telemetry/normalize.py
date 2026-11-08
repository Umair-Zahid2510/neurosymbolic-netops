"""Normalise heterogeneous raw telemetry records into ``TelemetryEvent``s.

Handles: Cisco-style syslog with or without ``<PRI>``, with RFC3164-like or ISO timestamps,
or with no timestamp (flagged ``missing_timestamp``); counter samples; probe results.
Interface names are canonicalised; timestamps become timezone-aware UTC; exact duplicate
records are dropped and counted; device attribution falls back to IP ownership when the
hostname is absent (flagged ``device_inferred``).
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Callable, List, Optional, Tuple

from core.parsers.ios import canonical_interface_name
from core.telemetry.schema import FlowSpec, TelemetryEvent

_SYSLOG = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?:(?P<ts>(?:\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:?\d{2})?)|(?:[A-Z][a-z]{2}\s+\d{1,2}\s+[\d:.]+))\s*(?:UTC)?\s+)?"
    r"(?:(?P<host>[A-Za-z0-9_.-]+):\s+)?"
    r"%(?P<mnem>[A-Z0-9_]+-\d-[A-Z0-9_]+):\s*(?P<msg>.*)$")
_INTF = re.compile(r"\b((?:GigabitEthernet|TenGigabitEthernet|Ethernet|Gi|Te|eth|Vlan|Loopback)\s?\d+(?:/\d+)*)\b", re.I)
_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _parse_ts(raw: Optional[str], year: int = 2026) -> Optional[datetime]:
    if not raw:
        return None
    raw = raw.strip()
    try:
        if "T" in raw:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        for fmt in ("%Y %b %d %H:%M:%S.%f", "%Y %b %d %H:%M:%S"):
            try:
                return datetime.strptime(f"{year} {' '.join(raw.split())}", fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    except ValueError:
        return None
    return None


class Normalizer:
    def __init__(self, ip_owner: Optional[Callable[[str], Optional[Tuple[str, str]]]] = None):
        self.ip_owner = ip_owner
        self.duplicates_dropped = 0
        self.unparsed: List[str] = []

    def _eid(self, payload: str) -> str:
        return "ev-" + hashlib.sha1(payload.encode()).hexdigest()[:12]

    def normalize(self, records: List[dict]) -> List[TelemetryEvent]:
        seen = set()
        events: List[TelemetryEvent] = []
        for r in records:
            key = repr(sorted(r.items()))
            if key in seen:
                self.duplicates_dropped += 1
                continue
            seen.add(key)
            ev = self._one(r, key)
            if ev is not None:
                events.append(ev)
        return events

    def _one(self, r: dict, key: str) -> Optional[TelemetryEvent]:
        t = r.get("type")
        if t == "syslog":
            return self._syslog(r["line"], key)
        if t == "counter":
            intf = canonical_interface_name(r["interface"]) if r.get("interface") else None
            return TelemetryEvent(event_id=self._eid(key), timestamp=_parse_ts(r.get("ts")), source="interface_counter",
                                  device=r.get("device"), interface=intf, metric=r["metric"], value=float(r["value"]),
                                  quality=[] if r.get("ts") else ["missing_timestamp"])
        if t == "probe":
            loss = r.get("loss_pct")
            return TelemetryEvent(event_id=self._eid(key), timestamp=_parse_ts(r.get("ts")), source="probe",
                                  device=r.get("agent"), metric="probe_loss_pct", value=float(loss) if loss is not None else None,
                                  flow=FlowSpec(**r["flow"]), message=f"rtt_ms={r.get('rtt_ms')}",
                                  severity=3 if loss else 6)
        self.unparsed.append(str(r)[:200])
        return None

    def _syslog(self, line: str, key: str) -> Optional[TelemetryEvent]:
        m = _SYSLOG.match(line.strip())
        if not m:
            self.unparsed.append(line[:200])
            return None
        quality = []
        ts = _parse_ts(m.group("ts"))
        if ts is None:
            quality.append("missing_timestamp")
        msg = m.group("msg")
        mnem = m.group("mnem")
        sev = int(mnem.split("-")[1])
        intf_m = _INTF.search(msg)
        intf = canonical_interface_name(intf_m.group(1).replace(" ", "")) if intf_m else None
        ips = _IP.findall(msg)
        peer_ip = ips[0] if ("neighbor" in msg or "peer" in msg.lower() or "MD5" in msg) and ips else None
        device = m.group("host")
        if not device and self.ip_owner and ips:
            owner = self.ip_owner(ips[-1])
            if owner:
                device = owner[0]
                quality.append("device_inferred")
        return TelemetryEvent(event_id=self._eid(key), timestamp=ts, source="syslog", device=device,
                              interface=intf, message=msg, mnemonic=mnem, severity=sev, peer_ip=peer_ip,
                              quality=quality)
