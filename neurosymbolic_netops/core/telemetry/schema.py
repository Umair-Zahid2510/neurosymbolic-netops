"""Tier-1 telemetry contracts.

``TelemetryEvent``  normalised raw observation (one syslog line, one counter sample, ...).
``AnomalyEvent``    output of the edge detectors: a compact, typed statement that something is
                    abnormal, with references back to the raw events that support it.
``IncidentDigest``  what Tier 1 hands to the central reasoning tier (analogous to BiAn's
                    compressed operational digest). Its size is measured so the
                    communication-overhead reduction can be reported.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, Field

Source = Literal["syslog", "interface_counter", "bgp_state", "probe", "system", "alarm"]

AnomalyKind = Literal[
    "link_down", "interface_errors", "bgp_session_down", "bgp_session_flap", "bgp_auth_failure",
    "bgp_peer_mismatch", "acl_drops", "probe_failure", "route_missing", "config_change",
    "resource_pressure", "log_anomaly",
]


class FlowSpec(BaseModel):
    src_ip: str
    dst_ip: str
    protocol: Literal["ip", "tcp", "udp", "icmp"] = "ip"
    dst_port: Optional[int] = None
    src_port: Optional[int] = None


class TelemetryEvent(BaseModel):
    event_id: str
    timestamp: Optional[datetime] = None  # timezone-aware UTC after normalisation
    source: Source
    device: Optional[str] = None
    interface: Optional[str] = None
    metric: Optional[str] = None
    value: Optional[float] = None
    message: Optional[str] = None
    mnemonic: Optional[str] = None  # e.g. "BGP-5-ADJCHANGE"
    severity: int = Field(default=6, ge=0, le=7)  # syslog semantics: 0 emergency .. 7 debug
    peer_ip: Optional[str] = None
    flow: Optional[FlowSpec] = None
    quality: List[str] = Field(default_factory=list)  # e.g. missing_timestamp, device_inferred


class AnomalyEvent(BaseModel):
    anomaly_id: str
    kind: AnomalyKind
    detector: str  # which edge detector produced it, e.g. "syslog_classifier", "counter_zscore"
    device: Optional[str] = None
    interface: Optional[str] = None
    peer_ip: Optional[str] = None
    flow: Optional[FlowSpec] = None
    severity: float = Field(ge=0.0, le=1.0)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    count: int = 1
    evidence_event_ids: List[str] = Field(default_factory=list)
    summary: str = ""


class IncidentDigest(BaseModel):
    incident_id: str
    anomalies: List[AnomalyEvent]
    raw_event_count: int
    suppressed_event_count: int
    raw_bytes: int
    digest_bytes: int = 0
    missing_data: List[str] = Field(default_factory=list)  # e.g. devices with no telemetry

    def finalize(self) -> "IncidentDigest":
        self.digest_bytes = len(self.model_dump_json(exclude={"digest_bytes"}).encode())
        return self
