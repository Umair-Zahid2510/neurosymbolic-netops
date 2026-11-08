"""Tier-1 edge anomaly detection (lightweight ML + robust statistics).

Components (what they actually are):

* ``SyslogClassifier`` - TF-IDF (word 1-2 grams over masked tokens) + multinomial logistic
  regression (scikit-learn). Classes: benign, link, bgp, acl, routing, resource. Trained on
  generator phrasings, evaluated on *held-out* phrasings. This is a small classical model,
  **not** a small language model (SLM); see LIMITATIONS.md.
* ``CounterDetector`` - robust z-score (median/MAD) against a per-series baseline window, plus
  explicit state-change rules for ``oper_status`` and ``rib_routes``.
* ``ProbeDetector`` - sustained synthetic-probe loss.
* ``EdgeDetector`` - runs all three, maps classified lines to typed ``AnomalyEvent``s with a
  deterministic keyword layer, deduplicates, and emits an ``IncidentDigest``.
"""

from __future__ import annotations

import pickle
import random
import re
import statistics
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.telemetry.schema import AnomalyEvent, FlowSpec, IncidentDigest, TelemetryEvent

MODEL_DIR = Path(__file__).resolve().parent.parent.parent / "models"
CLASSES = ["benign", "link", "bgp", "acl", "routing", "resource"]

_MASKS = [(re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?\b"), " IPADDR "),
          (re.compile(r"\b(?:GigabitEthernet|Gi|Ethernet|eth|Vlan|Loopback)\s?\d+(?:/\d+)*\b", re.I), " INTF "),
          (re.compile(r"\b[0-9A-F]{4}\b"), " HEX "),
          (re.compile(r"\b\d+\b"), " NUM ")]


def mask(text: str) -> str:
    for rx, rep in _MASKS:
        text = rx.sub(rep, text)
    return " ".join(text.split()).lower()


def build_corpus(seed: int, n_per_template: int, held_out: bool) -> Tuple[List[str], List[str]]:
    """Lines generated from the telemetry templates. held_out=True uses only the last phrasing
    of every template, which never appears in training data."""
    from core.telemetry.generator import TEMPLATES
    rng = random.Random(seed)
    fill = dict(intf="GigabitEthernet0/1", duplex="full", peer="Spine-1", pintf="GigabitEthernet0/2",
                pduplex="half", mtu=1400, peer_ip="10.0.1.1", asn_hex="FDE8", reason="Interface flap",
                local_ip="10.0.1.2", port=40000, acl="FILTER", proto="tcp", src="10.1.10.10", dst="10.1.20.10",
                sport=49152, dport=443, n=12, prefix="10.1.20.0/24", ip="172.16.1.5")
    X, y = [], []
    for cat, mnems in TEMPLATES.items():
        for mnem, variants in mnems.items():
            pool = variants[-1:] if held_out else variants[:-1]
            for _ in range(n_per_template):
                f = dict(fill)
                f.update(intf=f"GigabitEthernet0/{rng.randint(1, 48)}", peer_ip=f"10.{rng.randint(0,9)}.{rng.randint(0,9)}.{rng.randint(1,254)}",
                         ip=f"172.16.{rng.randint(0, 50)}.{rng.randint(1, 254)}", n=rng.randint(1, 999),
                         mtu=rng.choice([1400, 1450, 9000]), port=rng.randint(20000, 60000))
                X.append(f"%{mnem.replace('_SENT', '').replace('_RECV', '')}: {rng.choice(pool).format(**f)}")
                y.append(cat)
    return X, y


class SyslogClassifier:
    def __init__(self, use_mnemonic: bool = True):
        self.use_mnemonic = use_mnemonic
        self.pipeline = None
        self.metrics: Dict = {}

    def _prep(self, lines: List[str]) -> List[str]:
        out = []
        for l in lines:
            if not self.use_mnemonic:
                l = re.sub(r"%[A-Z0-9_]+-\d-[A-Z0-9_]+:", "", l)
            out.append(mask(l))
        return out

    def fit(self, X: List[str], y: List[str]) -> "SyslogClassifier":
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import make_pipeline
        self.pipeline = make_pipeline(TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True),
                                      LogisticRegression(max_iter=2000, C=4.0))
        self.pipeline.fit(self._prep(X), y)
        return self

    def predict(self, lines: List[str]) -> List[str]:
        return list(self.pipeline.predict(self._prep(lines))) if lines else []

    def evaluate(self, X: List[str], y: List[str]) -> Dict:
        from sklearn.metrics import accuracy_score, f1_score
        t0 = time.perf_counter()
        pred = self.predict(X)
        dt = time.perf_counter() - t0
        return {"n": len(X), "accuracy": round(accuracy_score(y, pred), 4),
                "macro_f1": round(f1_score(y, pred, average="macro"), 4),
                "latency_us_per_line": round(dt / max(1, len(X)) * 1e6, 2)}

    def save(self, path: Path) -> int:
        path.parent.mkdir(parents=True, exist_ok=True)
        import sklearn
        blob = pickle.dumps({"pipeline": self.pipeline, "use_mnemonic": self.use_mnemonic, "metrics": self.metrics,
                             "sklearn_version": sklearn.__version__})
        path.write_bytes(blob)
        return len(blob)

    @classmethod
    def load(cls, path: Path) -> "SyslogClassifier":
        d = pickle.loads(Path(path).read_bytes())  # local, self-produced artifact only
        c = cls(d["use_mnemonic"]); c.pipeline = d["pipeline"]; c.metrics = d.get("metrics", {})
        return c


def train_default(seed: int = 7, path: Optional[Path] = None) -> SyslogClassifier:
    """Train, evaluate on held-out phrasings (with and without mnemonics), save with metrics."""
    path = path or MODEL_DIR / "syslog_classifier.pkl"
    Xtr, ytr = build_corpus(seed, 40, held_out=False)
    Xte, yte = build_corpus(seed + 1, 40, held_out=True)
    t0 = time.perf_counter()
    clf = SyslogClassifier(use_mnemonic=True).fit(Xtr, ytr)
    train_s = time.perf_counter() - t0
    ablate = SyslogClassifier(use_mnemonic=False).fit(Xtr, ytr)
    clf.metrics = {"train_lines": len(Xtr), "train_seconds": round(train_s, 3),
                   "heldout_phrasing": clf.evaluate(Xte, yte),
                   "heldout_phrasing_message_only": ablate.evaluate(Xte, yte),
                   "seen_phrasing": clf.evaluate(*build_corpus(seed + 2, 10, held_out=False))}
    clf.metrics["model_bytes"] = clf.save(path)
    clf.save(path)  # re-save so the stored metrics include the model size
    return clf


def load_or_train(path: Optional[Path] = None) -> SyslogClassifier:
    """Load the locally trained model; retrain (deterministically) if absent or produced by a
    different scikit-learn version. Writes the evaluation metrics next to the model."""
    import json
    import sklearn
    path = path or MODEL_DIR / "syslog_classifier.pkl"
    if path.exists():
        d = pickle.loads(path.read_bytes())  # local, self-produced artifact only
        if d.get("sklearn_version") == sklearn.__version__:
            c = SyslogClassifier(d["use_mnemonic"]); c.pipeline = d["pipeline"]; c.metrics = d.get("metrics", {})
            return c
    clf = train_default(path=path)
    path.with_name("syslog_classifier_metrics.json").write_text(json.dumps(clf.metrics, indent=2), encoding="utf-8")
    return clf


# ------------------------------------------------------------------ typed anomaly extraction
SEVERITY = {"link_down": 0.9, "bgp_session_down": 0.8, "bgp_session_flap": 0.75, "bgp_auth_failure": 0.85,
            "bgp_peer_mismatch": 0.85, "acl_drops": 0.7, "route_missing": 0.6, "interface_errors": 0.7,
            "probe_failure": 0.6, "resource_pressure": 0.4, "log_anomaly": 0.3}


def kind_for(category: str, msg: str) -> str:
    m = msg.lower()
    if category == "link":
        if any(k in m for k in ("duplex", "giant", "mtu", "larger than")):
            return "interface_errors"
        return "link_down"
    if category == "bgp":
        if "md5" in m:
            return "bgp_auth_failure"
        if "wrong as" in m or "wrong-as" in m or "remote as" in m:
            return "bgp_peer_mismatch"
        if "hold time" in m or "hold timer" in m:
            return "bgp_session_flap"
        return "bgp_session_down"
    return {"acl": "acl_drops", "routing": "route_missing", "resource": "resource_pressure"}.get(category, "log_anomaly")


class EdgeDetector:
    def __init__(self, classifier: Optional[SyslogClassifier] = None, z_threshold: float = 6.0,
                 baseline_fraction: float = 0.33):
        self.clf = classifier or load_or_train()
        self.z = z_threshold
        self.baseline_fraction = baseline_fraction
        self.timings: Dict[str, float] = {}

    def detect(self, incident_id: str, events: List[TelemetryEvent], raw_bytes: int,
               expected_devices: Optional[List[str]] = None) -> IncidentDigest:
        t0 = time.perf_counter()
        anomalies: List[AnomalyEvent] = []
        sys_ev = [e for e in events if e.source == "syslog"]
        labels = self.clf.predict([f"%{e.mnemonic}: {e.message}" for e in sys_ev])
        t1 = time.perf_counter()
        suppressed = 0
        for e, cat in zip(sys_ev, labels):
            if cat == "benign":
                suppressed += 1
                continue
            kind = kind_for(cat, e.message or "")
            flow = None
            if kind == "acl_drops":
                ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", e.message or "")
                if len(ips) >= 2:
                    flow = FlowSpec(src_ip=ips[0], dst_ip=ips[1])
            anomalies.append(AnomalyEvent(anomaly_id="", kind=kind, detector="syslog_classifier", device=e.device,
                                          interface=e.interface, peer_ip=e.peer_ip, flow=flow,
                                          severity=SEVERITY[kind], first_seen=e.timestamp, last_seen=e.timestamp,
                                          evidence_event_ids=[e.event_id], summary=f"[{cat}] %{e.mnemonic}: {e.message}"))
        anomalies += self._counters([e for e in events if e.source == "interface_counter"])
        anomalies += self._probes([e for e in events if e.source == "probe"])
        t2 = time.perf_counter()
        merged = self._merge(anomalies)
        seen_devices = {e.device for e in events if e.device}
        missing = sorted(set(expected_devices or []) - seen_devices)
        self.timings = {"classify_ms": round((t1 - t0) * 1000, 3), "detect_ms": round((t2 - t1) * 1000, 3),
                        "total_ms": round((time.perf_counter() - t0) * 1000, 3)}
        return IncidentDigest(incident_id=incident_id, anomalies=merged, raw_event_count=len(events),
                              suppressed_event_count=suppressed, raw_bytes=raw_bytes,
                              missing_data=[f"no telemetry from {d}" for d in missing]).finalize()

    def _counters(self, events: List[TelemetryEvent]) -> List[AnomalyEvent]:
        series: Dict[Tuple, List[TelemetryEvent]] = defaultdict(list)
        for e in events:
            series[(e.device, e.interface, e.metric)].append(e)
        out = []
        for (dev, intf, metric), evs in series.items():
            evs.sort(key=lambda e: e.timestamp or 0)
            vals = [e.value for e in evs]
            nb = max(2, int(len(vals) * self.baseline_fraction))
            base, rest = vals[:nb], evs[nb:]
            if not rest:
                continue
            med = statistics.median(base)
            mad = statistics.median([abs(v - med) for v in base]) * 1.4826
            if metric == "oper_status":
                down = [e for e in rest if e.value < med]
                if down:
                    out.append(self._a("link_down", "counter_state", dev, intf, down, f"{intf} oper_status {med:.0f}->0"))
                continue
            if metric == "rib_routes":
                drop = [e for e in rest if e.value < med]
                if drop:
                    out.append(self._a("route_missing", "counter_state", dev, None, drop,
                                       f"RIB size dropped from {med:.0f} to {min(e.value for e in drop):.0f}"))
                continue
            hits = [e for e in rest if (e.value - med) / (mad + 1.0) > self.z and e.value - med >= 20]
            if not hits:
                continue
            if metric.startswith("acl_deny_delta"):
                kind, acl = "acl_drops", metric.split(":", 1)[1]
                summary = f"ACL {acl} deny counter rising on {intf}"
            elif metric in ("cpu_util_pct", "mem_util_pct"):
                kind, summary = "resource_pressure", f"{metric} anomalous"
            else:
                kind, summary = "interface_errors", f"{metric} on {intf}: {max(e.value for e in hits):.0f}/sample (baseline {med:.0f})"
            out.append(self._a(kind, "counter_zscore", dev, intf, hits, summary))
        return out

    def _probes(self, events: List[TelemetryEvent]) -> List[AnomalyEvent]:
        by_flow: Dict[str, List[TelemetryEvent]] = defaultdict(list)
        for e in events:
            by_flow[f"{e.device}|{e.flow.src_ip}|{e.flow.dst_ip}"].append(e)
        out = []
        for _, evs in by_flow.items():
            bad = [e for e in evs if e.value]
            if len(bad) >= 2:
                a = self._a("probe_failure", "probe_loss", evs[0].device, None, bad,
                            f"probe {evs[0].flow.src_ip}->{evs[0].flow.dst_ip} loss up to {max(e.value for e in bad):.0f}%")
                a.flow = evs[0].flow
                a.severity = min(1.0, 0.5 + max(e.value for e in bad) / 200)
                out.append(a)
        return out

    @staticmethod
    def _a(kind, detector, dev, intf, evs, summary) -> AnomalyEvent:
        ts = [e.timestamp for e in evs if e.timestamp]
        return AnomalyEvent(anomaly_id="", kind=kind, detector=detector, device=dev, interface=intf,
                            severity=SEVERITY[kind], first_seen=min(ts) if ts else None, last_seen=max(ts) if ts else None,
                            count=len(evs), evidence_event_ids=[e.event_id for e in evs][:20], summary=summary)

    @staticmethod
    def _merge(anoms: List[AnomalyEvent]) -> List[AnomalyEvent]:
        merged: Dict[Tuple, AnomalyEvent] = {}
        for a in anoms:
            key = (a.kind, a.device, a.interface, a.peer_ip, a.flow.model_dump_json() if a.flow else None)
            if key in merged:
                m = merged[key]
                m.count += a.count
                m.evidence_event_ids = (m.evidence_event_ids + a.evidence_event_ids)[:20]
                if a.detector not in m.detector.split("+"):
                    m.detector += "+" + a.detector
                ts = [t for t in (m.first_seen, a.first_seen) if t]
                m.first_seen = min(ts) if ts else None
                ts = [t for t in (m.last_seen, a.last_seen) if t]
                m.last_seen = max(ts) if ts else None
            else:
                merged[key] = a
        out = sorted(merged.values(), key=lambda a: (-a.severity, a.kind, a.device or "", a.interface or ""))
        for k, a in enumerate(out, 1):
            a.anomaly_id = f"A{k:02d}"
        return out
