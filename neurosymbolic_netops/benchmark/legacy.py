"""Migration of the original 25 hand-written scenarios into the new scenario format.

Migration: parse the legacy configs with the IR parser; rename the host SVIs (vlan10/vlan20) to
the routed host ports used by the canonical testbed (eth10/eth20); carry over the base
network's ``maximum-paths``. Ground-truth culprits come from the legacy files. Two legacy
data defects found by the audit are kept as-is and flagged in ``notes``:
FAULT_ACL_003 (ACL blocks only dst-port 179, so a session can still form) and FAULT_LINK_004
(str.replace changed both Spine-1 interfaces).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from core.config_ir import Network, copy_network
from core.inventory import Testbed
from core.renderers.ios import render_ios

LEGACY_DIR = Path(__file__).resolve().parent.parent / "dataset"


def migrate_legacy(parsed: Network, base: Network) -> Network:
    net = copy_network(parsed)
    for dev, cfg in net.items():
        for old, new in (("vlan10", "eth10"), ("vlan20", "eth20")):
            if old in cfg.interfaces:
                i = cfg.interfaces.pop(old)
                i.name = new
                cfg.interfaces[new] = i
        if cfg.bgp and base.get(dev) and base[dev].bgp:
            cfg.bgp.maximum_paths = base[dev].bgp.maximum_paths
    return net


def legacy_suite(tb: Testbed) -> List["Scenario"]:
    from benchmark.generator import Scenario, TelemetrySpec
    from core.parsers.ios import parse_ios
    from core.verification import make_verifier
    v = make_verifier("local", tb.topology)
    raw = json.loads((LEGACY_DIR / "ground_truth_faults.json").read_text()) + \
        json.loads((LEGACY_DIR / "advanced_stress_faults.json").read_text())
    out = []
    for k, s in enumerate(raw):
        net = migrate_legacy({d: parse_ios(t, d) for d, t in s["corrupted_configs"].items()}, tb.network)
        culprits = sorted(set(s.get("ground_truth_culprits") or [s["ground_truth_culprit_device"]]))
        noisy = s["fault_category"] == "NOISY-TELEMETRY"
        out.append(Scenario(scenario_id=f"LEGACY-{s['incident_id']}", split="legacy", category="LEGACY", faults=[],
                            culprits=culprits,
                            telemetry=TelemetrySpec(condition="noisy" if noisy else "clean", seed=5000 + k,
                                                    noise_rate=3.0 if noisy else 1.0, decoys=noisy),
                            violated_intents=v.verify(net, tb.intents).violated(),
                            legacy_configs={d: render_ios(c) for d, c in net.items()}))
    return out
