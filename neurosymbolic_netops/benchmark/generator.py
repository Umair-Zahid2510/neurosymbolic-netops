"""Parametric scenario generation with dev / held-out test splits.

A scenario = base network + injected faults (typed PatchOps) + telemetry options + ground truth.
Only scenarios whose faults violate at least one declared intent (under the local model) are
kept, so every scenario is a real incident.

Splits
  dev   : single faults from the original templates, seen telemetry phrasings, clean or noisy.
          Used while building the system (rule engine, prompts).
  test  : held-out - multi-fault combinations (k=2,3), the two NOVEL templates added after the
          rule engine was frozen, held-out log phrasings, noisy and missing telemetry.
  legacy: the original 25 hand-written scenarios, migrated (kept for continuity only).
"""

from __future__ import annotations

import itertools
import json
import random
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from benchmark.faults import NOVEL_TEMPLATES, TEMPLATES, FaultSpec, bgp_pairs, fabric_links
from benchmark.differential_verifier import enumerate_single_faults
from core.config_ir import Network
from core.inventory import Testbed
from core.patch_ops import PatchError, PatchPlan, apply_plan
from core.verification import make_verifier

SCENARIO_DIR = Path(__file__).resolve().parent / "scenarios"


class TelemetrySpec(BaseModel):
    condition: str = "clean"   # clean | noisy | missing
    seed: int = 0
    noise_rate: float = 1.0
    decoys: bool = False
    duplicate_prob: float = 0.0
    missing_ts_prob: float = 0.0
    line_drop_prob: float = 0.0
    dropout_devices: List[str] = Field(default_factory=list)
    held_out_phrasing: bool = False


class Scenario(BaseModel):
    scenario_id: str
    split: str
    category: str               # LINK | BGP | ACL | ROUTING | MULTI | LEGACY
    faults: List[FaultSpec]
    culprits: List[str]
    telemetry: TelemetrySpec
    violated_intents: List[str]
    legacy_configs: Optional[Dict[str, str]] = None

    def faulty_network(self, base: Network) -> Network:
        if self.legacy_configs is not None:
            from core.parsers.ios import parse_ios
            from benchmark.legacy import migrate_legacy
            return migrate_legacy({d: parse_ios(t, d) for d in self.legacy_configs for t in [self.legacy_configs[d]]}, base)
        net = base
        for f in self.faults:
            net = apply_plan(net, f.inject)
        return net


def _telemetry(rng: random.Random, condition: str, seed: int, devices: List[str], held_out: bool) -> TelemetrySpec:
    if condition == "noisy":
        return TelemetrySpec(condition="noisy", seed=seed, noise_rate=3.0, decoys=True, duplicate_prob=0.1,
                             missing_ts_prob=0.1, held_out_phrasing=held_out)
    if condition == "missing":
        return TelemetrySpec(condition="missing", seed=seed, line_drop_prob=0.25,
                             dropout_devices=[rng.choice(devices)], held_out_phrasing=held_out)
    return TelemetrySpec(condition="clean", seed=seed, held_out_phrasing=held_out)


def generate_suite(tb: Testbed, seed: int = 2026, n_multi: int = 20) -> List[Scenario]:
    rng = random.Random(seed)
    verifier = make_verifier("local", tb.topology)
    devices = sorted(tb.network)
    out: List[Scenario] = []

    def keep(sid, split, cat, faults, tel) -> None:
        try:
            net = tb.network
            for f in faults:
                net = apply_plan(net, f.inject)
        except PatchError:
            return
        v = verifier.verify(net, tb.intents).violated()
        if v:
            out.append(Scenario(scenario_id=sid, split=split, category=cat, faults=faults,
                                culprits=sorted({f.culprit for f in faults}), telemetry=tel, violated_intents=v))

    singles = enumerate_single_faults(tb)
    for k, f in enumerate(singles):
        cond = "noisy" if k % 3 == 2 else "clean"
        keep(f"DEV-{f.template}-{f.location.replace(':', '_')}", "dev", f.category, [f],
             _telemetry(rng, cond, seed + k, devices, held_out=False))
    # held-out: novel templates
    k = 0
    for dev, intf, _, _ in fabric_links(tb.topology):
        if tb.topology.metadata["nodes"][dev]["role"] == "spine":
            f = NOVEL_TEMPLATES["acl_out_deny_spine"](tb.network, tb.topology, dev=dev, intf=intf)
            keep(f"TEST-NOVEL-{f.template}-{dev}_{intf}", "test", f.category, [f],
                 _telemetry(rng, ["clean", "noisy", "missing"][k % 3], seed + 1000 + k, devices, True)); k += 1
    for dev, nbr in bgp_pairs(tb.network):
        if tb.topology.metadata["nodes"][dev]["role"] == "leaf":
            f = NOVEL_TEMPLATES["route_map_prefix_filter"](tb.network, tb.topology, dev=dev, nbr=nbr)
            keep(f"TEST-NOVEL-{f.template}-{dev}_{nbr}", "test", f.category, [f],
                 _telemetry(rng, ["clean", "noisy", "missing"][k % 3], seed + 1000 + k, devices, True)); k += 1
    # held-out: single faults under held-out phrasing + noisy/missing telemetry (sampled)
    for j, f in enumerate(rng.sample(singles, 16)):
        keep(f"TEST-SINGLE-{f.template}-{f.location.replace(':', '_')}-{j}", "test", f.category, [f],
             _telemetry(rng, "missing" if j % 2 else "noisy", seed + 2000 + j, devices, True))
    # held-out: multi-fault combinations on distinct locations
    tries = 0
    made = 0
    while made < n_multi and tries < 500:
        tries += 1
        kf = 2 if made % 2 == 0 else 3
        combo = rng.sample(singles, kf)
        if len({f.location.split(':')[0] + f.template for f in combo}) < kf or len({f.location for f in combo}) < kf:
            continue
        before = len(out)
        keep(f"TEST-MULTI-k{kf}-{made:02d}", "test", "MULTI", combo,
             _telemetry(rng, ["clean", "noisy", "missing"][made % 3], seed + 3000 + made, devices, True))
        made += len(out) > before
    return out


def save_suite(suite: List[Scenario], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([s.model_dump(mode="json") for s in suite], indent=1), encoding="utf-8")


def load_suite(path: Path) -> List[Scenario]:
    return [Scenario.model_validate(d) for d in json.loads(path.read_text(encoding="utf-8"))]


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from core.inventory import load_testbed
    tb = load_testbed()
    suite = generate_suite(tb)
    from benchmark.legacy import legacy_suite
    suite += legacy_suite(tb)
    save_suite(suite, SCENARIO_DIR / "suite_v1.json")
    from collections import Counter
    print(len(suite), Counter((s.split, s.category) for s in suite))
