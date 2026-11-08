"""Differential check: local_symbolic vs Batfish on every single-fault injection.

Usage:  python -m benchmark.differential_verifier [--out benchmark/results/differential.json]

For each fault template x location, both verifiers evaluate the faulty network against the
intent set. The output records, per case, the violated intents reported by each backend and
whether they agree. This quantifies the fidelity of the local model instead of assuming it.
Requires a running Batfish service.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from benchmark.faults import TEMPLATES, bgp_pairs, fabric_links, lan_of  # noqa: E402
from core.inventory import load_testbed  # noqa: E402
from core.patch_ops import apply_plan  # noqa: E402
from core.verification import make_verifier  # noqa: E402


def enumerate_single_faults(tb):
    net, topo = tb.network, tb.topology
    out = []
    for a, ai, b, bi in fabric_links(topo):
        for dev, intf in ((a, ai), (b, bi)):
            for t in ("iface_shutdown", "mtu_mismatch", "duplex_mismatch", "speed_mismatch", "acl_block_bgp", "acl_transit_deny"):
                out.append(TEMPLATES[t](net, topo, dev=dev, intf=intf))
    for dev, nbr in bgp_pairs(net):
        for t in ("remote_as_mismatch", "md5_unilateral", "neighbor_deactivated", "route_map_drop"):
            out.append(TEMPLATES[t](net, topo, dev=dev, nbr=nbr))
    for dev in sorted(net):
        if lan_of(net, topo, dev):
            out.append(TEMPLATES["missing_network"](net, topo, dev=dev))
        if "PERIMETER_SECURITY_POLICY" in net[dev].acls:
            for t in ("acl_deny_lan", "acl_supernet_deny"):
                out.append(TEMPLATES[t](net, topo, dev=dev))
            for port in (80, 443):
                out.append(TEMPLATES["acl_deny_service"](net, topo, dev=dev, port=port))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "benchmark" / "results" / "differential_local_vs_batfish.json"))
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()
    logging.disable(logging.WARNING)
    tb = load_testbed()
    local = make_verifier("local", tb.topology)
    bf = make_verifier("batfish", tb.topology)
    faults = enumerate_single_faults(tb)
    if args.limit:
        faults = faults[: args.limit]
    rows = []
    for k, f in enumerate(faults, 1):
        faulty = apply_plan(tb.network, f.inject)
        t0 = time.perf_counter(); rl = local.verify(faulty, tb.intents); tl = time.perf_counter() - t0
        t0 = time.perf_counter(); rb = bf.verify(faulty, tb.intents); tb_s = time.perf_counter() - t0
        vl, vb = rl.violated(), rb.violated()
        rows.append({"template": f.template, "location": f.location, "category": f.category,
                     "local_violated": vl, "batfish_violated": vb, "agree": vl == vb,
                     "only_local": sorted(set(vl) - set(vb)), "only_batfish": sorted(set(vb) - set(vl)),
                     "batfish_parse_issues": rb.parse_issues, "local_ms": round(tl * 1000, 1),
                     "batfish_ms": round(tb_s * 1000, 1)})
        print(f"[{k:3d}/{len(faults)}] {f.template:22s} {f.location:28s} agree={vl == vb} "
              f"only_local={rows[-1]['only_local']} only_batfish={rows[-1]['only_batfish']}", flush=True)
    summary = {"cases": len(rows), "agree": sum(r["agree"] for r in rows),
               "by_template": {}}
    for r in rows:
        s = summary["by_template"].setdefault(r["template"], {"cases": 0, "agree": 0})
        s["cases"] += 1; s["agree"] += r["agree"]
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps({"summary": summary, "rows": rows}, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
