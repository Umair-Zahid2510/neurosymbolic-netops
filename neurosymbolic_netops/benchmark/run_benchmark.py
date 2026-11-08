"""Benchmark runner: experimental conditions x scenarios x trials -> raw JSONL + summary.

Usage:
  python -m benchmark.run_benchmark --conditions C1,C1b,C1c --splits dev,test,legacy
  python -m benchmark.run_benchmark --conditions C2,C3,C4,C5 --splits test --trials 3   # needs an LLM key
  python -m benchmark.run_benchmark --oracle batfish ...   # independent final-state check (slow)

Conditions
  C1   rule_based, no verification gate           (deterministic baseline)
  C1b  rule_based + verification gate
  C1c  rule_based + gate + deployment-fault injection (1/3 apply-fail, 1/3 timeout)
  C2   LLM-only: no tools (configs in prompt), no gate
  C3   LLM + read-only tools, no gate
  C4   LLM + tools + verification gate + reflection   (neurosymbolic)
  C5   C4 + deployment-fault injection               (full closed loop)
Conditions without a gate still run the transaction engine, whose post-check can roll back an
unsafe change *after* it was deployed; that exposure is reported as ``unsafe_deployed``.
"""

from __future__ import annotations

import argparse
import json
import logging
import platform
import random
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.orchestrator import SystemConfig, run_incident  # noqa: E402
from benchmark.generator import SCENARIO_DIR, Scenario, load_suite  # noqa: E402
from core.actuation.adapters import FaultInjection  # noqa: E402
from core.config_ir import network_fingerprint  # noqa: E402
from core.inventory import load_testbed  # noqa: E402
from core.telemetry.anomaly import EdgeDetector, load_or_train  # noqa: E402
from core.telemetry.generator import GeneratorOptions  # noqa: E402
from core.verification import make_verifier  # noqa: E402

CONDITIONS = {
    "C1": dict(reasoning="rule_based", verifier="none"),
    "C1b": dict(reasoning="rule_based", verifier="local"),
    "C1c": dict(reasoning="rule_based", verifier="local", deploy_faults=True),
    "C2": dict(reasoning="llm", llm_tools=False, verifier="none"),
    "C3": dict(reasoning="llm", llm_tools=True, verifier="none"),
    "C4": dict(reasoning="llm", llm_tools=True, verifier="local"),
    "C5": dict(reasoning="llm", llm_tools=True, verifier="local", deploy_faults=True),
}


def deploy_faults(sc: Scenario, k: int) -> FaultInjection:
    if k % 3 == 0:
        return FaultInjection(fail_apply_on=set(sc.culprits))
    if k % 3 == 1:
        return FaultInjection(timeout_on=set(sc.culprits))
    return FaultInjection()


def metrics_for(sc: Scenario, run, base_fp: str, oracle, intents) -> Dict:
    r = run.record
    first = r.diagnoses[0].hypotheses if r.diagnoses else []
    all_h = [h for d in r.diagnoses for h in d.hypotheses]
    truth = set(sc.culprits)
    pred = {h.device for h in all_h}
    tp = len(pred & truth)
    prec = tp / len(pred) if pred else 0.0
    rec_ = tp / len(truth) if truth else 0.0
    f1 = 2 * prec * rec_ / (prec + rec_) if prec + rec_ else 0.0
    fault_hits = [any(h.device == f.culprit and (h.category == f.category or f.category == "ROUTING" and h.category in ("ROUTING", "BGP"))
                      for h in all_h) for f in sc.faults]
    tx = r.transaction
    final = run.final_network
    oracle_rep = oracle.verify(final, intents) if final is not None else None
    post_fail = bool(tx and any(s.step == "post_check" and not s.ok for s in tx.steps))
    return {
        "top1": bool(first and first[0].device in truth),
        "top3": bool({h.device for h in first[:3]} & truth),
        "precision": round(prec, 4), "recall": round(rec_, 4), "f1": round(f1, 4),
        "fault_recall": round(sum(fault_hits) / len(fault_hits), 4) if fault_hits else None,
        "n_hypotheses": len(first),
        "outcome": r.outcome,
        "repaired": r.outcome == "repaired",
        "final_intents_satisfied": bool(oracle_rep and oracle_rep.passed),
        "final_violations": oracle_rep.violated() if oracle_rep else None,
        "restored_to_baseline": bool(final is not None and network_fingerprint(final) == base_fp),
        "attempts": len(r.attempts),
        "gate_rejections": sum(a.disposition == "rejected" for a in r.attempts),
        "partial_adoptions": sum(a.disposition == "adopted_partial_progress" for a in r.attempts),
        "invalid_plans": sum(a.disposition == "invalid_plan" for a in r.attempts),
        "tx_status": tx.status if tx else None,
        "unsafe_deployed": bool(tx and tx.applied_devices and post_fail),
        "rolled_back": bool(tx and tx.status == "ROLLED_BACK"),
        "restore_verified": tx.restore_verified if tx else None,
        "tool_calls": len(r.tool_calls),
        "llm_calls": r.llm_usage.calls if r.llm_usage else 0,
        "prompt_tokens": r.llm_usage.prompt_tokens if r.llm_usage else 0,
        "completion_tokens": r.llm_usage.completion_tokens if r.llm_usage else 0,
        "llm_latency_ms": r.llm_usage.latency_ms if r.llm_usage else 0.0,
        "token_source": r.llm_usage.source if r.llm_usage else None,
        "invalid_llm_responses": r.llm_usage.invalid_responses if r.llm_usage else 0,
        "detection_ms": run.detection_ms, "raw_bytes": run.raw_bytes, "digest_bytes": run.digest_bytes,
        **{f"{k}_ms": v for k, v in r.timings_ms.items()},
        "audit_ok": run.audit_ok,
    }


def bootstrap_ci(values: List[float], n: int = 1000, seed: int = 0):
    if not values:
        return None
    rng = random.Random(seed)
    means = sorted(statistics.fmean(rng.choices(values, k=len(values))) for _ in range(n))
    return [round(means[int(0.025 * n)], 4), round(means[int(0.975 * n) - 1], 4)]


def summarize(rows: List[Dict]) -> Dict:
    out: Dict = {}
    keys = sorted({(r["condition"], r["split"]) for r in rows})
    for cond, split in keys:
        rs = [r for r in rows if r["condition"] == cond and r["split"] == split]
        m = [r["metrics"] for r in rs]
        rate = lambda k: [1.0 if x[k] else 0.0 for x in m if x[k] is not None]
        mean = lambda k: [x[k] for x in m if x.get(k) is not None]
        s = {"runs": len(rs)}
        for k in ("top1", "top3", "repaired", "final_intents_satisfied", "restored_to_baseline", "unsafe_deployed", "rolled_back"):
            v = rate(k)
            s[k] = {"mean": round(statistics.fmean(v), 4) if v else None, "ci95": bootstrap_ci(v)}
        for k in ("precision", "recall", "f1", "fault_recall"):
            v = mean(k)
            s[k] = {"mean": round(statistics.fmean(v), 4) if v else None, "ci95": bootstrap_ci(v)}
        for k in ("attempts", "gate_rejections", "tool_calls", "llm_calls", "prompt_tokens", "completion_tokens",
                  "total_ms", "detection_ms", "diagnose_ms", "plan_ms", "verify_ms", "execute_ms", "llm_latency_ms"):
            v = mean(k)
            s[k] = {"mean": round(statistics.fmean(v), 2), "median": round(statistics.median(v), 2)} if v else None
        rb = [x for x in m if x["rolled_back"]]
        s["rollback_restore_verified"] = f"{sum(1 for x in rb if x['restore_verified'])}/{len(rb)}"
        s["outcomes"] = {o: sum(1 for x in m if x["outcome"] == o) for o in sorted({x["outcome"] for x in m})}
        out[f"{cond}/{split}"] = s
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--conditions", default="C1,C1b,C1c")
    ap.add_argument("--splits", default="dev,test,legacy")
    ap.add_argument("--trials", type=int, default=1)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--oracle", choices=["local", "batfish"], default="local")
    ap.add_argument("--suite", default=str(SCENARIO_DIR / "suite_v1.json"))
    ap.add_argument("--out", default=str(ROOT / "benchmark" / "results"))
    args = ap.parse_args()
    logging.disable(logging.WARNING)

    tb = load_testbed()
    suite = [s for s in load_suite(Path(args.suite)) if s.split in args.splits.split(",")]
    if args.limit:
        suite = suite[: args.limit]
    detector = EdgeDetector(load_or_train())
    oracle = make_verifier(args.oracle, tb.topology)
    base_fp = network_fingerprint(tb.network)
    provider = None
    skipped = {}
    conds = args.conditions.split(",")
    if any(CONDITIONS[c]["reasoning"] == "llm" for c in conds):
        try:
            from agent.llm.base import provider_from_env
            provider = provider_from_env()
        except Exception as exc:  # explicit skip, never a silent substitute
            for c in conds:
                if CONDITIONS[c]["reasoning"] == "llm":
                    skipped[c] = f"skipped: {exc}"
            conds = [c for c in conds if c not in skipped]

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path(args.out) / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_path = out_dir / "raw.jsonl"
    rows = []
    t_start = time.time()
    with raw_path.open("w", encoding="utf-8") as fh:
        for cond in conds:
            spec = CONDITIONS[cond]
            trials = args.trials if spec["reasoning"] == "llm" else 1  # rule-based is deterministic
            for trial in range(trials):
                for k, sc in enumerate(suite):
                    cfg = SystemConfig(reasoning=spec["reasoning"], llm_tools=spec.get("llm_tools", True),
                                       verifier=spec["verifier"], llm_provider=provider,
                                       adapter_faults=deploy_faults(sc, k) if spec.get("deploy_faults") else FaultInjection())
                    t = sc.telemetry
                    opts = GeneratorOptions(seed=t.seed + 7919 * trial, noise_rate=t.noise_rate, decoys=t.decoys,
                                            duplicate_prob=t.duplicate_prob, missing_ts_prob=t.missing_ts_prob,
                                            line_drop_prob=t.line_drop_prob, dropout_devices=t.dropout_devices,
                                            held_out_phrasing=t.held_out_phrasing)
                    try:
                        run = run_incident(tb, sc.scenario_id, sc.faulty_network(tb.network), cfg, opts, detector)
                        m = metrics_for(sc, run, base_fp, oracle, tb.intents)
                        err = None
                    except Exception as exc:  # recorded, never hidden
                        m, err, run = None, f"{type(exc).__name__}: {exc}", None
                    row = {"condition": cond, "trial": trial, "scenario_id": sc.scenario_id, "split": sc.split,
                           "category": sc.category, "telemetry": t.condition, "culprits": sc.culprits,
                           "metrics": m, "error": err,
                           "record": run.record.model_dump(mode="json") if run else None}
                    fh.write(json.dumps(row, default=str) + "\n")
                    if m:
                        rows.append(row)
                    print(f"[{cond} t{trial}] {sc.scenario_id:60s} {m['outcome'] if m else 'ERROR ' + err}", flush=True)
    summary = summarize(rows)
    try:
        sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except Exception:
        sha = "unknown"
    manifest = {"run_id": run_id, "git_sha": sha, "conditions": conds, "skipped": skipped, "splits": args.splits,
                "trials": args.trials, "oracle": args.oracle, "scenarios": len(suite), "python": platform.python_version(),
                "llm": {"provider": provider.provider, "model": provider.model, "source": provider.source} if provider else None,
                "errors": sum(1 for _ in open(raw_path, encoding="utf-8")) - len(rows),
                "wall_seconds": round(time.time() - t_start, 1)}
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
