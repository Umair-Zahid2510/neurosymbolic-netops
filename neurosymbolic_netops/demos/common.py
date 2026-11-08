"""Shared narration for the end-to-end demonstrations."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
logging.disable(logging.WARNING)


def cli(description: str):
    ap = argparse.ArgumentParser(description=description)
    ap.add_argument("--reasoning", choices=["rule_based", "llm", "offline"], default="rule_based",
                    help="rule_based (default), llm (needs API key), offline (replay of recorded LLM calls)")
    ap.add_argument("--verifier", choices=["local", "batfish"], default="local",
                    help="local symbolic model (default) or a running Batfish service")
    ap.add_argument("--approval", choices=["auto_verified_simulation", "human", "deny"], default="auto_verified_simulation",
                    help="demos use the SIMULATED adapter; pass 'human' to approve interactively")
    ap.add_argument("--save", default=None, help="write the full incident record as JSON")
    ap.add_argument("--no-tools", action="store_true", help="LLM gets configs in the prompt instead of tool access (fewer calls)")
    ap.add_argument("--model", default=None, help="override NETOPS_LLM_MODEL")
    ap.add_argument("--record", action="store_true", help="record LLM exchanges to runtime/llm_cassette.json for offline replay")
    args = ap.parse_args()
    if args.model:
        import os
        os.environ["NETOPS_LLM_MODEL"] = args.model
    return args


def provider_for(mode: str, record: bool = False):
    if mode == "rule_based":
        return None
    from agent.llm.base import provider_from_env
    p = provider_from_env(mode)
    if record and mode == "llm":
        from agent.llm.replay import RecordingProvider
        p = RecordingProvider(inner=p)
    return p


def hr(title: str) -> None:
    print("\n" + "=" * 100 + f"\n{title}\n" + "=" * 100)


def narrate(run, tb, faults) -> None:
    r = run.record
    hr(f"INCIDENT {r.incident_id}")
    print("Components:", json.dumps(r.modes))
    print("Injected ground truth (hidden from the agents):")
    for f in faults:
        print(f"   - [{f.category}] {f.description}")
    hr("TIER 1  Telemetry -> edge detection -> anomaly digest")
    print(f"raw telemetry {run.raw_bytes} bytes -> digest {run.digest_bytes} bytes; detection {run.detection_ms} ms")
    for a in r.digest["anomalies"]:
        print(f"   {a['anomaly_id']} {a['kind']:18s} dev={a['device']} intf={a['interface']} peer={a['peer_ip']} "
              f"x{a['count']} via {a['detector']}: {a['summary'][:80]}")
    if r.digest["missing_data"]:
        print("   MISSING DATA:", r.digest["missing_data"])
    print("Topology-ranked candidates:", [(c["device"], c["score"]) for c in r.candidates])
    print("Intents violated at detection:", r.initially_violated)
    hr("TIER 2  Diagnosis (read-only skills)")
    for d in r.diagnoses:
        print(f"[{d.strategy}] {d.reasoning_summary}")
        for h in d.hypotheses[:8]:
            print(f"   {h.id}: {h.device} {h.fault_type} @ {h.location} :: {h.statement}  evidence={h.evidence[:3]}")
    print(f"skill calls: {len(r.tool_calls)}; first five: " +
          ", ".join(f"{c.call_id}:{c.skill}({','.join(f'{k}={v}' for k, v in c.args.items())})" for c in r.tool_calls[:5]))
    hr("TIER 2/3  Planning <-> symbolic verification (reflection loop)")
    for a in r.attempts:
        print(f"Attempt {a.attempt} [{a.strategy}] -> {a.disposition.upper()}  (verifier: {a.verification_backends}, {a.verify_ms} ms)")
        for line in (a.plan.describe() if a.plan else [a.plan_error or "no plan"]):
            print(f"      op: {line}")
        if a.disposition != "accepted":
            print(f"      violated after: {a.violated_after}   NEW violations: {a.new_violations}")
            for ce in a.counterexamples[:4]:
                print(f"      counterexample: {ce}")
    if r.final_plan:
        print("Final verified plan:", r.final_plan.describe(), "| final verification:", r.final_verification)
        print("Approval:", r.approval_decision, "| token for plan", r.approval.plan_hash[:12] if r.approval else None)
    if r.transaction:
        hr("TIER 4  Transactional actuation")
        tx = r.transaction
        print(f"{tx.tx_id} adapter={tx.adapter}/{tx.adapter_label} status={tx.status} failure={tx.failure}")
        for s in tx.steps:
            print(f"   {'OK ' if s.ok else 'ERR'} {s.step:24s} {s.detail[:90]}")
        if tx.diff:
            print("Configuration diff (IOS rendering):")
            print("\n".join("      " + l for l in tx.diff.splitlines()[:30]))
    hr(f"OUTCOME: {r.outcome}   final state: {r.state.value}")
    print("State path:", " -> ".join(["DETECTED"] + [t.to.value for t in r.transitions]))
    print(f"Timings (ms): {r.timings_ms}; audit chain verified: {run.audit_ok} ({run.audit_entries} entries)")
    if r.llm_usage:
        print("LLM usage:", r.llm_usage.model_dump())


def save(run, path):
    if path:
        Path(path).write_text(run.record.model_dump_json(indent=1), encoding="utf-8")
        print("record saved to", path)
