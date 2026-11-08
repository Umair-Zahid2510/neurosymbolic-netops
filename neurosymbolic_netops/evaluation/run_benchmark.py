"""Empirical Benchmark Execution Engine for Neurosymbolic NetOps Framework.

Executes all 15 fault scenarios across both Baseline Direct and Closed-Loop
Neurosymbolic modes, logging real execution traces, arithmetic metrics,
and token/latency statistics.
"""

import json
import time
import sys
from pathlib import Path
from typing import Dict, Any, List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pandas as pd
from agent.orchestrator import AutonomousNetOpsOrchestrator


def run_full_benchmark():
    root_dir = Path(__file__).resolve().parent.parent
    dataset_file = root_dir / "dataset" / "ground_truth_faults.json"
    metadata_file = root_dir / "configs" / "testbed_metadata.json"
    output_csv = root_dir / "evaluation" / "benchmark_metrics.csv"
    traces_file = root_dir / "evaluation" / "execution_traces.json"

    if not dataset_file.exists():
        raise FileNotFoundError(f"Dataset file {dataset_file} not found. Run generate_benchmark_dataset.py first.")

    scenarios: List[Dict[str, Any]] = json.loads(dataset_file.read_text(encoding="utf-8"))
    orchestrator = AutonomousNetOpsOrchestrator(metadata_file)

    print(f"================================================================")
    print(f"STARTING EMPIRICAL BENCHMARK: {len(scenarios)} SCENARIOS ACROSS 3 FAULT TIERS")
    print(f"================================================================\n")

    benchmark_rows = []
    recorded_traces = []

    for idx, sc in enumerate(scenarios, 1):
        inc_id = sc["incident_id"]
        category = sc["fault_category"]
        desc = sc["description"]
        print(f"[{idx:02d}/{len(scenarios):02d}] Evaluating {inc_id} ({category}): {desc}...")

        # 1. Run Baseline Direct (Without Batfish Symbolic Safety Gate / Reflection)
        # In baseline, for complex scenarios with multi-line nuances (like ACL/BGP route-maps),
        # an unverified first-try patch may miss side-effects
        res_baseline = orchestrator.process_incident(sc, enable_symbolic_gate=False)

        # 2. Run Neurosymbolic Closed-Loop (With Batfish Safety Gate & Reflection Loop)
        res_neurosymbolic = orchestrator.process_incident(sc, enable_symbolic_gate=True, max_reflection_turns=3)

        # Save trace
        recorded_traces.append({
            "incident_id": inc_id,
            "category": category,
            "description": desc,
            "baseline": res_baseline,
            "neurosymbolic": res_neurosymbolic
        })

        row = {
            "incident_id": inc_id,
            "fault_category": category,
            "description": desc,
            "ground_truth_culprit": sc["ground_truth_culprit_device"],
            "identified_culprit": res_neurosymbolic["identified_culprit"],
            "localization_correct": res_neurosymbolic["culprit_localized"],
            "baseline_repaired": res_baseline["repair_successful"],
            "neurosymbolic_repaired": res_neurosymbolic["repair_successful"],
            "invariant_violations_caught": res_neurosymbolic["invariant_violations_caught"],
            "reflection_turns": res_neurosymbolic["reflection_turns"],
            "watchdog_rollback": res_neurosymbolic["watchdog_rollback"],
            "token_reduction_pct": res_neurosymbolic["token_reduction_pct"],
            "prompt_tokens": res_neurosymbolic["prompt_tokens"],
            "completion_tokens": res_neurosymbolic["completion_tokens"],
            "latency_ms": res_neurosymbolic["total_latency_ms"]
        }
        benchmark_rows.append(row)
        print(f"   -> Localization: {'OK' if row['localization_correct'] else 'FAIL'} | "
              f"Baseline: {'PASS' if row['baseline_repaired'] else 'FAIL'} | "
              f"Neurosymbolic: {'PASS' if row['neurosymbolic_repaired'] else 'FAIL'} | "
              f"Latency: {row['latency_ms']:.1f}ms | Token Savings: {row['token_reduction_pct']}%")

    # Save to CSV
    df = pd.DataFrame(benchmark_rows)
    df.to_csv(output_csv, index=False)
    print(f"\nSaved raw metrics to {output_csv}")

    # Save traces to JSON
    traces_file.write_text(json.dumps(recorded_traces, indent=2), encoding="utf-8")
    print(f"Saved complete execution traces to {traces_file}")

    return df, recorded_traces


if __name__ == "__main__":
    run_full_benchmark()
