"""Master Unified Execution and Verification Engine for Neurosymbolic NetOps.

Executes:
1. Base Benchmark Suite (15 core scenarios across LINK, BGP, ACL)
2. Advanced Stress Suite (10 scenarios: 5 Multi-Fault k>=3, 5 Noisy Telemetry)
3. Aggregates 25 total scenarios to evaluation/extended_benchmark_metrics.csv
4. Regenerates publication-ready figures and BENCHMARK_RESULTS.md
5. Provides command-line dashboard launcher.
"""

import sys
import json
import time
from pathlib import Path
from typing import Dict, Any, List
import pandas as pd

# Add repository root to path
root_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(root_dir))

from agent.orchestrator import AutonomousNetOpsOrchestrator
from evaluation.generate_report import main as generate_report_main


def run_master_suite():
    dataset_base = root_dir / "dataset" / "ground_truth_faults.json"
    dataset_stress = root_dir / "dataset" / "advanced_stress_faults.json"
    metadata_file = root_dir / "configs" / "testbed_metadata.json"
    output_csv = root_dir / "evaluation" / "extended_benchmark_metrics.csv"
    traces_file = root_dir / "evaluation" / "extended_execution_traces.json"

    base_scenarios: List[Dict[str, Any]] = json.loads(dataset_base.read_text(encoding="utf-8")) if dataset_base.exists() else []
    stress_scenarios: List[Dict[str, Any]] = json.loads(dataset_stress.read_text(encoding="utf-8")) if dataset_stress.exists() else []

    all_scenarios = base_scenarios + stress_scenarios
    print("================================================================================")
    print(f"MASTER SUITE EXECUTION: {len(all_scenarios)} SCENARIOS (15 BASE + 10 ADVANCED STRESS)")
    print("================================================================================\n")

    orchestrator = AutonomousNetOpsOrchestrator(metadata_file)
    results = []
    traces = []

    for idx, sc in enumerate(all_scenarios, 1):
        iid = sc["incident_id"]
        cat = sc["fault_category"]
        desc = sc["description"]
        print(f"[{idx:02d}/{len(all_scenarios):02d}] Evaluating {iid} ({cat}): {desc}...")

        # 1. Baseline Direct (Bypassed safety gate)
        res_baseline = orchestrator.process_incident(sc, enable_symbolic_gate=False)

        # 2. Closed-Loop Neurosymbolic (Batfish formal safety gate with up to 5 reflection attempts)
        res_neuro = orchestrator.process_incident(sc, enable_symbolic_gate=True, max_reflection_turns=5)

        traces.append({
            "incident_id": iid,
            "category": cat,
            "description": desc,
            "baseline": res_baseline,
            "neurosymbolic": res_neuro
        })

        row = {
            "incident_id": iid,
            "fault_category": cat,
            "description": desc,
            "ground_truth_culprit": sc.get("ground_truth_culprit_device", "Multi-Device"),
            "identified_culprit": res_neuro["identified_culprit"],
            "localization_correct": res_neuro["culprit_localized"],
            "baseline_repaired": res_baseline["repair_successful"],
            "neurosymbolic_repaired": res_neuro["repair_successful"],
            "invariant_violations_caught": res_neuro["invariant_violations_caught"],
            "reflection_turns": res_neuro["reflection_turns"],
            "watchdog_rollback": res_neuro["watchdog_rollback"],
            "token_reduction_pct": res_neuro["token_reduction_pct"],
            "prompt_tokens": res_neuro["prompt_tokens"],
            "completion_tokens": res_neuro["completion_tokens"],
            "latency_ms": res_neuro["total_latency_ms"]
        }
        results.append(row)

        print(f"   -> Loc: {'OK' if row['localization_correct'] else 'FAIL'} | "
              f"Baseline: {'PASS' if row['baseline_repaired'] else 'FAIL'} | "
              f"Neurosymbolic: {'PASS' if row['neurosymbolic_repaired'] else 'FAIL'} (Turns: {row['reflection_turns']}) | "
              f"Latency: {row['latency_ms']:.1f}ms | Token Savings: {row['token_reduction_pct']}%")

    # Save to CSV
    df = pd.DataFrame(results)
    df.to_csv(output_csv, index=False)
    print(f"\nSaved extended benchmark metrics to: {output_csv}")

    # Save traces
    traces_file.write_text(json.dumps(traces, indent=2), encoding="utf-8")
    print(f"Saved complete execution traces to: {traces_file}")

    # Regenerate reports & charts
    print("\nRegenerating publication reports and charts...")
    generate_report_main()

    print("\n================================================================================")
    print("MASTER SUITE COMPLETED SUCCESSFULLY.")
    print("To launch the real-time Streamlit NetOps Dashboard, run:")
    print("    streamlit run neurosymbolic_netops/dashboard/app.py")
    print("================================================================================")
    return df


if __name__ == "__main__":
    run_master_suite()
