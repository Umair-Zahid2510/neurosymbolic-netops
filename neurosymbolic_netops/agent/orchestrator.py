"""Closed-Loop Autonomous NetOps Orchestrator.

Orchestrates the 4-tier pipeline:
1. Tier-1: Causal Topology Graph search space pruning
2. Tier-2: SADE Skill-Decomposed Cognitive Diagnostic Agent
3. Tier-3: Batfish Formal Symbolic Safety Gate & Reflection Loop
4. Tier-4: Transactional Two-Phase Actuator & Watchdog Rollback
"""

import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from core.causal_topology import CausalTopologyGraph
from core.batfish_verifier import BatfishVerifier
from core.transactional_actuator import TransactionalActuator
from agent.llm_interface import LLMDiagnosticInterface
from core.intent_schema import AgentDiagnosticOutput, ConfigurationPatch


class AutonomousNetOpsOrchestrator:
    """End-to-end closed-loop orchestrator for network fault diagnosis and remediation."""

    def __init__(self, metadata_path: Path):
        self.topology = CausalTopologyGraph(metadata_path)
        self.verifier = BatfishVerifier()
        self.actuator = TransactionalActuator(self.verifier)
        self.agent = LLMDiagnosticInterface()

    def process_incident(
        self,
        incident: Dict[str, Any],
        enable_symbolic_gate: bool = True,
        max_reflection_turns: int = 3
    ) -> Dict[str, Any]:
        """Processes a single incident scenario through the closed-loop pipeline."""
        start_time = time.time()
        incident_id = incident["incident_id"]
        fault_category = incident["fault_category"]
        telemetry_logs = incident["telemetry_logs"]
        initial_configs = dict(incident["corrupted_configs"])
        ground_truth_culprit = incident["ground_truth_culprit_device"]

        execution_trace = {
            "incident_id": incident_id,
            "fault_category": fault_category,
            "telemetry_logs": telemetry_logs,
            "turns": []
        }

        # TIER 1: Structural Causal Graph Pruning
        t1_start = time.time()
        pruned_configs, pruning_metrics = self.topology.prune_search_space(telemetry_logs, initial_configs)
        t1_latency = (time.time() - t1_start) * 1000

        # TIER 2 & TIER 3: Diagnostic Reasoning & Symbolic Verification Loop
        reflection_turn = 0
        current_feedback = None
        final_diagnostic: Optional[AgentDiagnosticOutput] = None
        verified_patch: Optional[ConfigurationPatch] = None
        verification_passed = False
        invariant_violations_caught = 0
        prompt_tokens_total = 0
        completion_tokens_total = 0

        candidate_snapshot = dict(initial_configs)
        applied_patches: List[ConfigurationPatch] = []

        # Initialize violation count from baseline snapshot
        init_v = self.verifier.verify_network_snapshot(initial_configs)
        last_violation_count = len(init_v.counterexamples) if init_v.counterexamples else 99
        current_counterexamples = set(init_v.counterexamples) if init_v.counterexamples else set()

        while reflection_turn <= (max_reflection_turns if enable_symbolic_gate else 0):
            reflection_turn += 1
            turn_start = time.time()

            # Current view of pruned configs with accumulated changes
            pruned_live_configs = {d: candidate_snapshot[d] for d in pruned_configs.keys() if d in candidate_snapshot}

            # Token estimation for turn
            prompt_chars = sum(len(c) for c in pruned_live_configs.values()) + sum(len(l) for l in telemetry_logs)
            if current_feedback:
                prompt_chars += len(current_feedback)
            turn_prompt_tokens = prompt_chars // 4
            prompt_tokens_total += turn_prompt_tokens

            # Tier 2 Reasoning
            diagnostic = self.agent.diagnose_and_plan(
                incident_id=incident_id,
                telemetry_logs=telemetry_logs,
                pruned_configs=pruned_live_configs,
                reflection_feedback=current_feedback,
                turn_number=reflection_turn
            )
            final_diagnostic = diagnostic

            completion_chars = len(diagnostic.model_dump_json())
            turn_completion_tokens = completion_chars // 4
            completion_tokens_total += turn_completion_tokens

            turn_info = {
                "turn": reflection_turn,
                "diagnostic_output": diagnostic.model_dump(),
                "reflection_feedback": current_feedback
            }

            if not enable_symbolic_gate:
                # Baseline mode: No symbolic safety gate reflection
                verified_patch = diagnostic.proposed_patch
                applied_patches.append(diagnostic.proposed_patch)
                verification_passed = True
                turn_info["symbolic_check"] = "BYPASSED_BASELINE"
                execution_trace["turns"].append(turn_info)
                break

            # Tier 3: Symbolic Invariant Verification on isolated test snapshot
            staged_candidate = self.actuator.apply_commands(
                candidate_snapshot[diagnostic.proposed_patch.target_device],
                diagnostic.proposed_patch.command_block
            )
            test_snapshot = dict(candidate_snapshot)
            test_snapshot[diagnostic.proposed_patch.target_device] = staged_candidate

            v_result = self.verifier.verify_network_snapshot(test_snapshot)
            turn_info["symbolic_check"] = v_result.to_dict()

            if v_result.passed:
                verification_passed = True
                verified_patch = diagnostic.proposed_patch
                candidate_snapshot = test_snapshot
                applied_patches.append(diagnostic.proposed_patch)
                execution_trace["turns"].append(turn_info)
                break
            else:
                invariant_violations_caught += 1
                current_feedback = self.verifier.format_reflection_prompt(v_result, diagnostic.proposed_patch)
                turn_info["rejection_trace"] = v_result.counterexamples
                execution_trace["turns"].append(turn_info)

                # Safe partial progress adoption when fixing multi-layer faults unmasks deeper invariants
                has_security_violation = any("Security invariant violation" in c for c in v_result.counterexamples)
                resolved_previous = bool(current_counterexamples - set(v_result.counterexamples))
                if not has_security_violation and (resolved_previous or len(v_result.counterexamples) < last_violation_count):
                    candidate_snapshot = test_snapshot
                    applied_patches.append(diagnostic.proposed_patch)
                    current_counterexamples = set(v_result.counterexamples)
                    last_violation_count = len(v_result.counterexamples)

        # TIER 4: Transactional Actuator & Sliding-Window Watchdog Rollback
        t4_start = time.time()
        actuation_result = None
        if verification_passed and applied_patches:
            if not enable_symbolic_gate:
                # Baseline directly attempts single patch on initial config
                actuation_result = self.actuator.execute_transaction(initial_configs, applied_patches[0])
            else:
                # Neurosymbolic commit confirmed across sliding window for full candidate snapshot
                final_target = applied_patches[-1].target_device
                actuation_result = self.actuator.execute_snapshot_transaction(
                    current_configs=initial_configs,
                    staged_configs=candidate_snapshot,
                    target_device=final_target
                )
        else:
            actuation_result = {
                "status": "ABORTED_UNVERIFIED",
                "watchdog_rollback": False,
                "latency_ms": 0.0,
                "checkpoints": {"PRE_CHANGE_STATE": None, "STAGED_STATE": None, "POST_VALIDATION_STATUS": "ABORTED"}
            }
        t4_latency = (time.time() - t4_start) * 1000

        total_latency_ms = (time.time() - start_time) * 1000

        # Evaluation metrics for incident
        ground_truth_culprits = incident.get("ground_truth_culprits", [ground_truth_culprit])
        culprit_localized = (final_diagnostic.identified_culprit_device in ground_truth_culprits) if final_diagnostic else False
        repair_successful = (actuation_result.get("status") == "COMMIT_CONFIRMED")

        return {
            "incident_id": incident_id,
            "fault_category": fault_category,
            "culprit_localized": culprit_localized,
            "identified_culprit": final_diagnostic.identified_culprit_device if final_diagnostic else None,
            "ground_truth_culprit": ground_truth_culprit,
            "verification_passed": verification_passed,
            "repair_successful": repair_successful,
            "reflection_turns": reflection_turn,
            "invariant_violations_caught": invariant_violations_caught,
            "watchdog_rollback": actuation_result.get("watchdog_rollback", False),
            "actuation_status": actuation_result.get("status"),
            "token_reduction_pct": pruning_metrics["token_reduction_pct"],
            "prompt_tokens": prompt_tokens_total,
            "completion_tokens": completion_tokens_total,
            "total_latency_ms": round(total_latency_ms, 2),
            "execution_trace": execution_trace
        }
