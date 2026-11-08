"""Tier-4 Transactional Actuator & Rollback Watchdog.

Implements two-phase commit emulation (Prepare -> Commit Confirmed),
synthetic post-validation data-plane probing, and instant auto-rollback on failure.
"""

import time
import re
from typing import Dict, Any, Tuple
from core.intent_schema import ConfigurationPatch
from core.batfish_verifier import BatfishVerifier


class TransactionalActuator:
    """Manages transactional patch execution, watchdog timers, and rollbacks."""

    def __init__(self, verifier: BatfishVerifier):
        self.verifier = verifier

    def apply_commands(self, config_text: str, command_block: str) -> str:
        """Applies configuration patch commands to a Cisco IOS / FRR configuration string."""
        updated = config_text
        commands = [cmd.strip() for cmd in command_block.splitlines() if cmd.strip() and not cmd.strip().startswith("!")]

        for cmd in commands:
            # 1. Interface shutdown / no shutdown
            if cmd == "no shutdown":
                updated = re.sub(r"(\binterface\s+\S+\b.*?)\bshutdown\b", r"\1no shutdown", updated, flags=re.DOTALL)
            elif cmd == "shutdown":
                updated = re.sub(r"(\binterface\s+\S+\b.*?)\bno shutdown\b", r"\1shutdown", updated, flags=re.DOTALL)

            # 2. MTU changes
            m_mtu = re.match(r"^mtu\s+(\d+)", cmd)
            if m_mtu:
                new_mtu = m_mtu.group(1)
                updated = re.sub(r"\bmtu\s+\d+\b", f"mtu {new_mtu}", updated)

            # 3. Speed / Duplex
            m_speed = re.match(r"^speed\s+(\S+)", cmd)
            if m_speed:
                new_speed = m_speed.group(1)
                updated = re.sub(r"\bspeed\s+\S+\b", f"speed {new_speed}", updated)
            m_duplex = re.match(r"^duplex\s+(\S+)", cmd)
            if m_duplex:
                new_duplex = m_duplex.group(1)
                updated = re.sub(r"\bduplex\s+\S+\b", f"duplex {new_duplex}", updated)

            # 4. Remote AS corrections
            m_remote = re.match(r"^neighbor\s+(\S+)\s+remote-as\s+(\d+)", cmd)
            if m_remote:
                peer = m_remote.group(1)
                asn = m_remote.group(2)
                updated = re.sub(rf"neighbor\s+{re.escape(peer)}\s+remote-as\s+\d+", f"neighbor {peer} remote-as {asn}", updated)

            # 5. Remove password / Remove route-map / Remove ACL group
            if cmd.startswith("no neighbor") and "password" in cmd:
                peer = re.search(r"no neighbor\s+(\S+)\s+password", cmd).group(1)
                updated = re.sub(rf"\s*neighbor\s+{re.escape(peer)}\s+password\s+\S+", "", updated)
            elif cmd.startswith("no neighbor") and "route-map" in cmd:
                peer = re.search(r"no neighbor\s+(\S+)\s+route-map", cmd).group(1)
                updated = re.sub(rf"\s*neighbor\s+{re.escape(peer)}\s+route-map\s+\S+\s+(?:in|out)", "", updated)
            elif cmd.startswith("no ip access-group"):
                updated = re.sub(r"\s*ip access-group\s+\S+\s+(?:in|out)", "", updated)

            # 6. BGP activate
            m_act = re.match(r"^neighbor\s+(\S+)\s+activate", cmd)
            if m_act:
                peer = m_act.group(1)
                updated = re.sub(rf"\s*no\s+neighbor\s+{re.escape(peer)}\s+activate", f"\n neighbor {peer} activate", updated)

            # 7. Add BGP network statement
            if cmd.startswith("network "):
                if "router bgp" in updated and cmd not in updated:
                    updated = re.sub(r"(router bgp\s+\d+.*?\n)", rf"\1 {cmd}\n", updated)

            # 8. ACL rule additions / removals
            if cmd.startswith("no deny ") or cmd.startswith("no permit "):
                target_rule = cmd[3:].strip()
                updated = re.sub(rf"^[ \t]*{re.escape(target_rule)}[^\n]*\n?", "", updated, flags=re.MULTILINE)
            elif cmd.startswith("deny ") or cmd.startswith("permit "):
                if "ip access-list extended" in updated and cmd not in updated:
                    updated = re.sub(r"(ip access-list extended\s+\S+.*?\n)", rf"\1 {cmd}\n", updated)

        return updated

    def execute_snapshot_transaction(
        self,
        current_configs: Dict[str, str],
        staged_configs: Dict[str, str],
        target_device: str,
        window_samples: int = 3,
        sample_interval_ms: int = 10
    ) -> Dict[str, Any]:
        """Executes sliding-window validation on a candidate snapshot with rollback to current_configs on failure."""
        start_time = time.time()
        target = target_device
        pre_change_state = {d: cfg for d, cfg in current_configs.items()}
        staged_state = staged_configs.get(target, "")

        window_probe_results = []
        all_samples_passed = True
        first_failure_reason = None

        for sample_idx in range(window_samples):
            v_sample = self.verifier.verify_network_snapshot(staged_configs)
            sample_time_ms = round((time.time() - start_time) * 1000, 2)
            if v_sample.passed:
                window_probe_results.append({
                    "sample": sample_idx + 1,
                    "time_ms": sample_time_ms,
                    "packet_loss_pct": 0.0,
                    "bgp_status": "CONVERGED_STABLE",
                    "status": "PASS"
                })
            else:
                all_samples_passed = False
                first_failure_reason = v_sample.counterexamples
                window_probe_results.append({
                    "sample": sample_idx + 1,
                    "time_ms": sample_time_ms,
                    "packet_loss_pct": 100.0,
                    "bgp_status": "DEGRADED_UNSTABLE",
                    "status": "FAIL",
                    "counterexamples": v_sample.counterexamples
                })
                break
            if sample_idx < window_samples - 1 and sample_interval_ms > 0:
                time.sleep(sample_interval_ms / 1000.0)

        latency_ms = (time.time() - start_time) * 1000

        if all_samples_passed:
            return {
                "status": "COMMIT_CONFIRMED",
                "target_device": target,
                "packet_loss_pct": 0.0,
                "watchdog_rollback": False,
                "latency_ms": round(latency_ms, 2),
                "sliding_window_samples": window_probe_results,
                "configs": staged_configs,
                "probe_result": f"SUCCESS: Continuous reachability verified across {window_samples}-sample sliding window",
                "checkpoints": {
                    "PRE_CHANGE_STATE": pre_change_state.get(target),
                    "STAGED_STATE": staged_state,
                    "POST_VALIDATION_STATUS": "COMMIT_CONFIRMED (WATCHDOG_DISARMED)"
                }
            }
        else:
            return {
                "status": "WATCHDOG_ROLLED_BACK",
                "target_device": target,
                "packet_loss_pct": 100.0,
                "watchdog_rollback": True,
                "latency_ms": round(latency_ms, 2),
                "sliding_window_samples": window_probe_results,
                "configs": current_configs,
                "probe_result": f"FAIL: Probe failure during sliding window. Auto-rollback executed. Counterexamples: {first_failure_reason}",
                "checkpoints": {
                    "PRE_CHANGE_STATE": pre_change_state.get(target),
                    "STAGED_STATE": staged_state,
                    "POST_VALIDATION_STATUS": "WATCHDOG_ROLLED_BACK (RESTORED_PRE_CHANGE)"
                }
            }

    def execute_transaction(
        self,
        current_configs: Dict[str, str],
        patch: ConfigurationPatch,
        window_samples: int = 3,
        sample_interval_ms: int = 10
    ) -> Dict[str, Any]:
        """Executes a two-phase commit with sliding-window multi-sample validation and watchdog rollback."""
        target = patch.target_device
        if target not in current_configs:
            return {
                "status": "FAILED",
                "reason": f"Target device {target} not found in active topology",
                "configs": current_configs,
                "watchdog_rollback": False,
                "checkpoints": {
                    "PRE_CHANGE_STATE": None,
                    "STAGED_STATE": None,
                    "POST_VALIDATION_STATUS": "TARGET_NOT_FOUND"
                }
            }
        staged_configs = dict(current_configs)
        staged_configs[target] = self.apply_commands(current_configs[target], patch.command_block)
        return self.execute_snapshot_transaction(current_configs, staged_configs, target, window_samples, sample_interval_ms)

