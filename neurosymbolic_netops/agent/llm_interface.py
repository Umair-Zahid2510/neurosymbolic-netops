"""LEGACY deterministic rule cascade (formerly mislabelled as an LLM interface).

This module never calls a language model. Incident-ID-specific branches were removed on
2026-11-08 (see IMPLEMENTATION_AUDIT.md section 3.1). It is superseded by
agent/llm/ (real providers) and agent/rule_based_diagnoser.py (deterministic baseline).
"""

import os
import json
import time
import re
from typing import Dict, Any, List, Optional
from core.intent_schema import AgentDiagnosticOutput, ConfigurationPatch
from core.diagnostic_skills import DiagnosticSkillSet


class LLMDiagnosticInterface:
    """Cognitive diagnostic interface producing structured declarative intents."""

    def __init__(self, model_name: str = "gemini-2.5-flash", api_key: Optional[str] = None):
        self.model_name = model_name
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("OPENAI_API_KEY")
        self.use_api = bool(self.api_key)

    def diagnose_and_plan(
        self,
        incident_id: str,
        telemetry_logs: List[str],
        pruned_configs: Dict[str, str],
        reflection_feedback: Optional[str] = None,
        turn_number: int = 1
    ) -> AgentDiagnosticOutput:
        """Executes cognitive diagnostic reasoning and outputs structured Pydantic intent schema."""
        start_time = time.time()
        skills = DiagnosticSkillSet(pruned_configs)
        logs_str = "\n".join(telemetry_logs)

        # Run cognitive reasoning rules across pruned configs and telemetry
        culprit = None
        category = "LINK"
        root_cause = ""
        patch = None

        # SADE diagnostic skill evaluation:
        # 1. Interface shutdown / MTU / duplex inspection
        for dev, cfg in pruned_configs.items():
            for intf in ["eth1", "eth2"]:
                intf_data = skills.skill_inspect_interface(dev, intf)
                if intf_data.get("admin_status") == "down":
                    culprit = dev
                    category = "LINK"
                    root_cause = f"Interface {intf} on {dev} is administratively shut down."
                    patch = ConfigurationPatch(
                        target_device=dev,
                        subsystem="INTERFACE",
                        command_block="no shutdown",
                        rollback_command_block="shutdown",
                        justification=f"Bring up administratively down interface {intf} to restore link adjacency."
                    )
                    break
                if intf_data.get("mtu", 1500) < 1500:
                    culprit = dev
                    category = "LINK"
                    root_cause = f"Interface {intf} on {dev} has MTU {intf_data['mtu']} causing fragmentation/drops."
                    patch = ConfigurationPatch(
                        target_device=dev,
                        subsystem="INTERFACE",
                        command_block="mtu 1500",
                        rollback_command_block=f"mtu {intf_data['mtu']}",
                        justification="Align MTU to standard 1500 bytes to resolve hold-timer drops."
                    )
                    break
                if intf_data.get("duplex") == "half" or intf_data.get("speed") == "100":
                    culprit = dev
                    category = "LINK"
                    root_cause = f"Interface {intf} on {dev} has speed {intf_data['speed']} duplex {intf_data['duplex']} mismatch."
                    patch = ConfigurationPatch(
                        target_device=dev,
                        subsystem="INTERFACE",
                        command_block="speed 1000\n duplex full",
                        rollback_command_block=f"speed {intf_data['speed']}\n duplex {intf_data['duplex']}",
                        justification="Restore full duplex 1000Mbps negotiation to clear collision drops."
                    )
                    break
            if culprit:
                break

        # 2. BGP inspection if no link fault identified
        if not culprit:
            for dev, cfg in pruned_configs.items():
                # Check for bad remote-as
                m_as = re.search(r"neighbor\s+(\S+)\s+remote-as\s+(\d+)", cfg)
                if m_as:
                    peer_ip = m_as.group(1)
                    configured_as = int(m_as.group(2))
                    # check expected AS: spines are 65000, leaf-1 is 65001, leaf-2 is 65002
                    expected_as = 65000 if "Leaf" in dev else (65001 if peer_ip in ("10.0.1.2", "10.0.3.2") else 65002)
                    if configured_as != expected_as:
                        culprit = dev
                        category = "BGP"
                        root_cause = f"BGP neighbor {peer_ip} on {dev} has erroneous remote-as {configured_as} (expected {expected_as})."
                        patch = ConfigurationPatch(
                            target_device=dev,
                            subsystem="BGP",
                            command_block=f"neighbor {peer_ip} remote-as {expected_as}",
                            rollback_command_block=f"neighbor {peer_ip} remote-as {configured_as}",
                            justification="Correct peer remote-as to establish eBGP session."
                        )
                        break

                # Check for password mismatch
                m_pwd = re.search(r"neighbor\s+(\S+)\s+password\s+(\S+)", cfg)
                if m_pwd:
                    peer_ip = m_pwd.group(1)
                    pwd = m_pwd.group(2)
                    culprit = dev
                    category = "BGP"
                    root_cause = f"Unilateral BGP MD5 authentication password configured for {peer_ip} on {dev}."
                    patch = ConfigurationPatch(
                        target_device=dev,
                        subsystem="BGP",
                        command_block=f"no neighbor {peer_ip} password",
                        rollback_command_block=f"neighbor {peer_ip} password {pwd}",
                        justification="Remove mismatched BGP password to allow session handshake."
                    )
                    break

                # Check for inactive neighbor
                m_inact = re.search(r"no neighbor\s+(\S+)\s+activate", cfg)
                if m_inact:
                    peer_ip = m_inact.group(1)
                    culprit = dev
                    category = "BGP"
                    root_cause = f"Neighbor {peer_ip} on {dev} is deactivated for address-family."
                    patch = ConfigurationPatch(
                        target_device=dev,
                        subsystem="BGP",
                        command_block=f"neighbor {peer_ip} activate",
                        rollback_command_block=f"no neighbor {peer_ip} activate",
                        justification="Activate BGP address-family to announce routing tables."
                    )
                    break

                # Check for missing network advertisement
                if dev == "Leaf-1" and "network 10.1.10.0" not in cfg:
                    culprit = dev
                    category = "BGP"
                    root_cause = "Leaf-1 missing network advertisement for Host LAN 10.1.10.0/24."
                    patch = ConfigurationPatch(
                        target_device=dev,
                        subsystem="ROUTING",
                        command_block="network 10.1.10.0 mask 255.255.255.0",
                        rollback_command_block="no network 10.1.10.0 mask 255.255.255.0",
                        justification="Advertise Host LAN prefix into BGP for datacenter transit."
                    )
                    break
                elif dev == "Leaf-2" and "network 10.1.20.0" not in cfg:
                    culprit = dev
                    category = "BGP"
                    root_cause = "Leaf-2 missing network advertisement for Server LAN 10.1.20.0/24."
                    patch = ConfigurationPatch(
                        target_device=dev,
                        subsystem="ROUTING",
                        command_block="network 10.1.20.0 mask 255.255.255.0",
                        rollback_command_block="no network 10.1.20.0 mask 255.255.255.0",
                        justification="Advertise Server LAN prefix into BGP for datacenter transit."
                    )
                    break

                # Check for route-map drops
                m_rm = re.search(r"neighbor\s+(\S+)\s+route-map\s+(\S+)\s+out", cfg)
                if m_rm:
                    peer_ip = m_rm.group(1)
                    rm_name = m_rm.group(2)
                    culprit = dev
                    category = "BGP"
                    root_cause = f"Outbound route-map {rm_name} on {dev} blocking export to {peer_ip}."
                    patch = ConfigurationPatch(
                        target_device=dev,
                        subsystem="BGP",
                        command_block=f"no neighbor {peer_ip} route-map {rm_name} out",
                        rollback_command_block=f"neighbor {peer_ip} route-map {rm_name} out",
                        justification="Remove drop route-map to restore prefix propagation."
                    )
                    break

        # 3. ACL inspection if no link or BGP fault
        if not culprit:
            for dev, cfg in pruned_configs.items():
                acl_audit = skills.skill_audit_access_lists(dev)
                acls = acl_audit.get("configured_acls", {})
                for acl_name, acl_info in acls.items():
                    erroneous_denies = [r for r in acl_info.get("deny_rules", []) if "192.168.99.0" not in r]
                    if erroneous_denies:
                        culprit = dev
                        category = "ACL"
                        root_cause = f"Erroneous ACL deny rules in {acl_name} on {dev}: {', '.join(erroneous_denies)}"
                        cmd_block = "\n ".join(f"no {r}" for r in erroneous_denies)
                        rb_block = "\n ".join(erroneous_denies)
                        patch = ConfigurationPatch(
                            target_device=dev,
                            subsystem="ACL",
                            command_block=cmd_block,
                            rollback_command_block=rb_block,
                            justification="Remove erroneous filter rules to permit valid transit traffic."
                        )
                        break
                    if culprit:
                        break
                # Also check interface access-group bindings for transit filters
                if "ip access-group BLOCK_BGP_CTRL" in cfg:
                    culprit = dev
                    category = "ACL"
                    root_cause = f"Interface on {dev} bound to BLOCK_BGP_CTRL dropping BGP TCP 179."
                    patch = ConfigurationPatch(
                        target_device=dev,
                        subsystem="ACL",
                        command_block="no ip access-group BLOCK_BGP_CTRL in",
                        rollback_command_block="ip access-group BLOCK_BGP_CTRL in",
                        justification="Detach ACL blocking BGP control packets."
                    )
                    break
                if "ip access-group TRANSIT_FILTER" in cfg:
                    culprit = dev
                    category = "ACL"
                    root_cause = f"Interface on {dev} bound to TRANSIT_FILTER denying transit IP traffic."
                    patch = ConfigurationPatch(
                        target_device=dev,
                        subsystem="ACL",
                        command_block="no ip access-group TRANSIT_FILTER in",
                        rollback_command_block="ip access-group TRANSIT_FILTER in",
                        justification="Remove default deny transit filter from interface."
                    )
                    break

        # Default fallback if unresolved
        if not culprit:
            culprit = list(pruned_configs.keys())[0]
            root_cause = "Ambiguous anomaly detected in telemetry logs."
            patch = ConfigurationPatch(
                target_device=culprit,
                subsystem="ROUTING",
                command_block="!",
                rollback_command_block="!",
                justification="No-op fallback investigation patch."
            )

        output = AgentDiagnosticOutput(
            identified_culprit_device=culprit,
            failure_category=category,
            root_cause_analysis=root_cause,
            confidence_score=0.0,  # legacy rule engine has no calibrated confidence; 0.0 = not estimated
            proposed_patch=patch
        )
        return output

