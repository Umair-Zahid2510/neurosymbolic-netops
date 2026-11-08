"""SADE-style modular read-only diagnostic skills for network inspection."""

import re
from typing import Dict, Any, Optional, List


class DiagnosticSkillSet:
    """Read-only diagnostic inspection skills."""

    def __init__(self, device_configs: Dict[str, str]):
        self.device_configs = device_configs

    def skill_inspect_interface(self, device: str, interface: str) -> Dict[str, Any]:
        """Inspects interface operational state, MTU, speed/duplex, and shutdown status."""
        config = self.device_configs.get(device, "")
        pattern = rf"^interface\s+{re.escape(interface)}\b(.*?)(?=^interface|^router|^ip access-list|^end|\Z)"
        match = re.search(pattern, config, re.MULTILINE | re.DOTALL)
        if not match:
            return {"status": "error", "message": f"Interface {interface} not found on {device}"}

        block = match.group(1)
        is_shutdown = bool(re.search(r"^\s*shutdown\b", block, re.MULTILINE))
        mtu_m = re.search(r"^\s*mtu\s+(\d+)", block, re.MULTILINE)
        speed_m = re.search(r"^\s*speed\s+(\S+)", block, re.MULTILINE)
        duplex_m = re.search(r"^\s*duplex\s+(\S+)", block, re.MULTILINE)
        ip_m = re.search(r"^\s*ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", block, re.MULTILINE)
        acl_m = re.search(r"^\s*ip\s+access-group\s+(\S+)\s+(in|out)", block, re.MULTILINE)

        return {
            "device": device,
            "interface": interface,
            "admin_status": "down" if is_shutdown else "up",
            "ip_address": ip_m.group(1) if ip_m else None,
            "subnet_mask": ip_m.group(2) if ip_m else None,
            "mtu": int(mtu_m.group(1)) if mtu_m else 1500,
            "speed": speed_m.group(1) if speed_m else "auto",
            "duplex": duplex_m.group(1) if duplex_m else "auto",
            "applied_acl": f"{acl_m.group(1)} {acl_m.group(2)}" if acl_m else None,
            "raw_block": block.strip()
        }

    def skill_check_bgp_peering(self, device: str, peer_ip: str) -> Dict[str, Any]:
        """Inspects BGP peering configuration, remote AS, auth keys, and activation status."""
        config = self.device_configs.get(device, "")
        bgp_match = re.search(r"^router bgp (\d+)(.*?)(?=^router|^interface|^ip access-list|^end|\Z)", config, re.MULTILINE | re.DOTALL)
        if not bgp_match:
            return {"status": "error", "message": f"BGP process not configured on {device}"}

        local_asn = bgp_match.group(1)
        bgp_block = bgp_match.group(2)

        peer_remote_as_m = re.search(rf"^\s*neighbor\s+{re.escape(peer_ip)}\s+remote-as\s+(\d+)", bgp_block, re.MULTILINE)
        peer_pass_m = re.search(rf"^\s*neighbor\s+{re.escape(peer_ip)}\s+password\s+(\S+)", bgp_block, re.MULTILINE)
        peer_rm_m = re.search(rf"^\s*neighbor\s+{re.escape(peer_ip)}\s+route-map\s+(\S+)\s+(in|out)", bgp_block, re.MULTILINE)
        peer_inactive_m = re.search(rf"^\s*no\s+neighbor\s+{re.escape(peer_ip)}\s+activate", bgp_block, re.MULTILINE)

        networks = re.findall(r"^\s*network\s+(\d+\.\d+\.\d+\.\d+)\s+mask\s+(\d+\.\d+\.\d+\.\d+)", bgp_block, re.MULTILINE)

        return {
            "device": device,
            "local_asn": int(local_asn),
            "peer_ip": peer_ip,
            "configured": bool(peer_remote_as_m),
            "remote_asn": int(peer_remote_as_m.group(1)) if peer_remote_as_m else None,
            "password_configured": peer_pass_m.group(1) if peer_pass_m else None,
            "route_map": f"{peer_rm_m.group(1)} {peer_rm_m.group(2)}" if peer_rm_m else None,
            "activated": not bool(peer_inactive_m),
            "advertised_networks": networks
        }

    def skill_inspect_routing_table(self, device: str, destination_prefix: str) -> Dict[str, Any]:
        """Evaluates whether destination prefix is advertised or reachability path exists."""
        config = self.device_configs.get(device, "")
        prefix_advertised = destination_prefix in config
        return {
            "device": device,
            "prefix": destination_prefix,
            "prefix_advertised": prefix_advertised,
            "has_bgp": "router bgp" in config,
            "has_static": f"ip route {destination_prefix}" in config
        }

    def skill_audit_access_lists(self, device: str) -> Dict[str, Any]:
        """Audits access-lists on the device for drop rules or anomalous restrictions."""
        config = self.device_configs.get(device, "")
        acls = {}
        acl_blocks = re.findall(r"^ip access-list extended\s+(\S+)(.*?)(?=^ip access-list|^interface|^router|^end|\Z)", config, re.MULTILINE | re.DOTALL)
        for name, rules in acl_blocks:
            rule_lines = [r.strip() for r in rules.strip().splitlines() if r.strip()]
            deny_rules = [r for r in rule_lines if r.startswith("deny")]
            permit_rules = [r for r in rule_lines if r.startswith("permit")]
            acls[name] = {
                "rules": rule_lines,
                "deny_count": len(deny_rules),
                "permit_count": len(permit_rules),
                "deny_rules": deny_rules
            }
        return {
            "device": device,
            "configured_acls": acls
        }
