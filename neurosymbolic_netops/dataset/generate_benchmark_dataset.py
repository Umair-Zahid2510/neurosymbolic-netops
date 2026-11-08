"""Automated Multi-Fault Benchmark Dataset Generator.

Generates 15 verified incident scenarios covering:
1. Physical / Link-Layer Impairments
2. Control-Plane Routing & BGP Misconfigurations
3. Security & Access Control List (ACL) Drops
"""

import json
from pathlib import Path
from typing import Dict, Any, List


def load_base_configs(base_dir: Path) -> Dict[str, str]:
    configs = {}
    for cfg_file in base_dir.glob("*.cfg"):
        node_name = cfg_file.stem
        configs[node_name] = cfg_file.read_text(encoding="utf-8")
    return configs


def build_scenarios(base_configs: Dict[str, str]) -> List[Dict[str, Any]]:
    scenarios: List[Dict[str, Any]] = []

    # 1. FAULT_LINK_001: Leaf-1 eth1 link shutdown
    c1 = dict(base_configs)
    c1["Leaf-1"] = c1["Leaf-1"].replace("interface eth1\n description Link to Spine-1 eth1\n ip address 10.0.1.2 255.255.255.252\n ip access-group PERIMETER_SECURITY_POLICY in\n mtu 1500\n speed 1000\n duplex full\n no shutdown",
                                        "interface eth1\n description Link to Spine-1 eth1\n ip address 10.0.1.2 255.255.255.252\n ip access-group PERIMETER_SECURITY_POLICY in\n mtu 1500\n speed 1000\n duplex full\n shutdown")
    scenarios.append({
        "incident_id": "FAULT_LINK_001",
        "fault_category": "LINK",
        "description": "Leaf-1 interface eth1 down via administrative shutdown",
        "ground_truth_culprit_device": "Leaf-1",
        "ground_truth_root_cause": "Interface eth1 is administratively down (shutdown).",
        "corrective_action": "Execute 'no shutdown' on interface eth1 of Leaf-1.",
        "target_invariants": {
            "reachability": True,
            "zero_loops": True,
            "bgp_established": ["Leaf-1:10.0.1.1", "Leaf-1:10.0.3.1", "Leaf-2:10.0.2.1", "Leaf-2:10.0.4.1"]
        },
        "telemetry_logs": [
            "%LINK-5-CHANGED: Interface eth1, changed state to administratively down",
            "%LINEPROTO-5-UPDOWN: Line protocol on Interface eth1, changed state to down",
            "%BGP-5-ADJCHANGE: neighbor 10.0.1.1 Down Interface flap / link down"
        ],
        "corrupted_configs": c1
    })

    # 2. FAULT_LINK_002: Spine-2 eth2 link shutdown
    c2 = dict(base_configs)
    c2["Spine-2"] = c2["Spine-2"].replace("interface eth2\n description Link to Leaf-2 eth2\n ip address 10.0.4.1 255.255.255.252\n mtu 1500\n speed 1000\n duplex full\n no shutdown",
                                          "interface eth2\n description Link to Leaf-2 eth2\n ip address 10.0.4.1 255.255.255.252\n mtu 1500\n speed 1000\n duplex full\n shutdown")
    scenarios.append({
        "incident_id": "FAULT_LINK_002",
        "fault_category": "LINK",
        "description": "Spine-2 interface eth2 down via administrative shutdown",
        "ground_truth_culprit_device": "Spine-2",
        "ground_truth_root_cause": "Interface eth2 on Spine-2 is administratively shutdown.",
        "corrective_action": "Execute 'no shutdown' on interface eth2 of Spine-2.",
        "target_invariants": {
            "reachability": True,
            "zero_loops": True,
            "bgp_established": ["Spine-2:10.0.4.2"]
        },
        "telemetry_logs": [
            "%LINK-3-UPDOWN: Interface eth2, changed state to down",
            "%BGP-5-ADJCHANGE: neighbor 10.0.4.2 Down Peer link down"
        ],
        "corrupted_configs": c2
    })

    # 3. FAULT_LINK_003: MTU mismatch on Leaf-2 eth1
    c3 = dict(base_configs)
    c3["Leaf-2"] = c3["Leaf-2"].replace("interface eth1\n description Link to Spine-1 eth2\n ip address 10.0.2.2 255.255.255.252\n ip access-group PERIMETER_SECURITY_POLICY in\n mtu 1500",
                                        "interface eth1\n description Link to Spine-1 eth2\n ip address 10.0.2.2 255.255.255.252\n ip access-group PERIMETER_SECURITY_POLICY in\n mtu 1400")
    scenarios.append({
        "incident_id": "FAULT_LINK_003",
        "fault_category": "LINK",
        "description": "MTU mismatch on Leaf-2 eth1 (1400 vs 1500)",
        "ground_truth_culprit_device": "Leaf-2",
        "ground_truth_root_cause": "Interface eth1 on Leaf-2 has MTU set to 1400, causing jumbo packet drops and BGP hold-time expiration.",
        "corrective_action": "Set 'mtu 1500' on interface eth1 of Leaf-2.",
        "target_invariants": {
            "reachability": True,
            "zero_loops": True,
            "bgp_established": ["Leaf-2:10.0.2.1"]
        },
        "telemetry_logs": [
            "%ETH-4-MTU_MISMATCH: MTU mismatch detected on eth1 (local 1400, remote 1500)",
            "%BGP-3-NOTIFICATION: sent to neighbor 10.0.2.1 4/0 (hold time expired)"
        ],
        "corrupted_configs": c3
    })

    # 4. FAULT_LINK_004: Duplex mismatch on Spine-1 eth1
    c4 = dict(base_configs)
    c4["Spine-1"] = c4["Spine-1"].replace("speed 1000\n duplex full", "speed 100\n duplex half")
    scenarios.append({
        "incident_id": "FAULT_LINK_004",
        "fault_category": "LINK",
        "description": "Speed/Duplex mismatch on Spine-1 eth1 (100/half vs 1000/full)",
        "ground_truth_culprit_device": "Spine-1",
        "ground_truth_root_cause": "Spine-1 eth1 speed/duplex misconfigured to speed 100 duplex half, causing collision drops and link instability.",
        "corrective_action": "Configure 'speed 1000' and 'duplex full' on Spine-1 eth1.",
        "target_invariants": {
            "reachability": True,
            "zero_loops": True,
            "bgp_established": ["Spine-1:10.0.1.2"]
        },
        "telemetry_logs": [
            "%CDP-4-DUPLEX_MISMATCH: full/half duplex mismatch on eth1",
            "%PORT-5-COLLISION: High late collision rate detected on Spine-1 eth1"
        ],
        "corrupted_configs": c4
    })

    # 5. FAULT_LINK_005: Leaf-2 eth2 interface shutdown
    c5 = dict(base_configs)
    c5["Leaf-2"] = c5["Leaf-2"].replace("interface eth2\n description Link to Spine-2 eth2\n ip address 10.0.4.2 255.255.255.252\n ip access-group PERIMETER_SECURITY_POLICY in\n mtu 1500\n speed 1000\n duplex full\n no shutdown",
                                        "interface eth2\n description Link to Spine-2 eth2\n ip address 10.0.4.2 255.255.255.252\n ip access-group PERIMETER_SECURITY_POLICY in\n mtu 1500\n speed 1000\n duplex full\n shutdown")
    scenarios.append({
        "incident_id": "FAULT_LINK_005",
        "fault_category": "LINK",
        "description": "Leaf-2 eth2 disabled via shutdown",
        "ground_truth_culprit_device": "Leaf-2",
        "ground_truth_root_cause": "Interface eth2 on Leaf-2 is shutdown, severing redundancy with Spine-2.",
        "corrective_action": "Execute 'no shutdown' on interface eth2 of Leaf-2.",
        "target_invariants": {
            "reachability": True,
            "zero_loops": True,
            "bgp_established": ["Leaf-2:10.0.4.1"]
        },
        "telemetry_logs": [
            "%LINK-5-CHANGED: Interface eth2, changed state to administratively down",
            "%BGP-5-ADJCHANGE: neighbor 10.0.4.1 Down Interface down"
        ],
        "corrupted_configs": c5
    })

    # 6. FAULT_BGP_001: Remote-AS mismatch on Leaf-1
    c6 = dict(base_configs)
    c6["Leaf-1"] = c6["Leaf-1"].replace("neighbor 10.0.1.1 remote-as 65000", "neighbor 10.0.1.1 remote-as 65099")
    scenarios.append({
        "incident_id": "FAULT_BGP_001",
        "fault_category": "BGP",
        "description": "BGP remote-as mismatch on Leaf-1 for Spine-1 (65099 instead of 65000)",
        "ground_truth_culprit_device": "Leaf-1",
        "ground_truth_root_cause": "Leaf-1 has configured neighbor 10.0.1.1 with wrong remote-as 65099 instead of 65000.",
        "corrective_action": "Set 'neighbor 10.0.1.1 remote-as 65000' on Leaf-1.",
        "target_invariants": {
            "reachability": True,
            "zero_loops": True,
            "bgp_established": ["Leaf-1:10.0.1.1"]
        },
        "telemetry_logs": [
            "%BGP-3-NOTIFICATION: received from neighbor 10.0.1.1 2/2 (bad peer AS 65099 expected 65000)",
            "%BGP-5-ADJCHANGE: neighbor 10.0.1.1 Down BGP peer AS mismatch"
        ],
        "corrupted_configs": c6
    })

    # 7. FAULT_BGP_002: Missing network statement on Leaf-1
    c7 = dict(base_configs)
    c7["Leaf-1"] = c7["Leaf-1"].replace("network 10.1.10.0 mask 255.255.255.0\n ", "")
    scenarios.append({
        "incident_id": "FAULT_BGP_002",
        "fault_category": "BGP",
        "description": "Missing BGP network advertisement for 10.1.10.0/24 on Leaf-1",
        "ground_truth_culprit_device": "Leaf-1",
        "ground_truth_root_cause": "Leaf-1 router bgp 65001 lacks 'network 10.1.10.0 mask 255.255.255.0', causing host subnet reachability failure.",
        "corrective_action": "Add 'network 10.1.10.0 mask 255.255.255.0' under router bgp 65001 on Leaf-1.",
        "target_invariants": {
            "reachability": True,
            "zero_loops": True,
            "bgp_established": ["Leaf-1:10.0.1.1", "Leaf-1:10.0.3.1"]
        },
        "telemetry_logs": [
            "%ROUTING-4-UNREACHABLE: Destination subnet 10.1.10.0/24 missing from Spine-1 and Leaf-2 RIB",
            "%FLOW-3-DROP: End-to-end synthetic probe from 10.1.20.1 to 10.1.10.1 dropped: No route to host"
        ],
        "corrupted_configs": c7
    })

    # 8. FAULT_BGP_003: Route-map dropping outbound advertisements on Spine-1
    c8 = dict(base_configs)
    c8["Spine-1"] = c8["Spine-1"].replace(
        "router bgp 65000\n bgp router-id 10.0.1.1\n neighbor 10.0.1.2 remote-as 65001\n neighbor 10.0.1.2 description Leaf-1\n neighbor 10.0.1.2 activate\n neighbor 10.0.2.2 remote-as 65002\n neighbor 10.0.2.2 description Leaf-2\n neighbor 10.0.2.2 activate",
        "route-map DROP_ALL deny 10\n!\nrouter bgp 65000\n bgp router-id 10.0.1.1\n neighbor 10.0.1.2 remote-as 65001\n neighbor 10.0.1.2 description Leaf-1\n neighbor 10.0.1.2 activate\n neighbor 10.0.2.2 remote-as 65002\n neighbor 10.0.2.2 description Leaf-2\n neighbor 10.0.2.2 activate\n neighbor 10.0.2.2 route-map DROP_ALL out"
    )
    scenarios.append({
        "incident_id": "FAULT_BGP_003",
        "fault_category": "BGP",
        "description": "Erroneous route-map DROP_ALL denying outbound prefix export to Leaf-2 on Spine-1",
        "ground_truth_culprit_device": "Spine-1",
        "ground_truth_root_cause": "Spine-1 has route-map DROP_ALL out applied to neighbor 10.0.2.2, filtering out routes to Leaf-2.",
        "corrective_action": "Remove 'neighbor 10.0.2.2 route-map DROP_ALL out' from Spine-1.",
        "target_invariants": {
            "reachability": True,
            "zero_loops": True,
            "bgp_established": ["Spine-1:10.0.2.2"]
        },
        "telemetry_logs": [
            "%BGP-4-ROUTEMAP_FILTER: 0 prefixes announced to peer 10.0.2.2 due to route-map DROP_ALL",
            "%SYNTH-4-PATH_DEGRADED: Traffic path Spine-1 -> Leaf-2 transit blackholed"
        ],
        "corrupted_configs": c8
    })

    # 9. FAULT_BGP_004: BGP MD5 authentication key mismatch on Leaf-2
    c9 = dict(base_configs)
    c9["Leaf-2"] = c9["Leaf-2"].replace(
        "neighbor 10.0.2.1 remote-as 65000",
        "neighbor 10.0.2.1 remote-as 65000\n neighbor 10.0.2.1 password INCORRECT_SECRET"
    )
    scenarios.append({
        "incident_id": "FAULT_BGP_004",
        "fault_category": "BGP",
        "description": "BGP MD5 password authentication mismatch on Leaf-2 towards Spine-1",
        "ground_truth_culprit_device": "Leaf-2",
        "ground_truth_root_cause": "Leaf-2 configured an unexpected BGP password for neighbor 10.0.2.1, causing MD5 checksum rejection.",
        "corrective_action": "Remove 'neighbor 10.0.2.1 password INCORRECT_SECRET' on Leaf-2.",
        "target_invariants": {
            "reachability": True,
            "zero_loops": True,
            "bgp_established": ["Leaf-2:10.0.2.1"]
        },
        "telemetry_logs": [
            "%TCP-6-BADAUTH: Invalid MD5 digest from 10.0.2.1:179 to 10.0.2.2:49152",
            "%BGP-5-ADJCHANGE: neighbor 10.0.2.1 Down BGP authentication failure"
        ],
        "corrupted_configs": c9
    })

    # 10. FAULT_BGP_005: Spine-2 BGP peer not activated for Leaf-1
    c10 = dict(base_configs)
    c10["Spine-2"] = c10["Spine-2"].replace(
        "neighbor 10.0.3.2 activate",
        "no neighbor 10.0.3.2 activate"
    )
    scenarios.append({
        "incident_id": "FAULT_BGP_005",
        "fault_category": "BGP",
        "description": "Spine-2 neighbor 10.0.3.2 not activated under BGP",
        "ground_truth_culprit_device": "Spine-2",
        "ground_truth_root_cause": "Spine-2 has disabled address-family activation for neighbor 10.0.3.2 (Leaf-1).",
        "corrective_action": "Execute 'neighbor 10.0.3.2 activate' under router bgp 65000 on Spine-2.",
        "target_invariants": {
            "reachability": True,
            "zero_loops": True,
            "bgp_established": ["Spine-2:10.0.3.2"]
        },
        "telemetry_logs": [
            "%BGP-3-PEER_INACTIVE: neighbor 10.0.3.2 is not activated for IPv4 Unicast",
            "%BGP-5-ADJCHANGE: neighbor 10.0.3.2 Down Address family inactive"
        ],
        "corrupted_configs": c10
    })

    # 11. FAULT_ACL_001: Erroneous ACL on Leaf-1 blocking 10.1.20.0/24
    c11 = dict(base_configs)
    c11["Leaf-1"] = c11["Leaf-1"].replace(
        "deny ip 192.168.99.0 0.0.0.255 any\n permit ip any any",
        "deny ip 192.168.99.0 0.0.0.255 any\n deny ip 10.1.20.0 0.0.0.255 any\n permit ip any any"
    )
    scenarios.append({
        "incident_id": "FAULT_ACL_001",
        "fault_category": "ACL",
        "description": "Leaf-1 inbound ACL erroneously dropping subnet 10.1.20.0/24",
        "ground_truth_culprit_device": "Leaf-1",
        "ground_truth_root_cause": "Access-list PERIMETER_SECURITY_POLICY on Leaf-1 contains erroneous statement 'deny ip 10.1.20.0 0.0.0.255 any' blocking traffic from Leaf-2.",
        "corrective_action": "Remove 'deny ip 10.1.20.0 0.0.0.255 any' from access-list PERIMETER_SECURITY_POLICY on Leaf-1.",
        "target_invariants": {
            "reachability": True,
            "zero_loops": True,
            "bgp_established": ["Leaf-1:10.0.1.1", "Leaf-1:10.0.3.1"]
        },
        "telemetry_logs": [
            "%SEC-6-IPACCESSLOGP: list PERIMETER_SECURITY_POLICY denied 10.1.20.1 -> 10.1.10.1, 150 packets",
            "%FLOW-3-PROBE_FAILED: End-to-end data-plane probe dropped by inbound ACL on Leaf-1"
        ],
        "corrupted_configs": c11
    })

    # 12. FAULT_ACL_002: Leaf-2 ACL blocking TCP ports 80/443 transit
    c12 = dict(base_configs)
    c12["Leaf-2"] = c12["Leaf-2"].replace(
        "permit ip any any",
        "deny tcp any any eq 80\n deny tcp any any eq 443\n permit ip any any"
    )
    scenarios.append({
        "incident_id": "FAULT_ACL_002",
        "fault_category": "ACL",
        "description": "Leaf-2 ACL blocking HTTP/HTTPS web traffic (ports 80 and 443)",
        "ground_truth_culprit_device": "Leaf-2",
        "ground_truth_root_cause": "Access-list PERIMETER_SECURITY_POLICY on Leaf-2 contains deny statements for TCP 80 and 443, violating datacenter transit policy.",
        "corrective_action": "Remove deny statements for TCP 80 and 443 from Leaf-2 ACL.",
        "target_invariants": {
            "reachability": True,
            "zero_loops": True,
            "bgp_established": ["Leaf-2:10.0.2.1", "Leaf-2:10.0.4.1"]
        },
        "telemetry_logs": [
            "%SEC-6-IPACCESSLOGP: list PERIMETER_SECURITY_POLICY denied TCP 10.1.10.10:51234 -> 10.1.20.10:443",
            "%APP-4-SERVICE_DEGRADED: Port 443 health-check failed across datacenter fabric"
        ],
        "corrupted_configs": c12
    })

    # 13. FAULT_ACL_003: Spine-1 inbound ACL blocking BGP port 179
    c13 = dict(base_configs)
    c13["Spine-1"] = c13["Spine-1"].replace(
        "ip routing",
        "ip routing\n!\nip access-list extended BLOCK_BGP_CTRL\n deny tcp any any eq 179\n permit ip any any\n!\ninterface eth1\n ip access-group BLOCK_BGP_CTRL in"
    ).replace(
        "interface eth1\n description Link to Leaf-1 eth1\n ip address 10.0.1.1 255.255.255.252",
        "interface eth1\n description Link to Leaf-1 eth1\n ip address 10.0.1.1 255.255.255.252\n ip access-group BLOCK_BGP_CTRL in"
    )
    scenarios.append({
        "incident_id": "FAULT_ACL_003",
        "fault_category": "ACL",
        "description": "Spine-1 ACL blocking BGP TCP port 179 on interface eth1",
        "ground_truth_culprit_device": "Spine-1",
        "ground_truth_root_cause": "Spine-1 interface eth1 has ACL BLOCK_BGP_CTRL denying TCP port 179, terminating BGP session to Leaf-1.",
        "corrective_action": "Remove 'ip access-group BLOCK_BGP_CTRL in' from Spine-1 eth1.",
        "target_invariants": {
            "reachability": True,
            "zero_loops": True,
            "bgp_established": ["Spine-1:10.0.1.2"]
        },
        "telemetry_logs": [
            "%SEC-6-IPACCESSLOGP: list BLOCK_BGP_CTRL denied tcp 10.0.1.2:179 -> 10.0.1.1:179",
            "%BGP-5-ADJCHANGE: neighbor 10.0.1.2 Down Peer closed connection"
        ],
        "corrupted_configs": c13
    })

    # 14. FAULT_ACL_004: Leaf-2 ACL blocking subnet 10.1.10.0/24
    c14 = dict(base_configs)
    c14["Leaf-2"] = c14["Leaf-2"].replace(
        "deny ip 192.168.99.0 0.0.0.255 any\n permit ip any any",
        "deny ip 192.168.99.0 0.0.0.255 any\n deny ip 10.1.10.0 0.0.0.255 any\n permit ip any any"
    )
    scenarios.append({
        "incident_id": "FAULT_ACL_004",
        "fault_category": "ACL",
        "description": "Leaf-2 inbound ACL dropping ingress packets from Host LAN 10.1.10.0/24",
        "ground_truth_culprit_device": "Leaf-2",
        "ground_truth_root_cause": "Leaf-2 PERIMETER_SECURITY_POLICY contains 'deny ip 10.1.10.0 0.0.0.255 any' dropping inbound host traffic.",
        "corrective_action": "Remove 'deny ip 10.1.10.0 0.0.0.255 any' from Leaf-2 ACL.",
        "target_invariants": {
            "reachability": True,
            "zero_loops": True,
            "bgp_established": ["Leaf-2:10.0.2.1", "Leaf-2:10.0.4.1"]
        },
        "telemetry_logs": [
            "%SEC-6-IPACCESSLOGP: list PERIMETER_SECURITY_POLICY denied 10.1.10.5 -> 10.1.20.10",
            "%NETOPS-3-INVARIANT_VIOLATION: Invariant reachability failed: Leaf-1 Host LAN -> Leaf-2 Server LAN"
        ],
        "corrupted_configs": c14
    })

    # 15. FAULT_ACL_005: Spine-2 default deny ACL dropping transit traffic
    c15 = dict(base_configs)
    c15["Spine-2"] = c15["Spine-2"].replace(
        "ip routing",
        "ip routing\n!\nip access-list extended TRANSIT_FILTER\n deny ip any any\n!\ninterface eth1\n ip access-group TRANSIT_FILTER in"
    ).replace(
        "interface eth1\n description Link to Leaf-1 eth2\n ip address 10.0.3.1 255.255.255.252",
        "interface eth1\n description Link to Leaf-1 eth2\n ip address 10.0.3.1 255.255.255.252\n ip access-group TRANSIT_FILTER in"
    )
    scenarios.append({
        "incident_id": "FAULT_ACL_005",
        "fault_category": "ACL",
        "description": "Spine-2 transit interface eth1 has default deny filter applied",
        "ground_truth_culprit_device": "Spine-2",
        "ground_truth_root_cause": "Spine-2 interface eth1 is bound to ACL TRANSIT_FILTER which denies all IP packets.",
        "corrective_action": "Remove 'ip access-group TRANSIT_FILTER in' on Spine-2 eth1.",
        "target_invariants": {
            "reachability": True,
            "zero_loops": True,
            "bgp_established": ["Spine-2:10.0.3.2"]
        },
        "telemetry_logs": [
            "%SEC-6-IPACCESSLOGP: list TRANSIT_FILTER denied 10.0.3.2 -> 10.0.3.1 (all traffic)",
            "%FLOW-3-TRANSIT_FAIL: ECMP path via Spine-2 dropping 100% transit packets"
        ],
        "corrupted_configs": c15
    })

    return scenarios


def main():
    base_dir = Path(__file__).resolve().parent.parent / "configs" / "base_topology"
    output_file = Path(__file__).resolve().parent / "ground_truth_faults.json"
    
    base_configs = load_base_configs(base_dir)
    print(f"Loaded base configs for devices: {list(base_configs.keys())}")
    
    scenarios = build_scenarios(base_configs)
    print(f"Generated {len(scenarios)} fault scenarios.")
    
    output_file.write_text(json.dumps(scenarios, indent=2), encoding="utf-8")
    print(f"Successfully saved benchmark suite to: {output_file}")


if __name__ == "__main__":
    main()
