"""Advanced Stress Dataset Generator for Neurosymbolic NetOps.

Generates 10 advanced stress scenarios:
1. 5 Combinatorial Multi-Fault Impairments (k >= 3)
2. 5 Saturated Noisy Telemetry Scenarios (Anti-Manufactured Causality Engine)
"""

import json
from pathlib import Path
from typing import Dict, Any, List


def load_base_configs(base_dir: Path) -> Dict[str, str]:
    configs = {}
    for cfg_file in base_dir.glob("*.cfg"):
        configs[cfg_file.stem] = cfg_file.read_text(encoding="utf-8")
    return configs


def build_advanced_stress_scenarios(base_configs: Dict[str, str]) -> List[Dict[str, Any]]:
    scenarios: List[Dict[str, Any]] = []

    # =========================================================================
    # PART 1: COMBINATORIAL MULTI-FAULT SCENARIOS (k >= 3)
    # =========================================================================

    # 1. MF-01: Leaf-1 eth1 shutdown + Leaf-2 BGP auth password + Leaf-1 rogue ACL
    c1 = dict(base_configs)
    # Fault 1: Leaf-1 eth1 shutdown
    c1["Leaf-1"] = c1["Leaf-1"].replace("speed 1000\n duplex full\n no shutdown", "speed 1000\n duplex full\n shutdown", 1)
    # Fault 2: Leaf-2 BGP password towards Spine-1
    c1["Leaf-2"] = c1["Leaf-2"].replace("neighbor 10.0.2.1 remote-as 65000", "neighbor 10.0.2.1 remote-as 65000\n neighbor 10.0.2.1 password BAD_MD5_KEY")
    # Fault 3: Leaf-1 rogue ACL drop
    c1["Leaf-1"] = c1["Leaf-1"].replace("deny ip 192.168.99.0 0.0.0.255 any\n permit ip any any", "deny ip 192.168.99.0 0.0.0.255 any\n deny ip 10.1.20.0 0.0.0.255 any\n permit ip any any")

    scenarios.append({
        "incident_id": "STRESS_MF_001",
        "fault_category": "MULTI-FAULT",
        "description": "Combinatorial k=3: Leaf-1 eth1 shutdown + Leaf-2 BGP MD5 auth mismatch + Leaf-1 rogue ACL drop",
        "ground_truth_culprits": ["Leaf-1", "Leaf-2"],
        "ground_truth_culprit_device": "Leaf-1",
        "multi_fault_count": 3,
        "telemetry_logs": [
            "%LINK-5-CHANGED: Interface eth1 on Leaf-1, changed state to administratively down",
            "%TCP-6-BADAUTH: Invalid MD5 digest from 10.0.2.1:179 to 10.0.2.2:49152 on Leaf-2",
            "%SEC-6-IPACCESSLOGP: list PERIMETER_SECURITY_POLICY denied 10.1.20.1 -> 10.1.10.1 on Leaf-1",
            "%BGP-5-ADJCHANGE: neighbor 10.0.1.1 Down Interface flap / link down"
        ],
        "corrupted_configs": c1
    })

    # 2. MF-02: Leaf-2 eth1 MTU 1400 + Leaf-1 missing network 10.1.10.0 + Spine-2 transit filter
    c2 = dict(base_configs)
    c2["Leaf-2"] = c2["Leaf-2"].replace("mtu 1500", "mtu 1400", 1)
    c2["Leaf-1"] = c2["Leaf-1"].replace("network 10.1.10.0 mask 255.255.255.0\n ", "")
    c2["Spine-2"] = c2["Spine-2"].replace("ip routing", "ip routing\n!\nip access-list extended TRANSIT_FILTER\n deny ip any any\n!\ninterface eth1\n ip access-group TRANSIT_FILTER in")
    c2["Spine-2"] = c2["Spine-2"].replace("description Link to Leaf-1 eth2\n ip address 10.0.3.1 255.255.255.252", "description Link to Leaf-1 eth2\n ip address 10.0.3.1 255.255.255.252\n ip access-group TRANSIT_FILTER in")

    scenarios.append({
        "incident_id": "STRESS_MF_002",
        "fault_category": "MULTI-FAULT",
        "description": "Combinatorial k=3: Leaf-2 eth1 MTU 1400 + Leaf-1 missing BGP network 10.1.10.0 + Spine-2 transit filter",
        "ground_truth_culprits": ["Leaf-2", "Leaf-1", "Spine-2"],
        "ground_truth_culprit_device": "Leaf-2",
        "multi_fault_count": 3,
        "telemetry_logs": [
            "%ETH-4-MTU_MISMATCH: MTU mismatch detected on Leaf-2 eth1 (local 1400, remote 1500)",
            "%ROUTING-4-UNREACHABLE: Destination subnet 10.1.10.0/24 missing from BGP RIB",
            "%SEC-6-IPACCESSLOGP: list TRANSIT_FILTER denied 10.0.3.2 -> 10.0.3.1 on Spine-2"
        ],
        "corrupted_configs": c2
    })

    # 3. MF-03: Spine-1 route-map DROP_ALL + Spine-2 peer 10.0.3.2 deactivated + Leaf-2 web ports 80/443 filter
    c3 = dict(base_configs)
    c3["Spine-1"] = c3["Spine-1"].replace(
        "neighbor 10.0.2.2 activate",
        "neighbor 10.0.2.2 activate\n neighbor 10.0.2.2 route-map DROP_ALL out\n!\nroute-map DROP_ALL deny 10"
    )
    c3["Spine-2"] = c3["Spine-2"].replace("neighbor 10.0.3.2 activate", "no neighbor 10.0.3.2 activate")
    c3["Leaf-2"] = c3["Leaf-2"].replace("permit ip any any", "deny tcp any any eq 80\n deny tcp any any eq 443\n permit ip any any")

    scenarios.append({
        "incident_id": "STRESS_MF_003",
        "fault_category": "MULTI-FAULT",
        "description": "Combinatorial k=3: Spine-1 route-map DROP_ALL out + Spine-2 BGP peer inactive + Leaf-2 port 80/443 filter",
        "ground_truth_culprits": ["Spine-1", "Spine-2", "Leaf-2"],
        "ground_truth_culprit_device": "Spine-1",
        "multi_fault_count": 3,
        "telemetry_logs": [
            "%BGP-4-ROUTEMAP_FILTER: 0 prefixes announced to peer 10.0.2.2 on Spine-1 due to route-map DROP_ALL",
            "%BGP-3-PEER_INACTIVE: neighbor 10.0.3.2 is not activated on Spine-2",
            "%SEC-6-IPACCESSLOGP: list PERIMETER_SECURITY_POLICY denied TCP on Leaf-2"
        ],
        "corrupted_configs": c3
    })

    # 4. MF-04: Spine-1 eth1 speed/duplex mismatch + Leaf-1 remote-as 65099 + Leaf-2 ACL dropping 10.1.10.0/24
    c4 = dict(base_configs)
    c4["Spine-1"] = c4["Spine-1"].replace("speed 1000\n duplex full", "speed 100\n duplex half", 1)
    c4["Leaf-1"] = c4["Leaf-1"].replace("neighbor 10.0.1.1 remote-as 65000", "neighbor 10.0.1.1 remote-as 65099")
    c4["Leaf-2"] = c4["Leaf-2"].replace("deny ip 192.168.99.0 0.0.0.255 any\n permit ip any any", "deny ip 192.168.99.0 0.0.0.255 any\n deny ip 10.1.10.0 0.0.0.255 any\n permit ip any any")

    scenarios.append({
        "incident_id": "STRESS_MF_004",
        "fault_category": "MULTI-FAULT",
        "description": "Combinatorial k=3: Spine-1 speed/duplex mismatch + Leaf-1 bad remote-as 65099 + Leaf-2 inbound ACL drop 10.1.10.0/24",
        "ground_truth_culprits": ["Spine-1", "Leaf-1", "Leaf-2"],
        "ground_truth_culprit_device": "Spine-1",
        "multi_fault_count": 3,
        "telemetry_logs": [
            "%CDP-4-DUPLEX_MISMATCH: full/half duplex mismatch on Spine-1 eth1",
            "%BGP-3-NOTIFICATION: bad peer AS 65099 on Leaf-1",
            "%SEC-6-IPACCESSLOGP: list PERIMETER_SECURITY_POLICY denied 10.1.10.10 on Leaf-2"
        ],
        "corrupted_configs": c4
    })

    # 5. MF-05: Leaf-2 eth2 shutdown + Spine-1 BLOCK_BGP_CTRL on eth1 + Leaf-2 missing network 10.1.20.0
    c5 = dict(base_configs)
    c5["Leaf-2"] = c5["Leaf-2"].replace("description Link to Spine-2 eth2\n ip address 10.0.4.2 255.255.255.252\n ip access-group PERIMETER_SECURITY_POLICY in\n mtu 1500\n speed 1000\n duplex full\n no shutdown",
                                        "description Link to Spine-2 eth2\n ip address 10.0.4.2 255.255.255.252\n ip access-group PERIMETER_SECURITY_POLICY in\n mtu 1500\n speed 1000\n duplex full\n shutdown")
    c5["Spine-1"] = c5["Spine-1"].replace("ip routing", "ip routing\n!\nip access-list extended BLOCK_BGP_CTRL\n deny tcp any any eq 179\n permit ip any any")
    c5["Spine-1"] = c5["Spine-1"].replace("description Link to Leaf-1 eth1\n ip address 10.0.1.1 255.255.255.252", "description Link to Leaf-1 eth1\n ip address 10.0.1.1 255.255.255.252\n ip access-group BLOCK_BGP_CTRL in")
    c5["Leaf-2"] = c5["Leaf-2"].replace("network 10.1.20.0 mask 255.255.255.0\n ", "")

    scenarios.append({
        "incident_id": "STRESS_MF_005",
        "fault_category": "MULTI-FAULT",
        "description": "Combinatorial k=3: Leaf-2 eth2 shutdown + Spine-1 BGP control port 179 filter + Leaf-2 missing BGP network 10.1.20.0",
        "ground_truth_culprits": ["Leaf-2", "Spine-1"],
        "ground_truth_culprit_device": "Leaf-2",
        "multi_fault_count": 3,
        "telemetry_logs": [
            "%LINK-5-CHANGED: Interface eth2 on Leaf-2 changed state to administratively down",
            "%SEC-6-IPACCESSLOGP: list BLOCK_BGP_CTRL denied tcp 10.0.1.2:179 on Spine-1",
            "%ROUTING-4-UNREACHABLE: Prefix 10.1.20.0/24 missing from Spine routing table"
        ],
        "corrupted_configs": c5
    })

    # =========================================================================
    # PART 2: NOISY TELEMETRY & ANTI-MANUFACTURED CAUSALITY SCENARIOS
    # =========================================================================

    benign_noise_logs = [
        "%SYS-5-CONFIG_I: Configured from console by admin on vty0 (192.168.1.10)",
        "%NTP-4-PEERUNREACH: Peer 192.168.1.50 is unreachable",
        "%STP-6-TOPOLOGY_CHANGE: Spanning tree topology change detected on VLAN 1",
        "%LINK-3-POLL: Interface SNMP counter collection polling completed (0 errors)",
        "%SYS-6-LOGGINGHOST_STARTSTOP: Logging to host 172.16.10.5 started",
        "%NTP-5-PEERSYNC: Synchronized to NTP server 192.168.1.51"
    ]

    # NOISE-01: Leaf-1 eth1 shutdown with heavy noise
    c_n1 = dict(base_configs)
    c_n1["Leaf-1"] = c_n1["Leaf-1"].replace("speed 1000\n duplex full\n no shutdown", "speed 1000\n duplex full\n shutdown", 1)
    scenarios.append({
        "incident_id": "STRESS_NOISE_001",
        "fault_category": "NOISY-TELEMETRY",
        "description": "Leaf-1 eth1 shutdown embedded in benign multi-switch telemetry noise",
        "ground_truth_culprit_device": "Leaf-1",
        "ground_truth_root_cause": "Interface eth1 on Leaf-1 is administratively shutdown.",
        "telemetry_logs": [
            benign_noise_logs[0],
            benign_noise_logs[1],
            "%LINK-5-CHANGED: Interface eth1 on Leaf-1, changed state to administratively down",
            benign_noise_logs[2],
            "%BGP-5-ADJCHANGE: neighbor 10.0.1.1 Down Interface flap / link down",
            benign_noise_logs[3],
            benign_noise_logs[4]
        ],
        "corrupted_configs": c_n1
    })

    # NOISE-02: Spine-2 eth2 shutdown with heavy noise
    c_n2 = dict(base_configs)
    c_n2["Spine-2"] = c_n2["Spine-2"].replace("speed 1000\n duplex full\n no shutdown", "speed 1000\n duplex full\n shutdown", 1)
    scenarios.append({
        "incident_id": "STRESS_NOISE_002",
        "fault_category": "NOISY-TELEMETRY",
        "description": "Spine-2 eth2 shutdown embedded in benign background NTP/STP noise",
        "ground_truth_culprit_device": "Spine-2",
        "ground_truth_root_cause": "Interface eth2 on Spine-2 is administratively shutdown.",
        "telemetry_logs": [
            benign_noise_logs[2],
            "%LINK-3-UPDOWN: Interface eth2, changed state to down",
            benign_noise_logs[3],
            "%BGP-5-ADJCHANGE: neighbor 10.0.4.2 Down Peer link down",
            benign_noise_logs[0],
            benign_noise_logs[1]
        ],
        "corrupted_configs": c_n2
    })

    # NOISE-03: Leaf-2 BGP auth mismatch with noise
    c_n3 = dict(base_configs)
    c_n3["Leaf-2"] = c_n3["Leaf-2"].replace("neighbor 10.0.2.1 remote-as 65000", "neighbor 10.0.2.1 remote-as 65000\n neighbor 10.0.2.1 password NOISY_SECRET")
    scenarios.append({
        "incident_id": "STRESS_NOISE_003",
        "fault_category": "NOISY-TELEMETRY",
        "description": "Leaf-2 BGP authentication mismatch amid high-frequency benign console events",
        "ground_truth_culprit_device": "Leaf-2",
        "ground_truth_root_cause": "Leaf-2 has configured unauthorized BGP password for neighbor 10.0.2.1.",
        "telemetry_logs": [
            benign_noise_logs[0],
            "%TCP-6-BADAUTH: Invalid MD5 digest from 10.0.2.1:179 to 10.0.2.2:49152 on Leaf-2",
            benign_noise_logs[4],
            "%BGP-5-ADJCHANGE: neighbor 10.0.2.1 Down BGP authentication failure",
            benign_noise_logs[1],
            benign_noise_logs[5]
        ],
        "corrupted_configs": c_n3
    })

    # NOISE-04: Leaf-1 inbound ACL drop with noise
    c_n4 = dict(base_configs)
    c_n4["Leaf-1"] = c_n4["Leaf-1"].replace(
        "deny ip 192.168.99.0 0.0.0.255 any\n permit ip any any",
        "deny ip 192.168.99.0 0.0.0.255 any\n deny ip 10.1.20.0 0.0.0.255 any\n permit ip any any"
    )
    scenarios.append({
        "incident_id": "STRESS_NOISE_004",
        "fault_category": "NOISY-TELEMETRY",
        "description": "Leaf-1 ACL drop on subnet 10.1.20.0/24 embedded in benign STP logs",
        "ground_truth_culprit_device": "Leaf-1",
        "ground_truth_root_cause": "Leaf-1 has ACL deny rule dropping 10.1.20.0/24.",
        "telemetry_logs": [
            benign_noise_logs[2],
            "%SEC-6-IPACCESSLOGP: list PERIMETER_SECURITY_POLICY denied 10.1.20.1 -> 10.1.10.1 on Leaf-1",
            benign_noise_logs[3],
            "%FLOW-3-PROBE_FAILED: End-to-end data-plane probe dropped by inbound ACL on Leaf-1",
            benign_noise_logs[0]
        ],
        "corrupted_configs": c_n4
    })

    # NOISE-05: Spine-1 eth1 duplex mismatch with noise
    c_n5 = dict(base_configs)
    c_n5["Spine-1"] = c_n5["Spine-1"].replace("speed 1000\n duplex full", "speed 100\n duplex half", 1)
    scenarios.append({
        "incident_id": "STRESS_NOISE_005",
        "fault_category": "NOISY-TELEMETRY",
        "description": "Spine-1 duplex mismatch obscured by benign NTP polling telemetry",
        "ground_truth_culprit_device": "Spine-1",
        "ground_truth_root_cause": "Spine-1 eth1 configured for speed 100 duplex half.",
        "telemetry_logs": [
            benign_noise_logs[1],
            "%CDP-4-DUPLEX_MISMATCH: full/half duplex mismatch on Spine-1 eth1",
            benign_noise_logs[5],
            "%PORT-5-COLLISION: High late collision rate detected on Spine-1 eth1",
            benign_noise_logs[3]
        ],
        "corrupted_configs": c_n5
    })

    return scenarios


def main():
    base_dir = Path(__file__).resolve().parent.parent / "configs" / "base_topology"
    output_file = Path(__file__).resolve().parent / "advanced_stress_faults.json"

    base_configs = load_base_configs(base_dir)
    scenarios = build_advanced_stress_scenarios(base_configs)
    output_file.write_text(json.dumps(scenarios, indent=2), encoding="utf-8")
    print(f"Generated {len(scenarios)} advanced stress test scenarios: {output_file}")


if __name__ == "__main__":
    main()
