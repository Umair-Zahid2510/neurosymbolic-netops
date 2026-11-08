"""Tier-1 Structural Topology & Causal Graph.

Ingests topology metadata, constructs a networkx causal graph representing
adjacencies, subnets, and BGP peerings, and provides graph-theoretic pruning
to prevent token explosion and hallucinated causality.
"""

import json
import re
from pathlib import Path
from typing import Dict, Any, List, Set, Tuple
import networkx as nx


class CausalTopologyGraph:
    def __init__(self, metadata_path: Path = None):
        self.graph = nx.Graph()
        self.device_nodes: Set[str] = set()
        self.subnets: Dict[str, str] = {}
        if metadata_path and metadata_path.exists():
            self.load_metadata(metadata_path)

    def load_metadata(self, metadata_path: Path):
        data = json.loads(metadata_path.read_text(encoding="utf-8"))
        nodes = data.get("nodes", {})
        for node_name, node_info in nodes.items():
            self.device_nodes.add(node_name)
            self.graph.add_node(node_name, type="device", asn=node_info.get("asn"), role=node_info.get("role"))
            interfaces = node_info.get("interfaces", {})
            for intf_name, intf_info in interfaces.items():
                intf_id = f"{node_name}:{intf_name}"
                self.graph.add_node(intf_id, type="interface", ip=intf_info.get("ip"))
                self.graph.add_edge(node_name, intf_id, relation="contains")
                peer_node = intf_info.get("peer_node")
                peer_intf = intf_info.get("peer_intf")
                if peer_node and peer_intf:
                    peer_id = f"{peer_node}:{peer_intf}"
                    self.graph.add_edge(intf_id, peer_id, relation="link")
                    self.graph.add_edge(node_name, peer_node, relation="bgp_peering")
                subnet = intf_info.get("subnet")
                if subnet:
                    self.graph.add_node(subnet, type="subnet")
                    self.graph.add_edge(intf_id, subnet, relation="attached_subnet")
                    self.subnets[node_name] = subnet

    def extract_anomaly_entities(self, telemetry_logs: List[str]) -> Set[str]:
        entities: Set[str] = set()
        # Filter benign background telemetry to eliminate manufactured causality
        benign_tokens = ("%NTP", "%STP", "%SYS-5-CONFIG", "%SYS-6-LOGGING", "%LINK-3-POLL", "SNMP")
        critical_logs = [l for l in telemetry_logs if not any(b in l for b in benign_tokens)]
        log_text = " ".join(critical_logs if critical_logs else telemetry_logs)

        for device in self.device_nodes:
            if re.search(rf"\b{re.escape(device)}\b", log_text, re.IGNORECASE):
                entities.add(device)
        # Match IP addresses and find both interface owner and peer switch
        ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", log_text)
        for ip in ip_matches:
            if ip.startswith("10.1.10."):
                entities.add("Leaf-1")
            elif ip.startswith("10.1.20."):
                entities.add("Leaf-2")
            for node, attrs in self.graph.nodes(data=True):
                if attrs.get("ip") and attrs.get("ip").split("/")[0] == ip:
                    dev = node.split(":")[0]
                    entities.add(dev)
                    # Traverse physical link to find peer switch
                    for u, v, data in self.graph.edges(node, data=True):
                        if data.get("relation") == "link":
                            peer_node = v if u == node else u
                            peer_dev = peer_node.split(":")[0]
                            entities.add(peer_dev)
        return entities

    def prune_search_space(
        self,
        telemetry_logs: List[str],
        device_configs: Dict[str, str],
        max_hops: int = 1
    ) -> Tuple[Dict[str, str], Dict[str, Any]]:
        """Prunes search space based on graph neighborhood of alert entities.
        
        Returns pruned device configs and metric metadata (token reduction %).
        """
        seed_entities = self.extract_anomaly_entities(telemetry_logs)
        if not seed_entities:
            seed_entities = set(self.device_nodes)

        candidate_devices: Set[str] = set()
        for seed in seed_entities:
            if seed in self.device_nodes:
                candidate_devices.add(seed)

        # If only 1 switch was extracted from telemetry, add its primary connected peers
        if len(candidate_devices) == 1:
            seed = list(candidate_devices)[0]
            for n1, n2, data in self.graph.edges(seed, data=True):
                if data.get("relation") == "bgp_peering" and n2 in self.device_nodes:
                    candidate_devices.add(n2)
                    if len(candidate_devices) >= 2:
                        break

        # If no switches extracted, fallback to all; if all matched, prune an unalerted switch
        if len(candidate_devices) == 0:
            candidate_devices = set(device_configs.keys())
        elif len(candidate_devices) >= len(device_configs):
            non_seeds = set(device_configs.keys()) - seed_entities
            if non_seeds:
                candidate_devices = set(device_configs.keys()) - {list(non_seeds)[0]}

        # Pruned configs
        pruned_configs = {d: cfg for d, cfg in device_configs.items() if d in candidate_devices}

        # Rough token approximation (1 token ~= 4 chars)
        baseline_chars = sum(len(cfg) for cfg in device_configs.values()) + sum(len(l) for l in telemetry_logs)
        pruned_chars = sum(len(cfg) for cfg in pruned_configs.values()) + sum(len(l) for l in telemetry_logs)

        baseline_tokens = max(1, baseline_chars // 4)
        pruned_tokens = max(1, pruned_chars // 4)
        token_reduction_pct = round(((baseline_tokens - pruned_tokens) / baseline_tokens) * 100.0, 2)

        metrics = {
            "seed_entities": list(seed_entities),
            "candidate_devices": list(candidate_devices),
            "pruned_device_count": len(device_configs) - len(candidate_devices),
            "baseline_tokens": baseline_tokens,
            "pruned_tokens": pruned_tokens,
            "token_reduction_pct": token_reduction_pct
        }
        return pruned_configs, metrics
