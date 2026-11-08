"""Load the testbed (base configs, topology metadata, intents) into typed objects."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from core.causal_topology import TopologyGraph
from core.config_ir import Network
from core.intent_schema import IntentSet
from core.parsers.ios import parse_ios

ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = ROOT / "configs"


def load_network(config_dir: Path = CONFIG_DIR / "base_topology") -> Network:
    return {p.stem: parse_ios(p.read_text(encoding="utf-8"), p.stem) for p in sorted(Path(config_dir).glob("*.cfg"))}


@dataclass
class Testbed:
    network: Network
    topology: TopologyGraph
    intents: IntentSet


def load_testbed(config_dir: Path = CONFIG_DIR) -> Testbed:
    net = load_network(Path(config_dir) / "base_topology")
    topo = TopologyGraph.from_file(Path(config_dir) / "testbed_metadata.json", net)
    return Testbed(network=net, topology=topo, intents=IntentSet.load(Path(config_dir) / "intents.yaml"))
