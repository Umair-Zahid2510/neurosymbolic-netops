"""Verification backends. Use ``make_verifier`` to obtain a labelled composite verifier."""

from __future__ import annotations

from typing import List, Literal

from core.causal_topology import TopologyGraph
from core.config_ir import Network, network_fingerprint
from core.intent_schema import IntentSet
from core.verification.base import VerificationReport, combine
from core.verification.local_symbolic import IrStaticBackend, LocalSymbolicBackend


class CompositeVerifier:
    """Runs a forwarding backend (local_symbolic or batfish) plus ir_static invariants."""

    def __init__(self, backends: List):
        self.backends = backends
        self.name = "+".join(b.name for b in backends)

    def verify(self, network: Network, intents: IntentSet) -> VerificationReport:
        return combine([b.verify(network, intents) for b in self.backends], network_fingerprint(network))


def make_verifier(kind: Literal["local", "batfish"], topology: TopologyGraph, **batfish_kwargs) -> CompositeVerifier:
    if kind == "local":
        return CompositeVerifier([LocalSymbolicBackend(topology), IrStaticBackend(topology)])
    if kind == "batfish":
        from core.verification.batfish_backend import BatfishBackend
        return CompositeVerifier([BatfishBackend(topology, **batfish_kwargs), IrStaticBackend(topology)])
    raise ValueError(f"unknown verifier kind {kind!r}")
