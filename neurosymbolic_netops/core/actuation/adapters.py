"""Device adapters used by the transaction engine.

``InMemoryAdapter`` (label: SIMULATED) holds device configurations in memory and supports
deterministic fault injection so every failure path of the transaction engine can be tested:
apply failure, timeout, partial deployment, a post-check failure caused by unexpected runtime
behaviour, and rollback failure. It is *not* a network device.

``FrrDockerAdapter`` (label: EMULATED) lives in ``core/actuation/frr_adapter.py`` and drives
FRRouting containers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Protocol, Set

from core.config_ir import DeviceConfig, Network, copy_network
from core.patch_ops import PatchPlan, apply_plan


class AdapterError(RuntimeError):
    pass


class AdapterTimeout(AdapterError):
    pass


class DeviceAdapter(Protocol):
    name: str
    label: str

    def devices(self) -> List[str]: ...
    def get_config(self, device: str) -> DeviceConfig: ...
    def push_config(self, device: str, config: DeviceConfig) -> None: ...
    def observed_network(self) -> Network: ...


@dataclass
class FaultInjection:
    fail_apply_on: Set[str] = field(default_factory=set)      # push raises AdapterError
    timeout_on: Set[str] = field(default_factory=set)         # push raises AdapterTimeout
    fail_rollback_on: Set[str] = field(default_factory=set)   # push of the *restore* config fails
    runtime_effect: Optional[PatchPlan] = None                 # applied to the live state after a commit
    runtime_effect_note: str = ""


class InMemoryAdapter:
    name = "inmemory"
    label = "SIMULATED"

    def __init__(self, network: Network, faults: Optional[FaultInjection] = None):
        self._net = copy_network(network)
        self.faults = faults or FaultInjection()
        self.push_log: List[str] = []
        self._restoring = False
        self._applied = False

    def devices(self) -> List[str]:
        return sorted(self._net)

    def get_config(self, device: str) -> DeviceConfig:
        if device not in self._net:
            raise AdapterError(f"unknown device {device}")
        return self._net[device].model_copy(deep=True)

    def begin_restore(self) -> None:
        self._restoring = True

    def push_config(self, device: str, config: DeviceConfig) -> None:
        f = self.faults
        if self._restoring and device in f.fail_rollback_on:
            self.push_log.append(f"{device}: RESTORE FAILED (injected)")
            raise AdapterError(f"{device}: injected rollback failure")
        if not self._restoring:
            if device in f.timeout_on:
                # the change lands but the acknowledgement is lost: state is now uncertain
                self._net[device] = config.model_copy(deep=True)
                self._applied = True
                self.push_log.append(f"{device}: TIMEOUT after partial apply (injected)")
                raise AdapterTimeout(f"{device}: injected connection timeout (change may have been applied)")
            if device in f.fail_apply_on:
                self.push_log.append(f"{device}: APPLY FAILED (injected)")
                raise AdapterError(f"{device}: injected configuration apply failure")
        self._net[device] = config.model_copy(deep=True)
        self._applied = self._applied or not self._restoring
        self.push_log.append(f"{device}: {'restored' if self._restoring else 'applied'}")

    def observed_network(self) -> Network:
        """Live state as seen by post-checks: pushed configs plus any injected runtime effect
        (e.g. a transceiver that keeps the link down despite 'no shutdown')."""
        live = copy_network(self._net)
        if self.faults.runtime_effect is not None and self._applied and not self._restoring:
            try:
                live = apply_plan(live, self.faults.runtime_effect)
            except Exception:  # effect not applicable to this state -> no effect
                pass
        return live
