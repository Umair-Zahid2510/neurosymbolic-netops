"""Demo 3 - verified plan, failed deployment, automatic rollback.

Fault: Spine-2 eth1 administratively shut. The repair ("no shutdown") passes symbolic
verification, but the device adapter injects a runtime fault (SIMULATED: the link stays down
after the change, as with a failed transceiver). The post-check on the *observed* state fails
and the transaction restores the captured configuration, verifies the restore, and records
every step in the HMAC-chained audit log (printed at the end).

python demos/demo3_failed_deployment_rollback.py [--reasoning ...] [--verifier ...]
"""
from common import ROOT, cli, hr, narrate, provider_for, save  # noqa: I001

from agent.orchestrator import SystemConfig, run_incident
from benchmark.faults import TEMPLATES
from core.actuation.adapters import FaultInjection
from core.actuation.audit import AuditLog
from core.inventory import load_testbed
from core.patch_ops import PatchPlan, SetInterfaceEnabled, apply_plan
from core.telemetry.generator import GeneratorOptions

if __name__ == "__main__":
    args = cli(__doc__)
    tb = load_testbed()
    f = TEMPLATES["iface_shutdown"](tb.network, tb.topology, dev="Spine-2", intf="eth1")
    effect = PatchPlan(ops=[SetInterfaceEnabled(device="Spine-2", interface="eth1", enabled=False)])
    audit_path = ROOT / "runtime" / "demo3_audit.jsonl"
    audit_path.unlink(missing_ok=True)
    run = run_incident(tb, "DEMO3-ROLLBACK", apply_plan(tb.network, f.inject),
                       SystemConfig(reasoning=args.reasoning, verifier=args.verifier, llm_tools=not args.no_tools,
                                    llm_provider=provider_for(args.reasoning, args.record),
                                    adapter_faults=FaultInjection(runtime_effect=effect,
                                                                  runtime_effect_note="link stays down after commit (SIMULATED)"),
                                    audit_path=audit_path),
                       GeneratorOptions(seed=33))
    narrate(run, tb, [f])
    hr("AUDIT RECORD (HMAC-SHA256 chained)")
    log = AuditLog(audit_path)
    for e in log.entries:
        print(f"   #{e['seq']:02d} {e['actor']:16s} {e['action']:28s} {str(e['payload'])[:70]}  mac={e['mac'][:12]}")
    print("chain verification:", log.verify())
    save(run, args.save)
