"""Demo 2 - multi-fault diagnosis with counterexample-driven self-correction.

Faults: (a) Leaf-2 uplink eth2 has the wrong ACL bound (a control-plane filter that blocks BGP
replaced the perimeter security ACL); (b) Leaf-1 stopped advertising its LAN prefix.
The obvious repair for (a) - strip the blocking rules - would expose Leaf-2's LAN to the
unauthorised admin subnet. The verifier rejects it with an isolation counterexample and the
planner revises the plan.

python demos/demo2_multifault_self_correction.py [--reasoning ...] [--verifier ...]
"""
from common import cli, narrate, provider_for, save  # noqa: I001

from agent.orchestrator import SystemConfig, run_incident
from benchmark.faults import TEMPLATES
from core.inventory import load_testbed
from core.patch_ops import apply_plan
from core.telemetry.generator import GeneratorOptions

if __name__ == "__main__":
    args = cli(__doc__)
    tb = load_testbed()
    f1 = TEMPLATES["acl_block_bgp"](tb.network, tb.topology, dev="Leaf-2", intf="eth2")
    net = apply_plan(tb.network, f1.inject)
    f2 = TEMPLATES["missing_network"](net, tb.topology, dev="Leaf-1")
    net = apply_plan(net, f2.inject)
    run = run_incident(tb, "DEMO2-MULTI", net,
                       SystemConfig(reasoning=args.reasoning, verifier=args.verifier, llm_tools=not args.no_tools,
                                    llm_provider=provider_for(args.reasoning, args.record)),
                       GeneratorOptions(seed=22, noise_rate=2.0))
    narrate(run, tb, [f1, f2])
    save(run, args.save)
