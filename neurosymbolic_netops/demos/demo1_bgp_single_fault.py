"""Demo 1 - single-fault diagnosis and repair: BGP remote-AS misconfiguration on Leaf-1.

python demos/demo1_bgp_single_fault.py [--reasoning rule_based|llm|offline] [--verifier local|batfish]
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
    f = TEMPLATES["remote_as_mismatch"](tb.network, tb.topology, dev="Leaf-1", nbr="10.0.1.1")
    run = run_incident(tb, "DEMO1-BGP", apply_plan(tb.network, f.inject),
                       SystemConfig(reasoning=args.reasoning, verifier=args.verifier, llm_tools=not args.no_tools,
                                    llm_provider=provider_for(args.reasoning, args.record)),
                       GeneratorOptions(seed=11, noise_rate=1.5, decoys=True))
    narrate(run, tb, [f])
    save(run, args.save)
