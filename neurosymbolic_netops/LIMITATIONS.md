# Limitations

This file is meant to be read alongside every result in the repository.

## Environment and integrations
1. **No real network devices, and no emulator.** All deployments go to `InMemoryAdapter`, which is labelled SIMULATED. The FRR container image was downloaded, but the FRR/Containerlab testbed adapter is **not implemented** (status: PLANNED). Post-deployment checks therefore read the adapter's simulated state. Failures in that state come from fault injection, not from real devices.
2. **Batfish is real but static.** It analyses configurations and does not model transients, timers or convergence. Our differential test (`benchmark/results/differential_local_vs_batfish.json`) found that Batfish keeps BGP sessions ESTABLISHED for:
   - MTU, duplex and speed mismatches;
   - unilateral MD5 passwords;
   - neighbors not activated for IPv4 unicast.

   The `ir_static` invariants cover these cases. They are configuration checks, not behavioural proofs.
3. **The local model is a simplification.** It covers single-hop eBGP only; there is no iBGP, OSPF, VRF, NAT or PBR. Forced speed mismatch is modelled as link down. Duplex or MTU mismatch is modelled as a degraded link whose sessions flap and carry no routes. An undefined ACL permits all traffic, and an undefined route-map denies all routes. The local verifier and the simulated world share this model, so a plan the local gate accepts cannot fail post-check unless a fault is injected. Independent checks therefore use Batfish wherever possible.

## LLM evaluation
4. **API quota limited the LLM evaluation.** The supplied Gemini key is on the free tier, which allows 20 requests per day per model. The pipeline makes 2–15 calls per incident. As a result:
   - the LLM benchmark conditions C2–C5 were **not run**; the runner records them as skipped;
   - the LLM results that do exist are three single demonstration runs across three models (`gemini-3.6-flash`, `gemini-3.5-flash-lite`, `gemini-3.1-flash-lite`).

   Those runs show the integration works end to end. They are anecdotes, not measurements of accuracy.
5. **Mocked tests prove interface logic only.** Tests under `tests/llm` mock the provider SDKs. They do not show that a live provider behaves the same way. Live behaviour is shown by the `-m live` smoke test and the demo transcripts in `demos/output/*__llm.txt`.
6. **Self-reported LLM confidence is stored as uncalibrated** and never used for gating. The rule-based strategy reports no confidence.

## Data and benchmark
7. **All telemetry is synthetic.** It is derived from simulated network state, using templates with several phrasings. The syslog classifier scores 100% on held-out phrasings when the syslog mnemonic is present, but only **75% when using the message text alone**: the mnemonic does most of the work. This tells us nothing about real vendor log diversity.
8. **Author contamination.** The fault library and the rule-based baseline were written by the same author, so the rule engine covers the fault taxonomy by design. Mitigations:
   - the held-out test split, containing two fault templates added after the rule engine was frozen at commit `a9fd5c4`, multi-fault combinations, held-out phrasings, and noisy or missing telemetry;
   - the commit history, which shows exactly when the one revision rule in `RuleBasedPlanner._alternative_for` was added. It was added *after* the test split was defined.
9. **The rule-based conditions are deterministic**, so they are run once. The bootstrap confidence intervals are over scenarios, not over trials.
10. **"Repaired" means the configuration-level intents are satisfied**, judged by the local oracle (`--oracle batfish` gives an independent check). It does not mean real traffic recovered. `restored_to_baseline` separates exact root-cause reversal from alternative fixes that also satisfy the intents.

## Components
11. **Causal discovery runs only on synthetic data.** The PC algorithm runs on data drawn from a topology-derived structural causal model. It is not wired into the localisation pipeline, and it does not remove links between variables that share an unobserved confounder (see results). No real time series were available.
12. **The edge model is a classical classifier,** TF-IDF features with logistic regression. It is not an SLM, GNN or neural encoder. NetLLM-style encoders and optical multimodal models are out of scope.
13. **Vendor translation coverage is narrow.** Translation covers only the IR feature subset. Behavioural equivalence was checked in Batfish on 10 networks (the base network plus 4 faults, × EOS and Junos) at the level of the declared intents. This is **not an SMT proof** of functional equivalence. The ACL `log` keyword is not translated, and speed/duplex settings are platform-dependent.
14. **Intents are not OpenConfig or YANG.** They use a project-specific Pydantic schema, and no standards compliance is claimed.
15. **Audit-log signatures are HMAC-SHA256 with a shared key.** This makes tampering evident to anyone holding the key. It is not PKI non-repudiation. If no key is configured, a development default is used and flagged.
16. **Not true two-phase commit.** Transactions follow a prepare/commit workflow with compensating rollback, applied one device at a time. True 2PC needs datastore support (for example NETCONF confirmed-commit), which the adapters don't have.
17. **MCP authentication is by role at registration.** A server process is started with a role and exposes only that role's tools. There is no per-request OAuth. Write tools also require an approval token that the server itself cannot issue.
