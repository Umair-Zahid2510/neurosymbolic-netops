# Implementation Status (2026-11-08)

Status values: **IMPLEMENTED** · **PARTIALLY IMPLEMENTED** · **SIMULATED** · **PLANNED** · **NOT IMPLEMENTED**.

| Area | Component | Status | Evidence |
|---|---|---|---|
| Config | Typed IR, IOS parser (reports unsupported lines), IOS renderer, lossless round-trip | IMPLEMENTED | `tests/unit/test_ios_parser.py` |
| Config | Typed patch operations (14 kinds), pure application, plan hash | IMPLEMENTED | `tests/unit/test_patch_ops.py` |
| Tier 1 | Telemetry schema, normaliser (syslog/counters/probes, timestamps, dedup, missing data) | IMPLEMENTED | `tests/unit/test_telemetry.py` |
| Tier 1 | Telemetry source | SIMULATED | generated from simulated state (`core/telemetry/generator.py`) |
| Tier 1 | Edge detection: TF-IDF+LR syslog classifier, robust z-score counters, probe loss | IMPLEMENTED (classical ML; not an SLM) | `models/syslog_classifier_metrics.json` |
| Tier 1 | Topology graph from metadata + configs; evidence-based candidate ranking | IMPLEMENTED | demos; benchmark top-1/top-3 |
| Tier 1 | Learned root-cause ranker (gradient-boosted trees on digest features; trained on dev, tested on held-out) | IMPLEMENTED; evaluated stand-alone, not yet used by the agents | `results/ranker_results.json` |
| Tier 1 | Causal discovery (PC algorithm) | PARTIALLY IMPLEMENTED (synthetic SCM only; not used for localisation) | `benchmark/results/causal_discovery_pc.json` |
| Tier 2 | Five agents, typed contracts, state machine, incident record | IMPLEMENTED | `tests/agents/` |
| Tier 2 | Rule-based diagnosis/planning baseline (generic, no incident IDs) | IMPLEMENTED | CI test forbids incident-ID strings in `agent/` and `core/` |
| Tier 2 | 16 typed read-only skills (5 more planned: OSPF, ARP, VLAN, DNS, firewall sessions) | PARTIALLY IMPLEMENTED | `core/skills/library.py` |
| LLM | Gemini provider: tool calling, structured output, retries/backoff, timeouts, token usage, redacted logs | IMPLEMENTED; **live-verified** | live smoke test passed; `demos/output/*__llm.txt` |
| LLM | OpenAI provider | IMPLEMENTED; mock-tested only (no key) | `tests/llm/test_llm_layer.py` |
| LLM | Offline mode (record/replay cassette, labelled `replay`) | IMPLEMENTED | `test_record_then_replay_is_labelled_and_misses_raise` |
| LLM | LLM benchmark conditions C2–C5 | NOT RUN (free-tier quota: 20 requests/day/model) | runner manifests record `skipped` |
| Tier 3 | Local symbolic verifier (sessions, ECMP reachability, redundancy, isolation, loops) | IMPLEMENTED (labelled `local_symbolic`) | `tests/unit/test_local_verifier.py` |
| Tier 3 | Static invariants (link and BGP-peer consistency) | IMPLEMENTED (`ir_static`) | same |
| Tier 3 | Batfish backend (pybatfish; parse gate; sessions, traceroute, detectLoops) | IMPLEMENTED; **live-verified** against `batfish/allinone` | `pytest -m batfish`; differential and oracle results |
| Tier 3 | Counterexample-driven bounded reflection with explicit partial-progress policy | IMPLEMENTED | demo 2 (rule-based and live LLM) |
| Tier 4 | Transaction engine: capture → syntax → verify → authorize → apply → post-check → commit / compensating rollback | IMPLEMENTED (not true 2PC) | `test_fault_injection_paths`, demo 3 |
| Tier 4 | One-time HMAC approval tokens bound to plan hash + candidate fingerprint | IMPLEMENTED | token replay / mismatch tests |
| Tier 4 | HMAC-chained audit log with tamper detection | IMPLEMENTED | `test_audit_tamper_detected` |
| Tier 4 | Device adapter | SIMULATED (`InMemoryAdapter` with fault injection) | – |
| Tier 4 | FRR / Containerlab emulator adapter; NETCONF / gNMI / RESTCONF | PLANNED / NOT IMPLEMENTED | FRR image pulled; no adapter code |
| MCP | Server (mcp 2.x) with read / verify / operator roles; token-gated writes; audit | IMPLEMENTED | `tests/mcp/` (real client↔server protocol exchange) |
| Translation | IR → Junos / EOS renderers; behavioural equivalence on intents in Batfish | PARTIALLY IMPLEMENTED (not SMT; IR subset) | 10/10 equivalent (`translation_validation.json`) |
| Intent | Declarative Pydantic intents | IMPLEMENTED (not OpenConfig/YANG) | `configs/intents.yaml` |
| Benchmark | Generator (dev/test/legacy splits), 7 conditions, metrics, bootstrap CIs, manifests, report | IMPLEMENTED | `benchmark/results/REPORT.md` |
| UI | Streamlit dashboard showing component labels; no hardcoded success text | IMPLEMENTED | `test_dashboard_loads` |

## Breaking changes from the pre-audit code

These are listed so that old callers can migrate.

| Old | New |
|---|---|
| `agent/llm_interface.LLMDiagnosticInterface` | Use `agent.llm_agents.LLMDiagnoser` with an explicit provider, or `agent.rule_based_diagnoser`. `llm_interface.py` is now a facade. |
| `core/batfish_verifier.BatfishVerifier` | `core.verification.make_verifier("batfish" or "local", topology)` |
| `core/transactional_actuator.TransactionalActuator` | `core.actuation.transaction.TransactionEngine` |
| `ConfigurationPatch.command_block` (raw CLI) | `core.patch_ops.PatchPlan` (typed ops); CLI text is rendered for display (`render_diff`) |
| `evaluation/run_benchmark.py`, `generate_report.py` | `benchmark/run_benchmark.py`, `benchmark/report.py` |
| Legacy results and figures | `legacy/2026-11_pre_audit/` (withdrawn) |
| `vlan10` / `vlan20` host SVIs | Routed ports `eth10` / `eth20`. Batfish deactivates SVIs that have no member ports. |
