# Architecture

The system is a four-tier closed loop. A vendor-neutral **configuration IR** and **typed patch operations** sit underneath all four tiers. Every result names the component that produced it. Each component carries one of these labels:

- **Reasoning:** `rule_based`, `llm:<provider>/<model>`, or `replay:<provider>/<model>`.
- **Verification:** `local_symbolic`, `ir_static`, or `batfish`.
- **Actuation:** `inmemory/SIMULATED`.

```mermaid
flowchart TD
    subgraph T1["Tier 1 · Telemetry (core/telemetry, core/causal_topology.py)"]
        G["generator.py<br/>SYNTHETIC telemetry derived from simulated state"] --> N["normalize.py<br/>syslog/counters/probes → TelemetryEvent"]
        N --> E["anomaly.py EdgeDetector<br/>TF-IDF+LR syslog classifier · robust z-score · probe loss"]
        E --> D["IncidentDigest (typed AnomalyEvents)"]
        D --> R["TopologyGraph.rank_candidates<br/>evidence × topology proximity"]
    end
    subgraph T2["Tier 2 · Agents (agent/)"]
        S["Supervisor<br/>state machine · budgets · partial-progress policy"] --> DA["DiagnosticAgent<br/>rule_based | LLM + read-only skills"]
        DA --> PA["PlanningAgent<br/>typed PatchPlan"]
    end
    subgraph T3["Tier 3 · Verification (core/verification)"]
        VA["VerificationAgent (never an LLM)"] --> LS["local_symbolic<br/>network_model.py"]
        VA --> BF["batfish<br/>pybatfish service"]
        VA --> IS["ir_static<br/>link + BGP-peer consistency"]
    end
    subgraph T4["Tier 4 · Actuation (core/actuation)"]
        EA["ExecutionAgent"] --> TX["TransactionEngine<br/>capture → candidate → syntax → verify → prepare →<br/>authorize (one-time HMAC token) → apply → post-check → commit | rollback"]
        TX --> AD["InMemoryAdapter (SIMULATED, fault injection)"]
        TX --> AU["AuditLog (HMAC-SHA256 chain)"]
    end
    R --> S
    PA --> VA
    VA -- "counterexamples" --> PA
    VA -- "verified" --> AP["Approval policy → token bound to plan hash + candidate fingerprint"] --> EA
    MCP["mcp_server/server.py<br/>roles read | verify | operator"] -.-> DA
    MCP -.-> VA
    MCP -.-> TX
```

## Incident state machine (`agent/workflow.py`)

```mermaid
stateDiagram-v2
    [*] --> DETECTED
    DETECTED --> DIAGNOSING
    DIAGNOSING --> ROOT_CAUSE_IDENTIFIED
    ROOT_CAUSE_IDENTIFIED --> PLANNING
    PLANNING --> VERIFYING
    PLANNING --> PLANNING: invalid plan
    VERIFYING --> PLANNING: rejected (counterexamples)
    VERIFYING --> DIAGNOSING: partial progress / re-diagnose
    VERIFYING --> APPROVED: verified + approved
    APPROVED --> EXECUTING
    EXECUTING --> POST_CHECK
    EXECUTING --> ROLLBACK: apply failure / timeout
    POST_CHECK --> COMPLETED
    POST_CHECK --> ROLLBACK: observed state violates intents
    ROLLBACK --> FAILED
    DIAGNOSING --> FAILED
    PLANNING --> FAILED
    VERIFYING --> FAILED: budget exhausted / approval denied
```

Illegal transitions raise `IllegalTransition`. The `IncidentRecord` stores the following:

- every transition;
- the digest and ranked candidates;
- every diagnosis and skill call, each with its evidence ID;
- every plan attempt, with its verification backends, the violations before and after, the new violations, the counterexamples and the disposition;
- the approval token, the transaction steps, the timings and the provider-reported LLM usage.

## Agents and their tool access

| Agent | Input → output | Tools | LLM? |
|---|---|---|---|
| DiagnosticAgent | digest, candidates, feedback → `DiagnosisReport` (hypotheses with evidence IDs) | read-only skills | strategy-dependent |
| PlanningAgent | hypotheses, configs, counterexamples → `PatchPlan` (typed ops only) | read-only skills | strategy-dependent |
| VerificationAgent | network → `VerificationReport` | verifier backends | **never** |
| ExecutionAgent | plan + approval token → `TransactionRecord` | transaction engine (write side) | never |
| Supervisor | orchestrates; owns budgets, the reflection policy, approval and the record | – | never |

## Key data contracts

| Contract | Module |
|---|---|
| `DeviceConfig` / `Network` (IR) | `core/config_ir.py` |
| `PatchOp` (14 kinds), `PatchPlan` (with stable `plan_hash`) | `core/patch_ops.py` |
| Intents (7 kinds) | `core/intent_schema.py`, `configs/intents.yaml` |
| `TelemetryEvent`, `AnomalyEvent`, `IncidentDigest` | `core/telemetry/schema.py` |
| `Hypothesis`, `DiagnosisReport`, `PlanProposal`, `LLMUsage` | `agent/contracts.py` |
| `CheckResult`, `Counterexample`, `VerificationReport` | `core/verification/base.py` |
| `ApprovalToken`, `TransactionRecord`, audit entries | `core/actuation/` |

## Interface name mapping

The IR uses canonical names. `parse_ios` maps vendor names to canonical ones, and the renderers map them back.

| IR | Cisco IOS | Arista EOS | Junos |
|---|---|---|---|
| `ethN` | `GigabitEthernet0/N` | `EthernetN` | `ge-0/0/N` (unit 0) |

The host LANs are routed ports: `eth10` on Leaf-1 and `eth20` on Leaf-2. Batfish deactivates Vlan SVIs that have no member switchports, which broke the original `vlan10`/`vlan20` design.

## Verification backends

| Backend | What it evaluates | Notes |
|---|---|---|
| `local_symbolic` | BGP sessions, reachability (every ECMP branch), redundancy (transit-disjoint paths), isolation, forwarding loops | Deterministic model in `core/network_model.py`, about 12 ms per verification |
| `ir_static` | link consistency (MTU, speed, duplex) and BGP peer consistency (remote AS, MD5 password, address-family activation) | Configuration invariants that Batfish does not model |
| `batfish` | `bgpSessionStatus`, `bgpSessionCompatibility`, `traceroute`, `detectLoops`, `fileParseStatus` | Real service; ~9 s per cold snapshot; snapshots cached by a hash of the rendered config text |

The verifier is always a composite: the forwarding backend (`local_symbolic` or `batfish`) plus `ir_static`. An intent passes only if no backend reports a violation and at least one backend evaluated it. A network with any unparsed configuration line cannot pass.
