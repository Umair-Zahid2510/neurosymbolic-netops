# WITHDRAWN RESULTS — DO NOT CITE

These files were produced by the project as it existed before the 2026-11-08 audit
(see `../../IMPLEMENTATION_AUDIT.md`). They are kept only for traceability.

They are reproducible from git commit `e649acf`, but they do **not** measure what they claim:

- No LLM was invoked; diagnosis was a hand-written rule cascade.
- Two "self-correction" cases were produced by branches keyed on the incident IDs
  `FAULT_ACL_001` and `FAULT_BGP_003`.
- "Batfish" verification was a local regex checker; Batfish was never queried.
- Rollback was unreachable by construction; latency was dominated by `time.sleep`.
- Token counts were `len(text) // 4` of prompts that were never sent.

Current results live in `benchmark/results/` and are documented in `EXPERIMENTAL_METHODOLOGY.md`.
