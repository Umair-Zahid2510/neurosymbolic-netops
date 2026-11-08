# Neurosymbolic NetOps Framework

Autonomous Fault Diagnosis and Closed-Loop Remediation in Telecommunication and Data Center Networks.

Realizes the 4-tier closed-loop pipeline from the survey paper:
- **Tier-1**: Structural Telemetry Preprocessing & Causal Topology Graph (`core/causal_topology.py`)
  - Graph-theoretic search space pruning and anti-manufactured causality noise filtering.
- **Tier-2**: Cognitive SADE Diagnostic Agent & Declarative Intent Engine (`core/diagnostic_skills.py`, `core/intent_schema.py`, `agent/llm_interface.py`)
  - Read-only telemetry inspection, AST parsing, and Pydantic schema validation.
- **Tier-3**: Formal Symbolic Safety Gate & Batfish Invariant Reflection Loop (`core/batfish_verifier.py`)
  - Multi-turn convergence checking reachability, loop freedom, BGP convergence, and security policy invariants.
- **Tier-4**: Transactional Actuator & Sliding-Window Watchdog Rollback (`core/transactional_actuator.py`)
  - Two-phase commit emulation with continuous multi-sample post-validation probing and instant auto-rollback.
- **Cross-Cutting**: Multi-Vendor Dialect Translator (`core/vendor_translator.py`)
  - ConfigTrans paradigm: cross-translation between Cisco IOS, Juniper Junos, and Arista EOS with formal semantic equivalence checking.

---

## Quickstart

### 1. Installation
```bash
pip install -r requirements.txt
```

### 2. Run Master Suite (25 Scenarios: 15 Base + 10 Advanced Stress)
```bash
python run_full_system.py
```
This executes:
- 15 Core Scenarios (LINK, BGP, ACL)
- 5 Combinatorial Multi-Fault Scenarios ($k \ge 3$)
- 5 Saturated Noisy Telemetry Scenarios (Anti-Manufactured Causality Engine)
- Saves `evaluation/extended_benchmark_metrics.csv` and regenerates `BENCHMARK_RESULTS.md` and charts.

### 3. Launch Interactive Streamlit NetOps Dashboard
```bash
streamlit run dashboard/app.py
```
Features 4 comprehensive views:
1. **Interactive DC Fabric Topology Map:** Interactive Plotly/NetworkX visualization of the 2-Spine 2-Leaf fabric with dynamic node status color-coding and live configuration inspection.
2. **Live Incident & Causal Pruning Monitor:** Active syslog streams, culprit identification, and token reduction metrics (~44.2% token savings).
3. **Reflection & Formal Symbolic Gate Inspector:** Step-by-step multi-turn reflection audit trail, Batfish counterexample trace visualization, and multi-vendor dialect translation (Cisco/Junos/Arista).
4. **Empirical Benchmark Analytics:** Interactive Plotly analytics, latency vs. token footprint scatterplots, baseline vs. neurosymbolic comparisons, and raw CSV download.

---

## Deliverables & Artifacts
- `BENCHMARK_RESULTS.md`: Complete empirical evaluation report with category breakdowns and execution traces.
- `evaluation/extended_benchmark_metrics.csv`: Full 25-scenario evaluation metrics.
- `evaluation/accuracy_comparison.png`: Accuracy & pass-rate bar chart across all 5 categories.
- `evaluation/latency_breakdown.png`: Wall-clock latency vs. token consumption chart.
- `dashboard/app.py`: Streamlit real-time dashboard application.
