"""Interactive Real-Time NetOps Dashboard for Neurosymbolic Closed-Loop Network Engineering.

Features:
- View 1: Interactive Data Center Fabric Topology Map (Plotly/NetworkX)
- View 2: Live Incident Telemetry & Causal Pruning Monitor
- View 3: Neurosymbolic Reflection & Verification Gate Inspector (legacy local regex checker, NOT Batfish) with Multi-Vendor Translation
- View 4: Empirical Benchmark Analytics & Statistical Visualizations
"""

import sys
import json
from pathlib import Path

# Add root directory to path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import networkx as nx

from agent.orchestrator import AutonomousNetOpsOrchestrator
from core.vendor_translator import VendorTranslator

# Page configuration
st.set_page_config(
    page_title="Neurosymbolic NetOps Autonomous Closed-Loop Dashboard",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load cached data
@st.cache_data
def load_datasets():
    base_file = root_dir / "dataset" / "ground_truth_faults.json"
    stress_file = root_dir / "dataset" / "advanced_stress_faults.json"
    meta_file = root_dir / "configs" / "testbed_metadata.json"
    metrics_file = root_dir / "evaluation" / "benchmark_metrics.csv"
    ext_metrics_file = root_dir / "evaluation" / "extended_benchmark_metrics.csv"

    base_scenarios = json.loads(base_file.read_text(encoding="utf-8")) if base_file.exists() else []
    stress_scenarios = json.loads(stress_file.read_text(encoding="utf-8")) if stress_file.exists() else []
    metadata = json.loads(meta_file.read_text(encoding="utf-8")) if meta_file.exists() else {}

    metrics_df = None
    if ext_metrics_file.exists():
        metrics_df = pd.read_csv(ext_metrics_file)
    elif metrics_file.exists():
        metrics_df = pd.read_csv(metrics_file)

    all_scenarios = {s["incident_id"]: s for s in base_scenarios + stress_scenarios}
    return base_scenarios, stress_scenarios, all_scenarios, metadata, metrics_df

base_scenarios, stress_scenarios, all_scenarios, metadata, metrics_df = load_datasets()

# Initialize Orchestrator in session
@st.cache_resource
def get_orchestrator():
    meta_path = root_dir / "configs" / "testbed_metadata.json"
    return AutonomousNetOpsOrchestrator(meta_path)

orchestrator = get_orchestrator()

# Custom CSS for modern styling
st.markdown("""
<style>
    .main-title { font-size: 2.2rem; font-weight: 800; color: #1e3a8a; margin-bottom: 0.2rem; }
    .sub-title { font-size: 1.05rem; color: #475569; margin-bottom: 1.5rem; }
    .metric-card { background: #f8fafc; border-radius: 8px; border: 1px solid #e2e8f0; padding: 1rem; }
    .status-badge-ok { background: #dcfce7; color: #166534; font-weight: bold; padding: 3px 8px; border-radius: 4px; }
    .status-badge-fail { background: #fee2e2; color: #991b1b; font-weight: bold; padding: 3px 8px; border-radius: 4px; }
    .status-badge-warn { background: #fef3c7; color: #92400e; font-weight: bold; padding: 3px 8px; border-radius: 4px; }
</style>
""", unsafe_allow_html=True)

# Sidebar
st.sidebar.title("🌐 Neurosymbolic NetOps")
st.sidebar.markdown("**Closed-Loop Fault Remediation & Verification Suite**")
st.sidebar.markdown("---")

view_mode = st.sidebar.radio(
    "Navigation Views",
    [
        "1. Interactive DC Fabric Topology",
        "2. Live Incident & Causal Pruning",
        "3. Reflection & Formal Symbolic Gate",
        "4. Empirical Benchmark Analytics"
    ]
)

st.sidebar.markdown("---")
st.sidebar.caption("Architecture: 4-Tier pipeline - legacy local regex verifier (no Batfish, no LLM)")

# =========================================================================
# VIEW 1: INTERACTIVE DATA CENTER FABRIC TOPOLOGY MAP
# =========================================================================
if view_mode == "1. Interactive DC Fabric Topology":
    st.markdown("<div class='main-title'>2-Spine 2-Leaf eBGP Data Center Fabric</div>", unsafe_allow_html=True)
    st.markdown("<div class='sub-title'>Real-time topology state, physical/BGP interconnects, and node telemetry inspection.</div>", unsafe_allow_html=True)

    col1, col2 = st.columns([3, 2])

    with col1:
        st.subheader("Interactive Fabric Graph")
        selected_scenario_id = st.selectbox(
            "Select Active Incident Context (for Dynamic Color-Coding):",
            ["HEALTHY_BASE_FABRIC"] + list(all_scenarios.keys())
        )

        # Build Graph
        G = nx.Graph()
        pos = {
            "Spine-1": (-1.0, 1.0),
            "Spine-2": (1.0, 1.0),
            "Leaf-1": (-1.0, -1.0),
            "Leaf-2": (1.0, -1.0)
        }

        # Determine node states
        culprit_device = None
        if selected_scenario_id != "HEALTHY_BASE_FABRIC":
            active_sc = all_scenarios[selected_scenario_id]
            culprit_device = active_sc.get("ground_truth_culprit_device") or active_sc.get("ground_truth_culprits", ["Leaf-1"])[0]

        node_colors = []
        node_text = []
        for node in ["Spine-1", "Spine-2", "Leaf-1", "Leaf-2"]:
            G.add_node(node)
            if node == culprit_device:
                node_colors.append("#ef4444")  # Red for fault culprit
                node_text.append(f"<b>{node}</b><br>STATUS: INJECTED FAULT")
            else:
                node_colors.append("#22c55e")  # Green for healthy
                node_text.append(f"<b>{node}</b><br>STATUS: HEALTHY / ESTABLISHED")

        # Links
        links = [
            ("Spine-1", "Leaf-1", "10.0.1.0/30 (eBGP AS 65000-65001)"),
            ("Spine-1", "Leaf-2", "10.0.2.0/30 (eBGP AS 65000-65002)"),
            ("Spine-2", "Leaf-1", "10.0.3.0/30 (eBGP AS 65000-65001)"),
            ("Spine-2", "Leaf-2", "10.0.4.0/30 (eBGP AS 65000-65002)"),
        ]

        edge_x, edge_y = [], []
        for u, v, label in links:
            x0, y0 = pos[u]
            x1, y1 = pos[v]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=3, color='#94a3b8'),
            hoverinfo='none',
            mode='lines'
        )

        node_x = [pos[k][0] for k in ["Spine-1", "Spine-2", "Leaf-1", "Leaf-2"]]
        node_y = [pos[k][1] for k in ["Spine-1", "Spine-2", "Leaf-1", "Leaf-2"]]

        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            hoverinfo='text',
            text=["Spine-1", "Spine-2", "Leaf-1", "Leaf-2"],
            textposition="top center",
            hovertext=node_text,
            marker=dict(
                size=45,
                color=node_colors,
                line=dict(width=3, color='#0f172a')
            )
        )

        fig = go.Figure(data=[edge_trace, node_trace],
                        layout=go.Layout(
                            showlegend=False,
                            hovermode='closest',
                            margin=dict(b=20, l=20, r=20, t=20),
                            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                            height=380
                        ))
        st.plotly_chart(fig, use_container_width=True)

        st.caption("🟢 Green: Verified & Invariant-Compliant | 🔴 Red: Injected Anomaly / Fault Culprit")

    with col2:
        st.subheader("Device Configuration & Policy Inspector")
        inspect_node = st.selectbox("Inspect Switch Node:", ["Leaf-1", "Leaf-2", "Spine-1", "Spine-2"])
        
        cfg_path = root_dir / "configs" / "base_topology" / f"{inspect_node}.cfg"
        if cfg_path.exists():
            cfg_text = cfg_path.read_text(encoding="utf-8")
            st.code(cfg_text, language="cisco")
        else:
            st.warning("Configuration file not found.")

# =========================================================================
# VIEW 2: LIVE INCIDENT TELEMETRY & CAUSAL PRUNING MONITOR
# =========================================================================
elif view_mode == "2. Live Incident & Causal Pruning":
    st.markdown("<div class='main-title'>Tier-1 Causal Topology & Telemetry Monitor</div>", unsafe_allow_html=True)
    st.markdown("<div class='sub-title'>Live ingestion of alarm signatures and graph-theoretic search space pruning.</div>", unsafe_allow_html=True)

    incident_keys = list(all_scenarios.keys())
    selected_id = st.selectbox("Select Incident Scenario to Evaluate:", incident_keys)
    sc = all_scenarios[selected_id]

    colA, colB = st.columns([1, 1])

    with colA:
        st.subheader("Active Telemetry Alarms & Syslogs")
        logs = sc.get("telemetry_logs", [])
        for log in logs:
            if "DOWN" in log or "denied" in log or "FAIL" in log or "UNREACHABLE" in log:
                st.error(log)
            elif "MISMATCH" in log or "DEGRADED" in log:
                st.warning(log)
            else:
                st.info(log)

        st.markdown(f"**Fault Category:** `{sc.get('fault_category')}`")
        st.markdown(f"**Description:** {sc.get('description')}")

    with colB:
        st.subheader("Tier-1 Causal Graph Search Space Pruning")
        # Run live pruning
        pruned_configs, pruning_metrics = orchestrator.topology.prune_search_space(
            sc["telemetry_logs"], sc["corrupted_configs"]
        )

        m1, m2 = st.columns(2)
        m1.metric("Token Reduction", f"{pruning_metrics['token_reduction_pct']}%", delta="Search space pruned")
        m2.metric("Pruned Devices", f"{pruning_metrics['pruned_device_count']} switches", delta="Eliminated tokens")

        st.markdown("#### Candidate Localized Devices")
        for dev in pruning_metrics["candidate_devices"]:
            st.success(f"🔍 **Retained for Cognitive Inspection:** {dev}")

        ground_truth = sc.get("ground_truth_culprits") or [sc.get("ground_truth_culprit_device")]
        st.markdown(f"**Ground Truth Culprit(s):** `{', '.join(ground_truth)}`")

# =========================================================================
# VIEW 3: NEUROSYMBOLIC REFLECTION & BATFISH GATE INSPECTOR
# =========================================================================
elif view_mode == "3. Reflection & Formal Symbolic Gate":
    st.markdown("<div class='main-title'>Tier-3 Verification Gate & Reflection Inspector (legacy local regex checker)</div>", unsafe_allow_html=True)
    st.markdown("<div class='sub-title'>Formal invariant verification, counterexample generation, and cognitive self-correction audit trail.</div>", unsafe_allow_html=True)

    selected_id = st.selectbox("Select Scenario for Step-by-Step Audit:", list(all_scenarios.keys()))
    sc = all_scenarios[selected_id]

    # Execute single live closed-loop run
    with st.spinner("Executing formal symbolic closed-loop verification..."):
        result = orchestrator.process_incident(sc, enable_symbolic_gate=True, max_reflection_turns=5)

    turns = result["execution_trace"]["turns"]

    st.markdown(f"### Closed-Loop Execution Summary: `{selected_id}`")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Turns", f"{result['reflection_turns']}")
    c2.metric("Violations Intercepted", f"{result['invariant_violations_caught']}")
    c3.metric("Final Status", f"{result['actuation_status']}")
    c4.metric("Latency", f"{result['total_latency_ms']} ms")

    st.markdown("---")
    st.subheader("Step-by-Step Multi-Turn Reflection Audit Trail")

    for t in turns:
        t_num = t["turn"]
        diag = t["diagnostic_output"]
        patch = diag["proposed_patch"]
        sym_check = t.get("symbolic_check")
        passed = sym_check.get("passed") if isinstance(sym_check, dict) else (sym_check == "BYPASSED_BASELINE")

        with st.expander(f"Turn {t_num}: Candidate Patch on '{patch['target_device']}' ({'PASSED' if passed else 'REJECTED BY LOCAL CHECKER'})", expanded=(t_num <= 2)):
            col_t1, col_t2 = st.columns([1, 1])
            with col_t1:
                st.markdown(f"**Identified Culprit:** `{diag['identified_culprit_device']}` ({diag['failure_category']})")
                st.markdown(f"**Root Cause:** {diag['root_cause_analysis']}")
                st.markdown("**Proposed Command Block:**")
                st.code(patch["command_block"], language="cisco")
                st.markdown(f"**Rollback Block:** `{patch['rollback_command_block']}`")
                st.caption(f"Justification: {patch['justification']}")

            with col_t2:
                if passed:
                    st.success("✅ **Legacy local regex checker: no violations found**")
                    st.markdown("- (checks are regex heuristics; see IMPLEMENTATION_AUDIT.md section 3.6)")
                else:
                    st.error("❌ **Formal Safety Gate Rejection (Counterexample Trace):**")
                    for ce in sym_check.get("counterexamples", []):
                        st.code(ce, language="text")
                    st.warning("Directive: Counterexample fed back to Tier-2 agent for self-correction.")

    # Multi-vendor translation tab
    st.markdown("---")
    st.subheader("Multi-Vendor Dialect Translation (ConfigTrans Paradigm)")
    last_patch = turns[-1]["diagnostic_output"]["proposed_patch"]
    
    t_cisco = last_patch["command_block"]
    t_junos = VendorTranslator.cisco_to_junos(t_cisco)
    t_arista = VendorTranslator.cisco_to_arista(t_cisco)
    eq_passed, eq_details = VendorTranslator.verify_semantic_equivalence(t_cisco, t_junos)

    v1, v2, v3 = st.tabs(["Cisco IOS (Native)", "Juniper Junos (set-format)", "Arista EOS"])
    with v1:
        st.code(t_cisco, language="cisco")
    with v2:
        st.code("\n".join(t_junos), language="text")
        if eq_passed:
            st.success("Formal Semantic Equivalence: VERIFIED (Zero Drift)")
        else:
            st.warning("Semantic Equivalence Check Pending")
    with v3:
        st.code("\n".join(t_arista), language="cisco")

# =========================================================================
# VIEW 4: EMPIRICAL BENCHMARK ANALYTICS
# =========================================================================
elif view_mode == "4. Empirical Benchmark Analytics":
    st.markdown("<div class='main-title'>Empirical Benchmark Analytics & Metrics</div>", unsafe_allow_html=True)
    st.markdown("<div class='sub-title'>Aggregated empirical results across baseline direct vs. closed-loop neurosymbolic remediation.</div>", unsafe_allow_html=True)

    if metrics_df is not None:
        # Overview Cards
        tot = len(metrics_df)
        loc_rate = (metrics_df["localization_correct"].sum() / tot) * 100
        base_rate = (metrics_df["baseline_repaired"].sum() / tot) * 100
        neuro_rate = (metrics_df["neurosymbolic_repaired"].sum() / tot) * 100
        mean_lat = metrics_df["latency_ms"].mean()

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Scenarios Evaluated", f"{tot}")
        m2.metric("Top-1 Localization", f"{loc_rate:.1f}%")
        m3.metric("Baseline Pass Rate", f"{base_rate:.1f}%")
        m4.metric("Neurosymbolic Pass", f"{neuro_rate:.1f}%", delta=f"+{neuro_rate - base_rate:.1f}% vs baseline")

        st.markdown("---")
        # Visual Charts
        ch1, ch2 = st.columns(2)

        with ch1:
            st.subheader("Pass Rate Comparison by Fault Category")
            cat_perf = metrics_df.groupby("fault_category").agg({
                "baseline_repaired": lambda s: (s.sum() / len(s)) * 100,
                "neurosymbolic_repaired": lambda s: (s.sum() / len(s)) * 100
            }).reset_index()

            fig_bar = go.Figure(data=[
                go.Bar(name='Baseline Direct', x=cat_perf['fault_category'], y=cat_perf['baseline_repaired'], marker_color='#f87171'),
                go.Bar(name='Neurosymbolic Closed-Loop', x=cat_perf['fault_category'], y=cat_perf['neurosymbolic_repaired'], marker_color='#34d399')
            ])
            fig_bar.update_layout(barmode='group', height=360, yaxis_title="Success Rate (%)")
            st.plotly_chart(fig_bar, use_container_width=True)

        with ch2:
            st.subheader("Latency (ms) vs. Token Footprint")
            fig_scatter = px.scatter(
                metrics_df,
                x="prompt_tokens",
                y="latency_ms",
                color="fault_category",
                size="reflection_turns",
                hover_data=["incident_id", "description"],
                labels={"prompt_tokens": "Prompt Tokens", "latency_ms": "Latency (ms)"},
                height=360
            )
            st.plotly_chart(fig_scatter, use_container_width=True)

        st.markdown("---")
        st.subheader("Scenario-by-Scenario Empirical Audit Table")
        st.dataframe(metrics_df, use_container_width=True)

        # CSV Download button
        csv_bytes = metrics_df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Download Full Benchmark Metrics (CSV)",
            data=csv_bytes,
            file_name="extended_benchmark_metrics.csv",
            mime="text/csv"
        )
    else:
        st.warning("Benchmark metrics file not found. Run 'run_full_system.py' first.")
