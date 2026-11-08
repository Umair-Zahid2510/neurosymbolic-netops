"""Streamlit dashboard for the neurosymbolic NetOps workflow.

streamlit run dashboard/app.py

Every view shows which component produced the data (rule_based / llm / replay reasoning,
local_symbolic / batfish / ir_static verification, SIMULATED in-memory adapter). No success
text is hardcoded: everything shown comes from an executed incident record or a results file.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import networkx as nx
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.orchestrator import SystemConfig, run_incident  # noqa: E402
from benchmark.faults import NOVEL_TEMPLATES, TEMPLATES, bgp_pairs, fabric_links  # noqa: E402
from core.actuation.adapters import FaultInjection  # noqa: E402
from core.inventory import load_testbed  # noqa: E402
from core.network_model import compute_state  # noqa: E402
from core.patch_ops import PatchPlan, SetInterfaceEnabled, apply_plan  # noqa: E402
from core.telemetry.generator import GeneratorOptions  # noqa: E402

st.set_page_config(page_title="Neurosymbolic NetOps", layout="wide")


@st.cache_resource
def testbed():
    return load_testbed()


tb = testbed()
ALL = {**TEMPLATES, **NOVEL_TEMPLATES}

st.sidebar.title("Neurosymbolic NetOps")
st.sidebar.caption("Testbed: 2-spine / 2-leaf eBGP fabric (configuration-level model; no live devices)")
view = st.sidebar.radio("View", ["Run an incident", "Topology", "Benchmark results"])


def location_args(template: str):
    if template in ("remote_as_mismatch", "md5_unilateral", "neighbor_deactivated", "route_map_drop", "route_map_prefix_filter"):
        opts = [f"{d}|{n}" for d, n in bgp_pairs(tb.network)]
        d, n = st.sidebar.selectbox("BGP session", opts).split("|")
        return dict(dev=d, nbr=n)
    if template in ("missing_network", "acl_deny_lan", "acl_supernet_deny", "acl_deny_service"):
        devs = [d for d in tb.network if tb.topology.metadata["nodes"][d]["role"] == "leaf"]
        return dict(dev=st.sidebar.selectbox("Device", devs))
    opts = [f"{a}|{ai}" for a, ai, _, _ in fabric_links(tb.topology)] + [f"{b}|{bi}" for _, _, b, bi in fabric_links(tb.topology)]
    d, i = st.sidebar.selectbox("Interface", sorted(opts)).split("|")
    return dict(dev=d, intf=i)


def topo_figure(net, highlight=()):
    st_ = compute_state(net, tb.topology)
    g = nx.Graph()
    pos = {"Spine-1": (0, 1), "Spine-2": (2, 1), "Leaf-1": (0, 0), "Leaf-2": (2, 0)}
    fig = go.Figure()
    for ls in st_.links:
        x0, y0 = pos[ls.a_dev]; x1, y1 = pos[ls.b_dev]
        color = "#2ca02c" if ls.up and not ls.degraded else ("#ff7f0e" if ls.up else "#d62728")
        fig.add_trace(go.Scatter(x=[x0, x1], y=[y0, y1], mode="lines", line=dict(color=color, width=4),
                                 hoverinfo="text", text=f"{ls.a_dev}:{ls.a_intf} - {ls.b_dev}:{ls.b_intf} "
                                 f"{'UP' if ls.up else 'DOWN'} {'; '.join(ls.down_reasons + ls.degraded)}"))
    for d, (x, y) in pos.items():
        fig.add_trace(go.Scatter(x=[x], y=[y], mode="markers+text", text=[d], textposition="top center",
                                 marker=dict(size=34, color="#d62728" if d in highlight else "#1f77b4")))
    fig.update_layout(showlegend=False, height=360, xaxis=dict(visible=False), yaxis=dict(visible=False),
                      margin=dict(l=10, r=10, t=10, b=10))
    return fig, st_


if view == "Run an incident":
    st.title("Closed-loop incident workflow")
    template = st.sidebar.selectbox("Fault template", sorted(ALL))
    kw = location_args(template)
    reasoning = st.sidebar.selectbox("Reasoning", ["rule_based", "llm", "offline"])
    verifier = st.sidebar.selectbox("Verifier", ["local", "batfish", "none"])
    deploy_fault = st.sidebar.selectbox("Deployment fault (SIMULATED)", ["none", "apply failure", "timeout", "post-check failure"])
    noisy = st.sidebar.checkbox("Noisy telemetry", value=True)
    if st.sidebar.button("Run incident", type="primary"):
        f = ALL[template](tb.network, tb.topology, **kw)
        faulty = apply_plan(tb.network, f.inject)
        provider = None
        if reasoning != "rule_based":
            from agent.llm.base import provider_from_env
            try:
                provider = provider_from_env(reasoning)
            except Exception as exc:
                st.error(f"LLM provider unavailable: {exc}")
                st.stop()
        faults = FaultInjection()
        if deploy_fault == "apply failure":
            faults = FaultInjection(fail_apply_on={f.culprit})
        elif deploy_fault == "timeout":
            faults = FaultInjection(timeout_on={f.culprit})
        elif deploy_fault == "post-check failure":
            first = f.inject.ops[0]
            if getattr(first, "interface", None):
                faults = FaultInjection(runtime_effect=PatchPlan(ops=[SetInterfaceEnabled(device=first.device, interface=first.interface, enabled=False)]))
        with st.spinner("Running Tier 1 -> Tier 4 ..."):
            run = run_incident(tb, f"UI-{template}", faulty, SystemConfig(reasoning=reasoning, verifier=verifier,
                               llm_provider=provider, adapter_faults=faults),
                               GeneratorOptions(seed=7, noise_rate=3.0 if noisy else 1.0, decoys=noisy))
        st.session_state["run"] = run
        st.session_state["fault"] = f
        st.session_state["faulty"] = faulty
    run = st.session_state.get("run")
    if run:
        r, f = run.record, st.session_state["fault"]
        st.info(f"Components: {json.dumps(r.modes)}")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Outcome", r.outcome)
        c2.metric("Plan attempts", len(r.attempts))
        c3.metric("Skill calls", len(r.tool_calls))
        c4.metric("Total time (ms)", r.timings_ms.get("total"))
        with st.expander("Ground truth (hidden from the agents)", expanded=False):
            st.write(f"[{f.category}] {f.description} - culprit {f.culprit}")
        left, right = st.columns([1, 1])
        with left:
            st.subheader("Topology (faulty network, local model)")
            fig, _ = topo_figure(st.session_state["faulty"], highlight=[h.device for h in r.final_hypotheses[:1]])
            st.plotly_chart(fig, use_container_width=True)
            st.subheader("Tier 1 - anomaly digest")
            st.dataframe(pd.DataFrame([{k: a[k] for k in ("anomaly_id", "kind", "device", "interface", "peer_ip", "count", "detector")}
                                       for a in r.digest["anomalies"]]), use_container_width=True)
            st.caption(f"raw {run.raw_bytes} B -> digest {run.digest_bytes} B; missing data: {r.digest['missing_data'] or 'none'}")
            st.write("Ranked candidates:", [(c["device"], c["score"]) for c in r.candidates])
        with right:
            st.subheader("Workflow state")
            st.code(" -> ".join(["DETECTED"] + [t.to.value for t in r.transitions]))
            st.subheader("Hypotheses")
            for d in r.diagnoses:
                st.caption(f"{d.strategy}: {d.reasoning_summary[:300]}")
                for h in d.hypotheses[:6]:
                    st.write(f"**{h.id}** {h.device} `{h.fault_type}` @ {h.location} - {h.statement}")
            st.subheader("Plans and verification (reflection loop)")
            for a in r.attempts:
                with st.expander(f"Attempt {a.attempt}: {a.disposition} [{', '.join(a.verification_backends)}]",
                                 expanded=a.disposition != "accepted"):
                    for line in (a.plan.describe() if a.plan else [a.plan_error]):
                        st.write("-", line)
                    if a.counterexamples:
                        st.write("Violations after plan:", a.violated_after, " NEW:", a.new_violations)
                        for ce in a.counterexamples[:6]:
                            st.code(ce, language="text")
        if r.transaction:
            st.subheader(f"Tier 4 - transaction {r.transaction.tx_id} ({r.transaction.adapter_label}): {r.transaction.status}")
            st.dataframe(pd.DataFrame([s.model_dump() for s in r.transaction.steps]), use_container_width=True)
            if r.transaction.diff:
                st.code(r.transaction.diff, language="diff")
        st.subheader("Skill call log (evidence)")
        st.dataframe(pd.DataFrame([{"call": c.call_id, "evidence": c.evidence_id, "skill": c.skill, "caller": c.caller,
                                    "ok": c.ok, "ms": c.duration_ms, "source": c.data_source} for c in r.tool_calls]),
                     use_container_width=True, height=240)

elif view == "Topology":
    st.title("Fabric topology and control-plane state (base configuration, local model)")
    fig, s = topo_figure(tb.network)
    st.plotly_chart(fig, use_container_width=True)
    st.dataframe(pd.DataFrame([{"device": x.device, "neighbor": x.neighbor_ip, "peer": x.peer_device, "state": x.state}
                               for x in s.sessions]))
    dev = st.selectbox("Running configuration", sorted(tb.network))
    from core.renderers.ios import render_ios
    st.code(render_ios(tb.network[dev]), language="text")

else:
    st.title("Benchmark results (generated from raw result files)")
    res = sorted((ROOT / "benchmark" / "results").glob("*/summary.json"))
    if not res:
        st.warning("No benchmark results yet. Run: python -m benchmark.run_benchmark")
    for p in res:
        man = json.loads((p.parent / "manifest.json").read_text())
        st.subheader(f"Run {man['run_id']} - oracle={man['oracle']} - commit {man['git_sha'][:8]}")
        if man.get("skipped"):
            st.warning(f"Skipped conditions: {man['skipped']}")
        summ = json.loads(p.read_text())
        rows = []
        for key, s in summ.items():
            rows.append({"condition/split": key, "runs": s["runs"], "top1": s["top1"]["mean"], "repaired": s["repaired"]["mean"],
                         "final intents OK": s["final_intents_satisfied"]["mean"], "unsafe deployed": s["unsafe_deployed"]["mean"],
                         "rolled back": s["rolled_back"]["mean"], "median ms": (s["total_ms"] or {}).get("median")})
        st.dataframe(pd.DataFrame(rows), use_container_width=True)
    for name in ("differential_local_vs_batfish.json", "translation_validation.json", "causal_discovery_pc.json"):
        p = ROOT / "benchmark" / "results" / name
        if p.exists():
            with st.expander(name):
                st.json(json.loads(p.read_text()), expanded=False)
