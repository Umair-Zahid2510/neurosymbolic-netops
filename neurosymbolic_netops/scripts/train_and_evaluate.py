"""Train and evaluate every learned / evaluated methodology, then write results and figures.

python scripts/train_and_evaluate.py            (about 5 minutes; no API key or Batfish needed)

Stages (outputs under results/):
  1. Edge syslog classifier   - train on training phrasings; 5-fold CV; test on held-out phrasings and
                                on telemetry generated for the held-out benchmark incidents; confusion matrix.
  2. Learned root-cause ranker - train on dev-split incidents (5 telemetry seeds each), test on the
                                held-out test split and the legacy split; compare with the topology heuristic.
  3. Closed-loop benchmark    - rule-based conditions C1 / C1b / C1c on all 151 scenarios.
  4. Causal discovery (PC)    - 5 seeds, confounder hidden vs observed.
  5. Report + figures         - results/RESULTS.md, results/figures/*.png, benchmark/results/REPORT.md.
Results that need Batfish or an LLM key (local-vs-Batfish differential, Batfish oracle, translation
equivalence, live LLM demos, Groq pilot) are produced by their own scripts; RESULTS.md links them.
"""

from __future__ import annotations

import json
import logging
import platform
import random
import statistics
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
logging.disable(logging.WARNING)

import matplotlib  # noqa: E402
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from benchmark.generator import SCENARIO_DIR, load_suite  # noqa: E402
from core.inventory import load_testbed  # noqa: E402
from core.telemetry.anomaly import CLASSES, EdgeDetector, SyslogClassifier, build_corpus, mask  # noqa: E402
from core.telemetry.generator import GeneratorOptions, generate  # noqa: E402
from core.telemetry.normalize import Normalizer  # noqa: E402
from core.telemetry.ranker import LearnedRanker, feature_names, featurize, ranking_metrics  # noqa: E402

OUT = ROOT / "results"
FIG = OUT / "figures"
MODELS = ROOT / "models"
SEED = 2026


def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def bootstrap_diff(a, b, n=2000, seed=0):
    rng = random.Random(seed)
    idx = list(range(len(a)))
    diffs = sorted(statistics.fmean(a[i] - b[i] for i in (rng.choices(idx, k=len(idx)))) for _ in range(n))
    return [round(diffs[int(0.025 * n)], 4), round(diffs[int(0.975 * n) - 1], 4)]


# ------------------------------------------------------------------ stage 1
def stage_classifier(tb, suite):
    from sklearn.metrics import classification_report, confusion_matrix, f1_score
    from sklearn.model_selection import StratifiedKFold
    log("stage 1: edge syslog classifier")
    Xtr, ytr = build_corpus(SEED, 60, held_out=False)
    Xte, yte = build_corpus(SEED + 1, 60, held_out=True)
    cv = []
    for k, (a, b) in enumerate(StratifiedKFold(5, shuffle=True, random_state=SEED).split(Xtr, ytr)):
        m = SyslogClassifier(True).fit([Xtr[i] for i in a], [ytr[i] for i in a])
        cv.append(m.evaluate([Xtr[i] for i in b], [ytr[i] for i in b]))
    t0 = time.perf_counter()
    clf = SyslogClassifier(True).fit(Xtr, ytr)
    train_s = time.perf_counter() - t0
    msg_only = SyslogClassifier(False).fit(Xtr, ytr)
    held = clf.evaluate(Xte, yte)
    held_msg = msg_only.evaluate(Xte, yte)
    # realistic test: lines emitted for the held-out benchmark incidents (noise, duplicates, held-out phrasing)
    lines, labels = [], []
    for sc in [s for s in suite if s.split == "test"]:
        t = sc.telemetry
        g = generate(tb.network, sc.faulty_network(tb.network), tb.topology, tb.intents,
                     GeneratorOptions(seed=t.seed, noise_rate=t.noise_rate, decoys=t.decoys, held_out_phrasing=True,
                                      duplicate_prob=t.duplicate_prob, missing_ts_prob=t.missing_ts_prob,
                                      line_drop_prob=t.line_drop_prob, dropout_devices=t.dropout_devices))
        for r, lab in zip(g.records, g.labels):
            if r["type"] == "syslog" and lab in CLASSES:
                lines.append("%" + r["line"].split("%", 1)[1])
                labels.append(lab)
    incident = clf.evaluate(lines, labels)
    pred = clf.predict(Xte)
    cm = confusion_matrix(yte, pred, labels=CLASSES)
    report = classification_report(yte, pred, labels=CLASSES, output_dict=True, zero_division=0)
    MODELS.mkdir(exist_ok=True)
    clf.metrics = {"heldout_phrasing": held, "heldout_phrasing_message_only": held_msg}
    size = clf.save(MODELS / "syslog_classifier.pkl")
    clf.metrics["model_bytes"] = size
    clf.save(MODELS / "syslog_classifier.pkl")
    res = {
        "model": "TF-IDF (word 1-2 grams over masked tokens) + multinomial logistic regression",
        "train_lines": len(Xtr), "train_seconds": round(train_s, 3), "model_bytes": size,
        "cv5_on_training_phrasings": {"accuracy_mean": round(statistics.fmean(c["accuracy"] for c in cv), 4),
                                      "accuracy_std": round(statistics.pstdev(c["accuracy"] for c in cv), 4),
                                      "macro_f1_mean": round(statistics.fmean(c["macro_f1"] for c in cv), 4)},
        "test_heldout_phrasing": held, "test_heldout_phrasing_message_only": held_msg,
        "test_on_heldout_incident_telemetry": incident,
        "per_class_heldout": {c: {k: round(v, 4) for k, v in report[c].items()} for c in CLASSES},
        "confusion_matrix_heldout": {"labels": CLASSES, "matrix": cm.tolist()},
    }
    (MODELS / "syslog_classifier_metrics.json").write_text(json.dumps(clf.metrics, indent=2))
    fig, ax = plt.subplots(figsize=(5.5, 4.5))
    ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(len(CLASSES)), CLASSES, rotation=45, ha="right")
    ax.set_yticks(range(len(CLASSES)), CLASSES)
    for i in range(len(CLASSES)):
        for j in range(len(CLASSES)):
            ax.text(j, i, cm[i, j], ha="center", va="center", fontsize=8, color="white" if cm[i, j] > cm.max() / 2 else "black")
    ax.set_xlabel("predicted"); ax.set_ylabel("true")
    ax.set_title(f"Syslog classifier, held-out phrasings (acc {held['accuracy']:.3f})")
    fig.tight_layout(); fig.savefig(FIG / "classifier_confusion_matrix.png", dpi=160); plt.close(fig)
    log(f"   cv acc {res['cv5_on_training_phrasings']['accuracy_mean']}, held-out acc {held['accuracy']}, "
        f"message-only {held_msg['accuracy']}, incident telemetry {incident['accuracy']}")
    return res, clf


# ------------------------------------------------------------------ stage 2
def incident_digest(tb, sc, detector, seed_offset=0, held_out=None):
    t = sc.telemetry
    opts = GeneratorOptions(seed=t.seed + 7919 * seed_offset, noise_rate=t.noise_rate, decoys=t.decoys,
                            duplicate_prob=t.duplicate_prob, missing_ts_prob=t.missing_ts_prob,
                            line_drop_prob=t.line_drop_prob, dropout_devices=t.dropout_devices,
                            held_out_phrasing=t.held_out_phrasing if held_out is None else held_out)
    net = sc.faulty_network(tb.network)
    g = generate(tb.network, net, tb.topology, tb.intents, opts)
    ev = Normalizer(lambda ip: tb.topology.owner_of_ip(ip, tb.network)).normalize(g.records)
    return net, detector.detect(sc.scenario_id, ev, 0, tb.topology.devices)


def stage_ranker(tb, suite, clf):
    log("stage 2: learned root-cause ranker")
    detector = EdgeDetector(clf)
    names = feature_names()

    def build(split, seeds):
        X, y, groups, meta = [], [], [], []
        for sc in [s for s in suite if s.split == split]:
            for k in range(seeds):
                net, dg = incident_digest(tb, sc, detector, k)
                devs, F = featurize(dg.anomalies, tb.topology, net)
                X.append(F); y += [1 if d in sc.culprits else 0 for d in devs]
                groups.append((sc, devs, F, dg))
        return (np.vstack(X) if X else np.zeros((0, len(names)))), np.asarray(y), groups

    Xtr, ytr, gtr = build("dev", 5)
    log(f"   training rows {len(ytr)} ({int(ytr.sum())} positive) from {len(gtr)} dev incidents")
    model = LearnedRanker(seed=SEED).fit(Xtr, ytr)
    size = model.save(MODELS / "root_cause_ranker.pkl")
    res = {"model": "HistGradientBoostingClassifier (200 iters, lr 0.05, 15 leaves)", "features": names,
           "train_incidents": len(gtr), "train_rows": int(len(ytr)), "model_bytes": size, "splits": {}}
    per_incident = {}
    for split, seeds in (("test", 3), ("legacy", 1)):
        _, _, groups = build(split, seeds)
        heur, learned, truths, h1, l1 = [], [], [], [], []
        for sc, devs, F, dg in groups:
            hr = [c.device for c in tb.topology.rank_candidates(dg.anomalies, sc.faulty_network(tb.network))]
            hr += [d for d in sorted(devs) if d not in hr]
            lr = [d for d, _ in model.rank(devs, F)]
            heur.append(hr); learned.append(lr); truths.append(set(sc.culprits))
            h1.append(1.0 if hr[0] in sc.culprits else 0.0); l1.append(1.0 if lr[0] in sc.culprits else 0.0)
        hm, lm = ranking_metrics(heur, truths), ranking_metrics(learned, truths)
        res["splits"][split] = {"heuristic": hm, "learned": lm,
                                "top1_difference_learned_minus_heuristic_ci95": bootstrap_diff(l1, h1),
                                "random_top1_expected": round(statistics.fmean(len(t) / 4 for t in truths), 4)}
        per_incident[split] = {"heuristic_top1": h1, "learned_top1": l1}
        log(f"   {split}: heuristic top1 {hm['top1']} mrr {hm['mrr']} | learned top1 {lm['top1']} mrr {lm['mrr']}")
    try:
        from sklearn.inspection import permutation_importance
        _, ytest, gtest = build("test", 1)
        Xtest = np.vstack([g[2] for g in gtest])
        pi = permutation_importance(model.model, Xtest, ytest, n_repeats=10, random_state=SEED, scoring="roc_auc")
        order = np.argsort(-pi.importances_mean)[:10]
        res["permutation_importance_test_auc"] = [[names[i], round(float(pi.importances_mean[i]), 4)] for i in order]
    except Exception as exc:  # recorded, not hidden
        res["permutation_importance_error"] = str(exc)
    fig, ax = plt.subplots(figsize=(6.5, 3.6))
    labels, x = ["top-1", "top-3", "MRR", "recall@2"], np.arange(4)
    for k, (split, off) in enumerate((("test", -0.2), ("legacy", 0.2))):
        pass
    t = res["splits"]["test"]
    ax.bar(x - 0.18, [t["heuristic"][m] for m in ("top1", "top3", "mrr", "recall_at_2")], 0.36, label="topology heuristic")
    ax.bar(x + 0.18, [t["learned"][m] for m in ("top1", "top3", "mrr", "recall_at_2")], 0.36, label="learned ranker")
    ax.axhline(t["random_top1_expected"], ls="--", c="grey", lw=1, label="random top-1")
    ax.set_xticks(x, labels); ax.set_ylim(0, 1.05); ax.legend(fontsize=8)
    ax.set_title(f"Root-cause ranking on held-out test split (n={t['learned']['n']} incidents)")
    fig.tight_layout(); fig.savefig(FIG / "ranker_heldout_comparison.png", dpi=160); plt.close(fig)
    return res


# ------------------------------------------------------------------ stage 3
def stage_benchmark():
    log("stage 3: closed-loop benchmark (C1, C1b, C1c; 151 scenarios)")
    before = set((ROOT / "benchmark" / "results").glob("2026*"))
    subprocess.run([sys.executable, "-m", "benchmark.run_benchmark", "--conditions", "C1,C1b,C1c"], cwd=ROOT,
                   check=True, stdout=subprocess.DEVNULL)
    run = sorted(set((ROOT / "benchmark" / "results").glob("2026*")) - before)[-1]
    summ = json.loads((run / "summary.json").read_text())
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.6))
    for ax, metric, title in ((axes[0], "repaired", "Repair success"), (axes[1], "unsafe_deployed", "Unsafe change deployed")):
        x = np.arange(3)
        for k, (cond, lab) in enumerate((("C1", "no gate"), ("C1b", "verification gate"))):
            vals = [summ[f"{cond}/{s}"][metric]["mean"] for s in ("dev", "test", "legacy")]
            err = [[v - summ[f"{cond}/{s}"][metric]["ci95"][0] for v, s in zip(vals, ("dev", "test", "legacy"))],
                   [summ[f"{cond}/{s}"][metric]["ci95"][1] - v for v, s in zip(vals, ("dev", "test", "legacy"))]]
            ax.bar(x + (k - 0.5) * 0.36, vals, 0.36, yerr=err, capsize=3, label=lab)
        ax.set_xticks(x, ["dev (88)", "test (38)", "legacy (25)"]); ax.set_ylim(0, 1.05); ax.set_title(title)
    axes[0].legend(fontsize=8)
    fig.suptitle("Rule-based closed loop: effect of the symbolic verification gate (95% bootstrap CI)", fontsize=10)
    fig.tight_layout(); fig.savefig(FIG / "verification_gate_effect.png", dpi=160); plt.close(fig)
    fig, ax = plt.subplots(figsize=(6.5, 3.4))
    phases = ["detection_ms", "diagnose_ms", "plan_ms", "verify_ms", "execute_ms"]
    left = 0
    for p in phases:
        v = summ["C1b/test"][p]["median"]
        ax.barh(["C1b / test"], [v], left=left, label=p.replace("_ms", ""))
        left += v
    ax.set_xlabel("median ms per incident"); ax.legend(fontsize=8, ncol=5, loc="upper center", bbox_to_anchor=(0.5, -0.35))
    fig.tight_layout(); fig.savefig(FIG / "latency_breakdown.png", dpi=160); plt.close(fig)
    return {"run_id": run.name, "summary": summ}


# ------------------------------------------------------------------ stage 4
def stage_causal(tb):
    log("stage 4: causal discovery (PC) on synthetic SCM")
    from core.causal_discovery import evaluate
    out = {}
    for oc in (False, True):
        runs = [evaluate(tb.topology, tb.network, tb.intents, seed=s, observe_confounder=oc) for s in range(5)]
        keys = [k for k, v in runs[0].items() if isinstance(v, (int, float)) and not isinstance(v, bool) and v is not None]
        out["confounder_observed" if oc else "confounder_hidden"] = {
            "mean_over_5_seeds": {k: round(statistics.fmean(r[k] for r in runs), 3) for k in keys}, "per_seed": runs}
    (ROOT / "benchmark" / "results" / "causal_discovery_pc.json").write_text(json.dumps(out, indent=1))
    fig, ax = plt.subplots(figsize=(5.5, 3.4))
    x = np.arange(2)
    h, o = out["confounder_hidden"]["mean_over_5_seeds"], out["confounder_observed"]["mean_over_5_seeds"]
    ax.bar(x - 0.18, [h["pc_skeleton_precision"], o["pc_skeleton_precision"]], 0.36, label="PC")
    ax.bar(x + 0.18, [h["correlation_precision"], o["correlation_precision"]], 0.36, label="|correlation| > 0.3")
    ax.set_xticks(x, ["confounder hidden", "confounder observed"]); ax.set_ylim(0, 1.05)
    ax.set_ylabel("edge precision vs ground truth"); ax.legend(fontsize=8); ax.set_title("Causal discovery (synthetic SCM)")
    fig.tight_layout(); fig.savefig(FIG / "causal_discovery_precision.png", dpi=160); plt.close(fig)
    return {k: v["mean_over_5_seeds"] for k, v in out.items()}


# ------------------------------------------------------------------ report
def write_report(cls, rk, bench, causal, wall):
    sh = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip() or "unknown"
    s = bench["summary"]
    g = lambda k, m: s[k][m]["mean"]
    t = rk["splits"]["test"]; lg = rk["splits"]["legacy"]
    lines = [
        "# Training and Evaluation Results", "",
        f"Generated by `python scripts/train_and_evaluate.py` on {datetime.now(timezone.utc).isoformat(timespec='seconds')} "
        f"(commit `{sh[:10]}`, Python {platform.python_version()}, wall time {wall:.0f} s). Every number below is read "
        "from the JSON written by that run (`results/*.json`, `benchmark/results/`).", "",
        "All telemetry is SYNTHETIC and deployment uses the SIMULATED in-memory adapter (see LIMITATIONS.md).", "",
        "## 1. Edge syslog classifier (trained)", "",
        f"- Model: {cls['model']}; {cls['train_lines']} training lines; trained in {cls['train_seconds']} s; {cls['model_bytes']} bytes.",
        f"- 5-fold CV on training phrasings: accuracy {cls['cv5_on_training_phrasings']['accuracy_mean']} "
        f"(± {cls['cv5_on_training_phrasings']['accuracy_std']}), macro-F1 {cls['cv5_on_training_phrasings']['macro_f1_mean']}.",
        f"- **Test, held-out phrasings:** accuracy {cls['test_heldout_phrasing']['accuracy']}, macro-F1 {cls['test_heldout_phrasing']['macro_f1']}, "
        f"{cls['test_heldout_phrasing']['latency_us_per_line']} µs/line.",
        f"- **Test, held-out phrasings with the syslog mnemonic removed:** accuracy {cls['test_heldout_phrasing_message_only']['accuracy']}, "
        f"macro-F1 {cls['test_heldout_phrasing_message_only']['macro_f1']}. The mnemonic carries most of the signal.",
        f"- **Test, every syslog line emitted for the 38 held-out benchmark incidents** (n = {cls['test_on_heldout_incident_telemetry']['n']}): "
        f"accuracy {cls['test_on_heldout_incident_telemetry']['accuracy']}, macro-F1 {cls['test_on_heldout_incident_telemetry']['macro_f1']}.",
        "- Confusion matrix: `results/figures/classifier_confusion_matrix.png`.", "",
        "## 2. Learned root-cause ranker (trained) vs topology heuristic", "",
        f"- Model: {rk['model']}; trained on {rk['train_incidents']} dev-split incidents ({rk['train_rows']} device rows); never sees test or legacy data.",
        "", "| split | ranker | top-1 | top-3 | MRR | recall@2 | n |", "|---|---|---|---|---|---|---|",
        f"| test | topology heuristic | {t['heuristic']['top1']} | {t['heuristic']['top3']} | {t['heuristic']['mrr']} | {t['heuristic']['recall_at_2']} | {t['heuristic']['n']} |",
        f"| test | **learned** | {t['learned']['top1']} | {t['learned']['top3']} | {t['learned']['mrr']} | {t['learned']['recall_at_2']} | {t['learned']['n']} |",
        f"| legacy | topology heuristic | {lg['heuristic']['top1']} | {lg['heuristic']['top3']} | {lg['heuristic']['mrr']} | {lg['heuristic']['recall_at_2']} | {lg['heuristic']['n']} |",
        f"| legacy | **learned** | {lg['learned']['top1']} | {lg['learned']['top3']} | {lg['learned']['mrr']} | {lg['learned']['recall_at_2']} | {lg['learned']['n']} |",
        "",
        f"- Top-1 difference (learned - heuristic), 95% bootstrap CI: test {t['top1_difference_learned_minus_heuristic_ci95']}, "
        f"legacy {lg['top1_difference_learned_minus_heuristic_ci95']}. Random top-1 on test would be {t['random_top1_expected']}.",
        "- The test split contains 3 telemetry seeds per held-out scenario, so its incidents are not fully independent.",
        f"- Most important features (permutation importance, test AUC): {rk.get('permutation_importance_test_auc', rk.get('permutation_importance_error'))}.",
        "- Figure: `results/figures/ranker_heldout_comparison.png`. The ranker is evaluated stand-alone; the closed-loop "
        "agents still use the heuristic ordering (integration is future work).", "",
        "## 3. Closed-loop benchmark (rule-based reasoning, evaluated)", "",
        f"Run `{bench['run_id']}`; full table in `benchmark/results/REPORT.md`.", "",
        "| split | condition | repaired | unsafe deployed | rolled back (restores verified) | median total ms |", "|---|---|---|---|---|---|"]
    for split in ("dev", "test", "legacy"):
        for cond, name in (("C1", "no gate"), ("C1b", "verification gate"), ("C1c", "gate + injected deploy faults")):
            k = f"{cond}/{split}"
            lines.append(f"| {split} | {name} | {g(k, 'repaired'):.3f} {s[k]['repaired']['ci95']} | {g(k, 'unsafe_deployed'):.3f} | "
                         f"{g(k, 'rolled_back'):.3f} ({s[k]['rollback_restore_verified']}) | {s[k]['total_ms']['median']} |")
    lines += ["", "- Figures: `results/figures/verification_gate_effect.png`, `results/figures/latency_breakdown.png`.", "",
              "## 4. Causal discovery (PC algorithm, synthetic SCM, mean of 5 seeds)", "",
              "| setting | PC skeleton precision | PC recall | correlation precision | spurious CPU edges (PC / correlation) |",
              "|---|---|---|---|---|"]
    for k, v in causal.items():
        lines.append(f"| {k} | {v['pc_skeleton_precision']} | {v['pc_skeleton_recall']} | {v['correlation_precision']} | "
                     f"{v['spurious_cpu_edges_by_pc']} / {v['spurious_cpu_associations_by_correlation']} |")
    lines += ["", "## 5. Results produced by other scripts (included in this package)", "",
              "| result | file | needs |", "|---|---|---|",
              "| Local model vs real Batfish, 90 single faults | `benchmark/results/differential_local_vs_batfish.json` | Batfish |",
              "| Gated held-out run with Batfish as independent oracle | `benchmark/results/20261108T164404Z/` | Batfish |",
              "| IOS -> EOS / Junos behavioural equivalence (10 networks) | `benchmark/results/translation_validation.json` | Batfish |",
              "| Live LLM demonstrations (Gemini) | `demos/output/*__llm.txt` | Gemini key |",
              "| Groq LLM pilot (C2 vs C4, 3 scenarios) | `benchmark/results/20261108T172920Z/` | Groq key |",
              "| Rule-based demonstrations | `demos/output/*__rule_based.txt` | - |", "",
              "## 6. What is not established", "",
              "- LLM diagnostic accuracy at benchmark scale (C2-C5): not run beyond a 3-scenario pilot, because of free-tier API quotas.",
              "- Real-device or emulator deployment: not implemented (simulated adapter only).",
              "- Generalisation to real telemetry: all telemetry is synthetic.", ""]
    (OUT / "RESULTS.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    t0 = time.time()
    OUT.mkdir(exist_ok=True); FIG.mkdir(parents=True, exist_ok=True); MODELS.mkdir(exist_ok=True)
    tb = load_testbed()
    suite = load_suite(SCENARIO_DIR / "suite_v1.json")
    cls, clf = stage_classifier(tb, suite)
    (OUT / "classifier_results.json").write_text(json.dumps(cls, indent=2))
    rk = stage_ranker(tb, suite, clf)
    (OUT / "ranker_results.json").write_text(json.dumps(rk, indent=2))
    bench = stage_benchmark()
    (OUT / "benchmark_summary.json").write_text(json.dumps(bench, indent=2))
    causal = stage_causal(tb)
    (OUT / "causal_results.json").write_text(json.dumps(causal, indent=2))
    subprocess.run([sys.executable, "-m", "benchmark.report"], cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    wall = time.time() - t0
    write_report(cls, rk, bench, causal, wall)
    (OUT / "run_manifest.json").write_text(json.dumps({"finished": datetime.now(timezone.utc).isoformat(), "wall_seconds": round(wall, 1),
                                                         "python": platform.python_version(), "seed": SEED}, indent=2))
    log(f"done in {wall:.0f} s -> results/RESULTS.md")


if __name__ == "__main__":
    main()
