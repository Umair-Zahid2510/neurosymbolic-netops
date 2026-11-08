# Submission: Neurosymbolic NetOps (code, trained models, results)

## What is in this package

| Folder / file | Contents |
|---|---|
| `core/`, `agent/`, `mcp_server/`, `dashboard/` | Source code of the four-tier system |
| `models/` | **Trained models:** `syslog_classifier.pkl` (edge log classifier) and `root_cause_ranker.pkl` (learned root-cause ranker), plus metrics |
| `results/RESULTS.md` | **Main results document.** Training and evaluation of every methodology, generated from the run's JSON files |
| `results/*.json`, `results/figures/*.png` | Raw metrics and 5 figures |
| `benchmark/` | Scenario generator, 151 scenarios (`scenarios/suite_v1.json`), runner, and every benchmark run's raw results (`results/<run_id>/raw.jsonl`, `summary.json`, `manifest.json`) |
| `benchmark/results/REPORT.md` | Auto-generated report over all benchmark runs (including the Batfish-oracle run, the translation check and the Groq LLM pilot) |
| `demos/output/` | Transcripts and incident records of the three end-to-end demonstrations (rule-based, plus live Gemini runs) |
| `tests/` | 80 default tests, plus 4 Batfish integration tests and 1 live-LLM test |
| `README.md`, `ARCHITECTURE.md`, `EXPERIMENTAL_METHODOLOGY.md`, `LIMITATIONS.md`, `LITERATURE_ALIGNMENT_MATRIX.md`, `IMPLEMENTATION_STATUS.md`, `IMPLEMENTATION_AUDIT.md` | Documentation |

## Methodologies: trained or evaluated

| Methodology | Trained? | Train data | Test data | Headline result (see `results/RESULTS.md`) |
|---|---|---|---|---|
| Edge syslog classifier (TF-IDF + logistic regression) | yes | training phrasings, 5-fold CV | held-out phrasings and the held-out incidents' telemetry | accurate on held-out phrasings; accuracy drops sharply without the syslog mnemonic |
| Learned root-cause ranker (gradient-boosted trees) | yes | 440 dev-split incidents | 114 held-out incidents and 25 legacy incidents | slightly better than the topology heuristic; not statistically significant |
| Closed-loop repair with symbolic verification gate | evaluated (deterministic rules) | – | 151 scenarios, 3 conditions | gate removes unsafe deployments and raises repair rate |
| Transactional rollback | evaluated | – | 98 injected deployment failures | every restore verified |
| Causal discovery (PC algorithm) | evaluated | – | synthetic SCM, 5 seeds | beats correlation only when the confounder is observed |
| Local model vs Batfish, translation equivalence | evaluated | – | 90 faults; 10 networks | produced with a running Batfish (results included) |
| LLM agents (Gemini, Groq) | evaluated (pilot only) | – | 3 live demos plus a 3-scenario pilot | not statistically meaningful (API quota) |

## Reproduce

Python 3.12 is assumed.

1. Create the environment and install the pinned dependencies:
   ```bash
   python -m venv .venv
   ```
   ```bash
   pip install -r requirements.txt
   ```
   Activate the environment between these two steps (`.venv\Scripts\activate` on Windows).
2. Train all models and run the full evaluation (about 5 minutes; no API key or Batfish needed). This rewrites `results/` and `models/`:
   ```bash
   python scripts/train_and_evaluate.py
   ```
3. Run the tests:
   ```bash
   python -m pytest
   ```
4. Run the three end-to-end demonstrations:
   ```bash
   python run_full_system.py demos
   ```

Optional, requires Batfish (`docker run -d -p 9996:9996 batfish/allinone`):
```bash
python -m benchmark.differential_verifier
```
```bash
python -m benchmark.run_benchmark --conditions C1b --splits test --oracle batfish
```

Optional, requires an LLM key in `.env` (copy `.env.example`):
```bash
python run_full_system.py demos --reasoning llm
```

All telemetry is synthetic and deployment is simulated. Read `LIMITATIONS.md` before citing any number.
