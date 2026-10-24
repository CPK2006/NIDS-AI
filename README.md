# NIDS-AI

NIDS-AI is a network intrusion detection project built around the CICIDS2017 flow dataset. It includes an ML evaluation pipeline, a Flask dashboard, and a Windows sensor runtime for flow capture, classification, event history, and optional forwarding to a hosted dashboard.

## What is included

- CICIDS2017 data preparation, cleaning, feature selection, training, and evaluation scripts.
- A six-algorithm comparison covering LightGBM, CatBoost, Extra Trees, Histogram Gradient Boosting, Passive Aggressive, and Isolation Forest.
- Leakage-aware sequential evaluation of a 20-feature CatBoost model.
- A Flask web app with local sensor and hosted web runtime roles.
- Saved evaluation models, metrics, and figures under [`results/`](results/).

The raw and prepared CICIDS2017 data files are not included because of their size. The six-model evaluation artifacts and the leakage-free Top-20 evaluation model are included in this branch. The separate V2 live-sensor model is not included in a clean checkout; see [Runtime and deployment roles](docs/RUNTIME_ROLES.md).

## Model results

### Six-algorithm comparison

These metrics come from the saved six-model comparison. The complete comparison, including precision, recall, ROC-AUC, and timing, is in [`all_six_model_comparison.csv`](results/models/all_six_model_comparison.csv); the ranked results are in [`all_six_model_ranking.csv`](results/models/all_six_model_ranking.csv).

| Model | Accuracy | F1 |
|---|---:|---:|
| CatBoost | 99.9153% | 99.7494% |
| LightGBM | 99.9107% | 99.7359% |
| Histogram Gradient Boosting | 99.9030% | 99.7131% |
| Extra Trees | 99.8402% | 99.5269% |
| Passive Aggressive | 94.4739% | 82.0499% |
| Isolation Forest | 86.3398% | 58.8928% |

### Leakage-free sequential Top-20 CatBoost

This is a separate, time-ordered evaluation: about 70% training, 10% validation, and 20% test, with no shuffling. The 0.004 decision threshold was selected on validation data and then evaluated on the untouched test set.

| Metric | Test result |
|---|---:|
| Accuracy | 99.0133% |
| Precision | 99.0981% |
| Recall | 97.9154% |
| F1 | 98.5032% |
| ROC-AUC | 99.8995% |

It uses 20 selected features. The model output and full metrics are in [`leakage_free_top20_model.cbm`](results/models/leakage_free_top20_model.cbm) and [`leakage_free_top20_results.json`](results/models/leakage_free_top20_results.json). The six-model comparison and the sequential evaluation use different evaluation runs, so their scores should not be compared as if they came from the same split and protocol.

## Run locally on Windows

Use Python 3.11.9, matching [`.python-version`](.python-version). From the project root, create an environment and install the local sensor dependencies:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-sensor.txt
Copy-Item .env.example .env
python app\app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000). The app loads `.env` when `python-dotenv` is installed. The example file contains placeholders; keep real credentials and keys in your private `.env` or environment variables, never in Git. Loopback-only local use does not require dashboard credentials by default. Configure authentication before exposing the service to another machine.

The local sensor role is the default. Packet capture requires a compatible Windows environment, Scapy, and appropriate capture permissions. A clean checkout does not include the V2 model file, so V2 live inference remains unavailable until the approved artifact is installed and verified as described in the runtime guide. The tracked LightGBM and CatBoost evaluation artifacts are under `results/models/`.

## Run the hosted web process

For Render or another Linux host, use the hosted dependency file and start script:

```sh
python -m pip install -r requirements-hosted.txt
sh scripts/start_hosted.sh
```

Configure the platform's environment with the required role, PostgreSQL connection, dashboard authentication, and sensor API key. See [Runtime and deployment roles](docs/RUNTIME_ROLES.md) for the separate `hosted_web`, `hosted_worker`, and `report_job` requirements, health endpoints, and deployment checks. Do not copy a credential-filled local `.env` to teammates or commit it.

## Data and evaluation workflow

The data files are intentionally excluded from Git. Put the extracted CICIDS2017 flow CSV files in `data/processed/`, then run the preparation and deduplication steps from the repository root:

```powershell
python scripts\prepare_dataset.py
python scripts\remove_duplicates.py
```

These create `data/sample/cicids2017_binary.csv` and `data/sample/cicids2017_binary_deduplicated.csv`. Continue with the scripts in `scripts/` for feature cleaning, splitting, selection, training, and evaluation. The safe workflow expects prepared data and intermediate feature files to exist; it exits with a list of missing inputs otherwise. To regenerate the final evaluation plots from the saved result files, run:

```powershell
python scripts\generate_final_plots.py
```

The stored results are already available under `results/models/` and `results/plots/`; rerunning training requires the dataset and generated intermediate files.

## Repository layout

| Path | Purpose |
|---|---|
| `app/` | Flask application, templates, and static assets |
| `v2/` | Local detector, feature extraction, event storage, forwarding, and reporting |
| `scripts/` | Dataset, training, comparison, plotting, and verification workflows |
| `data/` | Local datasets, splits, feature files, and SQLite event history; ignored by Git |
| `results/models/` | Trained evaluation models, scores, and comparison tables |
| `results/plots/` | Evaluation plots and report figures |
| `docs/RUNTIME_ROLES.md` | Local and hosted runtime/deployment guide |

## Limitations

CICIDS2017 is a benchmark dataset, and its traffic may not represent a deployment network. Test scores do not guarantee performance on new traffic. Validate on independently collected, representative data before relying on the detector operationally.

## License

See [LICENSE](LICENSE). This project is intended for academic and research purposes.
