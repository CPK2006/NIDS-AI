# NETRA verified report evidence

Collected 2026-10-24 (Asia/Calcutta). All model inspection and app tests used the isolated environment at `report_evidence/.venv`. The Flask test ran from a disposable source/model copy under `report_evidence/sandbox_app`, with forwarding/email disabled and SQLite redirected into that copy. No training was performed; no existing project file was intentionally modified.

## Task 1 — Deployed V1 LightGBM

- `results/models/lightgbm_top20_model.pkl` exists (524,660 bytes). SHA-256: `d4331502cab69f17fd123a4e87cdf3c481b6c236baed8a57e04683767bd0fa8d`. The hash matches its line in `model_artifacts.sha256`.
- The pickle loads as `lightgbm.sklearn.LGBMClassifier` using LightGBM 4.7.0. `n_features_in_` = 20; booster trees = 150; `classes_` = `[0, 1]`. The full `get_params()` and model feature names are in `v1_lightgbm_params.json`. Model-declared feature names are LightGBM-sanitized names; the input feature list in training/application code uses spaces and punctuation.
- Evaluated without fitting on `data/processed/Friday-WorkingHours-Morning.pcap_ISCX.csv`, following `train_lightgbm_top20.py` transformations and sequential split. 183,920 total rows; train 147,136; test 36,784. Total attacks 1,953; train attacks 1,575 (1.070438%); test attacks 378 (1.027621%); test benign 36,406.
- **The test slice has 378 attacks (1.027621% attack share).** This is a low attack share, not zero or only a handful of samples.

| Threshold | Accuracy | Precision | Recall | F1 | ROC-AUC | TN | FP | FN | TP | FPR | FNR |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 0.50 | 0.99994563 | 0.99473684 | 1.00000000 | 0.99736148 | 1.00000000 | 36404 | 2 | 0 | 378 | 0.00005494 | 0.00000000 |
| 0.004 | 0.99929317 | 0.93564356 | 1.00000000 | 0.96675192 | 1.00000000 | 36380 | 26 | 0 | 378 | 0.00071417 | 0.00000000 |

- Model parameters confirm 150 estimators, learning rate 0.05, 31 leaves, seed 42, and 20 input features. Current `scripts/train_lightgbm_top20.py:23-25,27-48,50-59,64-72` describes Friday Morning and its first-80%/last-20% split. However, the pkl is not Git-tracked and its artifact metadata does not encode its training dataset/split. Its filesystem timestamp (September 8, 2026, 19:33 local) is not proof of provenance. **Actual training dataset/split remains unverified.**

## Task 2 — Web app

- `scripts/test_web_prediction.py` completed in the isolated environment (exit 0); full output is `web_prediction_output.txt`. It loaded `results/models/leakage_free_top20_model.cbm` directly as CatBoost, not through Flask. It applied 0.004. Sample outcomes: expected BENIGN → BENIGN, attack probability 0.00000142; expected ATTACK → ATTACK, attack probability 0.99998099.
- Flask was tested via a disposable copy in `sandbox_app_test.py` / `sandbox_app/`, not the working app process. With default `NETRA_RUNTIME_ROLE=local_sensor`, it loaded `lightgbm.sklearn.LGBMClassifier`, threshold 0.50. GET `/` returned 200. Both sample POSTs returned 200 and were classified BENIGN with displayed attack probability 0.0006% each. Thus the second sample’s CatBoost prediction does not reproduce in the app’s LightGBM model on that request. Detailed output: `isolated_app_test_output.txt`.
- Before package installation, a direct import failed for missing Flask (`local_sensor_app_import.txt`); after installing only in the isolated environment, the copy-based test passed. `runtime_packages.txt` records the installed versions.
- No live server was bound; the Flask test client ran in a subprocess using copied files. Its local event and delivery databases are under `sandbox_app/data/`; network forwarding and email alerts were disabled.
- The panel is hard-coded in `app/templates/index.html:164-190`, literal metric strings at lines 175, 179, 183, 187: accuracy 99.0133%, precision 99.0981%, recall 97.9154%, F1 98.5032%. It is not populated from metrics JSON or route variables.
- Source role and model selection: `app/app.py:29` defaults to local_sensor; `:312-317` sets pkl path and threshold 0.50; `:346-360` loads LightGBM first and uses CatBoost fallback with 0.004 only if that load path fails.

## Task 3 — CatBoost artifact

- `leakage_free_top20_model.cbm` loads successfully. `tree_count_` = **272**; best iteration = 271. `get_all_params()` requested fields: iterations=500, depth=10, learning_rate=0.05000000075, l2_leaf_reg=3, random_seed=42, use_best_model=True, auto_class_weights=None. All 20 feature names are in `catboost_v1_artifact.json`.
- The result JSON says tree_count 272. Current `scripts/train_leakage_free_top20.py:353-369` requests 500 iterations, then calls fit with only training X/y; no eval_set, early stopping, or explicit `use_best_model`. That current version does not explain 272 trees.
- Git version `89054119` does contain validation `eval_set`, `use_best_model=True`, and `early_stopping_rounds=50`, with 500 iterations. The loaded artifact’s `use_best_model=True`, `od_wait=50`, best iteration 271, and 272 trees are consistent with that older workflow. They do not prove which script revision created the artifact. The CBM is not Git-tracked.

## Task 4 — Six-model sources

See `six_model_provenance.csv` for each result file, producing script, split, feature count, and configuration. All six scripts consume the 65-column scaled files and saved `data/splits/` labels. `scripts/split_dataset.py:39-45` makes those files with stratified random `train_test_split(test_size=0.20, random_state=42, stratify=y)`.

- `catboost_results.json` is written by `scripts/train_catboost.py:213-216`. That script uses `eval_set=(X_test,y_test)` and `early_stopping_rounds=30` (`:71-75`): the test split participates in stopping.
- No MLP implementation or result artifact was found. MLP mentions occur in report/presentation material. Repo-wide Git history search hits documentation/project commits, but no MLP code/model results were found. The checked-in six-model comparison substitutes Isolation Forest for MLP.
- Stored `data/splits/y_test.csv`: 503,902 rows; 85,137 attacks, 418,765 benign; 16.895547% attacks.
- Sequential final 20% of `data/sample/cicids2017_binary_deduplicated.csv`: 503,902 rows; 167,085 attacks, 336,817 benign; 33.158233% attacks. These test sets have materially different class distributions.

## Task 5 — Feature selection provenance

- `app/app.py:319-340` and `scripts/train_lightgbm_top20.py:27-48` contain identical hard-coded feature orders.
- Comparison from source and saved CSV confirms app `FEATURES` exactly equals the 20-row order in `results/models/catboost_top20_feature_importance.csv` (`feature_order_comparison.json`). That CSV is produced by `scripts/train_catboost_top20.py:213-223,269-271`, which sorts CatBoost feature importance descending. **The matching app order is a CatBoost importance ranking, not a LightGBM ranking.** The exact copy action into app.py is undocumented.
- `data/features/top20/top20_feature_names.json` and `results/models/top_20_features.json` have a different order and do not equal the app order. `select_top_features.py:13-16,63-94` copies that selected order; `analyze_feature_importance.py:25,49-79,138-166` creates `top_20_features.json` using `final_catboost_model.cbm` importance. `compare_catboost_feature_reduction.py` compares experiment metrics; it does not generate the app list.

## Remaining ambiguity

1. The LightGBM evaluation and artifact params are now verified, but the pickle’s exact historical training dataset and split cannot be proven from the untracked artifact.
2. CatBoost’s loaded metadata strongly matches the older early-stopping revision, but the artifact’s exact producing commit/run remains unproven.
3. No MLP evidence exists in source or saved results; its report metrics remain unsupported by repository artifacts.
4. The app feature order matches the CatBoost importance output, but its source-code history does not record where the literal list was copied from.
