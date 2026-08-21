# CICIDS2017 Network Intrusion Detection System

A machine-learning-based Network Intrusion Detection System (NIDS) built on the **CICIDS2017 dataset**. The project classifies network flows as **BENIGN** or **ATTACK**, with a focus on rigorous evaluation — avoiding data leakage, duplicate flows, and naive train/test splitting — rather than just chasing accuracy.

---

## Overview

- **Dataset:** CICIDS2017, prepared/deduplicated to 2,519,506 rows × 79 columns (78 features + 1 binary target). Excluded from Git due to size.
- **Evaluation strategy:** Sequential (time-ordered) train/validation/test split instead of random splitting, after finding significant train/test overlap via group-leakage analysis. Test set is never touched during model or threshold selection.
- **Feature reduction:** 78 → 20 features (see below), keeping performance while cutting model complexity.
- **Model:** CatBoost Classifier, threshold tuned on the validation set only.

---

## Final Model: Leakage-Free Top-20 CatBoost

| | |
|---|---|
| Features | 20 |
| Threshold | 0.004 |
| Accuracy | 99.0133% |
| Precision | 99.0981% |
| Recall | 97.9154% |
| F1-score | 98.5032% |
| ROC-AUC | 99.8995% |

**Confusion matrix (test set):**

```text
                 Predicted
              BENIGN   ATTACK
Actual BENIGN 335328    1489
Actual ATTACK   3483  163602
```

**Model comparison:**

| Model | Features | Threshold | Accuracy | F1 | ROC-AUC |
|---|---|---|---|---|---|
| Sequential CatBoost | 65 | 0.500 | 98.96% | 98.41% | 99.9959% |
| Sequential Train/Val/Test | 78 | 0.010 | 91.89% | 86.12% | 99.8604% |
| Sequential Top-20 | 20 | 0.003 | 99.00% | 98.49% | 99.9094% |
| **Leakage-Free Top-20 (final)** | **20** | **0.004** | **99.01%** | **98.50%** | **99.8995%** |

The leakage-free Top-20 model was selected as the final model because it achieved the highest F1-score among the evaluated models while using only 20 features, reducing the feature set from 78 to 20.

---

## Top-20 Features

Destination Port, Bwd Packet Length Std, Init_Win_bytes_forward, Init_Win_bytes_backward, Fwd Header Length, Average Packet Size, min_seg_size_forward, Flow IAT Mean, Bwd Header Length, PSH Flag Count, Flow IAT Min, Fwd Packet Length Max, Fwd IAT Min, Total Length of Bwd Packets, Max Packet Length, Fwd IAT Total, Packet Length Std, Flow Bytes/s, Bwd Packet Length Mean, Packet Length Variance

Top 5 by importance: Destination Port, Init_Win_bytes_backward, Fwd Packet Length Max, PSH Flag Count, Init_Win_bytes_forward. Full plot: `results/plots/top20_feature_importance.png`

---

## Methodology Notes

- **Leakage investigation:** Checked for flow/group/source-destination overlap between train and test. The available features lack Flow ID, IP, and protocol columns, but overlap was still detectable via network grouping — hence the switch to sequential (non-random) splitting.
- **Duplicate removal:** Duplicate flows were removed before the final split to stop near-identical samples leaking across train/test.
- **Sequential split:** ~70% train / 10% validation / 20% test, preserving original time order. Class balance shifts across splits (13% attack in training vs 33% in test), which better reflects a real deployment scenario than random splitting would.
- **Threshold selection:** The default 0.50 threshold performed poorly on the shifted test distribution. The threshold (0.004) was selected using validation data only, before the test set was evaluated.

---

## Project Structure

```text
NIDS-AI/
├── data/            # datasets and generated features/splits (gitignored)
├── results/
│   ├── models/      # trained CatBoost models (.cbm)
│   └── plots/       # feature importance, threshold analysis, model comparison
├── scripts/
│   ├── prepare_dataset.py, remove_duplicates.py, clean_features.py
│   ├── verify_dataset_integrity.py, verify_targets.py
│   ├── analyze_group_leakage.py, analyze_overlap.py
│   ├── analyze_feature_importance.py, analyze_sequential_thresholds.py, analyze_threshold_stability.py
│   ├── select_top_features.py
│   ├── train_catboost.py, train_sequential_catboost.py
│   ├── train_sequential_train_val_test.py, train_sequential_top20_train_val_test.py
│   ├── train_leakage_free_top20.py
│   └── final_model_comparison.py, generate_final_plots.py, safe_workflow.py
├── .gitignore
└── README.md
```

---

## Running the Project

The full workflow — checking required files, loading the deduplicated dataset and Top-20 features, sequential splitting, training, threshold selection, and evaluation on the untouched test set — is wrapped in one script:

```bash
python scripts/safe_workflow.py
```

To regenerate the result plots:

```bash
python scripts/generate_final_plots.py
```

For a step-by-step run instead of the wrapped workflow, the scripts under `scripts/` can be run individually in the order they're grouped above (prepare → dedupe → leakage analysis → feature selection → train → compare → plot).

---

## Limitations

CICIDS2017 is a benchmark dataset and doesn't fully represent real-world network traffic. Despite the leakage-aware, sequential evaluation used here, these results shouldn't be assumed to transfer directly to production networks — validation on independently collected traffic would be needed for that.

---

## License

This project is intended for academic and research purposes.