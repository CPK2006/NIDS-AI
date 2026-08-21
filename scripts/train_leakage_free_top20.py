import pandas as pd
import numpy as np
import os
import json
import time

from catboost import CatBoostClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix
)

print("=" * 70)
print("CICIDS2017 LEAKAGE-FREE TOP-20 CATBOOST")
print("=" * 70)

# ============================================================
# PATHS
# ============================================================

DATA_PATH = "data/sample/cicids2017_binary_deduplicated.csv"

MODEL_PATH = "results/models/leakage_free_top20_model.cbm"
RESULT_PATH = "results/models/leakage_free_top20_results.json"

os.makedirs("results/models", exist_ok=True)

# ============================================================
# TOP 20 FEATURES
# ============================================================
# These are the exact Top-20 features from your previous
# sequential Top-20 experiment.

selected_features = [
    "Destination Port",
    "Bwd Packet Length Std",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "Fwd Header Length",
    "Average Packet Size",
    "min_seg_size_forward",
    "Flow IAT Mean",
    "Bwd Header Length",
    "PSH Flag Count",
    "Flow IAT Min",
    "Fwd Packet Length Max",
    "Fwd IAT Min",
    "Total Length of Bwd Packets",
    "Max Packet Length",
    "Fwd IAT Total",
    "Packet Length Std",
    "Flow Bytes/s",
    "Bwd Packet Length Mean",
    "Packet Length Variance"
]

print("\nSelected Top-20 features:")

for i, feature in enumerate(selected_features, 1):
    print(f"{i:2d}. {feature}")

# ============================================================
# LOAD DATA
# ============================================================

print("\nLoading complete deduplicated dataset...")

df = pd.read_csv(DATA_PATH)

print("Dataset shape:", df.shape)

# ============================================================
# VERIFY FEATURES
# ============================================================

missing = [
    feature
    for feature in selected_features
    if feature not in df.columns
]

if missing:
    print("\nERROR: Missing features:")
    for feature in missing:
        print(" -", feature)

    raise ValueError("One or more Top-20 features are missing.")

# ============================================================
# FEATURES / TARGET
# ============================================================

X = df[selected_features].copy()
y = df["Binary_Label"].copy()

print("\nFeature matrix:", X.shape)
print("Target:", y.shape)

# ============================================================
# SEQUENTIAL SPLIT
# ============================================================

print("\n" + "=" * 70)
print("SEQUENTIAL SPLIT")
print("=" * 70)

n = len(df)

# 70% train
# 10% validation
# 20% test

train_end = int(n * 0.70)
val_end = int(n * 0.80)

X_train = X.iloc[:train_end]
y_train = y.iloc[:train_end]

X_val = X.iloc[train_end:val_end]
y_val = y.iloc[train_end:val_end]

X_test = X.iloc[val_end:]
y_test = y.iloc[val_end:]

print("\nTraining:")
print("X_train:", X_train.shape)
print("y_train:", y_train.shape)

print("\nValidation:")
print("X_val:", X_val.shape)
print("y_val:", y_val.shape)

print("\nTesting:")
print("X_test:", X_test.shape)
print("y_test:", y_test.shape)

# ============================================================
# CLASS DISTRIBUTION
# ============================================================

print("\n" + "=" * 70)
print("CLASS DISTRIBUTIONS")
print("=" * 70)

for name, target in [
    ("TRAIN", y_train),
    ("VALIDATION", y_val),
    ("TEST", y_test)
]:

    print(f"\n{name}:")
    print(target.value_counts())

    print(
        target.value_counts(normalize=True)
        .mul(100)
        .round(3)
    )

# ============================================================
# CATBOOST
# ============================================================

print("\n" + "=" * 70)
print("CATBOOST PARAMETERS")
print("=" * 70)

print("Iterations    : 500")
print("Depth         : 10")
print("Learning rate : 0.05")

model = CatBoostClassifier(
    iterations=500,
    depth=10,
    learning_rate=0.05,
    loss_function="Logloss",
    eval_metric="AUC",
    random_seed=42,
    verbose=100,
    thread_count=-1
)

# ============================================================
# TRAIN
# ============================================================

print("\n" + "=" * 70)
print("TRAINING LEAKAGE-FREE TOP-20 MODEL")
print("=" * 70)

start = time.time()

model.fit(
    X_train,
    y_train,
    eval_set=(X_val, y_val),
    use_best_model=True,
    early_stopping_rounds=50
)

training_time = time.time() - start

print("\nTraining completed.")
print("Training time:", round(training_time, 2), "seconds")
print("Trees:", model.tree_count_)

# ============================================================
# SAVE MODEL
# ============================================================

model.save_model(MODEL_PATH)

print("\nModel saved:")
print(MODEL_PATH)

# ============================================================
# VALIDATION PROBABILITIES
# ============================================================

print("\n" + "=" * 70)
print("VALIDATION THRESHOLD SELECTION")
print("=" * 70)

print("\nGenerating validation probabilities...")

val_prob = model.predict_proba(X_val)[:, 1]

# Test many thresholds
thresholds = np.arange(
    0.001,
    0.501,
    0.001
)

threshold_results = []

for threshold in thresholds:

    val_pred = (
        val_prob >= threshold
    ).astype(int)

    tn, fp, fn, tp = confusion_matrix(
        y_val,
        val_pred,
        labels=[0, 1]
    ).ravel()

    accuracy = accuracy_score(
        y_val,
        val_pred
    )

    precision = precision_score(
        y_val,
        val_pred,
        zero_division=0
    )

    recall = recall_score(
        y_val,
        val_pred,
        zero_division=0
    )

    f1 = f1_score(
        y_val,
        val_pred,
        zero_division=0
    )

    fpr = fp / (fp + tn)
    fnr = fn / (fn + tp)

    threshold_results.append({
        "Threshold": float(threshold),
        "Accuracy": float(accuracy),
        "Precision": float(precision),
        "Recall": float(recall),
        "F1": float(f1),
        "FPR": float(fpr),
        "FNR": float(fnr),
        "TN": int(tn),
        "FP": int(fp),
        "FN": int(fn),
        "TP": int(tp)
    })

threshold_df = pd.DataFrame(threshold_results)

# ============================================================
# BEST VALIDATION THRESHOLD
# ============================================================

best_row = threshold_df.loc[
    threshold_df["F1"].idxmax()
]

best_threshold = float(
    best_row["Threshold"]
)

print("\nBest validation threshold:")
print(best_threshold)

print("\nValidation performance:")
print(
    f"ACCURACY : {best_row['Accuracy']:.6f}"
)
print(
    f"PRECISION: {best_row['Precision']:.6f}"
)
print(
    f"RECALL   : {best_row['Recall']:.6f}"
)
print(
    f"F1       : {best_row['F1']:.6f}"
)
print(
    f"FPR      : {best_row['FPR']:.6f}"
)
print(
    f"FNR      : {best_row['FNR']:.6f}"
)

# ============================================================
# FINAL TEST
# ============================================================

print("\n" + "=" * 70)
print("FINAL TEST EVALUATION")
print("=" * 70)

print(
    "\nIMPORTANT: Test data has NOT been used "
    "for threshold selection."
)

print("\nGenerating test probabilities...")

test_prob = model.predict_proba(X_test)[:, 1]

# ------------------------------------------------------------
# Threshold 0.50
# ------------------------------------------------------------

test_pred_050 = (
    test_prob >= 0.50
).astype(int)

# ------------------------------------------------------------
# Validation-selected threshold
# ------------------------------------------------------------

test_pred_selected = (
    test_prob >= best_threshold
).astype(int)

# ============================================================
# METRIC FUNCTION
# ============================================================

def calculate_metrics(
    y_true,
    y_pred,
    probabilities
):

    tn, fp, fn, tp = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1]
    ).ravel()

    accuracy = accuracy_score(
        y_true,
        y_pred
    )

    precision = precision_score(
        y_true,
        y_pred,
        zero_division=0
    )

    recall = recall_score(
        y_true,
        y_pred,
        zero_division=0
    )

    f1 = f1_score(
        y_true,
        y_pred,
        zero_division=0
    )

    roc_auc = roc_auc_score(
        y_true,
        probabilities
    )

    fpr = fp / (fp + tn)
    fnr = fn / (fn + tp)

    return {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "roc_auc": float(roc_auc),
        "fpr": float(fpr),
        "fnr": float(fnr),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "total_errors": int(fp + fn)
    }


metrics_050 = calculate_metrics(
    y_test,
    test_pred_050,
    test_prob
)

metrics_selected = calculate_metrics(
    y_test,
    test_pred_selected,
    test_prob
)

# ============================================================
# COMPARISON
# ============================================================

print("\n" + "=" * 70)
print("FINAL TEST COMPARISON")
print("=" * 70)

print(
    f"{'Metric':25s}"
    f"{'Threshold 0.50':>20s}"
    f"{'Selected Threshold':>22s}"
)

print("-" * 70)

display_metrics = [
    ("Accuracy", "accuracy"),
    ("Precision", "precision"),
    ("Recall", "recall"),
    ("F1-score", "f1"),
    ("ROC-AUC", "roc_auc"),
    ("False Positive Rate", "fpr"),
    ("False Negative Rate", "fnr"),
    ("False Positives", "fp"),
    ("False Negatives", "fn"),
    ("Total Errors", "total_errors")
]

for label, key in display_metrics:

    a = metrics_050[key]
    b = metrics_selected[key]

    if isinstance(a, float):

        print(
            f"{label:25s}"
            f"{a:20.6f}"
            f"{b:22.6f}"
        )

    else:

        print(
            f"{label:25s}"
            f"{a:20d}"
            f"{b:22d}"
        )

# ============================================================
# CONFUSION MATRICES
# ============================================================

print("\n" + "=" * 70)
print("CONFUSION MATRICES")
print("=" * 70)

print("\nThreshold = 0.50")

print(
    confusion_matrix(
        y_test,
        test_pred_050
    )
)

print(
    f"\nValidation-selected threshold = "
    f"{best_threshold:.3f}"
)

print(
    confusion_matrix(
        y_test,
        test_pred_selected
    )
)

# ============================================================
# FEATURE IMPORTANCE
# ============================================================

print("\n" + "=" * 70)
print("TOP-20 FEATURE IMPORTANCE")
print("=" * 70)

importance = pd.DataFrame({
    "Feature": selected_features,
    "Importance": model.get_feature_importance()
})

importance = importance.sort_values(
    "Importance",
    ascending=False
)

print(
    importance.to_string(
        index=False
    )
)

# ============================================================
# SAVE THRESHOLD RESULTS
# ============================================================

threshold_output = (
    "results/models/"
    "leakage_free_top20_thresholds.csv"
)

threshold_df.to_csv(
    threshold_output,
    index=False
)

# ============================================================
# SAVE FINAL RESULTS
# ============================================================

result = {
    "dataset": "CICIDS2017",

    "method":
        "Leakage-free sequential Top-20",

    "dataset_shape":
        list(df.shape),

    "train_shape":
        list(X_train.shape),

    "validation_shape":
        list(X_val.shape),

    "test_shape":
        list(X_test.shape),

    "selected_features":
        selected_features,

    "catboost": {
        "iterations": 500,
        "depth": 10,
        "learning_rate": 0.05,
        "tree_count": int(model.tree_count_),
        "training_time_seconds":
            float(training_time)
    },

    "validation_threshold":
        best_threshold,

    "validation_metrics": {
        "accuracy":
            float(best_row["Accuracy"]),
        "precision":
            float(best_row["Precision"]),
        "recall":
            float(best_row["Recall"]),
        "f1":
            float(best_row["F1"]),
        "fpr":
            float(best_row["FPR"]),
        "fnr":
            float(best_row["FNR"])
    },

    "test_threshold_0.50":
        metrics_050,

    "test_selected_threshold":
        metrics_selected,

    "feature_importance": [
        {
            "Feature":
                row["Feature"],
            "Importance":
                float(row["Importance"])
        }
        for _, row in importance.iterrows()
    ]
}

with open(
    RESULT_PATH,
    "w"
) as f:

    json.dump(
        result,
        f,
        indent=4
    )

# ============================================================
# DONE
# ============================================================

print("\n" + "=" * 70)
print("FILES SAVED")
print("=" * 70)

print(MODEL_PATH)
print(RESULT_PATH)
print(threshold_output)

print("\n" + "=" * 70)
print("LEAKAGE-FREE TOP-20 TRAINING COMPLETED")
print("=" * 70)