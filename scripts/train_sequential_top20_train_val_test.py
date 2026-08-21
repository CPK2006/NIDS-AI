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
print("CICIDS2017 SEQUENTIAL TOP-20 TRAIN / VALIDATION / TEST")
print("=" * 70)

# ==============================================================
# PATHS
# ==============================================================

DATA_PATH = "data/sample/cicids2017_binary_deduplicated.csv"

TOP20_PATH = "results/models/catboost_top20_feature_importance.csv"

MODEL_OUTPUT = "results/models/sequential_top20_train_val_model.cbm"
RESULT_OUTPUT = "results/models/sequential_top20_train_val_test_results.json"
THRESHOLD_OUTPUT = "results/models/sequential_top20_validation_thresholds.csv"

os.makedirs("results/models", exist_ok=True)

# ==============================================================
# 1. LOAD DATA
# ==============================================================

print("\nLoading complete deduplicated dataset...")

df = pd.read_csv(DATA_PATH)

print("Dataset shape:", df.shape)

# ==============================================================
# 2. LOAD TOP 20 FEATURES
# ==============================================================

print("\nLoading Top 20 feature list...")

importance_df = pd.read_csv(TOP20_PATH)

# The previous feature-importance file contains:
# Feature, Importance

if "Feature" not in importance_df.columns:
    raise ValueError(
        "Top-20 feature importance file must contain a 'Feature' column."
    )

top20_features = importance_df["Feature"].head(20).tolist()

print("\nSelected Top 20 features:")
for i, feature in enumerate(top20_features, 1):
    print(f"{i:2d}. {feature}")

# ==============================================================
# 3. VERIFY FEATURES
# ==============================================================

missing_features = [
    feature for feature in top20_features
    if feature not in df.columns
]

if missing_features:
    print("\nERROR: Missing Top-20 features:")
    for feature in missing_features:
        print(" -", feature)

    raise ValueError("One or more Top-20 features are missing.")

# ==============================================================
# 4. SEPARATE FEATURES AND TARGET
# ==============================================================

X = df[top20_features]
y = df["Binary_Label"]

print("\nFeature matrix:", X.shape)
print("Target:", y.shape)

# ==============================================================
# 5. SEQUENTIAL TRAIN / VALIDATION / TEST SPLIT
# ==============================================================

print("\n" + "=" * 70)
print("SEQUENTIAL SPLIT")
print("=" * 70)

n = len(df)

train_end = int(n * 0.70)
val_end = int(n * 0.80)

X_train = X.iloc[:train_end].copy()
y_train = y.iloc[:train_end].copy()

X_val = X.iloc[train_end:val_end].copy()
y_val = y.iloc[train_end:val_end].copy()

X_test = X.iloc[val_end:].copy()
y_test = y.iloc[val_end:].copy()

print("\nTraining:")
print("X_train:", X_train.shape)
print("y_train:", y_train.shape)

print("\nValidation:")
print("X_val:", X_val.shape)
print("y_val:", y_val.shape)

print("\nTesting:")
print("X_test:", X_test.shape)
print("y_test:", y_test.shape)

# ==============================================================
# 6. CLASS DISTRIBUTIONS
# ==============================================================

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

# ==============================================================
# 7. CATBOOST PARAMETERS
# ==============================================================

ITERATIONS = 500
DEPTH = 10
LEARNING_RATE = 0.05

print("\n" + "=" * 70)
print("CATBOOST PARAMETERS")
print("=" * 70)

print("Iterations    :", ITERATIONS)
print("Depth         :", DEPTH)
print("Learning rate :", LEARNING_RATE)

# ==============================================================
# 8. TRAIN MODEL
# ==============================================================

print("\n" + "=" * 70)
print("TRAINING TOP-20 MODEL")
print("=" * 70)

model = CatBoostClassifier(
    iterations=ITERATIONS,
    depth=DEPTH,
    learning_rate=LEARNING_RATE,
    loss_function="Logloss",
    eval_metric="AUC",
    random_seed=42,
    verbose=100,
    allow_writing_files=False
)

start_time = time.time()

model.fit(
    X_train,
    y_train
)

training_time = time.time() - start_time

print("\nTraining completed.")
print(f"Training time: {training_time:.2f} seconds")
print("Trees:", model.tree_count_)

# ==============================================================
# 9. SAVE MODEL
# ==============================================================

model.save_model(MODEL_OUTPUT)

print("\nModel saved:")
print(MODEL_OUTPUT)

# ==============================================================
# 10. VALIDATION PROBABILITIES
# ==============================================================

print("\n" + "=" * 70)
print("VALIDATION THRESHOLD SELECTION")
print("=" * 70)

print("\nGenerating validation probabilities...")

val_probabilities = model.predict_proba(X_val)[:, 1]

# ==============================================================
# 11. SEARCH VALIDATION THRESHOLDS
# ==============================================================

thresholds = np.arange(
    0.001,
    0.501,
    0.001
)

threshold_results = []

for threshold in thresholds:

    y_val_pred = (
        val_probabilities >= threshold
    ).astype(int)

    tn, fp, fn, tp = confusion_matrix(
        y_val,
        y_val_pred,
        labels=[0, 1]
    ).ravel()

    accuracy = accuracy_score(
        y_val,
        y_val_pred
    )

    precision = precision_score(
        y_val,
        y_val_pred,
        zero_division=0
    )

    recall = recall_score(
        y_val,
        y_val_pred,
        zero_division=0
    )

    f1 = f1_score(
        y_val,
        y_val_pred,
        zero_division=0
    )

    fpr = fp / (fp + tn)

    fnr = fn / (fn + tp)

    threshold_results.append({
        "Threshold": threshold,
        "Accuracy": accuracy,
        "Precision": precision,
        "Recall": recall,
        "F1": f1,
        "FPR": fpr,
        "FNR": fnr,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "TP": tp
    })

threshold_df = pd.DataFrame(
    threshold_results
)

threshold_df.to_csv(
    THRESHOLD_OUTPUT,
    index=False
)

# ==============================================================
# 12. SELECT BEST VALIDATION THRESHOLD
# ==============================================================

# Primary criterion: maximum F1
best_row = threshold_df.loc[
    threshold_df["F1"].idxmax()
]

best_threshold = float(
    best_row["Threshold"]
)

print("\nBest validation threshold:")
print(best_threshold)

print("\nValidation performance at selected threshold:")

print(
    f"ACCURACY    : {best_row['Accuracy']:.6f}"
)

print(
    f"PRECISION   : {best_row['Precision']:.6f}"
)

print(
    f"RECALL      : {best_row['Recall']:.6f}"
)

print(
    f"F1          : {best_row['F1']:.6f}"
)

print(
    f"FPR         : {best_row['FPR']:.6f}"
)

print(
    f"FNR         : {best_row['FNR']:.6f}"
)

print(
    f"TN          : {best_row['TN']}"
)

print(
    f"FP          : {best_row['FP']}"
)

print(
    f"FN          : {best_row['FN']}"
)

print(
    f"TP          : {best_row['TP']}"
)

# ==============================================================
# 13. FINAL TEST EVALUATION
# ==============================================================

print("\n" + "=" * 70)
print("FINAL TEST EVALUATION")
print("=" * 70)

print(
    "\nIMPORTANT: Test data has NOT been used "
    "for threshold selection."
)

print("\nGenerating test probabilities...")

start_prediction = time.time()

test_probabilities = model.predict_proba(
    X_test
)[:, 1]

prediction_time = (
    time.time() - start_prediction
)

# --------------------------------------------------------------
# Threshold 0.50
# --------------------------------------------------------------

y_test_pred_50 = (
    test_probabilities >= 0.50
).astype(int)

# --------------------------------------------------------------
# Validation-selected threshold
# --------------------------------------------------------------

y_test_pred_selected = (
    test_probabilities >= best_threshold
).astype(int)

# ==============================================================
# 14. METRIC FUNCTION
# ==============================================================

def calculate_metrics(y_true, y_pred, probabilities):

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
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": roc_auc,
        "fpr": fpr,
        "fnr": fnr,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "total_errors": int(fp + fn)
    }

# ==============================================================
# 15. CALCULATE TEST METRICS
# ==============================================================

metrics_50 = calculate_metrics(
    y_test,
    y_test_pred_50,
    test_probabilities
)

metrics_selected = calculate_metrics(
    y_test,
    y_test_pred_selected,
    test_probabilities
)

# ==============================================================
# 16. DISPLAY COMPARISON
# ==============================================================

print("\n" + "=" * 70)
print("FINAL TEST COMPARISON")
print("=" * 70)

print(
    f"{'Metric':<22}"
    f"{'Threshold 0.50':>18}"
    f"{'Selected Threshold':>22}"
)

print("-" * 70)

comparison = [
    ("Accuracy",
     metrics_50["accuracy"],
     metrics_selected["accuracy"]),

    ("Precision",
     metrics_50["precision"],
     metrics_selected["precision"]),

    ("Recall",
     metrics_50["recall"],
     metrics_selected["recall"]),

    ("F1-score",
     metrics_50["f1"],
     metrics_selected["f1"]),

    ("ROC-AUC",
     metrics_50["roc_auc"],
     metrics_selected["roc_auc"]),

    ("False Positive Rate",
     metrics_50["fpr"],
     metrics_selected["fpr"]),

    ("False Negative Rate",
     metrics_50["fnr"],
     metrics_selected["fnr"]),

    ("False Positives",
     metrics_50["fp"],
     metrics_selected["fp"]),

    ("False Negatives",
     metrics_50["fn"],
     metrics_selected["fn"]),

    ("Total Errors",
     metrics_50["total_errors"],
     metrics_selected["total_errors"])
]

for name, value1, value2 in comparison:

    if name in [
        "False Positives",
        "False Negatives",
        "Total Errors"
    ]:

        print(
            f"{name:<22}"
            f"{value1:>18.0f}"
            f"{value2:>22.0f}"
        )

    else:

        print(
            f"{name:<22}"
            f"{value1:>18.6f}"
            f"{value2:>22.6f}"
        )

# ==============================================================
# 17. CONFUSION MATRICES
# ==============================================================

print("\n" + "=" * 70)
print("CONFUSION MATRICES")
print("=" * 70)

cm_50 = confusion_matrix(
    y_test,
    y_test_pred_50,
    labels=[0, 1]
)

cm_selected = confusion_matrix(
    y_test,
    y_test_pred_selected,
    labels=[0, 1]
)

print("\nThreshold = 0.50")
print(cm_50)

print(
    f"\nValidation-selected threshold = "
    f"{best_threshold:.3f}"
)

print(cm_selected)

# ==============================================================
# 18. FEATURE IMPORTANCE
# ==============================================================

print("\n" + "=" * 70)
print("TOP-20 FEATURE IMPORTANCE")
print("=" * 70)

feature_importance = pd.DataFrame({
    "Feature": top20_features,
    "Importance": model.get_feature_importance()
})

feature_importance = feature_importance.sort_values(
    "Importance",
    ascending=False
)

print(feature_importance.to_string(index=False))

# ==============================================================
# 19. SAVE RESULTS
# ==============================================================

results = {

    "experiment": "Sequential Top-20 Train Validation Test",

    "dataset": DATA_PATH,

    "feature_count": len(top20_features),

    "features": top20_features,

    "split": {
        "train": "first 70%",
        "validation": "next 10%",
        "test": "final 20%"
    },

    "shapes": {
        "train": list(X_train.shape),
        "validation": list(X_val.shape),
        "test": list(X_test.shape)
    },

    "catboost_parameters": {
        "iterations": ITERATIONS,
        "depth": DEPTH,
        "learning_rate": LEARNING_RATE,
        "random_seed": 42
    },

    "training_time_seconds": training_time,

    "prediction_time_seconds": prediction_time,

    "validation_threshold": best_threshold,

    "validation_metrics": {
        "accuracy": float(best_row["Accuracy"]),
        "precision": float(best_row["Precision"]),
        "recall": float(best_row["Recall"]),
        "f1": float(best_row["F1"]),
        "fpr": float(best_row["FPR"]),
        "fnr": float(best_row["FNR"]),
        "tn": int(best_row["TN"]),
        "fp": int(best_row["FP"]),
        "fn": int(best_row["FN"]),
        "tp": int(best_row["TP"])
    },

    "test_threshold_0_50": metrics_50,

    "test_selected_threshold": metrics_selected
}

with open(
    RESULT_OUTPUT,
    "w"
) as f:

    json.dump(
        results,
        f,
        indent=4
    )

print("\n" + "=" * 70)
print("FILES SAVED")
print("=" * 70)

print(MODEL_OUTPUT)
print(RESULT_OUTPUT)
print(THRESHOLD_OUTPUT)

print("\n" + "=" * 70)
print("SEQUENTIAL TOP-20 TRAIN / VALIDATION / TEST COMPLETED")
print("=" * 70)