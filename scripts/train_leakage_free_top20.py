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

# ==============================================================
# PATHS
# ==============================================================

DATA_PATH = "data/sample/cicids2017_binary_deduplicated.csv"

MODEL_OUTPUT = (
    "results/models/"
    "leakage_free_top20_catboost_model.cbm"
)

RESULT_OUTPUT = (
    "results/models/"
    "leakage_free_top20_results.json"
)

FEATURE_OUTPUT = (
    "results/models/"
    "leakage_free_top20_features.csv"
)

THRESHOLD_OUTPUT = (
    "results/models/"
    "leakage_free_top20_validation_thresholds.csv"
)

os.makedirs("results/models", exist_ok=True)

# ==============================================================
# PARAMETERS
# ==============================================================

SELECTION_ITERATIONS = 500
FINAL_ITERATIONS = 500
DEPTH = 10
LEARNING_RATE = 0.05
RANDOM_SEED = 42

TOP_K = 20

# ==============================================================
# 1. LOAD DATA
# ==============================================================

print("\nLoading complete deduplicated dataset...")

df = pd.read_csv(DATA_PATH)

print("Dataset shape:", df.shape)

# ==============================================================
# 2. SEPARATE FEATURES AND TARGET
# ==============================================================

X = df.drop(columns=["Binary_Label"])
y = df["Binary_Label"]

print("\nFeature matrix:", X.shape)
print("Target:", y.shape)

# ==============================================================
# 3. SEQUENTIAL 70 / 10 / 20 SPLIT
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
# 4. CLASS DISTRIBUTIONS
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
# 5. BASIC TRAINING-DATA CLEANING
#    IMPORTANT:
#    Everything here is calculated ONLY from TRAINING DATA.
# ==============================================================

print("\n" + "=" * 70)
print("TRAINING-ONLY FEATURE CLEANING")
print("=" * 70)

# --------------------------------------------------------------
# Remove constant features based ONLY on training data
# --------------------------------------------------------------

train_std = X_train.std()

constant_features = train_std[
    train_std == 0
].index.tolist()

print("\nConstant features found in training:", len(constant_features))

if constant_features:

    for feature in constant_features:
        print(" -", feature)

    X_train = X_train.drop(
        columns=constant_features
    )

    X_val = X_val.drop(
        columns=constant_features
    )

    X_test = X_test.drop(
        columns=constant_features
    )

# --------------------------------------------------------------
# Remove duplicate columns based ONLY on training data
# --------------------------------------------------------------

print("\nChecking duplicate feature columns...")

duplicate_columns = []

columns = X_train.columns

for i in range(len(columns)):

    for j in range(i + 1, len(columns)):

        col1 = columns[i]
        col2 = columns[j]

        if X_train[col1].equals(X_train[col2]):

            duplicate_columns.append(col2)

duplicate_columns = list(
    dict.fromkeys(duplicate_columns)
)

print(
    "Duplicate feature columns found:",
    len(duplicate_columns)
)

if duplicate_columns:

    for feature in duplicate_columns:
        print(" -", feature)

    X_train = X_train.drop(
        columns=duplicate_columns
    )

    X_val = X_val.drop(
        columns=duplicate_columns
    )

    X_test = X_test.drop(
        columns=duplicate_columns
    )

print(
    "\nFeatures available for selection:",
    X_train.shape[1]
)

# ==============================================================
# 6. TRAIN FEATURE-SELECTION MODEL
# ==============================================================

print("\n" + "=" * 70)
print("TRAINING FEATURE-SELECTION MODEL")
print("=" * 70)

print(
    "\nIMPORTANT:"
    "\nFeature selection uses TRAINING DATA ONLY."
    "\nValidation and test data are NOT used."
)

selection_model = CatBoostClassifier(
    iterations=SELECTION_ITERATIONS,
    depth=DEPTH,
    learning_rate=LEARNING_RATE,
    loss_function="Logloss",
    eval_metric="AUC",
    random_seed=RANDOM_SEED,
    verbose=100,
    allow_writing_files=False
)

selection_start = time.time()

selection_model.fit(
    X_train,
    y_train
)

selection_time = time.time() - selection_start

print(
    f"\nFeature-selection training time: "
    f"{selection_time:.2f} seconds"
)

# ==============================================================
# 7. FEATURE IMPORTANCE
# ==============================================================

print("\n" + "=" * 70)
print("SELECTING TOP 20 FEATURES")
print("=" * 70)

importance = selection_model.get_feature_importance()

importance_df = pd.DataFrame({
    "Feature": X_train.columns,
    "Importance": importance
})

importance_df = importance_df.sort_values(
    "Importance",
    ascending=False
).reset_index(drop=True)

top20_df = importance_df.head(TOP_K)

top20_features = top20_df["Feature"].tolist()

print("\nTop 20 features selected from TRAIN ONLY:")

for i, row in top20_df.iterrows():

    print(
        f"{i + 1:2d}. "
        f"{row['Feature']:<35} "
        f"{row['Importance']:.6f}"
    )

# Save feature importance
importance_df.to_csv(
    FEATURE_OUTPUT,
    index=False
)

print("\nFeature list saved:")
print(FEATURE_OUTPUT)

# ==============================================================
# 8. REDUCE DATASETS TO TOP 20
# ==============================================================

X_train_top20 = X_train[
    top20_features
].copy()

X_val_top20 = X_val[
    top20_features
].copy()

X_test_top20 = X_test[
    top20_features
].copy()

print("\nTop-20 shapes:")

print(
    "X_train_top20:",
    X_train_top20.shape
)

print(
    "X_val_top20  :",
    X_val_top20.shape
)

print(
    "X_test_top20 :",
    X_test_top20.shape
)

# ==============================================================
# 9. TRAIN FINAL TOP-20 MODEL
# ==============================================================

print("\n" + "=" * 70)
print("TRAINING FINAL TOP-20 CATBOOST")
print("=" * 70)

final_model = CatBoostClassifier(
    iterations=FINAL_ITERATIONS,
    depth=DEPTH,
    learning_rate=LEARNING_RATE,
    loss_function="Logloss",
    eval_metric="AUC",
    random_seed=RANDOM_SEED,
    verbose=100,
    allow_writing_files=False
)

final_start = time.time()

final_model.fit(
    X_train_top20,
    y_train
)

final_training_time = (
    time.time() - final_start
)

print(
    f"\nFinal training time: "
    f"{final_training_time:.2f} seconds"
)

print(
    "Trees:",
    final_model.tree_count_
)

# ==============================================================
# 10. SAVE FINAL MODEL
# ==============================================================

final_model.save_model(
    MODEL_OUTPUT
)

print("\nModel saved:")
print(MODEL_OUTPUT)

# ==============================================================
# 11. VALIDATION PROBABILITIES
# ==============================================================

print("\n" + "=" * 70)
print("VALIDATION THRESHOLD SELECTION")
print("=" * 70)

print(
    "\nGenerating validation probabilities..."
)

val_probabilities = final_model.predict_proba(
    X_val_top20
)[:, 1]

# ==============================================================
# 12. SEARCH THRESHOLDS
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
# 13. SELECT VALIDATION THRESHOLD
# ==============================================================

best_row = threshold_df.loc[
    threshold_df["F1"].idxmax()
]

best_threshold = float(
    best_row["Threshold"]
)

print("\nBest validation threshold:")
print(
    f"{best_threshold:.3f}"
)

print("\nValidation performance:")

print(
    f"Accuracy  : {best_row['Accuracy']:.6f}"
)

print(
    f"Precision : {best_row['Precision']:.6f}"
)

print(
    f"Recall    : {best_row['Recall']:.6f}"
)

print(
    f"F1        : {best_row['F1']:.6f}"
)

print(
    f"FPR       : {best_row['FPR']:.6f}"
)

print(
    f"FNR       : {best_row['FNR']:.6f}"
)

print(
    f"TN        : {int(best_row['TN'])}"
)

print(
    f"FP        : {int(best_row['FP'])}"
)

print(
    f"FN        : {int(best_row['FN'])}"
)

print(
    f"TP        : {int(best_row['TP'])}"
)

# ==============================================================
# 14. FINAL TEST EVALUATION
# ==============================================================

print("\n" + "=" * 70)
print("FINAL UNTOUCHED TEST EVALUATION")
print("=" * 70)

print(
    "\nIMPORTANT:"
    "\nTest data has NOT been used for:"
    "\n- feature selection"
    "\n- model training"
    "\n- threshold selection"
)

print(
    "\nGenerating test probabilities..."
)

prediction_start = time.time()

test_probabilities = final_model.predict_proba(
    X_test_top20
)[:, 1]

prediction_time = (
    time.time() - prediction_start
)

# ==============================================================
# 15. TEST PREDICTIONS
# ==============================================================

# Default threshold
y_test_pred_50 = (
    test_probabilities >= 0.50
).astype(int)

# Validation-selected threshold
y_test_pred_selected = (
    test_probabilities >= best_threshold
).astype(int)

# ==============================================================
# 16. METRIC FUNCTION
# ==============================================================

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

# ==============================================================
# 17. CALCULATE FINAL TEST METRICS
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
# 18. DISPLAY RESULTS
# ==============================================================

print("\n" + "=" * 70)
print("FINAL TEST RESULTS")
print("=" * 70)

print(
    f"\n{'Metric':<25}"
    f"{'Threshold 0.50':>18}"
    f"{'Selected Threshold':>22}"
)

print("-" * 70)

rows = [
    (
        "Accuracy",
        metrics_50["accuracy"],
        metrics_selected["accuracy"]
    ),
    (
        "Precision",
        metrics_50["precision"],
        metrics_selected["precision"]
    ),
    (
        "Recall",
        metrics_50["recall"],
        metrics_selected["recall"]
    ),
    (
        "F1-score",
        metrics_50["f1"],
        metrics_selected["f1"]
    ),
    (
        "ROC-AUC",
        metrics_50["roc_auc"],
        metrics_selected["roc_auc"]
    ),
    (
        "False Positive Rate",
        metrics_50["fpr"],
        metrics_selected["fpr"]
    ),
    (
        "False Negative Rate",
        metrics_50["fnr"],
        metrics_selected["fnr"]
    ),
    (
        "False Positives",
        metrics_50["fp"],
        metrics_selected["fp"]
    ),
    (
        "False Negatives",
        metrics_50["fn"],
        metrics_selected["fn"]
    ),
    (
        "Total Errors",
        metrics_50["total_errors"],
        metrics_selected["total_errors"]
    )
]

for name, a, b in rows:

    if name in [
        "False Positives",
        "False Negatives",
        "Total Errors"
    ]:

        print(
            f"{name:<25}"
            f"{a:>18.0f}"
            f"{b:>22.0f}"
        )

    else:

        print(
            f"{name:<25}"
            f"{a:>18.6f}"
            f"{b:>22.6f}"
        )

# ==============================================================
# 19. CONFUSION MATRICES
# ==============================================================

print("\n" + "=" * 70)
print("CONFUSION MATRICES")
print("=" * 70)

print("\nThreshold = 0.50")

cm_50 = confusion_matrix(
    y_test,
    y_test_pred_50,
    labels=[0, 1]
)

print(cm_50)

print(
    f"\nValidation-selected threshold = "
    f"{best_threshold:.3f}"
)

cm_selected = confusion_matrix(
    y_test,
    y_test_pred_selected,
    labels=[0, 1]
)

print(cm_selected)

# ==============================================================
# 20. FINAL FEATURE IMPORTANCE
# ==============================================================

print("\n" + "=" * 70)
print("FINAL TOP-20 FEATURE IMPORTANCE")
print("=" * 70)

final_importance = pd.DataFrame({
    "Feature": top20_features,
    "Importance": final_model.get_feature_importance()
})

final_importance = final_importance.sort_values(
    "Importance",
    ascending=False
)

print(
    final_importance.to_string(
        index=False
    )
)

# ==============================================================
# 21. SAVE JSON RESULTS
# ==============================================================

results = {

    "experiment":
        "Leakage-Free Sequential Top-20 CatBoost",

    "dataset":
        DATA_PATH,

    "feature_selection":
        "Training data only",

    "feature_count":
        len(top20_features),

    "top20_features":
        top20_features,

    "removed_constant_features":
        constant_features,

    "removed_duplicate_features":
        duplicate_columns,

    "split": {
        "train": "first 70%",
        "validation": "next 10%",
        "test": "final 20%"
    },

    "shapes": {
        "train":
            list(X_train_top20.shape),

        "validation":
            list(X_val_top20.shape),

        "test":
            list(X_test_top20.shape)
    },

    "parameters": {
        "selection_iterations":
            SELECTION_ITERATIONS,

        "final_iterations":
            FINAL_ITERATIONS,

        "depth":
            DEPTH,

        "learning_rate":
            LEARNING_RATE,

        "random_seed":
            RANDOM_SEED
    },

    "timing": {

        "feature_selection_training_seconds":
            selection_time,

        "final_training_seconds":
            final_training_time,

        "prediction_seconds":
            prediction_time
    },

    "validation_selected_threshold":
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
            float(best_row["FNR"]),

        "tn":
            int(best_row["TN"]),

        "fp":
            int(best_row["FP"]),

        "fn":
            int(best_row["FN"]),

        "tp":
            int(best_row["TP"])
    },

    "test_threshold_0_50":
        metrics_50,

    "test_validation_selected_threshold":
        metrics_selected
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

# ==============================================================
# 22. FINAL OUTPUT
# ==============================================================

print("\n" + "=" * 70)
print("FILES SAVED")
print("=" * 70)

print(
    MODEL_OUTPUT
)

print(
    RESULT_OUTPUT
)

print(
    FEATURE_OUTPUT
)

print(
    THRESHOLD_OUTPUT
)

print("\n" + "=" * 70)
print("LEAKAGE-FREE TOP-20 EXPERIMENT COMPLETED")
print("=" * 70)