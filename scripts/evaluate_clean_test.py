import pandas as pd
import numpy as np
import json
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
print("CICIDS2017 CLEAN TEST-SET EVALUATION")
print("=" * 70)

# ============================================================
# PATHS
# ============================================================

TRAIN_X = "data/features/X_train_scaled.csv"
TEST_X = "data/features/X_test_scaled.csv"

TRAIN_Y = "data/splits/y_train.csv"
TEST_Y = "data/splits/y_test.csv"

MODEL_PATH = "results/models/final_catboost_model.cbm"

# ============================================================
# LOAD DATA
# ============================================================

print("\nLoading training features...")
X_train = pd.read_csv(TRAIN_X)

print("Loading testing features...")
X_test = pd.read_csv(TEST_X)

print("Loading testing targets...")
y_test = pd.read_csv(TEST_Y)

if isinstance(y_test, pd.DataFrame):
    y_test = y_test.iloc[:, 0]

print("\nShapes:")
print("X_train:", X_train.shape)
print("X_test :", X_test.shape)
print("y_test :", y_test.shape)

# ============================================================
# FIND TRAIN/TEST OVERLAP
# ============================================================

print("\n" + "=" * 70)
print("FINDING TRAIN/TEST OVERLAP")
print("=" * 70)

print("Creating row hashes...")

train_hashes = pd.util.hash_pandas_object(
    X_train,
    index=False
)

test_hashes = pd.util.hash_pandas_object(
    X_test,
    index=False
)

train_hash_set = set(train_hashes)

overlap_mask = test_hashes.isin(train_hash_set)

overlap_count = int(overlap_mask.sum())

print("Total test samples:", len(X_test))
print("Overlapping test samples:", overlap_count)
print(
    "Overlap percentage:",
    f"{overlap_count / len(X_test) * 100:.6f}%"
)

# ============================================================
# CREATE CLEAN TEST SET
# ============================================================

clean_mask = ~overlap_mask

X_test_clean = X_test.loc[clean_mask].reset_index(drop=True)
y_test_clean = y_test.loc[clean_mask].reset_index(drop=True)

print("\nClean test shape:")
print("X_test_clean:", X_test_clean.shape)
print("y_test_clean:", y_test_clean.shape)

# ============================================================
# LOAD FINAL MODEL
# ============================================================

print("\n" + "=" * 70)
print("LOADING FINAL CATBOOST MODEL")
print("=" * 70)

model = CatBoostClassifier()

model.load_model(MODEL_PATH)

print("Model loaded successfully.")

# ============================================================
# ORIGINAL TEST EVALUATION
# ============================================================

print("\n" + "=" * 70)
print("ORIGINAL TEST SET")
print("=" * 70)

print("Generating predictions...")

y_pred_original = model.predict(X_test)

y_pred_original = np.asarray(
    y_pred_original
).reshape(-1)

y_prob_original = model.predict_proba(
    X_test
)[:, 1]

original_accuracy = accuracy_score(
    y_test,
    y_pred_original
)

original_precision = precision_score(
    y_test,
    y_pred_original,
    zero_division=0
)

original_recall = recall_score(
    y_test,
    y_pred_original,
    zero_division=0
)

original_f1 = f1_score(
    y_test,
    y_pred_original,
    zero_division=0
)

original_auc = roc_auc_score(
    y_test,
    y_prob_original
)

original_cm = confusion_matrix(
    y_test,
    y_pred_original
)

# ============================================================
# CLEAN TEST EVALUATION
# ============================================================

print("\n" + "=" * 70)
print("CLEAN TEST SET - OVERLAPPING ROWS REMOVED")
print("=" * 70)

print("Generating predictions...")

y_pred_clean = model.predict(X_test_clean)

y_pred_clean = np.asarray(
    y_pred_clean
).reshape(-1)

y_prob_clean = model.predict_proba(
    X_test_clean
)[:, 1]

clean_accuracy = accuracy_score(
    y_test_clean,
    y_pred_clean
)

clean_precision = precision_score(
    y_test_clean,
    y_pred_clean,
    zero_division=0
)

clean_recall = recall_score(
    y_test_clean,
    y_pred_clean,
    zero_division=0
)

clean_f1 = f1_score(
    y_test_clean,
    y_pred_clean,
    zero_division=0
)

clean_auc = roc_auc_score(
    y_test_clean,
    y_prob_clean
)

clean_cm = confusion_matrix(
    y_test_clean,
    y_pred_clean
)

# ============================================================
# DISPLAY RESULTS
# ============================================================

print("\n" + "=" * 70)
print("PERFORMANCE COMPARISON")
print("=" * 70)

print(
    f"{'Metric':<15}"
    f"{'Original':>15}"
    f"{'Clean Test':>15}"
    f"{'Change':>15}"
)

print("-" * 60)

metrics = [
    ("Accuracy", original_accuracy, clean_accuracy),
    ("Precision", original_precision, clean_precision),
    ("Recall", original_recall, clean_recall),
    ("F1-score", original_f1, clean_f1),
    ("ROC-AUC", original_auc, clean_auc)
]

for name, original, clean in metrics:

    change = clean - original

    print(
        f"{name:<15}"
        f"{original:>15.6f}"
        f"{clean:>15.6f}"
        f"{change:>+15.6f}"
    )

# ============================================================
# CONFUSION MATRICES
# ============================================================

print("\n" + "=" * 70)
print("ORIGINAL TEST CONFUSION MATRIX")
print("=" * 70)

print(original_cm)

print("\n" + "=" * 70)
print("CLEAN TEST CONFUSION MATRIX")
print("=" * 70)

print(clean_cm)

# ============================================================
# SAVE RESULTS
# ============================================================

results = {
    "total_test_samples": int(len(X_test)),
    "overlapping_test_samples": overlap_count,
    "overlap_percentage": float(
        overlap_count / len(X_test) * 100
    ),

    "clean_test_samples": int(len(X_test_clean)),

    "original": {
        "accuracy": float(original_accuracy),
        "precision": float(original_precision),
        "recall": float(original_recall),
        "f1_score": float(original_f1),
        "roc_auc": float(original_auc),
        "confusion_matrix": original_cm.tolist()
    },

    "clean_test": {
        "accuracy": float(clean_accuracy),
        "precision": float(clean_precision),
        "recall": float(clean_recall),
        "f1_score": float(clean_f1),
        "roc_auc": float(clean_auc),
        "confusion_matrix": clean_cm.tolist()
    },

    "change": {
        "accuracy": float(clean_accuracy - original_accuracy),
        "precision": float(clean_precision - original_precision),
        "recall": float(clean_recall - original_recall),
        "f1_score": float(clean_f1 - original_f1),
        "roc_auc": float(clean_auc - original_auc)
    }
}

output_path = (
    "results/models/clean_test_evaluation.json"
)

with open(output_path, "w") as f:
    json.dump(results, f, indent=4)

print("\nSaved:")
print(output_path)

print("\n" + "=" * 70)
print("CLEAN TEST EVALUATION COMPLETED")
print("=" * 70)