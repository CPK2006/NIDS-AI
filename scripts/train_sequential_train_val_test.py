import pandas as pd
import numpy as np
import os

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
print("CICIDS2017 RIGOROUS SEQUENTIAL TRAIN / VALIDATION / TEST")
print("=" * 70)

# --------------------------------------------------
# Paths
# --------------------------------------------------

DATA_PATH = "data/sample/cicids2017_binary_deduplicated.csv"

MODEL_PATH = "results/models/sequential_train_val_model.cbm"
RESULT_PATH = "results/models/sequential_train_val_test_results.json"

os.makedirs("results/models", exist_ok=True)

# --------------------------------------------------
# Load dataset
# --------------------------------------------------

print("\nLoading complete deduplicated dataset...")

df = pd.read_csv(DATA_PATH)

print("Dataset shape:", df.shape)

# --------------------------------------------------
# Separate features and target
# --------------------------------------------------

X = df.drop(columns=["Binary_Label"])
y = df["Binary_Label"]

print("\nFeature matrix:", X.shape)
print("Target:", y.shape)

# --------------------------------------------------
# Sequential 70 / 10 / 20 split
# --------------------------------------------------

n = len(df)

train_end = int(n * 0.70)
val_end = int(n * 0.80)

X_train = X.iloc[:train_end]
y_train = y.iloc[:train_end]

X_val = X.iloc[train_end:val_end]
y_val = y.iloc[train_end:val_end]

X_test = X.iloc[val_end:]
y_test = y.iloc[val_end:]

print("\n" + "=" * 70)
print("SEQUENTIAL SPLIT")
print("=" * 70)

print("\nTraining:")
print("X_train:", X_train.shape)
print("y_train:", y_train.shape)

print("\nValidation:")
print("X_val:", X_val.shape)
print("y_val:", y_val.shape)

print("\nTesting:")
print("X_test:", X_test.shape)
print("y_test:", y_test.shape)

# --------------------------------------------------
# Class distributions
# --------------------------------------------------

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
        (target.value_counts(normalize=True) * 100)
        .round(3)
    )

# --------------------------------------------------
# Train CatBoost
# --------------------------------------------------

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
    verbose=100,
    random_seed=42,
    thread_count=-1
)

print("\n" + "=" * 70)
print("TRAINING")
print("=" * 70)

model.fit(
    X_train,
    y_train
)

print("\nTraining completed.")

# --------------------------------------------------
# Save model
# --------------------------------------------------

model.save_model(MODEL_PATH)

print("\nModel saved:")
print(MODEL_PATH)

# --------------------------------------------------
# Validation probabilities
# --------------------------------------------------

print("\n" + "=" * 70)
print("VALIDATION THRESHOLD SELECTION")
print("=" * 70)

print("\nGenerating validation probabilities...")

val_prob = model.predict_proba(X_val)[:, 1]

# Thresholds
thresholds = np.arange(
    0.01,
    1.00,
    0.01
)

validation_results = []

for threshold in thresholds:

    y_pred = (
        val_prob >= threshold
    ).astype(int)

    tn, fp, fn, tp = confusion_matrix(
        y_val,
        y_pred,
        labels=[0, 1]
    ).ravel()

    accuracy = accuracy_score(
        y_val,
        y_pred
    )

    precision = precision_score(
        y_val,
        y_pred,
        zero_division=0
    )

    recall = recall_score(
        y_val,
        y_pred,
        zero_division=0
    )

    f1 = f1_score(
        y_val,
        y_pred,
        zero_division=0
    )

    fpr = fp / (fp + tn)
    fnr = fn / (fn + tp)

    validation_results.append({
        "threshold": float(threshold),
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "fnr": fnr,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp)
    })

validation_df = pd.DataFrame(
    validation_results
)

# --------------------------------------------------
# Select threshold by F1
# --------------------------------------------------

best_validation = validation_df.loc[
    validation_df["f1"].idxmax()
]

selected_threshold = float(
    best_validation["threshold"]
)

print("\nBest validation threshold:")
print(
    f"{selected_threshold:.2f}"
)

print("\nValidation performance at selected threshold:")

for column in [
    "accuracy",
    "precision",
    "recall",
    "f1",
    "fpr",
    "fnr",
    "tn",
    "fp",
    "fn",
    "tp"
]:
    print(
        f"{column.upper():<12}: "
        f"{best_validation[column]}"
    )

# --------------------------------------------------
# Final TEST evaluation
# --------------------------------------------------

print("\n" + "=" * 70)
print("FINAL TEST EVALUATION")
print("=" * 70)

print(
    "\nIMPORTANT: Test data has NOT been used "
    "for threshold selection."
)

print("\nGenerating test probabilities...")

test_prob = model.predict_proba(X_test)[:, 1]

# --------------------------------------------------
# Evaluate threshold 0.50
# --------------------------------------------------

def evaluate_threshold(
    y_true,
    probabilities,
    threshold
):

    predictions = (
        probabilities >= threshold
    ).astype(int)

    tn, fp, fn, tp = confusion_matrix(
        y_true,
        predictions,
        labels=[0, 1]
    ).ravel()

    accuracy = accuracy_score(
        y_true,
        predictions
    )

    precision = precision_score(
        y_true,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_true,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_true,
        predictions,
        zero_division=0
    )

    roc_auc = roc_auc_score(
        y_true,
        probabilities
    )

    fpr = fp / (fp + tn)
    fnr = fn / (fn + tp)

    return {
        "threshold": float(threshold),
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


default_test = evaluate_threshold(
    y_test,
    test_prob,
    0.50
)

selected_test = evaluate_threshold(
    y_test,
    test_prob,
    selected_threshold
)

# --------------------------------------------------
# Print comparison
# --------------------------------------------------

print("\n" + "=" * 70)
print("FINAL TEST COMPARISON")
print("=" * 70)

print(
    f"{'Metric':<20}"
    f"{'Threshold 0.50':<20}"
    f"{'Selected Threshold':<20}"
)

print("-" * 60)

metrics = [
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

for label, key in metrics:

    print(
        f"{label:<20}"
        f"{default_test[key]:<20.6f}"
        f"{selected_test[key]:<20.6f}"
    )

# --------------------------------------------------
# Confusion matrices
# --------------------------------------------------

print("\n" + "=" * 70)
print("CONFUSION MATRICES")
print("=" * 70)

print("\nThreshold = 0.50")

print(
    np.array([
        [default_test["tn"], default_test["fp"]],
        [default_test["fn"], default_test["tp"]]
    ])
)

print(
    "\nValidation-selected threshold = "
    f"{selected_threshold:.2f}"
)

print(
    np.array([
        [selected_test["tn"], selected_test["fp"]],
        [selected_test["fn"], selected_test["tp"]]
    ])
)

# --------------------------------------------------
# Save results
# --------------------------------------------------

output = {
    "dataset": {
        "total_samples": int(n),
        "features": int(X.shape[1])
    },

    "split": {
        "train_percentage": 70,
        "validation_percentage": 10,
        "test_percentage": 20,
        "train_samples": int(len(X_train)),
        "validation_samples": int(len(X_val)),
        "test_samples": int(len(X_test))
    },

    "threshold_selection": {
        "method": "Maximum validation F1",
        "selected_threshold": selected_threshold
    },

    "validation_best": {
        key: (
            float(value)
            if isinstance(value, (np.floating, float))
            else int(value)
        )
        for key, value
        in best_validation.to_dict().items()
    },

    "test_default_threshold_0.50": default_test,

    "test_selected_threshold": selected_test
}

import json

with open(
    RESULT_PATH,
    "w"
) as f:

    json.dump(
        output,
        f,
        indent=4
    )

# Save validation threshold table

validation_df.to_csv(
    "results/models/sequential_validation_thresholds.csv",
    index=False
)

print("\n" + "=" * 70)
print("FILES SAVED")
print("=" * 70)

print(MODEL_PATH)
print(RESULT_PATH)
print(
    "results/models/"
    "sequential_validation_thresholds.csv"
)

print("\n" + "=" * 70)
print("RIGOROUS SEQUENTIAL EVALUATION COMPLETED")
print("=" * 70)