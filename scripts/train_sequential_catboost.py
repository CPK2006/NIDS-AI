import pandas as pd
import numpy as np
import os
import time
import json

from catboost import CatBoostClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

print("=" * 70)
print("CICIDS2017 SEQUENTIAL CATBOOST EVALUATION")
print("=" * 70)

# --------------------------------------------------
# Paths
# --------------------------------------------------

DATA_PATH = "data/sample/cicids2017_binary_deduplicated.csv"
FEATURE_PATH = "data/features/selected_features.csv"

MODEL_OUTPUT = "results/models/sequential_catboost_model.cbm"
RESULT_OUTPUT = "results/models/sequential_catboost_results.json"

os.makedirs("results/models", exist_ok=True)

# --------------------------------------------------
# Load dataset
# --------------------------------------------------

print("\nLoading complete deduplicated dataset...")

df = pd.read_csv(DATA_PATH)

print("Dataset shape:", df.shape)

# --------------------------------------------------
# Load selected features
# --------------------------------------------------

selected_features = pd.read_csv(
    FEATURE_PATH
)["Feature"].tolist()

print("\nSelected features:", len(selected_features))

# Verify features
missing = [
    f for f in selected_features
    if f not in df.columns
]

if missing:
    print("\nERROR: Missing features:")
    for f in missing:
        print(" -", f)
    raise ValueError("Required features are missing.")

# --------------------------------------------------
# Separate X and y
# --------------------------------------------------

X = df[selected_features]
y = df["Binary_Label"]

print("\nFeature matrix:", X.shape)
print("Target:", y.shape)

# --------------------------------------------------
# Sequential 80/20 split
# --------------------------------------------------

split_index = int(len(df) * 0.80)

X_train = X.iloc[:split_index].copy()
y_train = y.iloc[:split_index].copy()

X_test = X.iloc[split_index:].copy()
y_test = y.iloc[split_index:].copy()

print("\n" + "=" * 70)
print("SEQUENTIAL SPLIT")
print("=" * 70)

print("\nTraining:")
print("X_train:", X_train.shape)
print("y_train:", y_train.shape)

print("\nTesting:")
print("X_test:", X_test.shape)
print("y_test:", y_test.shape)

# --------------------------------------------------
# Class distribution
# --------------------------------------------------

print("\nTraining class distribution:")
print(y_train.value_counts())

print("\nTraining percentages:")
print(
    (y_train.value_counts(normalize=True) * 100).round(3)
)

print("\nTesting class distribution:")
print(y_test.value_counts())

print("\nTesting percentages:")
print(
    (y_test.value_counts(normalize=True) * 100).round(3)
)

# --------------------------------------------------
# CatBoost parameters
# --------------------------------------------------

print("\n" + "=" * 70)
print("CATBOOST PARAMETERS")
print("=" * 70)

iterations = 500
depth = 10
learning_rate = 0.05

print("Iterations    :", iterations)
print("Depth         :", depth)
print("Learning rate :", learning_rate)

# --------------------------------------------------
# Train
# --------------------------------------------------

print("\n" + "=" * 70)
print("TRAINING SEQUENTIAL MODEL")
print("=" * 70)

model = CatBoostClassifier(
    iterations=iterations,
    depth=depth,
    learning_rate=learning_rate,
    loss_function="Logloss",
    eval_metric="AUC",
    verbose=100,
    random_seed=42,
    thread_count=-1,
    allow_writing_files=False
)

start_time = time.time()

model.fit(
    X_train,
    y_train
)

training_time = time.time() - start_time

print("\nTraining time:", round(training_time, 2), "seconds")
print("Trees:", model.tree_count_)

# --------------------------------------------------
# Predictions
# --------------------------------------------------

print("\nGenerating predictions...")

start_time = time.time()

y_pred = model.predict(X_test).flatten()

prediction_time = time.time() - start_time

print("Prediction time:", round(prediction_time, 2), "seconds")

# --------------------------------------------------
# Probabilities
# --------------------------------------------------

print("\nGenerating prediction probabilities...")

y_prob = model.predict_proba(X_test)[:, 1]

# --------------------------------------------------
# Metrics
# --------------------------------------------------

accuracy = accuracy_score(y_test, y_pred)

precision = precision_score(
    y_test,
    y_pred,
    zero_division=0
)

recall = recall_score(
    y_test,
    y_pred,
    zero_division=0
)

f1 = f1_score(
    y_test,
    y_pred,
    zero_division=0
)

roc_auc = roc_auc_score(
    y_test,
    y_prob
)

cm = confusion_matrix(
    y_test,
    y_pred
)

tn, fp, fn, tp = cm.ravel()

total_errors = fp + fn

fpr = fp / (fp + tn)
fnr = fn / (fn + tp)

# --------------------------------------------------
# Results
# --------------------------------------------------

print("\n" + "=" * 70)
print("SEQUENTIAL TEST PERFORMANCE")
print("=" * 70)

print(f"\nAccuracy : {accuracy:.6f}")
print(f"Precision: {precision:.6f}")
print(f"Recall   : {recall:.6f}")
print(f"F1-score : {f1:.6f}")
print(f"ROC-AUC  : {roc_auc:.6f}")

print("\nConfusion Matrix:")
print(cm)

print("\nTN:", tn)
print("FP:", fp)
print("FN:", fn)
print("TP:", tp)

print("\nTotal Errors:", total_errors)

print("\nFalse Positive Rate :", round(fpr, 6))
print("False Negative Rate :", round(fnr, 6))

# --------------------------------------------------
# Classification report
# --------------------------------------------------

print("\n" + "=" * 70)
print("CLASSIFICATION REPORT")
print("=" * 70)

print(
    classification_report(
        y_test,
        y_pred,
        target_names=["BENIGN", "ATTACK"],
        zero_division=0
    )
)

# --------------------------------------------------
# Save model
# --------------------------------------------------

model.save_model(MODEL_OUTPUT)

# --------------------------------------------------
# Save results
# --------------------------------------------------

results = {
    "evaluation_type": "Sequential 80/20 split",
    "dataset": "CICIDS2017",
    "dataset_rows": int(len(df)),
    "train_rows": int(len(X_train)),
    "test_rows": int(len(X_test)),
    "features": int(len(selected_features)),

    "split_method": "First 80% training, last 20% testing",

    "train_benign": int((y_train == 0).sum()),
    "train_attack": int((y_train == 1).sum()),

    "test_benign": int((y_test == 0).sum()),
    "test_attack": int((y_test == 1).sum()),

    "accuracy": float(accuracy),
    "precision": float(precision),
    "recall": float(recall),
    "f1_score": float(f1),
    "roc_auc": float(roc_auc),

    "tn": int(tn),
    "fp": int(fp),
    "fn": int(fn),
    "tp": int(tp),

    "total_errors": int(total_errors),

    "false_positive_rate": float(fpr),
    "false_negative_rate": float(fnr),

    "training_time": float(training_time),
    "prediction_time": float(prediction_time),

    "iterations": iterations,
    "depth": depth,
    "learning_rate": learning_rate
}

with open(RESULT_OUTPUT, "w") as f:
    json.dump(results, f, indent=4)

# --------------------------------------------------
# Final summary
# --------------------------------------------------

print("\n" + "=" * 70)
print("FILES SAVED")
print("=" * 70)

print(MODEL_OUTPUT)
print(RESULT_OUTPUT)

print("\n" + "=" * 70)
print("SEQUENTIAL CATBOOST EVALUATION COMPLETED")
print("=" * 70)