import pandas as pd
import numpy as np
import json
import os
import time

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
print("CICIDS2017 CATBOOST TOP 20 FEATURES")
print("=" * 70)

# ============================================================
# LOAD DATA
# ============================================================

print("\nLoading training features...")
X_train = pd.read_csv(
    "data/features/top20/X_train_top20.csv"
)

print("Loading testing features...")
X_test = pd.read_csv(
    "data/features/top20/X_test_top20.csv"
)

print("Loading training targets...")
y_train = pd.read_csv(
    "data/splits/y_train.csv"
).squeeze()

print("Loading testing targets...")
y_test = pd.read_csv(
    "data/splits/y_test.csv"
).squeeze()

print("\nTraining shape:", X_train.shape)
print("Testing shape :", X_test.shape)

# ============================================================
# LOAD FEATURE NAMES
# ============================================================

with open(
    "data/features/top20/top20_feature_names.json",
    "r"
) as f:
    feature_names = json.load(f)

print("\nNumber of features:", len(feature_names))

# ============================================================
# FINAL MODEL PARAMETERS
# Same optimized configuration as final CatBoost
# ============================================================

iterations = 500
depth = 10
learning_rate = 0.05

print("\n" + "=" * 70)
print("CATBOOST TOP 20 PARAMETERS")
print("=" * 70)

print("Iterations    :", iterations)
print("Depth         :", depth)
print("Learning rate :", learning_rate)

# ============================================================
# TRAINING
# ============================================================

print("\n" + "=" * 70)
print("TRAINING TOP 20 FEATURE MODEL")
print("=" * 70)

model = CatBoostClassifier(
    iterations=iterations,
    depth=depth,
    learning_rate=learning_rate,
    loss_function="Logloss",
    eval_metric="AUC",
    random_seed=42,
    verbose=False,
    thread_count=-1
)

start_time = time.time()

model.fit(
    X_train,
    y_train
)

training_time = time.time() - start_time

print("\nTraining time:", round(training_time, 2), "seconds")
print("Trees:", model.tree_count_)

# ============================================================
# PREDICTION
# ============================================================

print("\nGenerating predictions...")

start_time = time.time()

y_pred = model.predict(X_test)
y_pred = np.asarray(y_pred).ravel().astype(int)

prediction_time = time.time() - start_time

print("Prediction time:", round(prediction_time, 2), "seconds")

# ============================================================
# PREDICTION PROBABILITIES
# ============================================================

print("\nGenerating prediction probabilities...")

y_prob = model.predict_proba(X_test)[:, 1]

# ============================================================
# METRICS
# ============================================================

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

# ============================================================
# PERFORMANCE
# ============================================================

print("\n" + "=" * 70)
print("TOP 20 FEATURE MODEL PERFORMANCE")
print("=" * 70)

print(f"\nAccuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1-score : {f1:.4f}")
print(f"ROC-AUC  : {roc_auc:.4f}")

print("\nConfusion Matrix:")
print(cm)

print("\nTN:", tn)
print("FP:", fp)
print("FN:", fn)
print("TP:", tp)

print("\nTotal Errors:", total_errors)

# ============================================================
# CLASSIFICATION REPORT
# ============================================================

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        target_names=["BENIGN", "ATTACK"],
        zero_division=0
    )
)

# ============================================================
# FEATURE IMPORTANCE
# ============================================================

importance = model.get_feature_importance()

feature_importance = pd.DataFrame({
    "Feature": feature_names,
    "Importance": importance
})

feature_importance = feature_importance.sort_values(
    by="Importance",
    ascending=False
)

print("\nTop 20 Feature Importance:")
print(feature_importance.to_string(index=False))

# ============================================================
# SAVE RESULTS
# ============================================================

os.makedirs(
    "results/models",
    exist_ok=True
)

results = {
    "model": "CatBoost Top 20 Features",
    "features_used": 20,
    "accuracy": float(accuracy),
    "precision": float(precision),
    "recall": float(recall),
    "f1_score": float(f1),
    "roc_auc": float(roc_auc),
    "training_time": float(training_time),
    "prediction_time": float(prediction_time),
    "confusion_matrix": [
        [int(tn), int(fp)],
        [int(fn), int(tp)]
    ],
    "total_errors": int(total_errors),
    "tree_count": int(model.tree_count_),
    "depth": depth,
    "iterations": iterations,
    "learning_rate": learning_rate,
    "feature_count": 20
}

with open(
    "results/models/catboost_top20_results.json",
    "w"
) as f:
    json.dump(
        results,
        f,
        indent=4
    )

feature_importance.to_csv(
    "results/models/catboost_top20_feature_importance.csv",
    index=False
)

model.save_model(
    "results/models/catboost_top20_model.cbm"
)

print("\n" + "=" * 70)
print("FILES SAVED")
print("=" * 70)

print("results/models/catboost_top20_results.json")
print("results/models/catboost_top20_feature_importance.csv")
print("results/models/catboost_top20_model.cbm")

print("\n" + "=" * 70)
print("CATBOOST TOP 20 FEATURE TRAINING COMPLETED")
print("=" * 70)