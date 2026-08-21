import pandas as pd
import numpy as np
import json
import time
import joblib

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
print("CICIDS2017 FINAL CATBOOST MODEL")
print("=" * 70)

# ==============================================================
# LOAD DATA
# ==============================================================

print("\nLoading training features...")
X_train = pd.read_csv("data/features/X_train_scaled.csv")

print("Loading testing features...")
X_test = pd.read_csv("data/features/X_test_scaled.csv")

print("Loading training targets...")
y_train = pd.read_csv("data/splits/y_train.csv").squeeze()

print("Loading testing targets...")
y_test = pd.read_csv("data/splits/y_test.csv").squeeze()

print("\nTraining shape:", X_train.shape)
print("Testing shape :", X_test.shape)

# ==============================================================
# FINAL MODEL PARAMETERS
# ==============================================================

iterations = 500
depth = 10
learning_rate = 0.05

print("\n" + "=" * 70)
print("FINAL MODEL PARAMETERS")
print("=" * 70)

print("Iterations    :", iterations)
print("Depth         :", depth)
print("Learning rate :", learning_rate)

# ==============================================================
# CREATE MODEL
# ==============================================================

model = CatBoostClassifier(
    iterations=iterations,
    depth=depth,
    learning_rate=learning_rate,
    loss_function="Logloss",
    random_seed=42,
    verbose=False,
    thread_count=-1,
    l2_leaf_reg=3
)

# ==============================================================
# TRAIN ON COMPLETE TRAINING DATA
# ==============================================================

print("\n" + "=" * 70)
print("TRAINING FINAL MODEL")
print("=" * 70)

start_time = time.time()

model.fit(
    X_train,
    y_train,
    verbose=False
)

training_time = time.time() - start_time

print("\nTraining time:", f"{training_time:.2f}", "seconds")
print("Trees:", model.tree_count_)

# ==============================================================
# PREDICTION
# ==============================================================

print("\nGenerating predictions...")

start_time = time.time()

y_pred = model.predict(X_test).ravel()
y_prob = model.predict_proba(X_test)[:, 1]

prediction_time = time.time() - start_time

print("Prediction time:", f"{prediction_time:.2f}", "seconds")

# ==============================================================
# METRICS
# ==============================================================

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
roc_auc = roc_auc_score(y_test, y_prob)

cm = confusion_matrix(y_test, y_pred)

# ==============================================================
# PERFORMANCE
# ==============================================================

print("\n" + "=" * 70)
print("FINAL MODEL PERFORMANCE")
print("=" * 70)

print(f"\nAccuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1-score : {f1:.4f}")
print(f"ROC-AUC  : {roc_auc:.4f}")

print("\nConfusion Matrix:")
print(cm)

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        target_names=["BENIGN", "ATTACK"]
    )
)

# ==============================================================
# FEATURE IMPORTANCE
# ==============================================================

importance = model.get_feature_importance()

feature_importance = pd.DataFrame({
    "Feature": X_train.columns,
    "Importance": importance
})

feature_importance = feature_importance.sort_values(
    "Importance",
    ascending=False
)

print("\nTop 15 important features:")
print(feature_importance.head(15).to_string(index=False))

# ==============================================================
# SAVE MODEL
# ==============================================================

model.save_model(
    "results/models/final_catboost_model.cbm"
)

# ==============================================================
# SAVE FEATURE IMPORTANCE
# ==============================================================

feature_importance.to_csv(
    "results/models/final_catboost_feature_importance.csv",
    index=False
)

# ==============================================================
# SAVE RESULTS
# ==============================================================

tn, fp, fn, tp = cm.ravel()

results = {
    "model": "Final CatBoost",
    "iterations": int(iterations),
    "depth": int(depth),
    "learning_rate": float(learning_rate),
    "tree_count": int(model.tree_count_),

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
    ]
}

with open(
    "results/models/final_catboost_results.json",
    "w"
) as f:
    json.dump(results, f, indent=4)

print("\n" + "=" * 70)
print("FILES SAVED")
print("=" * 70)

print("results/models/final_catboost_model.cbm")
print("results/models/final_catboost_results.json")
print("results/models/final_catboost_feature_importance.csv")

print("\n" + "=" * 70)
print("FINAL CATBOOST TRAINING COMPLETED")
print("=" * 70)