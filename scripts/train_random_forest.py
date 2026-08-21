import pandas as pd
import numpy as np
import json
import time

from sklearn.ensemble import RandomForestClassifier
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
print("CICIDS2017 RANDOM FOREST")
print("=" * 70)


# ============================================================
# LOAD DATA
# ============================================================

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


# ============================================================
# CREATE RANDOM FOREST
# ============================================================

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)


# ============================================================
# TRAINING
# ============================================================

print("\n" + "=" * 70)
print("TRAINING")
print("=" * 70)

start_time = time.time()

model.fit(X_train, y_train)

training_time = time.time() - start_time

print(f"\nTraining time: {training_time:.2f} seconds")

print("Number of trees:", model.n_estimators)


# ============================================================
# PREDICTION
# ============================================================

print("\nGenerating predictions...")

start_time = time.time()

y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

prediction_time = time.time() - start_time

print(f"Prediction time: {prediction_time:.2f} seconds")


# ============================================================
# PERFORMANCE METRICS
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

cm = confusion_matrix(y_test, y_pred)

report = classification_report(
    y_test,
    y_pred,
    zero_division=0
)


# ============================================================
# DISPLAY RESULTS
# ============================================================

print("\n" + "=" * 70)
print("MODEL PERFORMANCE")
print("=" * 70)

print(f"\nAccuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1-score : {f1:.4f}")
print(f"ROC-AUC  : {roc_auc:.4f}")

print("\nConfusion Matrix:")
print(cm)

print("\nClassification Report:")
print(report)


# ============================================================
# FEATURE IMPORTANCE
# ============================================================

importance_df = pd.DataFrame({
    "Feature": X_train.columns,
    "Importance": model.feature_importances_
})

importance_df = importance_df.sort_values(
    by="Importance",
    ascending=False
)

print("\nTop 15 important features:")

print(
    importance_df.head(15).to_string(index=False)
)


# ============================================================
# SAVE RESULTS
# ============================================================

results = {
    "model": "Random Forest",

    "training_samples": int(X_train.shape[0]),
    "testing_samples": int(X_test.shape[0]),
    "features": int(X_train.shape[1]),

    "n_estimators": int(model.n_estimators),

    "training_time_seconds": float(training_time),
    "prediction_time_seconds": float(prediction_time),

    "accuracy": float(accuracy),
    "precision": float(precision),
    "recall": float(recall),
    "f1_score": float(f1),
    "roc_auc": float(roc_auc),

    "confusion_matrix": cm.tolist(),

    "classification_report": classification_report(
        y_test,
        y_pred,
        output_dict=True,
        zero_division=0
    )
}


# ============================================================
# SAVE JSON
# ============================================================

output_json = "results/models/random_forest_results.json"

with open(output_json, "w") as f:
    json.dump(results, f, indent=4)


# ============================================================
# SAVE FEATURE IMPORTANCE
# ============================================================

output_importance = "results/models/random_forest_feature_importance.csv"

importance_df.to_csv(
    output_importance,
    index=False
)


# ============================================================
# COMPLETED
# ============================================================

print("\nSaved:")
print(output_json)
print(output_importance)

print("\n" + "=" * 70)
print("RANDOM FOREST COMPLETED")
print("=" * 70)