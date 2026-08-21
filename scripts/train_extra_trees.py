import pandas as pd
import json
import time

from sklearn.ensemble import ExtraTreesClassifier
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
print("CICIDS2017 EXTRA TREES BASELINE")
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
# CREATE EXTRA TREES MODEL
# ============================================================

model = ExtraTreesClassifier(
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
print(f"Number of trees: {model.n_estimators}")


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

cm = confusion_matrix(
    y_test,
    y_pred
)


# ============================================================
# DISPLAY PERFORMANCE
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
print(
    classification_report(
        y_test,
        y_pred,
        zero_division=0
    )
)


# ============================================================
# FEATURE IMPORTANCE
# ============================================================

feature_importance = pd.DataFrame({
    "Feature": X_train.columns,
    "Importance": model.feature_importances_
})

feature_importance = feature_importance.sort_values(
    by="Importance",
    ascending=False
)

print("\nTop 15 important features:")
print(
    feature_importance
    .head(15)
    .to_string(index=False)
)


# ============================================================
# SAVE RESULTS
# ============================================================

results = {
    "model": "Extra Trees",
    "accuracy": float(accuracy),
    "precision": float(precision),
    "recall": float(recall),
    "f1_score": float(f1),
    "roc_auc": float(roc_auc),
    "training_time": float(training_time),
    "prediction_time": float(prediction_time),
    "confusion_matrix": cm.tolist(),
    "number_of_trees": int(model.n_estimators)
}

with open(
    "results/models/extra_trees_results.json",
    "w"
) as f:
    json.dump(
        results,
        f,
        indent=4
    )


feature_importance.to_csv(
    "results/models/extra_trees_feature_importance.csv",
    index=False
)


# ============================================================
# COMPLETED
# ============================================================

print("\nSaved:")
print("results/models/extra_trees_results.json")
print("results/models/extra_trees_feature_importance.csv")

print("\n" + "=" * 70)
print("EXTRA TREES BASELINE COMPLETED")
print("=" * 70)