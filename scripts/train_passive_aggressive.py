import pandas as pd
import numpy as np
import json
import time

from sklearn.linear_model import PassiveAggressiveClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

print("=" * 70)
print("CICIDS2017 PASSIVE AGGRESSIVE CLASSIFIER BASELINE")
print("=" * 70)

# ---------------------------------------------------------
# Load data
# ---------------------------------------------------------

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

# ---------------------------------------------------------
# Model
# ---------------------------------------------------------

model = PassiveAggressiveClassifier(
    C=1.0,
    max_iter=1000,
    tol=1e-3,
    random_state=42
)

print("\n" + "=" * 70)
print("TRAINING")
print("=" * 70)

start_time = time.time()

model.fit(X_train, y_train)

training_time = time.time() - start_time

print(f"\nTraining time: {training_time:.2f} seconds")

# ---------------------------------------------------------
# Prediction
# ---------------------------------------------------------

print("\nGenerating predictions...")

start_time = time.time()

y_pred = model.predict(X_test)

prediction_time = time.time() - start_time

print(f"Prediction time: {prediction_time:.2f} seconds")

# ---------------------------------------------------------
# Metrics
# ---------------------------------------------------------

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, zero_division=0)
recall = recall_score(y_test, y_pred, zero_division=0)
f1 = f1_score(y_test, y_pred, zero_division=0)

cm = confusion_matrix(y_test, y_pred)

print("\n" + "=" * 70)
print("MODEL PERFORMANCE")
print("=" * 70)

print(f"\nAccuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1-score : {f1:.4f}")

print("\nConfusion Matrix:")
print(cm)

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# ---------------------------------------------------------
# Results
# ---------------------------------------------------------

results = {
    "model": "Passive Aggressive Classifier",
    "accuracy": float(accuracy),
    "precision": float(precision),
    "recall": float(recall),
    "f1_score": float(f1),
    "training_time": float(training_time),
    "prediction_time": float(prediction_time),
    "confusion_matrix": cm.tolist()
}

# ---------------------------------------------------------
# Save results
# ---------------------------------------------------------

output_file = "results/models/passive_aggressive_results.json"

with open(output_file, "w") as f:
    json.dump(results, f, indent=4)

print("\nSaved:")
print(output_file)

print("\n" + "=" * 70)
print("PASSIVE AGGRESSIVE CLASSIFIER BASELINE COMPLETED")
print("=" * 70)