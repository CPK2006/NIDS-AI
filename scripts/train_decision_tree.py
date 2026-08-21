import pandas as pd
import time
import json
import os

from sklearn.tree import DecisionTreeClassifier
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
print("CICIDS2017 DECISION TREE")
print("=" * 70)

TRAIN_X = "data/features/X_train_clean.csv"
TEST_X = "data/features/X_test_clean.csv"
TRAIN_Y = "data/splits/y_train.csv"
TEST_Y = "data/splits/y_test.csv"

RESULT_DIR = "results/models"
os.makedirs(RESULT_DIR, exist_ok=True)

# --------------------------------------------------
# Load data
# --------------------------------------------------

print("\nLoading training features...")
X_train = pd.read_csv(TRAIN_X)

print("Loading testing features...")
X_test = pd.read_csv(TEST_X)

print("Loading targets...")
y_train = pd.read_csv(TRAIN_Y).iloc[:, 0]
y_test = pd.read_csv(TEST_Y).iloc[:, 0]

print("\nTraining shape:", X_train.shape)
print("Testing shape :", X_test.shape)

# --------------------------------------------------
# Create model
# --------------------------------------------------

model = DecisionTreeClassifier(
    criterion="gini",
    max_depth=20,
    min_samples_split=10,
    min_samples_leaf=5,
    class_weight="balanced",
    random_state=42
)

print("\n" + "=" * 70)
print("TRAINING")
print("=" * 70)

start_time = time.time()

model.fit(X_train, y_train)

training_time = time.time() - start_time

print(f"\nTraining time: {training_time:.2f} seconds")
print("Tree depth:", model.get_depth())
print("Number of leaves:", model.get_n_leaves())

# --------------------------------------------------
# Prediction
# --------------------------------------------------

print("\nGenerating predictions...")

start_time = time.time()

y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

prediction_time = time.time() - start_time

print(f"Prediction time: {prediction_time:.2f} seconds")

# --------------------------------------------------
# Metrics
# --------------------------------------------------

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
roc_auc = roc_auc_score(y_test, y_prob)

cm = confusion_matrix(y_test, y_pred)

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
print(classification_report(y_test, y_pred))

# --------------------------------------------------
# Feature importance
# --------------------------------------------------

importance = pd.DataFrame({
    "Feature": X_train.columns,
    "Importance": model.feature_importances_
}).sort_values(
    "Importance",
    ascending=False
)

importance_path = os.path.join(
    RESULT_DIR,
    "decision_tree_feature_importance.csv"
)

importance.to_csv(importance_path, index=False)

print("\nTop 15 important features:")
print(importance.head(15).to_string(index=False))

# --------------------------------------------------
# Save results
# --------------------------------------------------

results = {
    "model": "Decision Tree",
    "training_samples": len(X_train),
    "testing_samples": len(X_test),
    "features": X_train.shape[1],
    "criterion": "gini",
    "max_depth": 20,
    "min_samples_split": 10,
    "min_samples_leaf": 5,
    "class_weight": "balanced",
    "tree_depth": model.get_depth(),
    "number_of_leaves": model.get_n_leaves(),
    "accuracy": accuracy,
    "precision": precision,
    "recall": recall,
    "f1_score": f1,
    "roc_auc": roc_auc,
    "training_time_seconds": training_time,
    "prediction_time_seconds": prediction_time,
    "confusion_matrix": cm.tolist()
}

output_file = os.path.join(
    RESULT_DIR,
    "decision_tree_results.json"
)
def convert_numpy(obj):
    if hasattr(obj, "item"):
        return obj.item()
    elif hasattr(obj, "tolist"):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {key: convert_numpy(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy(value) for value in obj]
    else:
        return obj


results = convert_numpy(results)

with open(output_file, "w") as f:
    json.dump(results, f, indent=4)

print("\nSaved:")
print(output_file)
print(importance_path)

print("\n" + "=" * 70)
print("DECISION TREE COMPLETED")
print("=" * 70)