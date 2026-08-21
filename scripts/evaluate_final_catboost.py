import pandas as pd
import numpy as np
import json
import time
import matplotlib.pyplot as plt

from catboost import CatBoostClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
    roc_curve,
    precision_recall_curve,
    average_precision_score
)


# ==============================================================
# CICIDS2017 FINAL CATBOOST EVALUATION
# ==============================================================

print("=" * 70)
print("CICIDS2017 FINAL CATBOOST EVALUATION")
print("=" * 70)


# ==============================================================
# PATHS
# ==============================================================

MODEL_PATH = "results/models/final_catboost_model.cbm"

X_TEST_PATH = "data/features/X_test_scaled.csv"
Y_TEST_PATH = "data/splits/y_test.csv"

RESULTS_PATH = "results/models/final_catboost_evaluation.json"

ROC_PATH = "results/models/final_catboost_roc_curve.png"
PR_PATH = "results/models/final_catboost_precision_recall_curve.png"
CM_PATH = "results/models/final_catboost_confusion_matrix.png"


# ==============================================================
# LOAD TEST DATA
# ==============================================================

print("\nLoading testing features...")
X_test = pd.read_csv(X_TEST_PATH)

print("Loading testing targets...")
y_test = pd.read_csv(Y_TEST_PATH).squeeze()

print("\nTesting shape:")
print("X_test:", X_test.shape)
print("y_test:", y_test.shape)


# ==============================================================
# LOAD FINAL CATBOOST MODEL
# ==============================================================

print("\nLoading final CatBoost model...")

model = CatBoostClassifier()

model.load_model(MODEL_PATH)

print("Model loaded successfully.")


# ==============================================================
# GENERATE PREDICTIONS
# ==============================================================

print("\n" + "=" * 70)
print("GENERATING PREDICTIONS")
print("=" * 70)

start_time = time.time()

y_pred = model.predict(X_test)
y_pred = np.asarray(y_pred).ravel().astype(int)

prediction_time = time.time() - start_time

print(f"\nPrediction time: {prediction_time:.2f} seconds")


# ==============================================================
# PREDICT PROBABILITIES
# ==============================================================

print("\nGenerating prediction probabilities...")

y_prob = model.predict_proba(X_test)[:, 1]


# ==============================================================
# METRICS
# ==============================================================

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

average_precision = average_precision_score(
    y_test,
    y_prob
)


# ==============================================================
# CONFUSION MATRIX
# ==============================================================

cm = confusion_matrix(y_test, y_pred)

tn, fp, fn, tp = cm.ravel()

total_errors = fp + fn

false_positive_rate = fp / (fp + tn)

false_negative_rate = fn / (fn + tp)


# ==============================================================
# DISPLAY RESULTS
# ==============================================================

print("\n" + "=" * 70)
print("FINAL CATBOOST PERFORMANCE")
print("=" * 70)

print(f"\nAccuracy          : {accuracy:.6f}")
print(f"Precision         : {precision:.6f}")
print(f"Recall            : {recall:.6f}")
print(f"F1-score          : {f1:.6f}")
print(f"ROC-AUC           : {roc_auc:.6f}")
print(f"Average Precision : {average_precision:.6f}")

print("\nConfusion Matrix:")
print(cm)

print("\nTN:", tn)
print("FP:", fp)
print("FN:", fn)
print("TP:", tp)

print("\nTotal Errors:", total_errors)

print(f"\nFalse Positive Rate : {false_positive_rate:.6f}")
print(f"False Negative Rate : {false_negative_rate:.6f}")


# ==============================================================
# CLASSIFICATION REPORT
# ==============================================================

print("\n" + "=" * 70)
print("CLASSIFICATION REPORT")
print("=" * 70)

report = classification_report(
    y_test,
    y_pred,
    target_names=["BENIGN", "ATTACK"],
    zero_division=0
)

print(report)


# ==============================================================
# CONFUSION MATRIX PLOT
# ==============================================================

print("\nGenerating confusion matrix...")

plt.figure(figsize=(7, 6))

plt.imshow(cm)

plt.title("Final CatBoost - Confusion Matrix")
plt.xlabel("Predicted Label")
plt.ylabel("Actual Label")

plt.xticks(
    [0, 1],
    ["BENIGN", "ATTACK"]
)

plt.yticks(
    [0, 1],
    ["BENIGN", "ATTACK"]
)

for i in range(2):
    for j in range(2):
        plt.text(
            j,
            i,
            str(cm[i, j]),
            ha="center",
            va="center"
        )

plt.colorbar()
plt.tight_layout()

plt.savefig(CM_PATH, dpi=300)
plt.close()

print("Saved:", CM_PATH)


# ==============================================================
# ROC CURVE
# ==============================================================

print("\nGenerating ROC curve...")

fpr, tpr, thresholds = roc_curve(
    y_test,
    y_prob
)

plt.figure(figsize=(8, 6))

plt.plot(
    fpr,
    tpr,
    label=f"CatBoost (AUC = {roc_auc:.4f})"
)

plt.plot(
    [0, 1],
    [0, 1],
    linestyle="--",
    label="Random Classifier"
)

plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("Final CatBoost - ROC Curve")

plt.legend()
plt.grid(True)

plt.tight_layout()

plt.savefig(ROC_PATH, dpi=300)
plt.close()

print("Saved:", ROC_PATH)


# ==============================================================
# PRECISION-RECALL CURVE
# ==============================================================

print("\nGenerating Precision-Recall curve...")

pr_precision, pr_recall, pr_thresholds = precision_recall_curve(
    y_test,
    y_prob
)

plt.figure(figsize=(8, 6))

plt.plot(
    pr_recall,
    pr_precision,
    label=f"CatBoost (AP = {average_precision:.4f})"
)

plt.xlabel("Recall")
plt.ylabel("Precision")

plt.title("Final CatBoost - Precision-Recall Curve")

plt.legend()
plt.grid(True)

plt.tight_layout()

plt.savefig(PR_PATH, dpi=300)
plt.close()

print("Saved:", PR_PATH)


# ==============================================================
# SAVE RESULTS
# ==============================================================

results = {
    "model": "Final CatBoost",

    "accuracy": float(accuracy),
    "precision": float(precision),
    "recall": float(recall),
    "f1_score": float(f1),
    "roc_auc": float(roc_auc),
    "average_precision": float(average_precision),

    "true_negative": int(tn),
    "false_positive": int(fp),
    "false_negative": int(fn),
    "true_positive": int(tp),

    "total_errors": int(total_errors),

    "false_positive_rate": float(false_positive_rate),
    "false_negative_rate": float(false_negative_rate),

    "prediction_time": float(prediction_time),

    "test_samples": int(len(y_test)),
    "test_features": int(X_test.shape[1])
}


with open(RESULTS_PATH, "w") as f:
    json.dump(
        results,
        f,
        indent=4
    )


# ==============================================================
# FINAL SUMMARY
# ==============================================================

print("\n" + "=" * 70)
print("EVALUATION SUMMARY")
print("=" * 70)

print(f"Accuracy          : {accuracy:.4%}")
print(f"Precision         : {precision:.4%}")
print(f"Recall            : {recall:.4%}")
print(f"F1-score          : {f1:.4%}")
print(f"ROC-AUC           : {roc_auc:.4%}")
print(f"Average Precision : {average_precision:.4%}")

print("\nFalse Positives:", fp)
print("False Negatives:", fn)
print("Total Errors:", total_errors)

print("\n" + "=" * 70)
print("FILES SAVED")
print("=" * 70)

print(RESULTS_PATH)
print(CM_PATH)
print(ROC_PATH)
print(PR_PATH)

print("\n" + "=" * 70)
print("FINAL CATBOOST EVALUATION COMPLETED")
print("=" * 70)