import json
import pandas as pd
import matplotlib.pyplot as plt
import os

print("=" * 70)
print("CATBOOST FEATURE REDUCTION COMPARISON")
print("=" * 70)

# ============================================================
# LOAD RESULTS
# ============================================================

print("\nReading 65-feature Final CatBoost results...")

with open(
    "results/models/final_catboost_results.json",
    "r"
) as f:
    final_65 = json.load(f)

print("Reading 20-feature CatBoost results...")

with open(
    "results/models/catboost_top20_results.json",
    "r"
) as f:
    top20 = json.load(f)

# ============================================================
# CREATE COMPARISON TABLE
# ============================================================

comparison = pd.DataFrame([
    {
        "Model": "Final CatBoost (65 Features)",
        "Features": 65,
        "Accuracy": final_65["accuracy"],
        "Precision": final_65["precision"],
        "Recall": final_65["recall"],
        "F1-score": final_65["f1_score"],
        "ROC-AUC": final_65["roc_auc"],
        "Training Time (s)": final_65["training_time"],
        "Prediction Time (s)": final_65["prediction_time"],
        "Total Errors": (
            final_65["confusion_matrix"][0][1]
            + final_65["confusion_matrix"][1][0]
        )
    },
    {
        "Model": "CatBoost (Top 20 Features)",
        "Features": 20,
        "Accuracy": top20["accuracy"],
        "Precision": top20["precision"],
        "Recall": top20["recall"],
        "F1-score": top20["f1_score"],
        "ROC-AUC": top20["roc_auc"],
        "Training Time (s)": top20["training_time"],
        "Prediction Time (s)": top20["prediction_time"],
        "Total Errors": top20["total_errors"]
    }
])

# ============================================================
# DISPLAY COMPARISON
# ============================================================

print("\n" + "=" * 70)
print("PERFORMANCE COMPARISON")
print("=" * 70)

display_table = comparison.copy()

for column in [
    "Accuracy",
    "Precision",
    "Recall",
    "F1-score",
    "ROC-AUC"
]:
    display_table[column] = display_table[column].map(
        lambda x: f"{x:.6f}"
    )

print(display_table.to_string(index=False))

# ============================================================
# CALCULATE DIFFERENCES
# ============================================================

accuracy_change = top20["accuracy"] - final_65["accuracy"]
precision_change = top20["precision"] - final_65["precision"]
recall_change = top20["recall"] - final_65["recall"]
f1_change = top20["f1_score"] - final_65["f1_score"]
roc_auc_change = top20["roc_auc"] - final_65["roc_auc"]

feature_reduction = (
    (65 - 20) / 65
) * 100

training_change = (
    (top20["training_time"] - final_65["training_time"])
    / final_65["training_time"]
) * 100

prediction_change = (
    (top20["prediction_time"] - final_65["prediction_time"])
    / final_65["prediction_time"]
) * 100

error_change = (
    top20["total_errors"]
    - (
        final_65["confusion_matrix"][0][1]
        + final_65["confusion_matrix"][1][0]
    )
)

# ============================================================
# DIFFERENCE SUMMARY
# ============================================================

print("\n" + "=" * 70)
print("FEATURE REDUCTION ANALYSIS")
print("=" * 70)

print(f"\nFeatures:")
print("65-feature model :", 65)
print("20-feature model :", 20)
print(f"Feature reduction: {feature_reduction:.2f}%")

print("\nMetric changes (20 features - 65 features):")

print(f"Accuracy : {accuracy_change:+.6f}")
print(f"Precision: {precision_change:+.6f}")
print(f"Recall   : {recall_change:+.6f}")
print(f"F1-score : {f1_change:+.6f}")
print(f"ROC-AUC  : {roc_auc_change:+.6f}")

print("\nTraining time:")
print(
    f"65 features: {final_65['training_time']:.2f} seconds"
)
print(
    f"20 features: {top20['training_time']:.2f} seconds"
)
print(
    f"Change: {training_change:+.2f}%"
)

print("\nPrediction time:")
print(
    f"65 features: {final_65['prediction_time']:.2f} seconds"
)
print(
    f"20 features: {top20['prediction_time']:.2f} seconds"
)
print(
    f"Change: {prediction_change:+.2f}%"
)

print("\nTotal errors:")
print(
    "65 features:",
    final_65["confusion_matrix"][0][1]
    + final_65["confusion_matrix"][1][0]
)
print("20 features:", top20["total_errors"])
print(f"Change: {error_change:+d}")

# ============================================================
# SAVE COMPARISON
# ============================================================

os.makedirs(
    "results/models",
    exist_ok=True
)

comparison.to_csv(
    "results/models/catboost_feature_reduction_comparison.csv",
    index=False
)

print("\nSaved:")
print(
    "results/models/"
    "catboost_feature_reduction_comparison.csv"
)

# ============================================================
# GENERATE PERFORMANCE PLOT
# ============================================================

metrics = [
    "Accuracy",
    "Precision",
    "Recall",
    "F1-score",
    "ROC-AUC"
]

model1_values = [
    final_65["accuracy"],
    final_65["precision"],
    final_65["recall"],
    final_65["f1_score"],
    final_65["roc_auc"]
]

model2_values = [
    top20["accuracy"],
    top20["precision"],
    top20["recall"],
    top20["f1_score"],
    top20["roc_auc"]
]

x = range(len(metrics))
width = 0.35

plt.figure(figsize=(10, 6))

plt.bar(
    [i - width / 2 for i in x],
    model1_values,
    width,
    label="CatBoost - 65 Features"
)

plt.bar(
    [i + width / 2 for i in x],
    model2_values,
    width,
    label="CatBoost - Top 20 Features"
)

plt.xticks(x, metrics)
plt.ylabel("Score")
plt.title(
    "CatBoost Performance: 65 Features vs Top 20 Features"
)
plt.ylim(0.95, 1.001)
plt.legend()
plt.tight_layout()

plt.savefig(
    "results/models/catboost_feature_reduction_comparison.png",
    dpi=300
)

plt.close()

print(
    "results/models/"
    "catboost_feature_reduction_comparison.png"
)

# ============================================================
# FINAL CONCLUSION
# ============================================================

print("\n" + "=" * 70)
print("FEATURE REDUCTION CONCLUSION")
print("=" * 70)

print(
    f"\nThe feature set was reduced from 65 to 20 features "
    f"({feature_reduction:.2f}% reduction)."
)

print(
    f"The 20-feature model produced {top20['total_errors']} "
    f"errors compared with "
    f"{final_65['confusion_matrix'][0][1] + final_65['confusion_matrix'][1][0]} "
    f"errors for the 65-feature model."
)

print(
    f"Accuracy changed from "
    f"{final_65['accuracy']:.6f} to "
    f"{top20['accuracy']:.6f}."
)

print(
    f"F1-score changed from "
    f"{final_65['f1_score']:.6f} to "
    f"{top20['f1_score']:.6f}."
)

print(
    f"ROC-AUC changed from "
    f"{final_65['roc_auc']:.6f} to "
    f"{top20['roc_auc']:.6f}."
)

print("\nThe 20 most important features retain nearly")
print("the same detection performance while reducing")
print("the number of input features substantially.")

print("\n" + "=" * 70)
print("FEATURE REDUCTION COMPARISON COMPLETED")
print("=" * 70)