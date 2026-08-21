import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

print("=" * 70)
print("CICIDS2017 FINAL 6-MODEL COMPARISON")
print("=" * 70)

# ---------------------------------------------------------
# Model result files
# ---------------------------------------------------------

model_files = {
    "LightGBM": "results/models/lightgbm_results.json",
    "CatBoost": "results/models/catboost_results.json",
    "Extra Trees": "results/models/extra_trees_results.json",
    "Histogram Gradient Boosting":
        "results/models/histogram_gradient_boosting_results.json",
    "Passive Aggressive":
        "results/models/passive_aggressive_results.json",
    "Isolation Forest":
        "results/models/isolation_forest_results.json"
}

# ---------------------------------------------------------
# Read results
# ---------------------------------------------------------

results = []

for model_name, file_path in model_files.items():

    print(f"\nReading: {file_path}")

    with open(file_path, "r") as f:
        data = json.load(f)

    cm = np.array(data["confusion_matrix"])

    tn = int(cm[0][0])
    fp = int(cm[0][1])
    fn = int(cm[1][0])
    tp = int(cm[1][1])

    total_errors = fp + fn

    results.append({
        "Model": model_name,
        "Accuracy": data["accuracy"],
        "Precision": data["precision"],
        "Recall": data["recall"],
        "F1-score": data["f1_score"],
        "ROC-AUC": data.get("roc_auc", np.nan),
        "Training Time (s)": data["training_time"],
        "Prediction Time (s)": data["prediction_time"],
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "TP": tp,
        "Total Errors": total_errors
    })

df = pd.DataFrame(results)

# ---------------------------------------------------------
# Performance comparison
# ---------------------------------------------------------

print("\n" + "=" * 70)
print("MODEL PERFORMANCE COMPARISON")
print("=" * 70)

performance = df[
    [
        "Model",
        "Accuracy",
        "Precision",
        "Recall",
        "F1-score",
        "ROC-AUC"
    ]
]

print(performance.to_string(index=False))

# ---------------------------------------------------------
# Training / prediction time
# ---------------------------------------------------------

print("\n" + "=" * 70)
print("TRAINING / PREDICTION TIME")
print("=" * 70)

timing = df[
    [
        "Model",
        "Training Time (s)",
        "Prediction Time (s)"
    ]
]

print(timing.to_string(index=False))

# ---------------------------------------------------------
# Confusion matrix comparison
# ---------------------------------------------------------

print("\n" + "=" * 70)
print("CONFUSION MATRIX COMPARISON")
print("=" * 70)

errors = df[
    [
        "Model",
        "TN",
        "FP",
        "FN",
        "TP",
        "Total Errors"
    ]
]

print(errors.to_string(index=False))

# ---------------------------------------------------------
# Best model by each metric
# ---------------------------------------------------------

print("\n" + "=" * 70)
print("BEST MODEL BY METRIC")
print("=" * 70)

metrics = [
    "Accuracy",
    "Precision",
    "Recall",
    "F1-score",
    "ROC-AUC"
]

for metric in metrics:

    valid = df.dropna(subset=[metric])

    best_index = valid[metric].idxmax()

    best_model = valid.loc[best_index, "Model"]
    best_value = valid.loc[best_index, metric]

    print(f"{metric:<12}: {best_model:<30} ({best_value:.4f})")

# ---------------------------------------------------------
# Lowest errors
# ---------------------------------------------------------

lowest_error_index = df["Total Errors"].idxmin()

lowest_error_model = df.loc[
    lowest_error_index,
    "Model"
]

lowest_errors = int(
    df.loc[lowest_error_index, "Total Errors"]
)

print(
    f"\nLowest total errors: "
    f"{lowest_error_model} ({lowest_errors})"
)

# ---------------------------------------------------------
# Overall score
#
# Average of the available performance metrics:
# Accuracy, Precision, Recall, F1, ROC-AUC
#
# Passive Aggressive has no ROC-AUC in its result file,
# so its average uses the four available metrics.
# ---------------------------------------------------------

score_metrics = [
    "Accuracy",
    "Precision",
    "Recall",
    "F1-score",
    "ROC-AUC"
]

df["Average Metric Score"] = df[score_metrics].mean(axis=1)

best_overall_index = df["Average Metric Score"].idxmax()

best_overall_model = df.loc[
    best_overall_index,
    "Model"
]

best_overall_score = df.loc[
    best_overall_index,
    "Average Metric Score"
]

print("\n" + "=" * 70)
print("OVERALL BASELINE MODEL")
print("=" * 70)

print(
    f"{best_overall_model} "
    f"(average metric score: {best_overall_score:.4f})"
)

# ---------------------------------------------------------
# Final ranking
# ---------------------------------------------------------

ranking = df.sort_values(
    by="Average Metric Score",
    ascending=False
).reset_index(drop=True)

ranking.insert(
    0,
    "Rank",
    range(1, len(ranking) + 1)
)

print("\n" + "=" * 70)
print("FINAL MODEL RANKING")
print("=" * 70)

print(
    ranking[
        [
            "Rank",
            "Model",
            "Accuracy",
            "Precision",
            "Recall",
            "F1-score",
            "ROC-AUC",
            "Total Errors"
        ]
    ].to_string(index=False)
)

# ---------------------------------------------------------
# Save complete comparison
# ---------------------------------------------------------

output_csv = "results/models/all_six_model_comparison.csv"

df.to_csv(
    output_csv,
    index=False
)

print("\nSaved:")
print(output_csv)

# ---------------------------------------------------------
# Save ranking
# ---------------------------------------------------------

ranking_csv = "results/models/all_six_model_ranking.csv"

ranking.to_csv(
    ranking_csv,
    index=False
)

print(ranking_csv)

# ---------------------------------------------------------
# Performance plot
# ---------------------------------------------------------

plot_df = df.set_index("Model")[
    [
        "Accuracy",
        "Precision",
        "Recall",
        "F1-score"
    ]
]

ax = plot_df.plot(
    kind="bar",
    figsize=(12, 7)
)

ax.set_title(
    "CICIDS2017 - Final Six NIDS Models"
)

ax.set_ylabel("Score")
ax.set_ylim(0, 1.05)

plt.xticks(rotation=30, ha="right")
plt.tight_layout()

performance_plot = (
    "results/models/all_six_model_performance.png"
)

plt.savefig(
    performance_plot,
    dpi=300
)

plt.close()

print(performance_plot)

# ---------------------------------------------------------
# Error plot
# ---------------------------------------------------------

error_df = df.set_index("Model")[
    [
        "FP",
        "FN"
    ]
]

ax = error_df.plot(
    kind="bar",
    figsize=(12, 7)
)

ax.set_title(
    "CICIDS2017 - False Positive / False Negative Comparison"
)

ax.set_ylabel("Number of Errors")

plt.xticks(rotation=30, ha="right")
plt.tight_layout()

error_plot = (
    "results/models/all_six_model_errors.png"
)

plt.savefig(
    error_plot,
    dpi=300
)

plt.close()

print(error_plot)

print("\n" + "=" * 70)
print("FINAL 6-MODEL COMPARISON COMPLETED")
print("=" * 70)