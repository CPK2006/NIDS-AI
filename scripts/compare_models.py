import json
import os
import pandas as pd
import matplotlib.pyplot as plt


print("=" * 70)
print("CICIDS2017 MODEL COMPARISON")
print("=" * 70)


# ============================================================
# RESULT FILES
# ============================================================

model_files = {
    "Logistic Regression":
        "results/models/logistic_regression_results.json",

    "Decision Tree":
        "results/models/decision_tree_results.json",

    "Random Forest":
        "results/models/random_forest_results.json"
}


# ============================================================
# LOAD RESULTS
# ============================================================

results = []

for model_name, file_path in model_files.items():

    print(f"\nReading: {file_path}")

    with open(file_path, "r") as f:
        data = json.load(f)

    cm = data["confusion_matrix"]

    # Confusion matrix:
    # [[TN, FP],
    #  [FN, TP]]

    tn = cm[0][0]
    fp = cm[0][1]
    fn = cm[1][0]
    tp = cm[1][1]

    results.append({
        "Model": model_name,

        "Accuracy": data["accuracy"],
        "Precision": data["precision"],
        "Recall": data["recall"],
        "F1-score": data["f1_score"],
        "ROC-AUC": data["roc_auc"],

        "Training Time (s)": data["training_time_seconds"],
        "Prediction Time (s)": data["prediction_time_seconds"],

        "TN": tn,
        "FP": fp,
        "FN": fn,
        "TP": tp,

        "Total Errors": fp + fn
    })


# ============================================================
# CREATE DATAFRAME
# ============================================================

df = pd.DataFrame(results)


print("\n" + "=" * 70)
print("MODEL PERFORMANCE COMPARISON")
print("=" * 70)

print(
    df[
        [
            "Model",
            "Accuracy",
            "Precision",
            "Recall",
            "F1-score",
            "ROC-AUC"
        ]
    ].to_string(index=False)
)


# ============================================================
# TIME COMPARISON
# ============================================================

print("\n" + "=" * 70)
print("TRAINING / PREDICTION TIME")
print("=" * 70)

print(
    df[
        [
            "Model",
            "Training Time (s)",
            "Prediction Time (s)"
        ]
    ].to_string(index=False)
)


# ============================================================
# CONFUSION MATRIX COMPARISON
# ============================================================

print("\n" + "=" * 70)
print("CONFUSION MATRIX COMPARISON")
print("=" * 70)

print(
    df[
        [
            "Model",
            "TN",
            "FP",
            "FN",
            "TP",
            "Total Errors"
        ]
    ].to_string(index=False)
)


# ============================================================
# BEST MODEL FOR EACH METRIC
# ============================================================

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

best_models = {}

for metric in metrics:

    best_index = df[metric].idxmax()

    best_model = df.loc[best_index, "Model"]
    best_value = df.loc[best_index, metric]

    best_models[metric] = best_model

    print(
        f"{metric:<12}: "
        f"{best_model:<20} "
        f"({best_value:.4f})"
    )


# ============================================================
# LOWEST ERROR MODEL
# ============================================================

best_error_index = df["Total Errors"].idxmin()

best_error_model = df.loc[
    best_error_index,
    "Model"
]

best_error_count = int(
    df.loc[best_error_index, "Total Errors"]
)

print(
    f"\nLowest total errors: "
    f"{best_error_model} "
    f"({best_error_count})"
)


# ============================================================
# OVERALL BEST MODEL
# ============================================================

# Average of the five performance metrics
df["Average Performance"] = df[
    metrics
].mean(axis=1)

overall_index = df[
    "Average Performance"
].idxmax()

overall_model = df.loc[
    overall_index,
    "Model"
]

overall_score = df.loc[
    overall_index,
    "Average Performance"
]


print("\n" + "=" * 70)
print("OVERALL BASELINE MODEL")
print("=" * 70)

print(
    f"{overall_model} "
    f"(average metric score: {overall_score:.4f})"
)


# ============================================================
# SAVE CSV
# ============================================================

output_csv = "results/models/model_comparison.csv"

df.to_csv(
    output_csv,
    index=False
)

print("\nSaved:")
print(output_csv)


# ============================================================
# PERFORMANCE VISUALIZATION
# ============================================================

plot_df = df[
    [
        "Model",
        "Accuracy",
        "Precision",
        "Recall",
        "F1-score",
        "ROC-AUC"
    ]
].set_index("Model")

ax = plot_df.plot(
    kind="bar",
    figsize=(12, 7)
)

ax.set_title(
    "CICIDS2017 Model Performance Comparison"
)

ax.set_ylabel("Score")
ax.set_ylim(0.85, 1.01)

plt.xticks(rotation=0)
plt.legend(loc="lower right")
plt.tight_layout()

output_plot = "results/models/model_comparison.png"

plt.savefig(
    output_plot,
    dpi=300
)

plt.close()

print(output_plot)


# ============================================================
# FINAL SUMMARY
# ============================================================

print("\n" + "=" * 70)
print("MODEL COMPARISON COMPLETED")
print("=" * 70)

print("\nModels compared:")
for model in df["Model"]:
    print(" -", model)

print("\nOverall best baseline:", overall_model)
print("Lowest-error model:", best_error_model)