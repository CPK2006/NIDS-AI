import json
import os
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np


print("=" * 70)
print("CICIDS2017 MODEL EVALUATION")
print("=" * 70)


# ============================================================
# LOAD MODEL RESULTS
# ============================================================

model_files = {
    "Logistic Regression":
        "results/models/logistic_regression_results.json",

    "Decision Tree":
        "results/models/decision_tree_results.json",

    "Random Forest":
        "results/models/random_forest_results.json"
}


results = {}

for model_name, file_path in model_files.items():

    print(f"\nReading: {file_path}")

    with open(file_path, "r") as f:
        results[model_name] = json.load(f)


# ============================================================
# CREATE RESULTS DATAFRAME
# ============================================================

rows = []

for model_name, data in results.items():

    rows.append({
        "Model": model_name,
        "Accuracy": data["accuracy"],
        "Precision": data["precision"],
        "Recall": data["recall"],
        "F1-score": data["f1_score"],
        "ROC-AUC": data["roc_auc"],
        "Training Time": data["training_time_seconds"],
        "Prediction Time": data["prediction_time_seconds"]
    })


df = pd.DataFrame(rows)


# ============================================================
# PRINT SUMMARY
# ============================================================

print("\n" + "=" * 70)
print("MODEL PERFORMANCE")
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
# CONFUSION MATRIX VISUALIZATION
# ============================================================

print("\nGenerating confusion matrices...")


for model_name, data in results.items():

    cm = np.array(data["confusion_matrix"])

    fig, ax = plt.subplots(figsize=(7, 6))

    image = ax.imshow(cm)

    ax.set_title(
        f"{model_name} - Confusion Matrix"
    )

    ax.set_xlabel("Predicted Label")
    ax.set_ylabel("Actual Label")

    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])

    ax.set_xticklabels(["BENIGN", "ATTACK"])
    ax.set_yticklabels(["BENIGN", "ATTACK"])

    # Display values inside cells
    for i in range(2):
        for j in range(2):

            ax.text(
                j,
                i,
                f"{cm[i, j]:,}",
                ha="center",
                va="center"
            )

    plt.colorbar(image)

    plt.tight_layout()

    safe_name = model_name.lower().replace(" ", "_")

    output_file = (
        f"results/models/"
        f"{safe_name}_confusion_matrix.png"
    )

    plt.savefig(
        output_file,
        dpi=300
    )

    plt.close()

    print(f"Saved: {output_file}")


# ============================================================
# METRIC COMPARISON
# ============================================================

print("\nGenerating metric comparison...")


metrics = [
    "Accuracy",
    "Precision",
    "Recall",
    "F1-score",
    "ROC-AUC"
]

plot_df = df[
    ["Model"] + metrics
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

output_file = (
    "results/models/"
    "model_metrics_comparison.png"
)

plt.savefig(
    output_file,
    dpi=300
)

plt.close()

print(f"Saved: {output_file}")


# ============================================================
# ERROR COMPARISON
# ============================================================

print("\nGenerating error comparison...")


error_rows = []

for model_name, data in results.items():

    cm = data["confusion_matrix"]

    tn = cm[0][0]
    fp = cm[0][1]
    fn = cm[1][0]
    tp = cm[1][1]

    error_rows.append({
        "Model": model_name,
        "False Positives": fp,
        "False Negatives": fn,
        "Total Errors": fp + fn
    })


error_df = pd.DataFrame(error_rows)


print(
    error_df.to_string(index=False)
)


ax = error_df.set_index("Model")[
    ["False Positives", "False Negatives"]
].plot(
    kind="bar",
    figsize=(10, 6)
)

ax.set_title(
    "False Positive and False Negative Comparison"
)

ax.set_ylabel("Number of Samples")

plt.xticks(rotation=0)

plt.tight_layout()

output_file = (
    "results/models/"
    "model_error_comparison.png"
)

plt.savefig(
    output_file,
    dpi=300
)

plt.close()

print(f"Saved: {output_file}")


# ============================================================
# SAVE EVALUATION SUMMARY
# ============================================================

evaluation_df = pd.merge(
    df,
    error_df,
    on="Model"
)

output_csv = (
    "results/models/"
    "model_evaluation_summary.csv"
)

evaluation_df.to_csv(
    output_csv,
    index=False
)

print(f"\nSaved: {output_csv}")


# ============================================================
# INTERPRETATION
# ============================================================

print("\n" + "=" * 70)
print("EVALUATION SUMMARY")
print("=" * 70)


best_accuracy = df.loc[
    df["Accuracy"].idxmax(),
    "Model"
]

best_precision = df.loc[
    df["Precision"].idxmax(),
    "Model"
]

best_recall = df.loc[
    df["Recall"].idxmax(),
    "Model"
]

best_f1 = df.loc[
    df["F1-score"].idxmax(),
    "Model"
]

best_auc = df.loc[
    df["ROC-AUC"].idxmax(),
    "Model"
]

lowest_errors = error_df.loc[
    error_df["Total Errors"].idxmin(),
    "Model"
]


print(f"Best Accuracy : {best_accuracy}")
print(f"Best Precision: {best_precision}")
print(f"Best Recall   : {best_recall}")
print(f"Best F1-score : {best_f1}")
print(f"Best ROC-AUC  : {best_auc}")
print(f"Fewest Errors : {lowest_errors}")


print("\n" + "=" * 70)
print("EVALUATION COMPLETED")
print("=" * 70)