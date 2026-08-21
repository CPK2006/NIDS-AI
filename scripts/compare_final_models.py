import pandas as pd
import json
import numpy as np

print("=" * 70)
print("CICIDS2017 FINAL MODEL COMPARISON")
print("=" * 70)

# ==============================================================
# MODEL RESULT FILES
# ==============================================================

model_files = {
    "Logistic Regression":
        "results/models/logistic_regression_results.json",

    "Decision Tree":
        "results/models/decision_tree_results.json",

    "Random Forest":
        "results/models/random_forest_results.json",

    "LightGBM":
        "results/models/lightgbm_results.json",

    "CatBoost":
        "results/models/catboost_results.json",

    "Extra Trees":
        "results/models/extra_trees_results.json",

    "Histogram Gradient Boosting":
        "results/models/histogram_gradient_boosting_results.json",

    "Passive Aggressive":
        "results/models/passive_aggressive_results.json",

    "Isolation Forest":
        "results/models/isolation_forest_results.json",

    "Final CatBoost":
        "results/models/final_catboost_results.json"
}

# ==============================================================
# READ RESULTS
# ==============================================================

results = []

for model_name, file_path in model_files.items():

    print("\nReading:", file_path)

    with open(file_path, "r") as f:
        data = json.load(f)

    data["model"] = model_name

    # ----------------------------------------------------------
    # Confusion matrix
    # ----------------------------------------------------------

    if "confusion_matrix" in data:

        cm = data["confusion_matrix"]

        tn = int(cm[0][0])
        fp = int(cm[0][1])
        fn = int(cm[1][0])
        tp = int(cm[1][1])

        data["TN"] = tn
        data["FP"] = fp
        data["FN"] = fn
        data["TP"] = tp
        data["total_errors"] = fp + fn

    else:
        data["TN"] = np.nan
        data["FP"] = np.nan
        data["FN"] = np.nan
        data["TP"] = np.nan
        data["total_errors"] = np.nan

    results.append(data)

# ==============================================================
# CREATE DATAFRAME
# ==============================================================

df = pd.DataFrame(results)

# ==============================================================
# PERFORMANCE COMPARISON
# ==============================================================

print("\n" + "=" * 70)
print("FINAL MODEL PERFORMANCE")
print("=" * 70)

performance_columns = [
    "model",
    "accuracy",
    "precision",
    "recall",
    "f1_score",
    "roc_auc"
]

print(
    df[performance_columns].to_string(index=False)
)

# ==============================================================
# CONFUSION MATRIX COMPARISON
# ==============================================================

print("\n" + "=" * 70)
print("CONFUSION MATRIX COMPARISON")
print("=" * 70)

error_columns = [
    "model",
    "TN",
    "FP",
    "FN",
    "TP",
    "total_errors"
]

print(
    df[error_columns].to_string(index=False)
)

# ==============================================================
# TRAINING / PREDICTION TIME
# ==============================================================

if "training_time" in df.columns:

    print("\n" + "=" * 70)
    print("TRAINING / PREDICTION TIME")
    print("=" * 70)

    time_columns = [
        "model",
        "training_time",
        "prediction_time"
    ]

    print(
        df[time_columns].to_string(index=False)
    )

# ==============================================================
# BEST MODEL BY EACH METRIC
# ==============================================================

print("\n" + "=" * 70)
print("BEST MODEL BY METRIC")
print("=" * 70)

metrics = {
    "Accuracy": "accuracy",
    "Precision": "precision",
    "Recall": "recall",
    "F1-score": "f1_score",
    "ROC-AUC": "roc_auc"
}

for display_name, column in metrics.items():

    valid = df.dropna(subset=[column])

    best_index = valid[column].idxmax()

    best_model = df.loc[best_index, "model"]
    best_value = df.loc[best_index, column]

    print(
        f"{display_name:<12}: "
        f"{best_model:<30} "
        f"({best_value:.6f})"
    )

# ==============================================================
# LOWEST ERROR MODEL
# ==============================================================

valid_errors = df.dropna(subset=["total_errors"])

best_error_index = valid_errors["total_errors"].idxmin()

best_error_model = df.loc[
    best_error_index,
    "model"
]

best_error_count = int(
    df.loc[best_error_index, "total_errors"]
)

print(
    f"\nLowest total errors: "
    f"{best_error_model} ({best_error_count})"
)

# ==============================================================
# OVERALL SCORE
# ==============================================================
#
# Average of:
# Accuracy
# Precision
# Recall
# F1
# ROC-AUC
#
# Passive Aggressive has no ROC-AUC in its result,
# so its average uses the available metrics.
# ==============================================================

score_columns = [
    "accuracy",
    "precision",
    "recall",
    "f1_score",
    "roc_auc"
]

df["average_metric_score"] = df[
    score_columns
].mean(axis=1)

overall_index = df[
    "average_metric_score"
].idxmax()

overall_model = df.loc[
    overall_index,
    "model"
]

overall_score = df.loc[
    overall_index,
    "average_metric_score"
]

print("\n" + "=" * 70)
print("OVERALL BEST MODEL")
print("=" * 70)

print(
    f"{overall_model} "
    f"(average metric score: {overall_score:.6f})"
)

# ==============================================================
# FINAL RANKING
# ==============================================================

df["rank"] = (
    df["average_metric_score"]
    .rank(
        ascending=False,
        method="min"
    )
    .astype(int)
)

ranking_columns = [
    "rank",
    "model",
    "accuracy",
    "precision",
    "recall",
    "f1_score",
    "roc_auc",
    "total_errors"
]

ranking = df[
    ranking_columns
].sort_values("rank")

print("\n" + "=" * 70)
print("FINAL MODEL RANKING")
print("=" * 70)

print(
    ranking.to_string(index=False)
)

# ==============================================================
# SAVE COMPLETE COMPARISON
# ==============================================================

df.to_csv(
    "results/models/final_model_comparison.csv",
    index=False
)

ranking.to_csv(
    "results/models/final_model_ranking.csv",
    index=False
)

# ==============================================================
# SAVE FINAL SELECTION
# ==============================================================

final_selection = {
    "overall_best_model": overall_model,
    "average_metric_score": float(overall_score),
    "lowest_error_model": best_error_model,
    "lowest_total_errors": best_error_count
}

with open(
    "results/models/final_model_selection.json",
    "w"
) as f:
    json.dump(
        final_selection,
        f,
        indent=4
    )

# ==============================================================
# COMPLETION
# ==============================================================

print("\n" + "=" * 70)
print("FILES SAVED")
print("=" * 70)

print("results/models/final_model_comparison.csv")
print("results/models/final_model_ranking.csv")
print("results/models/final_model_selection.json")

print("\n" + "=" * 70)
print("FINAL MODEL COMPARISON COMPLETED")
print("=" * 70)