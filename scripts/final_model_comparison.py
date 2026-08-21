import json
import os
import pandas as pd

print("=" * 80)
print("CICIDS2017 FINAL NIDS MODEL COMPARISON")
print("=" * 80)

RESULTS_DIR = "results/models"


# ------------------------------------------------------------
# Results collected from the rigorous sequential evaluations
# ------------------------------------------------------------

models = [
    {
        "Model": "Sequential CatBoost",
        "Features": 65,
        "Threshold": 0.50,
        "Accuracy": 0.989635,
        "Precision": 0.999796,
        "Recall": 0.968938,
        "F1": 0.984125,
        "ROC-AUC": 0.999959,
        "FP": 33,
        "FN": 5190,
        "Total Errors": 5223,
    },

    {
        "Model": "Sequential Train/Val/Test CatBoost",
        "Features": 78,
        "Threshold": 0.01,
        "Accuracy": 0.918887,
        "Precision": 0.995408,
        "Recall": 0.758877,
        "F1": 0.861197,
        "ROC-AUC": 0.998604,
        "FP": 585,
        "FN": 40288,
        "Total Errors": 40873,
    },

    {
        "Model": "Sequential Top-20 CatBoost",
        "Features": 20,
        "Threshold": 0.003,
        "Accuracy": 0.990012,
        "Precision": 0.990015,
        "Recall": 0.979759,
        "F1": 0.984860,
        "ROC-AUC": 0.999094,
        "FP": 1651,
        "FN": 3382,
        "Total Errors": 5033,
    },

    {
        "Model": "Leakage-Free Top-20 CatBoost",
        "Features": 20,
        "Threshold": 0.004,
        "Accuracy": 0.990133,
        "Precision": 0.990981,
        "Recall": 0.979154,
        "F1": 0.985032,
        "ROC-AUC": 0.998995,
        "FP": 1489,
        "FN": 3483,
        "Total Errors": 4972,
    },
]


df = pd.DataFrame(models)


# ------------------------------------------------------------
# Display comparison
# ------------------------------------------------------------

print("\n" + "=" * 80)
print("PERFORMANCE COMPARISON")
print("=" * 80)

display_df = df.copy()

for column in [
    "Accuracy",
    "Precision",
    "Recall",
    "F1",
    "ROC-AUC"
]:
    display_df[column] = display_df[column].map(
        lambda x: f"{x:.6f}"
    )

print(
    display_df[
        [
            "Model",
            "Features",
            "Threshold",
            "Accuracy",
            "Precision",
            "Recall",
            "F1",
            "ROC-AUC",
            "FP",
            "FN",
            "Total Errors",
        ]
    ].to_string(index=False)
)


# ------------------------------------------------------------
# Ranking
# ------------------------------------------------------------

print("\n" + "=" * 80)
print("MODEL RANKING")
print("=" * 80)

ranking = df.sort_values(
    by="F1",
    ascending=False
).reset_index(drop=True)

for i, row in ranking.iterrows():
    print(
        f"{i + 1}. {row['Model']} "
        f"| F1={row['F1']:.6f} "
        f"| Recall={row['Recall']:.6f} "
        f"| FP={int(row['FP'])} "
        f"| FN={int(row['FN'])}"
    )


# ------------------------------------------------------------
# Best model
# ------------------------------------------------------------

best = ranking.iloc[0]

print("\n" + "=" * 80)
print("BEST MODEL")
print("=" * 80)

print("Model      :", best["Model"])
print("Features   :", int(best["Features"]))
print("Threshold  :", best["Threshold"])
print("Accuracy   :", f"{best['Accuracy']:.6f}")
print("Precision  :", f"{best['Precision']:.6f}")
print("Recall     :", f"{best['Recall']:.6f}")
print("F1-score   :", f"{best['F1']:.6f}")
print("ROC-AUC    :", f"{best['ROC-AUC']:.6f}")
print("False Pos. :", int(best["FP"]))
print("False Neg. :", int(best["FN"]))
print("Errors     :", int(best["Total Errors"]))


# ------------------------------------------------------------
# Feature efficiency
# ------------------------------------------------------------

print("\n" + "=" * 80)
print("FEATURE EFFICIENCY")
print("=" * 80)

for _, row in df.iterrows():

    f1_per_feature = row["F1"] / row["Features"]

    print(
        f"{row['Model']:<35} "
        f"Features={int(row['Features']):>3} "
        f"F1/feature={f1_per_feature:.6f}"
    )


# ------------------------------------------------------------
# Save
# ------------------------------------------------------------

output_path = (
    f"{RESULTS_DIR}/final_model_comparison.csv"
)

df.to_csv(
    output_path,
    index=False
)

print("\nSaved:")
print(output_path)

print("\n" + "=" * 80)
print("FINAL MODEL COMPARISON COMPLETED")
print("=" * 80)