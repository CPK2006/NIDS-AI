import pandas as pd
import matplotlib.pyplot as plt
import json

from catboost import CatBoostClassifier


# ==============================================================
# CICIDS2017 FINAL CATBOOST FEATURE IMPORTANCE ANALYSIS
# ==============================================================

print("=" * 70)
print("CICIDS2017 FINAL CATBOOST FEATURE IMPORTANCE ANALYSIS")
print("=" * 70)


# ==============================================================
# PATHS
# ==============================================================

MODEL_PATH = "results/models/final_catboost_model.cbm"

FEATURE_PATH = "data/features/X_train_clean.csv"

IMPORTANCE_PATH = "results/models/final_catboost_feature_importance_analysis.csv"

PLOT_PATH = "results/models/final_catboost_feature_importance.png"

TOP_FEATURES_PATH = "results/models/top_20_features.json"


# ==============================================================
# LOAD MODEL
# ==============================================================

print("\nLoading final CatBoost model...")

model = CatBoostClassifier()

model.load_model(MODEL_PATH)

print("Model loaded successfully.")


# ==============================================================
# LOAD FEATURE NAMES
# ==============================================================

print("\nLoading feature names...")

X_train = pd.read_csv(
    FEATURE_PATH,
    nrows=1
)

feature_names = list(X_train.columns)

print("Number of features:", len(feature_names))


# ==============================================================
# GET FEATURE IMPORTANCE
# ==============================================================

print("\nCalculating feature importance...")

importance = model.get_feature_importance()

importance_df = pd.DataFrame({
    "Feature": feature_names,
    "Importance": importance
})


# ==============================================================
# SORT FEATURES
# ==============================================================

importance_df = importance_df.sort_values(
    by="Importance",
    ascending=False
).reset_index(drop=True)


# ==============================================================
# IMPORTANCE PERCENTAGE
# ==============================================================

importance_df["Importance_Percentage"] = (
    importance_df["Importance"]
    / importance_df["Importance"].sum()
) * 100


# ==============================================================
# CUMULATIVE IMPORTANCE
# ==============================================================

importance_df["Cumulative_Importance"] = (
    importance_df["Importance_Percentage"].cumsum()
)


# ==============================================================
# DISPLAY TOP 20
# ==============================================================

print("\n" + "=" * 70)
print("TOP 20 MOST IMPORTANT FEATURES")
print("=" * 70)

print(
    importance_df[
        [
            "Feature",
            "Importance",
            "Importance_Percentage",
            "Cumulative_Importance"
        ]
    ].head(20).to_string(index=False)
)


# ==============================================================
# SAVE COMPLETE FEATURE IMPORTANCE
# ==============================================================

importance_df.to_csv(
    IMPORTANCE_PATH,
    index=False
)

print("\nSaved:")
print(IMPORTANCE_PATH)


# ==============================================================
# SAVE TOP 20 FEATURES AS JSON
# ==============================================================

top_20 = importance_df.head(20)

top_features = []

for _, row in top_20.iterrows():

    top_features.append({
        "rank": int(row.name + 1),
        "feature": row["Feature"],
        "importance": float(row["Importance"]),
        "importance_percentage": float(
            row["Importance_Percentage"]
        )
    })


with open(TOP_FEATURES_PATH, "w") as f:

    json.dump(
        top_features,
        f,
        indent=4
    )


print(TOP_FEATURES_PATH)


# ==============================================================
# TOP 15 FEATURE IMPORTANCE PLOT
# ==============================================================

print("\nGenerating feature importance plot...")

top_15 = importance_df.head(15).sort_values(
    by="Importance",
    ascending=True
)


plt.figure(figsize=(10, 8))

plt.barh(
    top_15["Feature"],
    top_15["Importance"]
)

plt.xlabel("Feature Importance")
plt.ylabel("Feature")

plt.title(
    "Final CatBoost - Top 15 Feature Importance"
)

plt.tight_layout()

plt.savefig(
    PLOT_PATH,
    dpi=300
)

plt.close()

print("Saved:")
print(PLOT_PATH)


# ==============================================================
# TOP 5 FEATURES
# ==============================================================

print("\n" + "=" * 70)
print("TOP 5 FEATURES")
print("=" * 70)

for i, row in importance_df.head(5).iterrows():

    print(
        f"{i + 1}. {row['Feature']} "
        f"({row['Importance_Percentage']:.2f}%)"
    )


# ==============================================================
# CUMULATIVE IMPORTANCE ANALYSIS
# ==============================================================

print("\n" + "=" * 70)
print("CUMULATIVE FEATURE IMPORTANCE")
print("=" * 70)

for n in [5, 10, 15, 20, 30, 40, 50, 65]:

    cumulative = importance_df.iloc[n - 1][
        "Cumulative_Importance"
    ]

    print(
        f"Top {n:2d} features: "
        f"{cumulative:.2f}% of total importance"
    )


# ==============================================================
# FINAL SUMMARY
# ==============================================================

print("\n" + "=" * 70)
print("FEATURE IMPORTANCE ANALYSIS COMPLETED")
print("=" * 70)

print("\nFiles saved:")
print("1.", IMPORTANCE_PATH)
print("2.", TOP_FEATURES_PATH)
print("3.", PLOT_PATH)

print("\n" + "=" * 70)