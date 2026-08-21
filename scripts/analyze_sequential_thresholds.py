import pandas as pd
import numpy as np
from catboost import CatBoostClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

print("=" * 70)
print("CICIDS2017 SEQUENTIAL CATBOOST THRESHOLD ANALYSIS")
print("=" * 70)

# --------------------------------------------------
# Paths
# --------------------------------------------------

DATA_PATH = "data/sample/cicids2017_binary_deduplicated.csv"
MODEL_PATH = "results/models/sequential_catboost_model.cbm"

OUTPUT_CSV = "results/models/sequential_threshold_analysis.csv"

# --------------------------------------------------
# Load dataset
# --------------------------------------------------

print("\nLoading dataset...")

df = pd.read_csv(DATA_PATH)

print("Dataset shape:", df.shape)

# --------------------------------------------------
# Features and target
# --------------------------------------------------

X = df.drop(columns=["Binary_Label"])
y = df["Binary_Label"]

# Same sequential split used during training
split_index = int(len(df) * 0.80)

X_test = X.iloc[split_index:]
y_test = y.iloc[split_index:]

print("\nSequential test shape:")
print("X_test:", X_test.shape)
print("y_test:", y_test.shape)

# --------------------------------------------------
# Load model
# --------------------------------------------------

print("\nLoading sequential CatBoost model...")

model = CatBoostClassifier()

model.load_model(MODEL_PATH)

print("Model loaded successfully.")

# --------------------------------------------------
# Generate probabilities
# --------------------------------------------------

print("\nGenerating attack probabilities...")

y_probability = model.predict_proba(X_test)[:, 1]

# --------------------------------------------------
# Threshold analysis
# --------------------------------------------------

thresholds = [
    0.10,
    0.15,
    0.20,
    0.25,
    0.30,
    0.35,
    0.40,
    0.45,
    0.50,
    0.55,
    0.60,
    0.65,
    0.70,
    0.75,
    0.80,
    0.85,
    0.90,
    0.95
]

results = []

print("\n" + "=" * 70)
print("THRESHOLD PERFORMANCE")
print("=" * 70)

print(
    f"{'Threshold':<10}"
    f"{'Accuracy':<12}"
    f"{'Precision':<12}"
    f"{'Recall':<12}"
    f"{'F1':<12}"
    f"{'FPR':<12}"
    f"{'FNR':<12}"
    f"{'FP':<10}"
    f"{'FN':<10}"
)

print("-" * 100)

for threshold in thresholds:

    y_pred = (y_probability >= threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(
        y_test,
        y_pred,
        labels=[0, 1]
    ).ravel()

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

    fpr = fp / (fp + tn)
    fnr = fn / (fn + tp)

    results.append({
        "Threshold": threshold,
        "Accuracy": accuracy,
        "Precision": precision,
        "Recall": recall,
        "F1": f1,
        "FPR": fpr,
        "FNR": fnr,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "TP": tp
    })

    print(
        f"{threshold:<10.2f}"
        f"{accuracy:<12.6f}"
        f"{precision:<12.6f}"
        f"{recall:<12.6f}"
        f"{f1:<12.6f}"
        f"{fpr:<12.6f}"
        f"{fnr:<12.6f}"
        f"{fp:<10}"
        f"{fn:<10}"
    )

# --------------------------------------------------
# DataFrame
# --------------------------------------------------

results_df = pd.DataFrame(results)

# --------------------------------------------------
# Best thresholds
# --------------------------------------------------

best_f1 = results_df.loc[
    results_df["F1"].idxmax()
]

best_recall = results_df.loc[
    results_df["Recall"].idxmax()
]

best_accuracy = results_df.loc[
    results_df["Accuracy"].idxmax()
]

# Best threshold with FPR <= 0.001
low_fpr = results_df[
    results_df["FPR"] <= 0.001
]

if len(low_fpr) > 0:
    best_low_fpr = low_fpr.loc[
        low_fpr["Recall"].idxmax()
    ]
else:
    best_low_fpr = None

# --------------------------------------------------
# Display
# --------------------------------------------------

print("\n" + "=" * 70)
print("BEST THRESHOLD BY F1")
print("=" * 70)

print(best_f1)

print("\n" + "=" * 70)
print("BEST THRESHOLD BY RECALL")
print("=" * 70)

print(best_recall)

print("\n" + "=" * 70)
print("BEST THRESHOLD BY ACCURACY")
print("=" * 70)

print(best_accuracy)

if best_low_fpr is not None:

    print("\n" + "=" * 70)
    print("BEST RECALL WITH FPR <= 0.1%")
    print("=" * 70)

    print(best_low_fpr)

# --------------------------------------------------
# Save
# --------------------------------------------------

results_df.to_csv(
    OUTPUT_CSV,
    index=False
)

print("\nSaved:")
print(OUTPUT_CSV)

print("\n" + "=" * 70)
print("SEQUENTIAL THRESHOLD ANALYSIS COMPLETED")
print("=" * 70)