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
print("CICIDS2017 THRESHOLD STABILITY ANALYSIS")
print("=" * 70)

# --------------------------------------------------
# Paths
# --------------------------------------------------

DATA_PATH = "data/sample/cicids2017_binary_deduplicated.csv"
MODEL_PATH = "results/models/sequential_train_val_model.cbm"

# --------------------------------------------------
# Load dataset
# --------------------------------------------------

print("\nLoading dataset...")

df = pd.read_csv(DATA_PATH)

X = df.drop(columns=["Binary_Label"])
y = df["Binary_Label"]

print("Dataset shape:", df.shape)

# --------------------------------------------------
# Same sequential split used previously
# --------------------------------------------------

n = len(df)

train_end = int(n * 0.70)
val_end = int(n * 0.80)

X_train = X.iloc[:train_end]
y_train = y.iloc[:train_end]

X_val = X.iloc[train_end:val_end]
y_val = y.iloc[train_end:val_end]

X_test = X.iloc[val_end:]
y_test = y.iloc[val_end:]

print("\nSequential split:")
print("Training   :", X_train.shape)
print("Validation :", X_val.shape)
print("Testing    :", X_test.shape)

# --------------------------------------------------
# Load model
# --------------------------------------------------

print("\nLoading model...")

model = CatBoostClassifier()
model.load_model(MODEL_PATH)

print("Model loaded successfully.")

# --------------------------------------------------
# Validation probabilities
# --------------------------------------------------

print("\nGenerating validation probabilities...")

val_prob = model.predict_proba(X_val)[:, 1]

# --------------------------------------------------
# Split validation into chronological chunks
# --------------------------------------------------

NUM_CHUNKS = 5

chunk_size = len(X_val) // NUM_CHUNKS

thresholds = [
    0.001,
    0.005,
    0.01,
    0.02,
    0.05,
    0.10,
    0.20,
    0.30,
    0.50
]

all_results = []

print("\n" + "=" * 70)
print("VALIDATION CHUNK ANALYSIS")
print("=" * 70)

for chunk in range(NUM_CHUNKS):

    start = chunk * chunk_size

    if chunk == NUM_CHUNKS - 1:
        end = len(X_val)
    else:
        end = (chunk + 1) * chunk_size

    y_chunk = y_val.iloc[start:end]
    p_chunk = val_prob[start:end]

    print(
        f"\nChunk {chunk + 1}: "
        f"{start}:{end}"
    )

    print(
        "Samples:",
        len(y_chunk),
        "| Attack rate:",
        round(y_chunk.mean() * 100, 3),
        "%"
    )

    for threshold in thresholds:

        y_pred = (p_chunk >= threshold).astype(int)

        tn, fp, fn, tp = confusion_matrix(
            y_chunk,
            y_pred,
            labels=[0, 1]
        ).ravel()

        accuracy = accuracy_score(
            y_chunk,
            y_pred
        )

        precision = precision_score(
            y_chunk,
            y_pred,
            zero_division=0
        )

        recall = recall_score(
            y_chunk,
            y_pred,
            zero_division=0
        )

        f1 = f1_score(
            y_chunk,
            y_pred,
            zero_division=0
        )

        fpr = fp / (fp + tn)

        fnr = fn / (fn + tp)

        all_results.append({
            "Chunk": chunk + 1,
            "Threshold": threshold,
            "Attack_Rate": y_chunk.mean(),
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

# --------------------------------------------------
# Results
# --------------------------------------------------

results = pd.DataFrame(all_results)

print("\n" + "=" * 70)
print("AVERAGE PERFORMANCE ACROSS VALIDATION CHUNKS")
print("=" * 70)

summary = (
    results
    .groupby("Threshold")
    .agg({
        "Accuracy": "mean",
        "Precision": "mean",
        "Recall": "mean",
        "F1": "mean",
        "FPR": "mean",
        "FNR": "mean"
    })
    .reset_index()
)

print(summary.to_string(index=False))

# --------------------------------------------------
# Stability statistics
# --------------------------------------------------

print("\n" + "=" * 70)
print("THRESHOLD STABILITY")
print("=" * 70)

stability = (
    results
    .groupby("Threshold")
    .agg(
        Mean_F1=("F1", "mean"),
        Std_F1=("F1", "std"),
        Min_F1=("F1", "min"),
        Mean_Recall=("Recall", "mean"),
        Std_Recall=("Recall", "std"),
        Min_Recall=("Recall", "min"),
        Mean_FPR=("FPR", "mean"),
        Max_FPR=("FPR", "max")
    )
    .reset_index()
)

print(stability.to_string(index=False))

# --------------------------------------------------
# Best threshold by average F1
# --------------------------------------------------

best_f1 = stability.loc[
    stability["Mean_F1"].idxmax()
]

print("\n" + "=" * 70)
print("BEST THRESHOLD BY MEAN VALIDATION F1")
print("=" * 70)

print(best_f1)

# --------------------------------------------------
# Best threshold with FPR <= 0.1%
# --------------------------------------------------

allowed = stability[
    stability["Max_FPR"] <= 0.001
]

if len(allowed) > 0:

    best_low_fpr = allowed.loc[
        allowed["Mean_Recall"].idxmax()
    ]

    print("\n" + "=" * 70)
    print("BEST RECALL WITH MAX FPR <= 0.1%")
    print("=" * 70)

    print(best_low_fpr)

else:

    print(
        "\nNo threshold satisfied "
        "Max FPR <= 0.1% across all validation chunks."
    )

# --------------------------------------------------
# Save
# --------------------------------------------------

output_path = (
    "results/models/"
    "threshold_stability_results.csv"
)

results.to_csv(
    output_path,
    index=False
)

summary.to_csv(
    "results/models/"
    "threshold_stability_summary.csv",
    index=False
)

stability.to_csv(
    "results/models/"
    "threshold_stability_statistics.csv",
    index=False
)

print("\nSaved:")
print(output_path)
print(
    "results/models/"
    "threshold_stability_summary.csv"
)
print(
    "results/models/"
    "threshold_stability_statistics.csv"
)

print("\n" + "=" * 70)
print("THRESHOLD STABILITY ANALYSIS COMPLETED")
print("=" * 70)