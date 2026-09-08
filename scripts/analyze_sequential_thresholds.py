import pandas as pd
import numpy as np
import os
import json

from catboost import CatBoostClassifier

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix
)

print("=" * 70)
print("CICIDS2017 SEQUENTIAL CATBOOST THRESHOLD ANALYSIS")
print("=" * 70)

# --------------------------------------------------
# Paths
# --------------------------------------------------

DATA_PATH = "data/sample/cicids2017_binary_deduplicated.csv"
FEATURE_PATH = "data/features/selected_features.csv"
MODEL_PATH = "results/models/sequential_catboost_model.cbm"

OUTPUT_CSV = "results/models/sequential_threshold_analysis.csv"
OUTPUT_JSON = "results/models/best_sequential_threshold.json"

# --------------------------------------------------
# Load data
# --------------------------------------------------

print("\nLoading dataset...")

df = pd.read_csv(DATA_PATH)

selected_features = pd.read_csv(
    FEATURE_PATH
)["Feature"].tolist()

X = df[selected_features]
y = df["Binary_Label"]

# --------------------------------------------------
# Sequential split
# --------------------------------------------------

split_index = int(len(df) * 0.80)

X_test = X.iloc[split_index:]
y_test = y.iloc[split_index:]

print("Test shape:", X_test.shape)
print("Number of features:", len(selected_features))

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

y_prob = model.predict_proba(X_test)[:, 1]

print("Probabilities generated.")

# --------------------------------------------------
# Threshold analysis
# --------------------------------------------------

print("\n" + "=" * 70)
print("THRESHOLD ANALYSIS")
print("=" * 70)

thresholds = np.arange(
    0.05,
    1.00,
    0.05
)

results = []

for threshold in thresholds:

    y_pred = (
        y_prob >= threshold
    ).astype(int)

    tn, fp, fn, tp = confusion_matrix(
        y_test,
        y_pred
    ).ravel()

    accuracy = accuracy_score(
        y_test,
        y_pred
    )

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

    total_errors = fp + fn

    results.append({
        "threshold": round(float(threshold), 2),
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "total_errors": int(total_errors)
    })

results_df = pd.DataFrame(results)

# --------------------------------------------------
# Display results
# --------------------------------------------------

print("\n")
print(
    results_df[
        [
            "threshold",
            "accuracy",
            "precision",
            "recall",
            "f1_score",
            "false_positive_rate",
            "false_negative_rate",
            "total_errors"
        ]
    ].to_string(index=False)
)

# --------------------------------------------------
# Best thresholds
# --------------------------------------------------

best_f1 = results_df.loc[
    results_df["f1_score"].idxmax()
]

best_recall = results_df.loc[
    results_df["recall"].idxmax()
]

best_accuracy = results_df.loc[
    results_df["accuracy"].idxmax()
]

# --------------------------------------------------
# NIDS-oriented threshold
# --------------------------------------------------
# We want at least 99% attack recall
# while minimizing false positives.

high_recall = results_df[
    results_df["recall"] >= 0.99
].copy()

if len(high_recall) > 0:

    best_nids = high_recall.loc[
        high_recall["false_positive_rate"].idxmin()
    ]

else:

    best_nids = best_recall

# --------------------------------------------------
# Print best thresholds
# --------------------------------------------------

print("\n" + "=" * 70)
print("BEST THRESHOLDS")
print("=" * 70)

print(
    f"\nBest F1 threshold: "
    f"{best_f1['threshold']:.2f}"
)

print(
    f"F1-score: "
    f"{best_f1['f1_score']:.6f}"
)

print(
    f"Recall: "
    f"{best_f1['recall']:.6f}"
)

print(
    f"Precision: "
    f"{best_f1['precision']:.6f}"
)

print(
    f"\nBest accuracy threshold: "
    f"{best_accuracy['threshold']:.2f}"
)

print(
    f"Accuracy: "
    f"{best_accuracy['accuracy']:.6f}"
)

print(
    f"\nBest recall threshold: "
    f"{best_recall['threshold']:.2f}"
)

print(
    f"Recall: "
    f"{best_recall['recall']:.6f}"
)

print("\n" + "-" * 70)

print(
    f"\nNIDS-oriented threshold: "
    f"{best_nids['threshold']:.2f}"
)

print(
    f"Accuracy          : "
    f"{best_nids['accuracy']:.6f}"
)

print(
    f"Precision         : "
    f"{best_nids['precision']:.6f}"
)

print(
    f"Recall            : "
    f"{best_nids['recall']:.6f}"
)

print(
    f"F1-score          : "
    f"{best_nids['f1_score']:.6f}"
)

print(
    f"False Positive Rate: "
    f"{best_nids['false_positive_rate']:.6f}"
)

print(
    f"False Negative Rate: "
    f"{best_nids['false_negative_rate']:.6f}"
)

print(
    f"False Positives   : "
    f"{int(best_nids['fp'])}"
)

print(
    f"False Negatives   : "
    f"{int(best_nids['fn'])}"
)

# --------------------------------------------------
# Save CSV
# --------------------------------------------------

results_df.to_csv(
    OUTPUT_CSV,
    index=False
)

# --------------------------------------------------
# Save best threshold
# --------------------------------------------------

best_result = {
    "threshold": float(best_nids["threshold"]),
    "accuracy": float(best_nids["accuracy"]),
    "precision": float(best_nids["precision"]),
    "recall": float(best_nids["recall"]),
    "f1_score": float(best_nids["f1_score"]),
    "false_positive_rate": float(
        best_nids["false_positive_rate"]
    ),
    "false_negative_rate": float(
        best_nids["false_negative_rate"]
    ),
    "true_negatives": int(best_nids["tn"]),
    "false_positives": int(best_nids["fp"]),
    "false_negatives": int(best_nids["fn"]),
    "true_positives": int(best_nids["tp"]),
    "total_errors": int(best_nids["total_errors"])
}

with open(
    OUTPUT_JSON,
    "w"
) as f:

    json.dump(
        best_result,
        f,
        indent=4
    )

# --------------------------------------------------
# Final output
# --------------------------------------------------

print("\n" + "=" * 70)
print("FILES SAVED")
print("=" * 70)

print(OUTPUT_CSV)
print(OUTPUT_JSON)

print("\n" + "=" * 70)
print("THRESHOLD ANALYSIS COMPLETED")
print("=" * 70)