import os
import json
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.metrics import ConfusionMatrixDisplay

# ============================================================
# CICIDS2017 FINAL PLOT GENERATION
# Uses already trained leakage-free Top-20 model results
# NO RETRAINING
# ============================================================

RESULTS_DIR = "results/models"
PLOTS_DIR = "results/plots"

os.makedirs(PLOTS_DIR, exist_ok=True)

print("=" * 80)
print("CICIDS2017 FINAL PLOT GENERATION")
print("=" * 80)

# ------------------------------------------------------------
# Load final results
# ------------------------------------------------------------

RESULT_FILE = f"{RESULTS_DIR}/safe_workflow_results.json"
THRESHOLD_FILE = f"{RESULTS_DIR}/safe_workflow_thresholds.csv"
COMPARISON_FILE = f"{RESULTS_DIR}/final_model_comparison.csv"

print("\nLoading saved results...")

with open(RESULT_FILE, "r") as f:
    results = json.load(f)

thresholds = pd.read_csv(THRESHOLD_FILE)

print("[OK] Results loaded")

# ============================================================
# 1. MODEL PERFORMANCE COMPARISON
# ============================================================

print("\nGenerating model performance comparison...")

if os.path.exists(COMPARISON_FILE):

    comparison = pd.read_csv(COMPARISON_FILE)

    # Normalize possible column names
    metric_columns = [
        "Accuracy",
        "Precision",
        "Recall",
        "F1",
        "ROC-AUC"
    ]

    available = [
        c for c in metric_columns
        if c in comparison.columns
    ]

    if available:

        comparison.set_index("Model")[available].plot(
            kind="bar",
            figsize=(12, 7)
        )

        plt.title(
            "CICIDS2017 NIDS Model Performance Comparison"
        )

        plt.ylabel("Score")
        plt.xlabel("Model")
        plt.ylim(0, 1.05)
        plt.xticks(rotation=20, ha="right")
        plt.legend(title="Metric")
        plt.tight_layout()

        path = f"{PLOTS_DIR}/model_performance_comparison.png"
        plt.savefig(path, dpi=300)
        plt.close()

        print("[OK]", path)

# ============================================================
# 2. FEATURE IMPORTANCE
# ============================================================

print("\nGenerating Top-20 feature importance plot...")

feature_data = results.get("feature_importance", None)

if feature_data:

    feature_df = pd.DataFrame(feature_data)

    if "Feature" in feature_df.columns and \
       "Importance" in feature_df.columns:

        feature_df = feature_df.sort_values(
            "Importance",
            ascending=True
        )

        plt.figure(figsize=(10, 8))

        plt.barh(
            feature_df["Feature"],
            feature_df["Importance"]
        )

        plt.title(
            "CICIDS2017 Top-20 Feature Importance"
        )

        plt.xlabel("Importance")
        plt.ylabel("Feature")

        plt.tight_layout()

        path = f"{PLOTS_DIR}/top20_feature_importance.png"
        plt.savefig(path, dpi=300)
        plt.close()

        print("[OK]", path)

# ============================================================
# 3. THRESHOLD VS F1
# ============================================================

print("\nGenerating threshold vs F1 plot...")

threshold_col = "Threshold"

if threshold_col in thresholds.columns:

    if "F1" in thresholds.columns:

        plt.figure(figsize=(9, 6))

        plt.plot(
            thresholds["Threshold"],
            thresholds["F1"],
            marker="o"
        )

        best_idx = thresholds["F1"].idxmax()

        plt.scatter(
            thresholds.loc[best_idx, "Threshold"],
            thresholds.loc[best_idx, "F1"],
            s=100
        )

        plt.annotate(
            f"Best = {thresholds.loc[best_idx, 'Threshold']:.3f}",
            (
                thresholds.loc[best_idx, "Threshold"],
                thresholds.loc[best_idx, "F1"]
            )
        )

        plt.title(
            "Validation Threshold vs F1-score"
        )

        plt.xlabel("Classification Threshold")
        plt.ylabel("F1-score")
        plt.grid(True, alpha=0.3)

        plt.tight_layout()

        path = f"{PLOTS_DIR}/threshold_vs_f1.png"
        plt.savefig(path, dpi=300)
        plt.close()

        print("[OK]", path)

# ============================================================
# 4. THRESHOLD VS RECALL
# ============================================================

print("\nGenerating threshold vs Recall plot...")

if "Recall" in thresholds.columns:

    plt.figure(figsize=(9, 6))

    plt.plot(
        thresholds["Threshold"],
        thresholds["Recall"],
        marker="o"
    )

    plt.title(
        "Validation Threshold vs Recall"
    )

    plt.xlabel("Classification Threshold")
    plt.ylabel("Recall")
    plt.grid(True, alpha=0.3)

    plt.tight_layout()

    path = f"{PLOTS_DIR}/threshold_vs_recall.png"
    plt.savefig(path, dpi=300)
    plt.close()

    print("[OK]", path)

# ============================================================
# 5. THRESHOLD VS FPR
# ============================================================

print("\nGenerating threshold vs FPR plot...")

if "FPR" in thresholds.columns:

    plt.figure(figsize=(9, 6))

    plt.plot(
        thresholds["Threshold"],
        thresholds["FPR"],
        marker="o"
    )

    plt.title(
        "Validation Threshold vs False Positive Rate"
    )

    plt.xlabel("Classification Threshold")
    plt.ylabel("False Positive Rate")
    plt.grid(True, alpha=0.3)

    plt.tight_layout()

    path = f"{PLOTS_DIR}/threshold_vs_fpr.png"
    plt.savefig(path, dpi=300)
    plt.close()

    print("[OK]", path)

# ============================================================
# 6. FINAL CONFUSION MATRIX
# ============================================================

print("\nGenerating final confusion matrix...")

cm = results.get("confusion_matrix", None)

if cm:

    disp = ConfusionMatrixDisplay(
        confusion_matrix=cm,
        display_labels=["BENIGN", "ATTACK"]
    )

    disp.plot()

    plt.title(
        "CICIDS2017 Final Test Confusion Matrix"
    )

    plt.tight_layout()

    path = f"{PLOTS_DIR}/final_confusion_matrix.png"
    plt.savefig(path, dpi=300)
    plt.close()

    print("[OK]", path)

# ============================================================
# 7. FINAL METRICS BAR CHART
# ============================================================

print("\nGenerating final model metrics...")

metrics = {}

for key in [
    "accuracy",
    "precision",
    "recall",
    "f1",
    "roc_auc"
]:

    if key in results:
        metrics[key.upper()] = results[key]

if metrics:

    plt.figure(figsize=(9, 6))

    plt.bar(
        list(metrics.keys()),
        list(metrics.values())
    )

    plt.title(
        "Leakage-Free Top-20 CatBoost Final Test Performance"
    )

    plt.ylabel("Score")
    plt.ylim(0, 1.05)

    plt.tight_layout()

    path = f"{PLOTS_DIR}/final_model_metrics.png"
    plt.savefig(path, dpi=300)
    plt.close()

    print("[OK]", path)

# ============================================================
# FINAL
# ============================================================

print("\n" + "=" * 80)
print("PLOTS GENERATED")
print("=" * 80)

files = os.listdir(PLOTS_DIR)

if files:

    print("\nGenerated files:")

    for file in sorted(files):
        print(" -", file)

else:

    print("\nWARNING: No plots were generated.")

print("\nPlot directory:")
print(PLOTS_DIR)

print("\n" + "=" * 80)