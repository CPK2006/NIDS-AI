import pandas as pd
import numpy as np
import json
import time

from catboost import CatBoostClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score
)

print("=" * 70)
print("CICIDS2017 CATBOOST HYPERPARAMETER TUNING")
print("=" * 70)

# ==============================================================
# LOAD DATA
# ==============================================================

print("\nLoading training features...")
X = pd.read_csv("data/features/X_train_scaled.csv")

print("Loading training targets...")
y = pd.read_csv("data/splits/y_train.csv").squeeze()

print("Training shape:", X.shape)
print("Target shape  :", y.shape)

# ==============================================================
# VALIDATION SPLIT
# ==============================================================

print("\nCreating validation split...")

X_train, X_val, y_train, y_val = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("Training subset   :", X_train.shape)
print("Validation subset :", X_val.shape)

# ==============================================================
# PARAMETER SETS
# ==============================================================

models = {
    "CatBoost_1": {
        "iterations": 300,
        "depth": 8,
        "learning_rate": 0.1
    },

    "CatBoost_2": {
        "iterations": 500,
        "depth": 8,
        "learning_rate": 0.05
    },

    "CatBoost_3": {
        "iterations": 500,
        "depth": 10,
        "learning_rate": 0.05
    },

    "CatBoost_4": {
        "iterations": 700,
        "depth": 8,
        "learning_rate": 0.05
    },

    "CatBoost_5": {
        "iterations": 500,
        "depth": 6,
        "learning_rate": 0.05
    }
}

results = []

# ==============================================================
# TRAIN EACH CONFIGURATION
# ==============================================================

for name, params in models.items():

    print("\n" + "=" * 70)
    print(name)
    print("=" * 70)

    print("Parameters:")
    print("Iterations     :", params["iterations"])
    print("Depth          :", params["depth"])
    print("Learning rate  :", params["learning_rate"])

    model = CatBoostClassifier(
        iterations=params["iterations"],
        depth=params["depth"],
        learning_rate=params["learning_rate"],
        loss_function="Logloss",
        eval_metric="AUC",
        random_seed=42,
        verbose=False,
        thread_count=-1,
        l2_leaf_reg=3
    )

    start_time = time.time()

    model.fit(
        X_train,
        y_train,
        eval_set=(X_val, y_val),
        early_stopping_rounds=30,
        verbose=False
    )

    training_time = time.time() - start_time

    # ----------------------------------------------------------
    # VALIDATION PREDICTIONS
    # ----------------------------------------------------------

    y_pred = model.predict(X_val).ravel()
    y_prob = model.predict_proba(X_val)[:, 1]

    accuracy = accuracy_score(y_val, y_pred)
    precision = precision_score(y_val, y_pred)
    recall = recall_score(y_val, y_pred)
    f1 = f1_score(y_val, y_pred)
    roc_auc = roc_auc_score(y_val, y_prob)

    tree_count = model.tree_count_

    print("\nValidation Performance")
    print("-" * 70)
    print(f"Accuracy       : {accuracy:.6f}")
    print(f"Precision      : {precision:.6f}")
    print(f"Recall         : {recall:.6f}")
    print(f"F1-score       : {f1:.6f}")
    print(f"ROC-AUC        : {roc_auc:.6f}")
    print(f"Trees used     : {tree_count}")
    print(f"Training time  : {training_time:.2f} seconds")

    results.append({
        "model": name,
        "iterations": params["iterations"],
        "depth": params["depth"],
        "learning_rate": params["learning_rate"],
        "tree_count": int(tree_count),
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "roc_auc": float(roc_auc),
        "training_time": float(training_time)
    })

# ==============================================================
# RESULTS
# ==============================================================

results_df = pd.DataFrame(results)

print("\n" + "=" * 70)
print("CATBOOST TUNING RESULTS")
print("=" * 70)

print(
    results_df[
        [
            "model",
            "depth",
            "iterations",
            "learning_rate",
            "tree_count",
            "accuracy",
            "precision",
            "recall",
            "f1_score",
            "roc_auc"
        ]
    ].to_string(index=False)
)

# ==============================================================
# SELECT BEST MODEL
# ==============================================================

best_index = results_df["f1_score"].idxmax()
best = results_df.loc[best_index]

print("\n" + "=" * 70)
print("BEST CATBOOST CONFIGURATION")
print("=" * 70)

print("Model          :", best["model"])
print("Depth          :", int(best["depth"]))
print("Iterations     :", int(best["iterations"]))
print("Learning rate  :", best["learning_rate"])
print("Trees used     :", int(best["tree_count"]))
print("Accuracy       :", f"{best['accuracy']:.6f}")
print("Precision      :", f"{best['precision']:.6f}")
print("Recall         :", f"{best['recall']:.6f}")
print("F1-score       :", f"{best['f1_score']:.6f}")
print("ROC-AUC        :", f"{best['roc_auc']:.6f}")

# ==============================================================
# SAVE RESULTS
# ==============================================================

results_df.to_csv(
    "results/models/catboost_tuning_results.csv",
    index=False
)

with open(
    "results/models/best_catboost_parameters.json",
    "w"
) as f:

    json.dump(
        {
            "model": str(best["model"]),
            "iterations": int(best["iterations"]),
            "depth": int(best["depth"]),
            "learning_rate": float(best["learning_rate"]),
            "tree_count": int(best["tree_count"]),
            "validation_accuracy": float(best["accuracy"]),
            "validation_precision": float(best["precision"]),
            "validation_recall": float(best["recall"]),
            "validation_f1_score": float(best["f1_score"]),
            "validation_roc_auc": float(best["roc_auc"])
        },
        f,
        indent=4
    )

print("\nSaved:")
print("results/models/catboost_tuning_results.csv")
print("results/models/best_catboost_parameters.json")

print("\n" + "=" * 70)
print("CATBOOST TUNING COMPLETED")
print("=" * 70)