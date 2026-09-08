import pandas as pd
import numpy as np
import os
import joblib
import json
import time

from lightgbm import LGBMClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

print("=" * 70)
print("NIDS-AI: TRAINING LIGHTGBM TOP-20 PRODUCTION MODEL")
print("=" * 70)

DATASET = "data/processed/Friday-WorkingHours-Morning.pcap_ISCX.csv"
MODEL_DIR = "results/models"
MODEL_FILE = os.path.join(MODEL_DIR, "lightgbm_top20_model.pkl")

FEATURES = [
    "Destination Port",
    "Bwd Packet Length Std",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "Fwd Header Length",
    "Average Packet Size",
    "min_seg_size_forward",
    "Flow IAT Mean",
    "Bwd Header Length",
    "PSH Flag Count",
    "Flow IAT Min",
    "Fwd Packet Length Max",
    "Fwd IAT Min",
    "Total Length of Bwd Packets",
    "Max Packet Length",
    "Fwd IAT Total",
    "Packet Length Std",
    "Flow Bytes/s",
    "Bwd Packet Length Mean",
    "Packet Length Variance"
]

print("\nLoading dataset:", DATASET)
df = pd.read_csv(DATASET)
df["Binary_Label"] = df["Label"].apply(lambda x: 0 if str(x).strip() == "BENIGN" else 1)

X = df[FEATURES].fillna(0).replace([float("inf"), float("-inf")], 0)
y = df["Binary_Label"]

split_index = int(len(X) * 0.8)
X_train, X_test = X.iloc[:split_index], X.iloc[split_index:]
y_train, y_test = y.iloc[:split_index], y.iloc[split_index:]

print(f"Training rows: {len(X_train):,}")
print(f"Testing rows : {len(X_test):,}")

model = LGBMClassifier(
    n_estimators=150,
    learning_rate=0.05,
    num_leaves=31,
    random_state=42,
    n_jobs=-1,
    verbosity=-1
)

print("\nTraining LightGBM model...")
start_time = time.time()
model.fit(X_train, y_train)
train_time = time.time() - start_time
print(f"Training completed in {train_time:.2f} seconds.")

y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred, zero_division=0)
rec = recall_score(y_test, y_pred, zero_division=0)
f1 = f1_score(y_test, y_pred, zero_division=0)
auc = roc_auc_score(y_test, y_prob)

print("\n" + "=" * 70)
print("MODEL EVALUATION")
print("=" * 70)
print(f"Accuracy : {acc * 100:.4f}%")
print(f"Precision: {prec * 100:.4f}%")
print(f"Recall   : {rec * 100:.4f}%")
print(f"F1-Score : {f1 * 100:.4f}%")
print(f"ROC-AUC  : {auc * 100:.4f}%")

os.makedirs(MODEL_DIR, exist_ok=True)
joblib.dump(model, MODEL_FILE)
print(f"\nModel saved successfully to: {MODEL_FILE}")
