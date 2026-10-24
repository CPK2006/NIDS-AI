import pandas as pd
import os
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report


# ============================================================
# CONFIGURATION
# ============================================================

DATASET = "data/processed/Friday-WorkingHours-Morning.pcap_ISCX.csv"

MODEL_DIR = "v2/model"

MODEL_FILE = os.path.join(
    MODEL_DIR,
    "nids_v2_model.pkl"
)

FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Bwd Packet Length Mean",
    "Packet Length Mean",
    "Flow Bytes/s",
]


# ============================================================
# LOAD DATASET
# ============================================================

print("=" * 70)
print("NIDS-AI V2 - MODEL TRAINING")
print("=" * 70)

print()
print("Loading CICIDS2017 dataset...")
print("File:", DATASET)

df = pd.read_csv(DATASET)

print("Rows loaded:", len(df))


# ============================================================
# CHECK FEATURES
# ============================================================

missing_features = [
    feature
    for feature in FEATURES
    if feature not in df.columns
]

if missing_features:

    print()
    print("ERROR: Missing features:")

    for feature in missing_features:
        print("-", feature)

    raise SystemExit


print()
print("All 10 features found.")


# ============================================================
# CREATE BINARY LABEL
# ============================================================

print()
print("Original labels:")
print(df["Label"].value_counts())


# BENIGN = 0
# Everything else = ATTACK

df["Binary_Label"] = (
    df["Label"]
    .apply(lambda x: 0 if str(x).strip() == "BENIGN" else 1)
)


print()
print("Binary labels:")
print(
    df["Binary_Label"]
    .value_counts()
    .sort_index()
)

print()
print("0 = BENIGN")
print("1 = ATTACK")


# ============================================================
# PREPARE FEATURES
# ============================================================

X = df[FEATURES].copy()

y = df["Binary_Label"]


# Replace infinite values

X = X.replace(
    [float("inf"), float("-inf")],
    pd.NA
)

# Remove rows containing missing values

valid = X.notna().all(axis=1)

X = X[valid]
y = y[valid]


print()
print("Rows after cleaning:", len(X))


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


print()
print("Training rows :", len(X_train))
print("Testing rows  :", len(X_test))


# ============================================================
# TRAIN RANDOM FOREST
# ============================================================

print()
print("Training Random Forest...")

model = RandomForestClassifier(
    n_estimators=150,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

model.fit(
    X_train,
    y_train
)


# ============================================================
# EVALUATION
# ============================================================

y_pred = model.predict(X_test)


accuracy = accuracy_score(
    y_test,
    y_pred
)

cm = confusion_matrix(
    y_test,
    y_pred
)

print()
print("=" * 70)
print("MODEL EVALUATION")
print("=" * 70)

print()
print(
    f"Accuracy: {accuracy:.4f}"
)

print()
print("Confusion Matrix:")
print(cm)

print()
print("Classification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        target_names=[
            "BENIGN",
            "ATTACK"
        ]
    )
)


# ============================================================
# FEATURE IMPORTANCE
# ============================================================

print()
print("=" * 70)
print("FEATURE IMPORTANCE")
print("=" * 70)

importance = pd.DataFrame({
    "Feature": FEATURES,
    "Importance": model.feature_importances_
})

importance = importance.sort_values(
    "Importance",
    ascending=False
)

print()
print(
    importance.to_string(
        index=False
    )
)


# ============================================================
# SAVE MODEL
# ============================================================

os.makedirs(
    MODEL_DIR,
    exist_ok=True
)

joblib.dump(
    model,
    MODEL_FILE
)

print()
print("=" * 70)
print("MODEL SAVED")
print("=" * 70)

print()
print("Model:", MODEL_FILE)

print()
print("NIDS-AI V2 TRAINING COMPLETED")
print("=" * 70)