import os
import pandas as pd
from catboost import CatBoostClassifier


# ============================================================
# CONFIGURATION
# ============================================================

DATA_PATH = "data/sample/cicids2017_binary_deduplicated.csv"

MODEL_PATH = "results/models/leakage_free_top20_model.cbm"

THRESHOLD = 0.004


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


# ============================================================
# CHECK FILES
# ============================================================

if not os.path.exists(DATA_PATH):
    raise FileNotFoundError(DATA_PATH)

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(MODEL_PATH)


# ============================================================
# LOAD DATA
# ============================================================

print("=" * 70)
print("CICIDS2017 WEB PREDICTION TEST")
print("=" * 70)

print("\nLoading dataset...")

data = pd.read_csv(DATA_PATH)

print("Dataset shape:", data.shape)


# ============================================================
# LOAD MODEL
# ============================================================

print("\nLoading model...")

model = CatBoostClassifier()
model.load_model(MODEL_PATH)

print("Model loaded successfully.")


# ============================================================
# SELECT ONE BENIGN AND ONE ATTACK ROW
# ============================================================

benign = data[data["Binary_Label"] == 0].iloc[0]

attack = data[data["Binary_Label"] == 1].iloc[0]


# ============================================================
# FUNCTION
# ============================================================

def test_row(row, name):

    X = pd.DataFrame(
        [[row[f] for f in FEATURES]],
        columns=FEATURES
    )

    probability = model.predict_proba(X)[0][1]

    if probability >= THRESHOLD:
        prediction = "ATTACK"
    else:
        prediction = "BENIGN"

    print("\n" + "=" * 70)
    print(name)
    print("=" * 70)

    print("\nExpected label:")
    print(
        "BENIGN"
        if row["Binary_Label"] == 0
        else "ATTACK"
    )

    print("\nModel prediction:")
    print(prediction)

    print("\nAttack probability:")
    print(f"{probability:.8f}")

    print("\nThreshold:")
    print(THRESHOLD)

    print("\n20 values to enter in the web application:")
    print("-" * 70)

    for feature in FEATURES:
        print(
            f"{feature}: {row[feature]}"
        )

    print("-" * 70)

    print("\nWeb form order:")
    print(",".join(str(row[f]) for f in FEATURES))

    return probability, prediction


# ============================================================
# TEST BENIGN
# ============================================================

benign_probability, benign_prediction = test_row(
    benign,
    "TEST 1 - BENIGN FLOW"
)


# ============================================================
# TEST ATTACK
# ============================================================

attack_probability, attack_prediction = test_row(
    attack,
    "TEST 2 - ATTACK FLOW"
)


# ============================================================
# SUMMARY
# ============================================================

print("\n" + "=" * 70)
print("TEST SUMMARY")
print("=" * 70)

print(
    f"BENIGN row -> Prediction: {benign_prediction} | "
    f"Attack probability: {benign_probability:.8f}"
)

print(
    f"ATTACK row -> Prediction: {attack_prediction} | "
    f"Attack probability: {attack_probability:.8f}"
)

print("\nUse the printed values in the Flask web form.")
print("=" * 70)