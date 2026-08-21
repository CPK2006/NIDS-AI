import pandas as pd
import os

INPUT_DIR = "data/splits"
OUTPUT_DIR = "data/features"

os.makedirs(OUTPUT_DIR, exist_ok=True)

print("=" * 70)
print("CICIDS2017 FEATURE CLEANING")
print("=" * 70)

# --------------------------------------------------
# Features selected for removal
# --------------------------------------------------

REMOVE_FEATURES = [
    # Constant features
    "Bwd PSH Flags",
    "Bwd URG Flags",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",

    # Exact duplicate / redundant features
    "Subflow Fwd Packets",
    "Subflow Bwd Packets",
    "Fwd Header Length.1",

    # Duplicate semantic representation
    "Fwd PSH Flags",
    "Fwd URG Flags",
]

print("\nFeatures selected for removal:")
for feature in REMOVE_FEATURES:
    print(" -", feature)

# --------------------------------------------------
# Load training data
# --------------------------------------------------

print("\nReading training data...")

X_train = pd.read_csv(
    f"{INPUT_DIR}/X_train.csv"
)

print("Original X_train shape:", X_train.shape)

# --------------------------------------------------
# Verify features exist
# --------------------------------------------------

missing_features = [
    feature
    for feature in REMOVE_FEATURES
    if feature not in X_train.columns
]

if missing_features:
    print("\nERROR: These features were not found:")
    for feature in missing_features:
        print(" -", feature)

    raise ValueError(
        "One or more selected features are missing."
    )

# --------------------------------------------------
# Remove features
# --------------------------------------------------

X_train_clean = X_train.drop(
    columns=REMOVE_FEATURES
)

print("\nCleaned X_train shape:")
print(X_train_clean.shape)

print(
    "\nFeatures removed:",
    X_train.shape[1] - X_train_clean.shape[1]
)

print(
    "Features remaining:",
    X_train_clean.shape[1]
)

# --------------------------------------------------
# Save selected feature list
# --------------------------------------------------

feature_list = pd.DataFrame({
    "Feature": X_train_clean.columns
})

feature_list.to_csv(
    f"{OUTPUT_DIR}/selected_features.csv",
    index=False
)

# --------------------------------------------------
# Save cleaned training data
# --------------------------------------------------

X_train_clean.to_csv(
    f"{OUTPUT_DIR}/X_train_clean.csv",
    index=False
)

print("\nSaved:")
print(
    f"{OUTPUT_DIR}/X_train_clean.csv"
)
print(
    f"{OUTPUT_DIR}/selected_features.csv"
)

print("\n" + "=" * 70)
print("FEATURE CLEANING COMPLETED")
print("=" * 70)