import pandas as pd
import os
from sklearn.model_selection import train_test_split

INPUT_FILE = "data/sample/cicids2017_binary_deduplicated.csv"
OUTPUT_DIR = "data/splits"

os.makedirs(OUTPUT_DIR, exist_ok=True)

print("=" * 70)
print("CICIDS2017 TRAIN / TEST SPLIT")
print("=" * 70)

# --------------------------------------------------
# Load dataset
# --------------------------------------------------

print(f"Reading: {INPUT_FILE}")

df = pd.read_csv(INPUT_FILE)

print("\nDataset shape:")
print(df.shape)

# --------------------------------------------------
# Separate features and target
# --------------------------------------------------

X = df.drop(columns=["Binary_Label"])
y = df["Binary_Label"]

print("\nFeature matrix:", X.shape)
print("Target:", y.shape)

# --------------------------------------------------
# Train / Test split
# --------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\n" + "=" * 70)
print("SPLIT RESULTS")
print("=" * 70)

print("\nTraining set:")
print("X_train:", X_train.shape)
print("y_train:", y_train.shape)

print("\nTesting set:")
print("X_test:", X_test.shape)
print("y_test:", y_test.shape)

# --------------------------------------------------
# Class distributions
# --------------------------------------------------

print("\nTraining class distribution:")
print(y_train.value_counts())

print("\nTraining class percentages:")
print(
    (y_train.value_counts(normalize=True) * 100).round(3)
)

print("\nTesting class distribution:")
print(y_test.value_counts())

print("\nTesting class percentages:")
print(
    (y_test.value_counts(normalize=True) * 100).round(3)
)

# --------------------------------------------------
# Save
# --------------------------------------------------

X_train.to_csv(
    f"{OUTPUT_DIR}/X_train.csv",
    index=False
)

X_test.to_csv(
    f"{OUTPUT_DIR}/X_test.csv",
    index=False
)

y_train.to_csv(
    f"{OUTPUT_DIR}/y_train.csv",
    index=False
)

y_test.to_csv(
    f"{OUTPUT_DIR}/y_test.csv",
    index=False
)

print("\nSaved files:")
print(f"{OUTPUT_DIR}/X_train.csv")
print(f"{OUTPUT_DIR}/X_test.csv")
print(f"{OUTPUT_DIR}/y_train.csv")
print(f"{OUTPUT_DIR}/y_test.csv")

print("\n" + "=" * 70)
print("TRAIN / TEST SPLIT COMPLETED")
print("=" * 70)