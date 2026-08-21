import pandas as pd
import json
import os

print("=" * 70)
print("CICIDS2017 TOP FEATURE SELECTION")
print("=" * 70)

# ============================================================
# LOAD TOP 20 FEATURES
# ============================================================

print("\nLoading top 20 feature names...")

with open("results/models/top_20_features.json", "r") as f:
    top_features_data = json.load(f)

# Extract only the feature names from dictionaries
top_features = [item["feature"] for item in top_features_data]

print(f"Number of selected features: {len(top_features)}")

print("\nSelected features:")
for i, feature in enumerate(top_features, 1):
    print(f"{i:2d}. {feature}")

# ============================================================
# LOAD DATA
# ============================================================

print("\nLoading training data...")
X_train = pd.read_csv("data/features/X_train_clean.csv")

print("Loading testing data...")
X_test = pd.read_csv("data/features/X_test_clean.csv")

print("\nOriginal shapes:")
print(f"X_train: {X_train.shape}")
print(f"X_test : {X_test.shape}")

# ============================================================
# CHECK FEATURES
# ============================================================

missing_train = set(top_features) - set(X_train.columns)
missing_test = set(top_features) - set(X_test.columns)

if missing_train:
    print("\nERROR: Features missing from training data:")
    for feature in missing_train:
        print(" -", feature)
    raise ValueError("Missing features in training data")

if missing_test:
    print("\nERROR: Features missing from testing data:")
    for feature in missing_test:
        print(" -", feature)
    raise ValueError("Missing features in testing data")

print("\nAll selected features are present.")

# ============================================================
# SELECT TOP FEATURES
# ============================================================

X_train_top = X_train[top_features]
X_test_top = X_test[top_features]

print("\nReduced shapes:")
print(f"X_train_top: {X_train_top.shape}")
print(f"X_test_top : {X_test_top.shape}")

# ============================================================
# SAVE
# ============================================================

os.makedirs("data/features/top20", exist_ok=True)

X_train_top.to_csv(
    "data/features/top20/X_train_top20.csv",
    index=False
)

X_test_top.to_csv(
    "data/features/top20/X_test_top20.csv",
    index=False
)

# Save feature names
with open(
    "data/features/top20/top20_feature_names.json",
    "w"
) as f:
    json.dump(top_features, f, indent=4)

print("\nSaved:")
print("data/features/top20/X_train_top20.csv")
print("data/features/top20/X_test_top20.csv")
print("data/features/top20/top20_feature_names.json")

# ============================================================
# FINAL VERIFICATION
# ============================================================

print("\n" + "=" * 70)
print("TOP FEATURE SELECTION COMPLETED")
print("=" * 70)

print(f"\nOriginal features : {X_train.shape[1]}")
print(f"Selected features : {X_train_top.shape[1]}")
print(f"Features removed  : {X_train.shape[1] - X_train_top.shape[1]}")

print("\nFeature order identical:")
print(list(X_train_top.columns) == list(X_test_top.columns))

print("\nSelected feature list:")
for i, feature in enumerate(X_train_top.columns, 1):
    print(f"{i:2d}. {feature}")