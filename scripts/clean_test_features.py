import pandas as pd

print("=" * 70)
print("CICIDS2017 TEST FEATURE CLEANING")
print("=" * 70)

# Paths
TEST_PATH = "data/splits/X_test.csv"
SELECTED_PATH = "data/features/selected_features.csv"
OUTPUT_PATH = "data/features/X_test_clean.csv"

# Load selected training features
selected_features = pd.read_csv(SELECTED_PATH)["Feature"].tolist()

print(f"Selected features: {len(selected_features)}")

# Read test data
print("\nReading test data...")
X_test = pd.read_csv(TEST_PATH)

print(f"Original X_test shape: {X_test.shape}")

# Check that all selected features exist
missing_features = [
    feature for feature in selected_features
    if feature not in X_test.columns
]

if missing_features:
    print("\nERROR: Missing features in test data:")
    for feature in missing_features:
        print(" -", feature)
    raise ValueError("Test data does not contain all selected features.")

# Select exactly the same features and same order
X_test_clean = X_test[selected_features]

print("\nCleaned X_test shape:")
print(X_test_clean.shape)

print(f"\nFeatures remaining: {len(X_test_clean.columns)}")

# Save
X_test_clean.to_csv(OUTPUT_PATH, index=False)

print("\nSaved:")
print(OUTPUT_PATH)

print("\n" + "=" * 70)
print("TEST FEATURE CLEANING COMPLETED")
print("=" * 70)