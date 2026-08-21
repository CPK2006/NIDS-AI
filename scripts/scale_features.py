import pandas as pd
from sklearn.preprocessing import StandardScaler
import joblib

print("=" * 70)
print("CICIDS2017 FEATURE SCALING")
print("=" * 70)

TRAIN_PATH = "data/features/X_train_clean.csv"
TEST_PATH = "data/features/X_test_clean.csv"

TRAIN_OUTPUT = "data/features/X_train_scaled.csv"
TEST_OUTPUT = "data/features/X_test_scaled.csv"
SCALER_OUTPUT = "data/features/scaler.pkl"

# --------------------------------------------------
# Load data
# --------------------------------------------------

print("\nReading training data...")
X_train = pd.read_csv(TRAIN_PATH)

print("Reading test data...")
X_test = pd.read_csv(TEST_PATH)

print("\nTraining shape:", X_train.shape)
print("Testing shape:", X_test.shape)

# --------------------------------------------------
# Create scaler
# --------------------------------------------------

print("\nFitting StandardScaler on training data...")

scaler = StandardScaler()

X_train_scaled = scaler.fit_transform(X_train)

print("Transforming test data...")
X_test_scaled = scaler.transform(X_test)

# Convert back to DataFrame
X_train_scaled = pd.DataFrame(
    X_train_scaled,
    columns=X_train.columns
)

X_test_scaled = pd.DataFrame(
    X_test_scaled,
    columns=X_test.columns
)

# --------------------------------------------------
# Save scaled datasets
# --------------------------------------------------

X_train_scaled.to_csv(TRAIN_OUTPUT, index=False)
X_test_scaled.to_csv(TEST_OUTPUT, index=False)

# Save scaler
joblib.dump(scaler, SCALER_OUTPUT)

print("\nScaled training shape:")
print(X_train_scaled.shape)

print("\nScaled testing shape:")
print(X_test_scaled.shape)

print("\nSaved:")
print(TRAIN_OUTPUT)
print(TEST_OUTPUT)
print(SCALER_OUTPUT)

print("\n" + "=" * 70)
print("FEATURE SCALING COMPLETED")
print("=" * 70)