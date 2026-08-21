import pandas as pd
import numpy as np
import json
import os

print("=" * 70)
print("CICIDS2017 DATASET INTEGRITY & LEAKAGE VERIFICATION")
print("=" * 70)

# ============================================================
# PATHS
# ============================================================

TRAIN_X = "data/features/X_train_scaled.csv"
TEST_X = "data/features/X_test_scaled.csv"

TRAIN_Y = "data/splits/y_train.csv"
TEST_Y = "data/splits/y_test.csv"

RESULT_DIR = "results/models"
os.makedirs(RESULT_DIR, exist_ok=True)

# ============================================================
# 1. LOAD DATA
# ============================================================

print("\n" + "=" * 70)
print("1. LOADING DATA")
print("=" * 70)

print("Loading training features...")
X_train = pd.read_csv(TRAIN_X)

print("Loading testing features...")
X_test = pd.read_csv(TEST_X)

print("Loading training targets...")
y_train = pd.read_csv(TRAIN_Y)

print("Loading testing targets...")
y_test = pd.read_csv(TEST_Y)

# Convert target to Series if necessary
if isinstance(y_train, pd.DataFrame):
    y_train = y_train.iloc[:, 0]

if isinstance(y_test, pd.DataFrame):
    y_test = y_test.iloc[:, 0]

print("\nTraining:")
print("X_train:", X_train.shape)
print("y_train:", y_train.shape)

print("\nTesting:")
print("X_test :", X_test.shape)
print("y_test :", y_test.shape)

# ============================================================
# 2. BASIC INTEGRITY
# ============================================================

print("\n" + "=" * 70)
print("2. BASIC DATA INTEGRITY")
print("=" * 70)

checks = {}

checks["train_feature_target_alignment"] = len(X_train) == len(y_train)
checks["test_feature_target_alignment"] = len(X_test) == len(y_test)
checks["same_feature_count"] = X_train.shape[1] == X_test.shape[1]
checks["same_feature_names"] = list(X_train.columns) == list(X_test.columns)

print(
    "Training feature/target alignment:",
    checks["train_feature_target_alignment"]
)

print(
    "Testing feature/target alignment:",
    checks["test_feature_target_alignment"]
)

print(
    "Same number of features:",
    checks["same_feature_count"]
)

print(
    "Same feature names/order:",
    checks["same_feature_names"]
)

# ============================================================
# 3. TARGET DISTRIBUTION
# ============================================================

print("\n" + "=" * 70)
print("3. TARGET DISTRIBUTION")
print("=" * 70)

train_distribution = y_train.value_counts().sort_index()
test_distribution = y_test.value_counts().sort_index()

print("\nTraining target distribution:")
print(train_distribution)

print("\nTraining percentages:")
print((train_distribution / len(y_train) * 100).round(3))

print("\nTesting target distribution:")
print(test_distribution)

print("\nTesting percentages:")
print((test_distribution / len(y_test) * 100).round(3))

train_ratio = train_distribution / len(y_train)
test_ratio = test_distribution / len(y_test)

print("\nDifference in class percentages:")

for cls in sorted(set(y_train.unique()) | set(y_test.unique())):
    train_pct = train_ratio.get(cls, 0) * 100
    test_pct = test_ratio.get(cls, 0) * 100
    difference = test_pct - train_pct

    print(
        f"Class {cls}: "
        f"Train={train_pct:.3f}% | "
        f"Test={test_pct:.3f}% | "
        f"Difference={difference:+.3f}%"
    )

# ============================================================
# 4. NaN / INFINITY CHECK
# ============================================================

print("\n" + "=" * 70)
print("4. NaN / INFINITY CHECK")
print("=" * 70)

train_nan = int(X_train.isna().sum().sum())
test_nan = int(X_test.isna().sum().sum())

train_inf = int(np.isinf(X_train.to_numpy()).sum())
test_inf = int(np.isinf(X_test.to_numpy()).sum())

print("Training NaN values:", train_nan)
print("Testing NaN values :", test_nan)

print("Training infinite values:", train_inf)
print("Testing infinite values :", test_inf)

checks["no_train_nan"] = train_nan == 0
checks["no_test_nan"] = test_nan == 0
checks["no_train_inf"] = train_inf == 0
checks["no_test_inf"] = test_inf == 0

# ============================================================
# 5. CONSTANT / LOW-VARIANCE FEATURES
# ============================================================

print("\n" + "=" * 70)
print("5. CONSTANT / LOW-VARIANCE FEATURES")
print("=" * 70)

train_nunique = X_train.nunique()

constant_features = train_nunique[train_nunique <= 1]

print("Constant features:", len(constant_features))

if len(constant_features) > 0:
    print(constant_features.index.tolist())
else:
    print("No constant features found.")

# Near-zero variance
train_std = X_train.std()

near_zero_features = train_std[train_std < 0.001]

print("\nFeatures with std < 0.001:", len(near_zero_features))

if len(near_zero_features) > 0:
    print(near_zero_features.index.tolist())

# ============================================================
# 6. EXACT TRAIN/TEST DUPLICATE ROWS
# ============================================================

print("\n" + "=" * 70)
print("6. EXACT TRAIN/TEST DUPLICATE ROW CHECK")
print("=" * 70)

print("Creating row hashes...")

train_hashes = pd.util.hash_pandas_object(X_train, index=False)
test_hashes = pd.util.hash_pandas_object(X_test, index=False)

train_hash_set = set(train_hashes)
test_hash_set = set(test_hashes)

common_hashes = train_hash_set.intersection(test_hash_set)

print("Unique training rows:", len(train_hash_set))
print("Unique testing rows :", len(test_hash_set))
print("Common row hashes   :", len(common_hashes))

if len(common_hashes) == 0:
    print("\nRESULT: No exact feature-row overlap detected.")
else:
    print("\nWARNING: Exact feature-row overlap detected!")

checks["no_exact_train_test_overlap"] = len(common_hashes) == 0

# ============================================================
# 7. DUPLICATE FEATURE VECTORS WITH DIFFERENT LABELS
# ============================================================

print("\n" + "=" * 70)
print("7. CROSS-SPLIT DUPLICATE + LABEL CHECK")
print("=" * 70)

if len(common_hashes) > 0:

    print("Checking labels for overlapping feature vectors...")

    train_lookup = pd.DataFrame({
        "hash": train_hashes,
        "target": y_train.to_numpy()
    })

    test_lookup = pd.DataFrame({
        "hash": test_hashes,
        "target": y_test.to_numpy()
    })

    overlap = train_lookup.merge(
        test_lookup,
        on="hash",
        suffixes=("_train", "_test")
    )

    conflicting = overlap[
        overlap["target_train"] != overlap["target_test"]
    ]

    print("Overlapping rows:", len(overlap))
    print("Conflicting labels:", len(conflicting))

    if len(conflicting) > 0:
        print("WARNING: Same feature vector has different labels.")
    else:
        print("No conflicting labels among overlaps.")

else:
    print("No overlapping feature vectors, so conflicting-label check is unnecessary.")

# ============================================================
# 8. FEATURE DISTRIBUTION COMPARISON
# ============================================================

print("\n" + "=" * 70)
print("8. TRAIN / TEST FEATURE DISTRIBUTION")
print("=" * 70)

print("Calculating distribution differences...")

distribution_results = []

for feature in X_train.columns:

    train_mean = X_train[feature].mean()
    test_mean = X_test[feature].mean()

    train_std_value = X_train[feature].std()
    test_std_value = X_test[feature].std()

    mean_difference = abs(train_mean - test_mean)

    if train_std_value != 0:
        standardized_difference = (
            abs(train_mean - test_mean) / train_std_value
        )
    else:
        standardized_difference = 0

    distribution_results.append({
        "Feature": feature,
        "Train_Mean": train_mean,
        "Test_Mean": test_mean,
        "Mean_Difference": mean_difference,
        "Train_Std": train_std_value,
        "Test_Std": test_std_value,
        "Standardized_Mean_Difference": standardized_difference
    })

distribution_df = pd.DataFrame(distribution_results)

distribution_df = distribution_df.sort_values(
    "Standardized_Mean_Difference",
    ascending=False
)

print("\nTop 15 features with largest train/test mean difference:")

print(
    distribution_df.head(15).to_string(index=False)
)

distribution_df.to_csv(
    f"{RESULT_DIR}/train_test_feature_distribution.csv",
    index=False
)

# ============================================================
# 9. SUSPICIOUSLY PREDICTIVE SINGLE FEATURES
# ============================================================

print("\n" + "=" * 70)
print("9. SINGLE-FEATURE TARGET RELATIONSHIP CHECK")
print("=" * 70)

print("Calculating correlation between features and target...")

target_numeric = pd.Series(
    y_train.to_numpy(),
    index=X_train.index
)

correlations = X_train.corrwith(target_numeric).abs()

correlation_df = pd.DataFrame({
    "Feature": correlations.index,
    "Absolute_Correlation": correlations.values
})

correlation_df = correlation_df.sort_values(
    "Absolute_Correlation",
    ascending=False
)

print("\nTop 20 feature-target correlations:")

print(
    correlation_df.head(20).to_string(index=False)
)

correlation_df.to_csv(
    f"{RESULT_DIR}/feature_target_correlations.csv",
    index=False
)

# ============================================================
# 10. FEATURE RANGE COMPARISON
# ============================================================

print("\n" + "=" * 70)
print("10. TRAIN / TEST RANGE CHECK")
print("=" * 70)

range_results = []

for feature in X_train.columns:

    train_min = X_train[feature].min()
    train_max = X_train[feature].max()

    test_min = X_test[feature].min()
    test_max = X_test[feature].max()

    test_outside_train = (
        test_min < train_min or
        test_max > train_max
    )

    range_results.append({
        "Feature": feature,
        "Train_Min": train_min,
        "Train_Max": train_max,
        "Test_Min": test_min,
        "Test_Max": test_max,
        "Test_Outside_Train_Range": test_outside_train
    })

range_df = pd.DataFrame(range_results)

outside_count = int(
    range_df["Test_Outside_Train_Range"].sum()
)

print(
    "Features where test contains values outside "
    f"training range: {outside_count}"
)

if outside_count > 0:
    print("\nFirst 15:")
    print(
        range_df[
            range_df["Test_Outside_Train_Range"]
        ].head(15).to_string(index=False)
    )

range_df.to_csv(
    f"{RESULT_DIR}/train_test_feature_ranges.csv",
    index=False
)

# ============================================================
# 11. FEATURE NAME CHECK FOR OBVIOUS TARGET LEAKAGE
# ============================================================

print("\n" + "=" * 70)
print("11. FEATURE NAME LEAKAGE CHECK")
print("=" * 70)

suspicious_keywords = [
    "label",
    "target",
    "attack",
    "class",
    "benign",
    "malicious",
    "category"
]

suspicious_features = []

for feature in X_train.columns:

    feature_lower = feature.lower()

    for keyword in suspicious_keywords:

        if keyword in feature_lower:
            suspicious_features.append(
                (feature, keyword)
            )

            break

if suspicious_features:

    print("Potentially suspicious feature names:")

    for feature, keyword in suspicious_features:
        print(
            f"  {feature}  <-- contains '{keyword}'"
        )

else:

    print(
        "No obvious target/label-related feature names found."
    )

checks["no_obvious_target_feature_names"] = (
    len(suspicious_features) == 0
)

# ============================================================
# 12. SCALING VERIFICATION
# ============================================================

print("\n" + "=" * 70)
print("12. SCALING VERIFICATION")
print("=" * 70)

train_mean_abs = X_train.mean().abs().max()
train_std_mean = X_train.std().mean()

test_mean_abs = X_test.mean().abs().max()
test_std_mean = X_test.std().mean()

print(
    "Training maximum absolute mean:",
    train_mean_abs
)

print(
    "Training mean standard deviation:",
    train_std_mean
)

print(
    "Testing maximum absolute mean:",
    test_mean_abs
)

print(
    "Testing mean standard deviation:",
    test_std_mean
)

# ============================================================
# 13. FINAL INTEGRITY SUMMARY
# ============================================================

print("\n" + "=" * 70)
print("13. VERIFICATION SUMMARY")
print("=" * 70)

print("\nBasic checks:")

for name, result in checks.items():

    status = "PASS" if result else "WARNING"

    print(
        f"{name:45s}: {status}"
    )

# ============================================================
# SAVE SUMMARY
# ============================================================

summary = {
    "train_shape": list(X_train.shape),
    "test_shape": list(X_test.shape),
    "train_target_shape": list(y_train.shape),
    "test_target_shape": list(y_test.shape),

    "exact_train_test_overlap_hashes": int(
        len(common_hashes)
    ),

    "constant_features": int(
        len(constant_features)
    ),

    "near_zero_variance_features": int(
        len(near_zero_features)
    ),

    "train_nan_values": train_nan,
    "test_nan_values": test_nan,

    "train_infinite_values": train_inf,
    "test_infinite_values": test_inf,

    "test_features_outside_train_range": outside_count,

    "maximum_train_absolute_mean": float(
        train_mean_abs
    ),

    "maximum_test_absolute_mean": float(
        test_mean_abs
    ),

    "checks": checks
}

summary_path = (
    f"{RESULT_DIR}/dataset_integrity_verification.json"
)

with open(summary_path, "w") as f:
    json.dump(summary, f, indent=4)

print("\nSaved:")
print(summary_path)

print("\n" + "=" * 70)
print("DATASET INTEGRITY VERIFICATION COMPLETED")
print("=" * 70)