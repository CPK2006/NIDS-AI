import pandas as pd
import numpy as np
import os

print("=" * 70)
print("CICIDS2017 GROUP / SESSION LEAKAGE ANALYSIS")
print("=" * 70)

TRAIN_PATH = "data/splits/X_train.csv"
TEST_PATH = "data/splits/X_test.csv"

print("\nLoading data...")
X_train = pd.read_csv(TRAIN_PATH)
X_test = pd.read_csv(TEST_PATH)

print("X_train:", X_train.shape)
print("X_test :", X_test.shape)

print("\nAvailable columns:")
for col in X_train.columns:
    print(" -", col)

# ------------------------------------------------------------
# Helper function
# ------------------------------------------------------------

def check_overlap(name, columns):
    columns = [c for c in columns if c in X_train.columns and c in X_test.columns]

    if not columns:
        print(f"\n{name}: columns not available")
        return

    print("\n" + "-" * 70)
    print(name)
    print("-" * 70)

    print("Columns:", columns)

    # Use fast pandas hashing
    train_hash = pd.util.hash_pandas_object(
        X_train[columns],
        index=False
    )

    test_hash = pd.util.hash_pandas_object(
        X_test[columns],
        index=False
    )

    train_set = set(train_hash)
    test_set = set(test_hash)

    common = train_set.intersection(test_set)

    # Number of test rows belonging to groups also seen in train
    test_overlap = test_hash.isin(train_set)

    overlap_count = test_overlap.sum()
    overlap_percentage = overlap_count / len(X_test) * 100

    print("Unique train groups :", len(train_set))
    print("Unique test groups  :", len(test_set))
    print("Common groups       :", len(common))
    print("Test rows in train groups:", overlap_count)
    print(f"Test overlap percentage : {overlap_percentage:.6f}%")

    return {
        "name": name,
        "columns": columns,
        "train_groups": len(train_set),
        "test_groups": len(test_set),
        "common_groups": len(common),
        "test_overlap_rows": int(overlap_count),
        "test_overlap_percentage": float(overlap_percentage)
    }


results = []

# ------------------------------------------------------------
# 1. Flow ID
# ------------------------------------------------------------

results.append(
    check_overlap(
        "1. FLOW ID OVERLAP",
        ["Flow ID"]
    )
)

# ------------------------------------------------------------
# 2. Network 5-tuple
# ------------------------------------------------------------

results.append(
    check_overlap(
        "2. NETWORK 5-TUPLE OVERLAP",
        [
            "Source IP",
            "Destination IP",
            "Source Port",
            "Destination Port",
            "Protocol"
        ]
    )
)

# ------------------------------------------------------------
# 3. Communication pair
# ------------------------------------------------------------

results.append(
    check_overlap(
        "3. SOURCE / DESTINATION PAIR OVERLAP",
        [
            "Source IP",
            "Destination IP"
        ]
    )
)

# ------------------------------------------------------------
# 4. Source host
# ------------------------------------------------------------

results.append(
    check_overlap(
        "4. SOURCE IP OVERLAP",
        ["Source IP"]
    )
)

# ------------------------------------------------------------
# 5. Destination host
# ------------------------------------------------------------

results.append(
    check_overlap(
        "5. DESTINATION IP OVERLAP",
        ["Destination IP"]
    )
)

# ------------------------------------------------------------
# 6. Protocol + destination port
# ------------------------------------------------------------

results.append(
    check_overlap(
        "6. PROTOCOL + DESTINATION PORT OVERLAP",
        [
            "Protocol",
            "Destination Port"
        ]
    )
)

# ------------------------------------------------------------
# Save results
# ------------------------------------------------------------

results = [
    r for r in results
    if r is not None
]

results_df = pd.DataFrame(results)

os.makedirs("results/models", exist_ok=True)

OUTPUT = "results/models/group_leakage_analysis.csv"

results_df.to_csv(
    OUTPUT,
    index=False
)

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)

print(
    results_df[
        [
            "name",
            "common_groups",
            "test_overlap_rows",
            "test_overlap_percentage"
        ]
    ].to_string(index=False)
)

print("\nSaved:")
print(OUTPUT)

print("\n" + "=" * 70)
print("GROUP / SESSION LEAKAGE ANALYSIS COMPLETED")
print("=" * 70)