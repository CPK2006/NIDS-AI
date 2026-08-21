import pandas as pd
import numpy as np
import os

INPUT_FILE = "data/splits/X_train.csv"
OUTPUT_DIR = "results/features"

os.makedirs(OUTPUT_DIR, exist_ok=True)

print("=" * 70)
print("CICIDS2017 FEATURE INSPECTION")
print("=" * 70)

# --------------------------------------------------
# Load training features ONLY
# --------------------------------------------------

print(f"Reading: {INPUT_FILE}")

X = pd.read_csv(INPUT_FILE)

print("\nDataset shape:")
print(X.shape)

print("\nNumber of features:", X.shape[1])

# --------------------------------------------------
# Data types
# --------------------------------------------------

print("\n" + "=" * 70)
print("DATA TYPES")
print("=" * 70)

print(X.dtypes.value_counts())

non_numeric = X.select_dtypes(exclude=np.number).columns.tolist()

print("\nNon-numeric features:", len(non_numeric))

if non_numeric:
    print(non_numeric)

# --------------------------------------------------
# Missing values
# --------------------------------------------------

print("\n" + "=" * 70)
print("MISSING VALUES")
print("=" * 70)

missing = X.isna().sum()

missing = missing[missing > 0]

if len(missing) == 0:
    print("No missing values.")
else:
    print(missing)

# --------------------------------------------------
# Infinite values
# --------------------------------------------------

print("\n" + "=" * 70)
print("INFINITE VALUES")
print("=" * 70)

numeric_X = X.select_dtypes(include=np.number)

infinite = np.isinf(numeric_X).sum()

infinite = infinite[infinite > 0]

if len(infinite) == 0:
    print("No infinite values.")
else:
    print(infinite)

# --------------------------------------------------
# Constant features
# --------------------------------------------------

print("\n" + "=" * 70)
print("CONSTANT FEATURES")
print("=" * 70)

nunique = X.nunique()

constant_features = nunique[nunique <= 1].index.tolist()

print("Number of constant features:", len(constant_features))

if constant_features:
    for feature in constant_features:
        print(f"  - {feature}")

# --------------------------------------------------
# Duplicate feature columns
# --------------------------------------------------

print("\n" + "=" * 70)
print("DUPLICATE FEATURE COLUMNS")
print("=" * 70)

duplicate_columns = []

columns = X.columns

for i in range(len(columns)):
    for j in range(i + 1, len(columns)):

        col1 = columns[i]
        col2 = columns[j]

        if X[col1].equals(X[col2]):
            duplicate_columns.append((col1, col2))

print("Number of duplicate column pairs:", len(duplicate_columns))

if duplicate_columns:
    for col1, col2 in duplicate_columns:
        print(f"  - {col1} == {col2}")

# --------------------------------------------------
# Highly correlated features
# --------------------------------------------------

print("\n" + "=" * 70)
print("HIGHLY CORRELATED FEATURES")
print("=" * 70)

# Remove constant columns before correlation
variable_features = [
    col for col in numeric_X.columns
    if col not in constant_features
]

X_variable = X[variable_features]

print("Calculating correlation matrix...")
print("This may take some time...")

corr_matrix = X_variable.corr()

threshold = 0.95

high_corr_pairs = []

for i in range(len(corr_matrix.columns)):
    for j in range(i + 1, len(corr_matrix.columns)):

        correlation = corr_matrix.iloc[i, j]

        if abs(correlation) >= threshold:
            high_corr_pairs.append(
                (
                    corr_matrix.columns[i],
                    corr_matrix.columns[j],
                    correlation
                )
            )

print(
    f"\nPairs with absolute correlation >= {threshold}:",
    len(high_corr_pairs)
)

for feature1, feature2, correlation in high_corr_pairs:
    print(
        f"  - {feature1} <-> {feature2}: "
        f"{correlation:.4f}"
    )

# --------------------------------------------------
# Feature cardinality
# --------------------------------------------------

print("\n" + "=" * 70)
print("LOW-CARDINALITY FEATURES")
print("=" * 70)

low_cardinality = []

for col in X.columns:

    unique_count = X[col].nunique()

    if unique_count <= 10:
        low_cardinality.append(
            (col, unique_count)
        )

print(
    "Features with <= 10 unique values:",
    len(low_cardinality)
)

for feature, count in low_cardinality:
    print(f"  - {feature}: {count} unique values")

# --------------------------------------------------
# Save reports
# --------------------------------------------------

# Constant features
constant_df = pd.DataFrame({
    "Feature": constant_features
})

constant_df.to_csv(
    f"{OUTPUT_DIR}/constant_features.csv",
    index=False
)

# Duplicate columns
duplicate_df = pd.DataFrame(
    duplicate_columns,
    columns=["Feature_1", "Feature_2"]
)

duplicate_df.to_csv(
    f"{OUTPUT_DIR}/duplicate_features.csv",
    index=False
)

# High correlation
correlation_df = pd.DataFrame(
    high_corr_pairs,
    columns=[
        "Feature_1",
        "Feature_2",
        "Correlation"
    ]
)

correlation_df.to_csv(
    f"{OUTPUT_DIR}/high_correlation_features.csv",
    index=False
)

# Feature cardinality
cardinality_df = pd.DataFrame(
    low_cardinality,
    columns=[
        "Feature",
        "Unique_Values"
    ]
)

cardinality_df.to_csv(
    f"{OUTPUT_DIR}/low_cardinality_features.csv",
    index=False
)

print("\n" + "=" * 70)
print("REPORTS SAVED")
print("=" * 70)

print(f"{OUTPUT_DIR}/constant_features.csv")
print(f"{OUTPUT_DIR}/duplicate_features.csv")
print(f"{OUTPUT_DIR}/high_correlation_features.csv")
print(f"{OUTPUT_DIR}/low_cardinality_features.csv")

print("\n" + "=" * 70)
print("FEATURE INSPECTION COMPLETED")
print("=" * 70)