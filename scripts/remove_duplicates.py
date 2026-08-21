import pandas as pd
import os

INPUT_FILE = "data/sample/cicids2017_binary.csv"
OUTPUT_FILE = "data/sample/cicids2017_binary_deduplicated.csv"

print("=" * 70)
print("CICIDS2017 DUPLICATE REMOVAL")
print("=" * 70)

print(f"Reading: {INPUT_FILE}")

df = pd.read_csv(INPUT_FILE)

print("\nOriginal dataset")
print("-" * 70)
print("Rows:", len(df))
print("Columns:", len(df.columns))

print("\nClass distribution before duplicate removal:")
print(df["Binary_Label"].value_counts())

duplicates = df.duplicated().sum()

print("\nDuplicate rows:", duplicates)

# Remove exact duplicate rows
df = df.drop_duplicates().reset_index(drop=True)

print("\nAfter duplicate removal")
print("-" * 70)
print("Rows:", len(df))
print("Rows removed:", duplicates)

print("\nClass distribution after duplicate removal:")
print(df["Binary_Label"].value_counts())

print("\nClass percentages:")
print(
    (df["Binary_Label"].value_counts(normalize=True) * 100)
    .round(3)
)

# Save
df.to_csv(OUTPUT_FILE, index=False)

print("\nSaved:", OUTPUT_FILE)

print("\n" + "=" * 70)
print("DUPLICATE REMOVAL COMPLETED")
print("=" * 70)