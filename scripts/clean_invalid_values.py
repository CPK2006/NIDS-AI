import pandas as pd
import glob
import os

INPUT_DIR = "data/processed"
OUTPUT_DIR = "data/processed"

INVALID_COLUMNS = [
    "Flow Duration",
    "Flow IAT Min",
    "Flow IAT Mean",
    "Flow IAT Max",
    "Flow Packets/s",
    "Flow Bytes/s",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Header Length.1",
    "min_seg_size_forward",
    "Fwd IAT Min"
]

files = glob.glob(os.path.join(INPUT_DIR, "*.csv"))

print("=" * 70)
print("CICIDS2017 INVALID VALUE CLEANING")
print("=" * 70)

total_removed = 0

for file in files:

    print("\n" + "=" * 70)
    print("Processing:", os.path.basename(file))
    print("=" * 70)

    df = pd.read_csv(file)

    original_rows = len(df)

    # Identify rows containing invalid negative values
    invalid_mask = (df[INVALID_COLUMNS] < 0).any(axis=1)

    invalid_rows = invalid_mask.sum()

    print("Original rows:", original_rows)
    print("Invalid rows:", invalid_rows)

    if invalid_rows > 0:
        print("\nInvalid rows by class:")
        print(df.loc[invalid_mask, "Label"].value_counts())

    # Remove invalid rows
    df = df.loc[~invalid_mask].copy()

    removed = original_rows - len(df)
    total_removed += removed

    print("\nRows removed:", removed)
    print("Rows remaining:", len(df))

    # Save back to processed dataset
    df.to_csv(file, index=False)

    print("Saved:", file)

print("\n" + "=" * 70)
print("INVALID VALUE CLEANING COMPLETED")
print("=" * 70)
print("Total rows removed:", total_removed)