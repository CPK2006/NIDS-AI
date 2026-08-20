import os
import glob
import numpy as np
import pandas as pd


RAW_DIR = "data/raw"


def inspect_file(file_path):
    print("\n" + "=" * 70)
    print(f"FILE: {os.path.basename(file_path)}")
    print("=" * 70)

    df = pd.read_csv(file_path)

    print(f"Rows: {len(df):,}")
    print(f"Columns: {len(df.columns)}")

    # Clean column names temporarily for inspection only
    df.columns = df.columns.str.strip()

    # Missing values
    missing = df.isnull().sum()
    missing = missing[missing > 0]

    print("\nMissing values:")
    if missing.empty:
        print("None")
    else:
        print(missing)

    # Infinite values in numerical columns
    numeric_df = df.select_dtypes(include=np.number)

    infinite_counts = np.isinf(numeric_df).sum()
    infinite_counts = infinite_counts[infinite_counts > 0]

    print("\nInfinite values:")
    if infinite_counts.empty:
        print("None")
    else:
        print(infinite_counts)

    # Duplicate rows
    duplicates = df.duplicated().sum()

    print(f"\nDuplicate rows: {duplicates:,}")

    # Data types
    print("\nData types:")
    print(df.dtypes.value_counts())

    # Label distribution
    print("\nLabels:")
    print(df["Label"].value_counts())


def main():
    files = sorted(glob.glob(os.path.join(RAW_DIR, "*.csv")))

    print("CICIDS2017 DATA QUALITY INSPECTION")
    print(f"Files found: {len(files)}")

    for file_path in files:
        inspect_file(file_path)


if __name__ == "__main__":
    main()