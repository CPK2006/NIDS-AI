import os
import glob
import numpy as np
import pandas as pd


RAW_DIR = "data/raw"
PROCESSED_DIR = "data/processed"


def clean_file(file_path):
    filename = os.path.basename(file_path)

    print("\n" + "=" * 70)
    print(f"Processing: {filename}")
    print("=" * 70)

    # Load raw data
    df = pd.read_csv(file_path)

    print(f"Original rows: {len(df):,}")

    # ---------------------------------------------------------
    # 1. Clean column names
    # ---------------------------------------------------------
    df.columns = df.columns.str.strip()

    # ---------------------------------------------------------
    # 2. Normalize label text
    # ---------------------------------------------------------
    df["Label"] = df["Label"].astype(str).str.strip()

    # Fix encoding/display issue in Web Attack labels
    df["Label"] = df["Label"].replace({
        "Web Attack � Brute Force": "Web Attack - Brute Force",
        "Web Attack � XSS": "Web Attack - XSS",
        "Web Attack � Sql Injection": "Web Attack - Sql Injection"
    })

    # ---------------------------------------------------------
    # 3. Convert infinite values to NaN
    # ---------------------------------------------------------
    numeric_columns = df.select_dtypes(include=np.number).columns

    infinite_count = np.isinf(df[numeric_columns]).sum().sum()

    print(f"Infinite values found: {infinite_count:,}")

    df[numeric_columns] = df[numeric_columns].replace(
        [np.inf, -np.inf],
        np.nan
    )

    # ---------------------------------------------------------
    # 4. Handle missing numerical values
    # ---------------------------------------------------------
    missing_before = df[numeric_columns].isna().sum().sum()

    print(f"Missing numerical values: {missing_before:,}")

    # Median imputation
    for column in numeric_columns:
        if df[column].isna().any():
            median_value = df[column].median()
            df[column] = df[column].fillna(median_value)

    missing_after = df[numeric_columns].isna().sum().sum()

    print(f"Missing numerical values after imputation: {missing_after:,}")

    # ---------------------------------------------------------
    # 5. Remove exact duplicate rows
    # ---------------------------------------------------------
    duplicate_count = df.duplicated().sum()

    print(f"Duplicate rows found: {duplicate_count:,}")

    df = df.drop_duplicates().reset_index(drop=True)

    print(f"Rows after duplicate removal: {len(df):,}")

    # ---------------------------------------------------------
    # 6. Save cleaned data
    # ---------------------------------------------------------
    output_path = os.path.join(PROCESSED_DIR, filename)

    df.to_csv(output_path, index=False)

    print(f"Saved: {output_path}")


def main():
    os.makedirs(PROCESSED_DIR, exist_ok=True)

    files = sorted(glob.glob(os.path.join(RAW_DIR, "*.csv")))

    print("=" * 70)
    print("CICIDS2017 DATA CLEANING")
    print("=" * 70)

    print(f"Raw files found: {len(files)}")

    for file_path in files:
        clean_file(file_path)

    print("\n" + "=" * 70)
    print("DATA CLEANING COMPLETED")
    print("=" * 70)


if __name__ == "__main__":
    main()