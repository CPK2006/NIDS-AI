import os
import glob
import pandas as pd


RAW_DIR = "data/raw"


def verify_dataset():
    files = sorted(glob.glob(os.path.join(RAW_DIR, "*.csv")))

    print("=" * 70)
    print("CICIDS2017 DATASET VERIFICATION")
    print("=" * 70)

    print(f"\nNumber of CSV files: {len(files)}")

    total_rows = 0

    for file in files:
        print("\n" + "-" * 70)
        print(f"File: {os.path.basename(file)}")

        # Read only the label column for efficient verification
        df = pd.read_csv(file, usecols=[" Label"])

        rows = len(df)
        total_rows += rows

        print(f"Rows: {rows:,}")
        print(f"Label column: {df.columns[0]}")

        print("\nLabels:")
        print(df[" Label"].value_counts())

    print("\n" + "=" * 70)
    print(f"TOTAL ROWS: {total_rows:,}")
    print("=" * 70)


if __name__ == "__main__":
    verify_dataset()