import os
import glob
import pandas as pd
import numpy as np


PROCESSED_DIR = "data/processed"
RESULTS_DIR = "results/eda"


def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)

    print("=" * 70)
    print("CICIDS2017 FEATURE STATISTICS")
    print("=" * 70)

    files = sorted(glob.glob(os.path.join(PROCESSED_DIR, "*.csv")))

    # Read a sample from every processed file.
    # We do not need the complete 2.57M rows for basic statistics.
    samples = []

    for file_path in files:
        print(f"Reading sample: {os.path.basename(file_path)}")

        df = pd.read_csv(
            file_path,
            nrows=100000
        )

        samples.append(df)

    data = pd.concat(samples, ignore_index=True)

    print(f"\nSample records used: {len(data):,}")
    print(f"Total columns: {len(data.columns)}")

    # ---------------------------------------------------------
    # Remove label
    # ---------------------------------------------------------
    X = data.drop(columns=["Label"])

    numeric = X.select_dtypes(include=np.number)

    print(f"Numerical features: {len(numeric.columns)}")

    # ---------------------------------------------------------
    # Basic statistics
    # ---------------------------------------------------------
    statistics = numeric.describe().T

    statistics["missing"] = numeric.isna().sum()

    statistics["infinite"] = np.isinf(numeric).sum()

    statistics["unique"] = numeric.nunique()

    # ---------------------------------------------------------
    # Constant features
    # ---------------------------------------------------------
    statistics["constant"] = statistics["std"] == 0

    # ---------------------------------------------------------
    # Very low variance
    # ---------------------------------------------------------
    statistics["near_zero_variance"] = (
        statistics["std"] < 1e-10
    )

    output_file = os.path.join(
        RESULTS_DIR,
        "feature_statistics.csv"
    )

    statistics.to_csv(output_file)

    print("\nFeature statistics:")
    print(statistics[
        ["count", "mean", "std", "min", "max",
         "missing", "infinite", "unique"]
    ].to_string())

    # ---------------------------------------------------------
    # Constant features
    # ---------------------------------------------------------
    constant_features = statistics[
        statistics["constant"]
    ].index.tolist()

    print("\nConstant features:")
    if constant_features:
        for feature in constant_features:
            print("-", feature)
    else:
        print("None")

    # ---------------------------------------------------------
    # Near-zero variance features
    # ---------------------------------------------------------
    nzv_features = statistics[
        statistics["near_zero_variance"]
    ].index.tolist()

    print("\nNear-zero variance features:")
    if nzv_features:
        for feature in nzv_features:
            print("-", feature)
    else:
        print("None")

    print(f"\nSaved: {output_file}")


if __name__ == "__main__":
    main()