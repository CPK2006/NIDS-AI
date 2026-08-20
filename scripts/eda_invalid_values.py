import os
import glob
import pandas as pd
import numpy as np


PROCESSED_DIR = "data/processed"
RESULTS_DIR = "results/eda"


def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)

    print("=" * 70)
    print("CICIDS2017 INVALID VALUE ANALYSIS")
    print("=" * 70)

    files = sorted(
        glob.glob(os.path.join(PROCESSED_DIR, "*.csv"))
    )

    negative_counts = {}

    for file_path in files:
        print(f"\nProcessing: {os.path.basename(file_path)}")

        df = pd.read_csv(file_path)

        numeric = df.select_dtypes(include=np.number)

        # Count negative values
        counts = (numeric < 0).sum()

        counts = counts[counts > 0]

        if len(counts) > 0:
            negative_counts[
                os.path.basename(file_path)
            ] = counts

            print("\nNegative values:")
            print(counts.sort_values(ascending=False))

        else:
            print("No negative values found.")

    # ---------------------------------------------------------
    # Combine results
    # ---------------------------------------------------------
    if negative_counts:

        result = pd.DataFrame(negative_counts).fillna(0)

        result["Total"] = result.sum(axis=1)

        result = result.sort_values(
            "Total",
            ascending=False
        )

        output_file = os.path.join(
            RESULTS_DIR,
            "negative_value_analysis.csv"
        )

        result.to_csv(output_file)

        print("\n" + "=" * 70)
        print("OVERALL NEGATIVE VALUE SUMMARY")
        print("=" * 70)

        print(result.to_string())

        print(f"\nSaved: {output_file}")

    else:
        print("\nNo negative values found in the dataset.")


if __name__ == "__main__":
    main()