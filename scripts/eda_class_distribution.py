import os
import glob
import pandas as pd
import matplotlib.pyplot as plt


PROCESSED_DIR = "data/processed"
RESULTS_DIR = "results/eda"


def load_labels():
    files = sorted(glob.glob(os.path.join(PROCESSED_DIR, "*.csv")))

    frames = []

    for file_path in files:
        print(f"Reading: {os.path.basename(file_path)}")

        df = pd.read_csv(file_path, usecols=["Label"])

        frames.append(df)

    return pd.concat(frames, ignore_index=True)


def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)

    print("=" * 70)
    print("CICIDS2017 CLASS DISTRIBUTION ANALYSIS")
    print("=" * 70)

    labels = load_labels()

    print(f"\nTotal records: {len(labels):,}")

    # ---------------------------------------------------------
    # Overall class distribution
    # ---------------------------------------------------------
    distribution = labels["Label"].value_counts()

    print("\nOverall class distribution:")
    print(distribution)

    # Percentages
    percentages = labels["Label"].value_counts(normalize=True) * 100

    print("\nClass percentages:")
    print(percentages.round(4))

    # Save results
    result_df = pd.DataFrame({
        "Count": distribution,
        "Percentage": percentages.round(4)
    })

    result_df.to_csv(
        os.path.join(RESULTS_DIR, "class_distribution.csv")
    )

    # ---------------------------------------------------------
    # Plot
    # ---------------------------------------------------------
    plt.figure(figsize=(12, 7))

    distribution.sort_values(ascending=True).plot(
        kind="barh"
    )

    plt.title("CICIDS2017 Attack Class Distribution")
    plt.xlabel("Number of Records")
    plt.ylabel("Attack Class")

    plt.tight_layout()

    output_path = os.path.join(
        RESULTS_DIR,
        "class_distribution.png"
    )

    plt.savefig(output_path, dpi=300)
    plt.close()

    print(f"\nSaved distribution table:")
    print(os.path.join(RESULTS_DIR, "class_distribution.csv"))

    print(f"Saved visualization:")
    print(output_path)


if __name__ == "__main__":
    main()