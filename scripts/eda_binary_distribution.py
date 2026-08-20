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
    print("CICIDS2017 BINARY CLASS DISTRIBUTION")
    print("=" * 70)

    labels = load_labels()

    # ---------------------------------------------------------
    # Convert multiclass labels to binary labels
    # ---------------------------------------------------------
    labels["Binary_Label"] = labels["Label"].apply(
        lambda x: "BENIGN" if x == "BENIGN" else "ATTACK"
    )

    distribution = labels["Binary_Label"].value_counts()

    percentages = (
        labels["Binary_Label"]
        .value_counts(normalize=True)
        * 100
    )

    print("\nBinary class distribution:")
    print(distribution)

    print("\nBinary class percentages:")
    print(percentages.round(4))

    # ---------------------------------------------------------
    # Save results
    # ---------------------------------------------------------
    result_df = pd.DataFrame({
        "Count": distribution,
        "Percentage": percentages.round(4)
    })

    output_csv = os.path.join(
        RESULTS_DIR,
        "binary_class_distribution.csv"
    )

    result_df.to_csv(output_csv)

    # ---------------------------------------------------------
    # Plot
    # ---------------------------------------------------------
    plt.figure(figsize=(8, 6))

    distribution.plot(kind="bar")

    plt.title("CICIDS2017 Binary Class Distribution")
    plt.xlabel("Traffic Class")
    plt.ylabel("Number of Records")
    plt.xticks(rotation=0)

    plt.tight_layout()

    output_png = os.path.join(
        RESULTS_DIR,
        "binary_class_distribution.png"
    )

    plt.savefig(output_png, dpi=300)
    plt.close()

    print(f"\nSaved: {output_csv}")
    print(f"Saved: {output_png}")


if __name__ == "__main__":
    main()