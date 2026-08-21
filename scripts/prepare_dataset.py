import pandas as pd
import glob
import os

INPUT_DIR = "data/processed"
OUTPUT_DIR = "data/sample"

files = glob.glob(os.path.join(INPUT_DIR, "*.csv"))

print("=" * 70)
print("CICIDS2017 ML DATASET PREPARATION")
print("=" * 70)

all_data = []

for file in files:
    print("Reading:", os.path.basename(file))

    df = pd.read_csv(file)

    # Normalize column names
    df.columns = df.columns.str.strip()

    # Create binary target
    df["Binary_Label"] = df["Label"].apply(
        lambda x: 0 if x == "BENIGN" else 1
    )

    all_data.append(df)

# Combine all processed files
data = pd.concat(all_data, ignore_index=True)

print("\n" + "=" * 70)
print("COMBINED DATASET")
print("=" * 70)

print("Total rows:", len(data))
print("Total columns:", len(data.columns))

print("\nBinary class distribution:")
print(data["Binary_Label"].value_counts())

print("\nBinary class percentages:")
print(
    data["Binary_Label"]
    .value_counts(normalize=True)
    .mul(100)
    .round(4)
)

# Remove original text label from ML features
X = data.drop(columns=["Label", "Binary_Label"])
y = data["Binary_Label"]

print("\nFeature matrix shape:", X.shape)
print("Target shape:", y.shape)

# Save combined ML dataset
os.makedirs(OUTPUT_DIR, exist_ok=True)

output_file = os.path.join(
    OUTPUT_DIR,
    "cicids2017_binary.csv"
)

prepared_data = pd.concat(
    [X, y.rename("Binary_Label")],
    axis=1
)

prepared_data.to_csv(output_file, index=False)

print("\nSaved:", output_file)

print("\n" + "=" * 70)
print("DATASET PREPARATION COMPLETED")
print("=" * 70)