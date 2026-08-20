import pandas as pd
import numpy as np
import glob
import os

RAW_DIR = "data/raw"

files = glob.glob(os.path.join(RAW_DIR, "*.csv"))

print("=" * 70)
print("CICIDS2017 NEGATIVE VALUE DETAIL ANALYSIS")
print("=" * 70)

overall = {}

for file in files:

    print("\n" + "=" * 70)
    print("FILE:", os.path.basename(file))
    print("=" * 70)

    df = pd.read_csv(file)

    numeric_cols = df.select_dtypes(include=np.number).columns

    for col in numeric_cols:

        negative = df.loc[df[col] < 0, col]

        if len(negative) > 0:

            counts = negative.value_counts().sort_index()

            print("\n" + col)
            print("Negative count:", len(negative))
            print("Unique negative values:", negative.nunique())
            print("Minimum:", negative.min())
            print("Maximum:", negative.max())

            print("Values:")
            print(counts.head(20))

            if col not in overall:
                overall[col] = []

            overall[col].append({
                "file": os.path.basename(file),
                "negative_count": len(negative),
                "unique_negative_values": negative.nunique(),
                "minimum": negative.min(),
                "maximum": negative.max()
            })


print("\n")
print("=" * 70)
print("OVERALL NEGATIVE VALUE SUMMARY")
print("=" * 70)

rows = []

for column, entries in overall.items():

    total = sum(x["negative_count"] for x in entries)

    minimum = min(x["minimum"] for x in entries)
    maximum = max(x["maximum"] for x in entries)

    rows.append({
        "Feature": column,
        "Total_Negative": total,
        "Minimum_Negative": minimum,
        "Maximum_Negative": maximum
    })

summary = pd.DataFrame(rows)

if not summary.empty:
    summary = summary.sort_values(
        "Total_Negative",
        ascending=False
    )

    print(summary.to_string(index=False))

    os.makedirs("results/eda", exist_ok=True)

    output = "results/eda/negative_value_details.csv"

    summary.to_csv(output, index=False)

    print("\nSaved:", output)

else:
    print("No negative values found.")