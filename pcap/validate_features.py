import os
import sys
import pandas as pd
import numpy as np


# ============================================================
# CONFIGURATION
# ============================================================

SCAPY_FEATURE_FILE = "data/pcap/test_100k_features_v7.csv"

CICIDS_REFERENCE_FILE = (
    "data/processed/"
    "Friday-WorkingHours-Morning.pcap_ISCX.csv"
)

OUTPUT_FILE = "data/pcap/feature_validation.csv"


# ============================================================
# EXACT TOP-20 FEATURES
# ============================================================

FEATURES = [
    "Destination Port",
    "Bwd Packet Length Std",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "Fwd Header Length",
    "Average Packet Size",
    "min_seg_size_forward",
    "Flow IAT Mean",
    "Bwd Header Length",
    "PSH Flag Count",
    "Flow IAT Min",
    "Fwd Packet Length Max",
    "Fwd IAT Min",
    "Total Length of Bwd Packets",
    "Max Packet Length",
    "Fwd IAT Total",
    "Packet Length Std",
    "Flow Bytes/s",
    "Bwd Packet Length Mean",
    "Packet Length Variance",
]


# ============================================================
# LOAD DATA
# ============================================================

def load_data():

    if not os.path.exists(SCAPY_FEATURE_FILE):

        raise FileNotFoundError(
            f"Scapy feature file not found:\n"
            f"{SCAPY_FEATURE_FILE}"
        )

    if not os.path.exists(CICIDS_REFERENCE_FILE):

        raise FileNotFoundError(
            f"CICIDS2017 reference file not found:\n"
            f"{CICIDS_REFERENCE_FILE}"
        )

    print("=" * 80)
    print("CICIDS2017 NIDS - FEATURE VALIDATION")
    print("=" * 80)

    print()
    print("Loading Scapy-generated features...")
    print(
        f"File: {SCAPY_FEATURE_FILE}"
    )

    scapy_df = pd.read_csv(
        SCAPY_FEATURE_FILE
    )

    print(
        f"Rows: {len(scapy_df):,}"
    )

    print()
    print("Loading CICIDS2017 reference...")
    print(
        f"File: {CICIDS_REFERENCE_FILE}"
    )

    # We only need the required columns.
    cicids_df = pd.read_csv(
        CICIDS_REFERENCE_FILE,
        usecols=FEATURES
    )

    print(
        f"Rows: {len(cicids_df):,}"
    )

    return scapy_df, cicids_df


# ============================================================
# VALIDATE COLUMNS
# ============================================================

def validate_columns(
    scapy_df,
    cicids_df
):

    print()
    print("=" * 80)
    print("COLUMN VALIDATION")
    print("=" * 80)

    scapy_missing = [
        feature
        for feature in FEATURES
        if feature not in scapy_df.columns
    ]

    cicids_missing = [
        feature
        for feature in FEATURES
        if feature not in cicids_df.columns
    ]

    if scapy_missing:

        print()
        print("ERROR: Missing from Scapy output:")

        for feature in scapy_missing:

            print(
                f"  - {feature}"
            )

        return False

    if cicids_missing:

        print()
        print(
            "ERROR: Missing from CICIDS2017:"
        )

        for feature in cicids_missing:

            print(
                f"  - {feature}"
            )

        return False

    print()
    print("All 20 features exist in both datasets.")

    return True


# ============================================================
# STATISTICS
# ============================================================

def calculate_statistics(
    df,
    feature
):

    series = pd.to_numeric(
        df[feature],
        errors="coerce"
    ).dropna()

    if len(series) == 0:

        return {
            "count": 0,
            "mean": np.nan,
            "median": np.nan,
            "std": np.nan,
            "min": np.nan,
            "p25": np.nan,
            "p75": np.nan,
            "max": np.nan
        }

    return {
        "count": len(series),

        "mean": series.mean(),

        "median": series.median(),

        "std": series.std(),

        "min": series.min(),

        "p25": series.quantile(0.25),

        "p75": series.quantile(0.75),

        "max": series.max()
    }


# ============================================================
# COMPARE DISTRIBUTIONS
# ============================================================

def compare_features(
    scapy_df,
    cicids_df
):

    results = []

    for feature in FEATURES:

        scapy = calculate_statistics(
            scapy_df,
            feature
        )

        cicids = calculate_statistics(
            cicids_df,
            feature
        )

        # ----------------------------------------------------
        # Mean difference
        # ----------------------------------------------------

        if (
            pd.notna(scapy["mean"])
            and
            pd.notna(cicids["mean"])
            and
            cicids["mean"] != 0
        ):

            mean_difference_percent = (
                abs(
                    scapy["mean"]
                    -
                    cicids["mean"]
                )
                /
                abs(cicids["mean"])
            ) * 100

        else:

            mean_difference_percent = np.nan

        # ----------------------------------------------------
        # Median difference
        # ----------------------------------------------------

        if (
            pd.notna(scapy["median"])
            and
            pd.notna(cicids["median"])
            and
            cicids["median"] != 0
        ):

            median_difference_percent = (
                abs(
                    scapy["median"]
                    -
                    cicids["median"]
                )
                /
                abs(cicids["median"])
            ) * 100

        else:

            median_difference_percent = np.nan

        results.append({

            "Feature": feature,

            "Scapy Count":
                scapy["count"],

            "CICIDS Count":
                cicids["count"],

            "Scapy Mean":
                scapy["mean"],

            "CICIDS Mean":
                cicids["mean"],

            "Mean Difference %":
                mean_difference_percent,

            "Scapy Median":
                scapy["median"],

            "CICIDS Median":
                cicids["median"],

            "Median Difference %":
                median_difference_percent,

            "Scapy Std":
                scapy["std"],

            "CICIDS Std":
                cicids["std"],

            "Scapy Min":
                scapy["min"],

            "CICIDS Min":
                cicids["min"],

            "Scapy P25":
                scapy["p25"],

            "CICIDS P25":
                cicids["p25"],

            "Scapy P75":
                scapy["p75"],

            "CICIDS P75":
                cicids["p75"],

            "Scapy Max":
                scapy["max"],

            "CICIDS Max":
                cicids["max"]
        })

    return pd.DataFrame(results)


# ============================================================
# PRINT COMPARISON
# ============================================================

def print_comparison(
    results
):

    print()
    print("=" * 120)
    print("FEATURE DISTRIBUTION COMPARISON")
    print("=" * 120)

    pd.set_option(
        "display.max_rows",
        None
    )

    pd.set_option(
        "display.max_columns",
        None
    )

    pd.set_option(
        "display.width",
        250
    )

    pd.set_option(
        "display.float_format",
        lambda x: f"{x:.6g}"
    )

    display_columns = [
        "Feature",
        "Scapy Mean",
        "CICIDS Mean",
        "Mean Difference %",
        "Scapy Median",
        "CICIDS Median",
        "Median Difference %"
    ]

    print()

    print(
        results[
            display_columns
        ].to_string(index=False)
    )


# ============================================================
# SAVE RESULTS
# ============================================================

def save_results(
    results
):

    output_directory = os.path.dirname(
        OUTPUT_FILE
    )

    if output_directory:

        os.makedirs(
            output_directory,
            exist_ok=True
        )

    results.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print()
    print(
        f"Full validation results saved to:"
    )

    print(
        OUTPUT_FILE
    )


# ============================================================
# MAIN
# ============================================================

def main():

    scapy_df, cicids_df = load_data()

    if not validate_columns(
        scapy_df,
        cicids_df
    ):

        sys.exit(1)

    results = compare_features(
        scapy_df,
        cicids_df
    )

    print_comparison(
        results
    )

    save_results(
        results
    )

    print()
    print("=" * 80)
    print("VALIDATION COMPLETED")
    print("=" * 80)

    print()
    print(
        "IMPORTANT:"
    )

    print(
        "These are distribution-level comparisons."
    )

    print(
        "They do NOT prove that individual PCAP "
        "flows correspond to individual CICIDS2017 rows."
    )

    print(
        "Use this result to identify potentially "
        "incorrect feature definitions."
    )


if __name__ == "__main__":

    main()