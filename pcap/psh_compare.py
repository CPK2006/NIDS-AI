import pandas as pd
from pathlib import Path

# ============================================================
# PSH FLAG COUNT COMPARISON
# ============================================================

SCAPY_FILE = r"data\pcap\test_100k_features_v5.csv"
CICIDS_FILE = r"data\processed\Friday-WorkingHours-Morning.pcap_ISCX.csv"

print("=" * 80)
print("PSH FLAG COUNT COMPARISON")
print("=" * 80)

# ------------------------------------------------------------
# Load datasets
# ------------------------------------------------------------

print("\nLoading Scapy features...")
scapy = pd.read_csv(SCAPY_FILE, usecols=["PSH Flag Count"])

print("Loading CICIDS2017 reference...")
cicids = pd.read_csv(CICIDS_FILE, usecols=["PSH Flag Count"])

# ------------------------------------------------------------
# Basic statistics
# ------------------------------------------------------------

print("\n" + "=" * 80)
print("BASIC STATISTICS")
print("=" * 80)

print("\nScapy:")
print(scapy["PSH Flag Count"].describe())

print("\nCICIDS2017:")
print(cicids["PSH Flag Count"].describe())

# ------------------------------------------------------------
# Frequency distributions
# ------------------------------------------------------------

print("\n" + "=" * 80)
print("SCAPY PSH DISTRIBUTION")
print("=" * 80)

print(
    scapy["PSH Flag Count"]
    .value_counts()
    .sort_index()
    .head(30)
)

print("\n" + "=" * 80)
print("CICIDS2017 PSH DISTRIBUTION")
print("=" * 80)

print(
    cicids["PSH Flag Count"]
    .value_counts()
    .sort_index()
    .head(30)
)

# ------------------------------------------------------------
# Percentage of flows with PSH
# ------------------------------------------------------------

scapy_psh = (scapy["PSH Flag Count"] > 0).sum()
cicids_psh = (cicids["PSH Flag Count"] > 0).sum()

print("\n" + "=" * 80)
print("FLOWS WITH PSH")
print("=" * 80)

print(
    f"Scapy flows with PSH     : {scapy_psh:,} "
    f"/ {len(scapy):,} "
    f"({scapy_psh / len(scapy) * 100:.2f}%)"
)

print(
    f"CICIDS flows with PSH    : {cicids_psh:,} "
    f"/ {len(cicids):,} "
    f"({cicids_psh / len(cicids) * 100:.2f}%)"
)

# ------------------------------------------------------------
# Important PSH values
# ------------------------------------------------------------

print("\n" + "=" * 80)
print("PSH SUMMARY")
print("=" * 80)

for name, series in [
    ("Scapy", scapy["PSH Flag Count"]),
    ("CICIDS2017", cicids["PSH Flag Count"]),
]:
    print(f"\n{name}")
    print("-" * 40)
    print("Zero PSH :", (series == 0).sum())
    print("PSH > 0  :", (series > 0).sum())
    print("PSH >= 5  :", (series >= 5).sum())
    print("PSH >= 10 :", (series >= 10).sum())
    print("Maximum   :", series.max())

print("\n" + "=" * 80)
print("END")
print("=" * 80)