import os
import subprocess
import sys

print("=" * 80)
print("CICIDS2017 SAFE FINAL WORKFLOW")
print("=" * 80)

# --------------------------------------------------
# Required directories
# --------------------------------------------------

os.makedirs("results/models", exist_ok=True)
os.makedirs("results/plots", exist_ok=True)

# --------------------------------------------------
# Check important files
# --------------------------------------------------

required_files = [
    "data/sample/cicids2017_binary_deduplicated.csv",
    "data/features/selected_features.csv",
    "results/models/leakage_free_top20_model.cbm",
    "results/models/leakage_free_top20_results.json",
    "results/models/leakage_free_top20_thresholds.csv",
    "results/models/final_model_comparison.csv",
]

print("\nChecking required files...")

missing = []

for file in required_files:
    if os.path.exists(file):
        print("[OK]     ", file)
    else:
        print("[MISSING]", file)
        missing.append(file)

if missing:
    print("\nERROR: Required files are missing.")
    print("Fix the missing files before continuing.")
    sys.exit(1)

print("\nAll required files are available.")

# --------------------------------------------------
# Run final plots
# --------------------------------------------------

plot_script = "scripts/generate_final_plots.py"

if not os.path.exists(plot_script):
    print("\nERROR:")
    print(f"{plot_script} does not exist.")
    print("\nCreate it first using:")
    print(f"code {plot_script}")
    sys.exit(1)

print("\n" + "=" * 80)
print("GENERATING FINAL PLOTS")
print("=" * 80)

result = subprocess.run(
    [sys.executable, plot_script],
    check=False
)

if result.returncode != 0:
    print("\nERROR: Plot generation failed.")
    sys.exit(result.returncode)

print("\n" + "=" * 80)
print("SAFE WORKFLOW COMPLETED")
print("=" * 80)

print("\nCheck:")
print("results/plots/")