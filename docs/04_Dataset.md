# Dataset

## Dataset Name

CICIDS2017 (Canadian Institute for Cybersecurity Intrusion Detection System 2017)

## Purpose

CICIDS2017 is used as the primary network traffic dataset for the Network Intrusion Detection System (NIDS).

The dataset contains labeled network-flow records representing both benign and malicious network traffic.

## Dataset Structure

The downloaded Machine Learning CSV dataset contains:

- 8 CSV files
- 79 columns per file
- 78 network traffic features
- 1 target/label column
- Approximately 2.83 million total records

The label column is named:

`Label`

The original CSV files contain leading spaces in several column names. These will be cleaned during preprocessing.

## Traffic Classes

### Benign

- BENIGN

### Attack Classes

- DDoS
- PortScan
- Bot
- Infiltration
- FTP-Patator
- SSH-Patator
- DoS Hulk
- DoS GoldenEye
- DoS slowloris
- DoS Slowhttptest
- Heartbleed
- Web Attack - Brute Force
- Web Attack - XSS
- Web Attack - Sql Injection

## Dataset Files

The following files are stored locally under `data/raw/`:

1. Monday-WorkingHours.pcap_ISCX.csv
2. Tuesday-WorkingHours.pcap_ISCX.csv
3. Wednesday-workingHours.pcap_ISCX.csv
4. Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
5. Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
6. Friday-WorkingHours-Morning.pcap_ISCX.csv
7. Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
8. Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv

## Dataset Distribution

The dataset is highly imbalanced.

Examples of high-frequency classes include:

- BENIGN
- DoS Hulk
- PortScan
- DDoS

Examples of low-frequency classes include:

- Infiltration
- Heartbleed
- Web Attack - Sql Injection

Class imbalance will therefore be considered during preprocessing, training, and evaluation.

## Data Integrity

The original files under `data/raw/` will not be modified.

All cleaning, transformation, feature selection, and label processing will be performed on copies of the data and stored under `data/processed/`.

## NIDS Tasks

Two classification tasks will be investigated:

### Binary Classification

Traffic will be classified as:

- BENIGN
- ATTACK

### Multiclass Classification

The original attack categories will be retained or appropriately grouped after exploratory data analysis.

## Algorithms

The project will evaluate six machine learning algorithms that are outside the algorithms covered in the project team's primary ML syllabus:

1. LightGBM
2. CatBoost
3. Extra Trees
4. Histogram Gradient Boosting
5. Passive Aggressive
6. Isolation Forest

The first five algorithms will be evaluated as supervised classifiers.

Isolation Forest will be evaluated separately as an anomaly detection approach.

## Data Processing Principles

The preprocessing pipeline will include, where required:

- Column name normalization
- Missing-value handling
- Infinite-value handling
- Duplicate detection
- Feature validation
- Label normalization
- Feature scaling where required by the algorithm
- Train/test splitting
- Class distribution analysis

Raw data will remain unchanged throughout the project.

---

## Data Quality Assessment

An initial quality inspection was performed on all eight raw CICIDS2017 CSV files.

### Missing Values

Missing values were found only in the `Flow Bytes/s` feature.

The missing values will be handled during preprocessing rather than modifying the raw dataset.

### Infinite Values

Infinite values were found in:

- `Flow Bytes/s`
- `Flow Packets/s`

These values are caused by network-flow rate calculations and will be converted to missing values during preprocessing.

### Duplicate Records

Exact duplicate records were found in several files. Some files contain a substantial number of duplicates.

Duplicate records will be removed during preprocessing to reduce the possibility of data leakage and artificially inflated model performance.

### Data Types

The dataset contains:

- 54 integer features
- 24 floating-point features
- 1 string label column

No unexpected categorical feature columns were identified during the initial inspection.

## Cleaning Strategy

The preprocessing pipeline will:

1. Normalize column names by removing leading and trailing whitespace.
2. Normalize attack-label text.
3. Convert positive and negative infinite numerical values to missing values.
4. Handle missing numerical values using median imputation.
5. Remove exact duplicate records.
6. Preserve the original raw CSV files without modification.
7. Store cleaned datasets under `data/processed/`.

The cleaned data will be used for subsequent exploratory analysis and machine learning experiments.