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