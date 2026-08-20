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

---

## Exploratory Data Analysis — Class Distribution

An exploratory analysis was performed on the cleaned CICIDS2017 dataset.

The cleaned dataset contains:

**2,574,264 network-flow records**

### Overall Distribution

| Category | Records | Percentage |
|---|---:|---:|
| BENIGN | 2,148,386 | 83.4563% |
| ATTACK | 425,878 | 16.5437% |

The dataset is therefore imbalanced, with benign traffic representing approximately 83.46% of all records.

### Multiclass Distribution

| Label | Records | Percentage |
|---|---:|---:|
| BENIGN | 2,148,386 | 83.4563% |
| DoS Hulk | 172,849 | 6.7145% |
| DDoS | 128,016 | 4.9729% |
| PortScan | 90,819 | 3.5280% |
| DoS GoldenEye | 10,286 | 0.3996% |
| FTP-Patator | 5,933 | 0.2305% |
| DoS slowloris | 5,385 | 0.2092% |
| DoS Slowhttptest | 5,228 | 0.2031% |
| SSH-Patator | 3,219 | 0.1250% |
| Bot | 1,953 | 0.0759% |
| Web Attack - Brute Force | 1,470 | 0.0571% |
| Web Attack - XSS | 652 | 0.0253% |
| Infiltration | 36 | 0.0014% |
| Web Attack - Sql Injection | 21 | 0.0008% |
| Heartbleed | 11 | 0.0004% |

### EDA Observation

The dataset exhibits significant class imbalance.

The BENIGN class is dominant, while several attack categories contain very few observations. In particular, Infiltration, Web Attack - Sql Injection, and Heartbleed have extremely small sample sizes.

Therefore, accuracy alone will not be sufficient for evaluating the NIDS.

The project will emphasize:

- Precision
- Recall
- F1-score
- Confusion Matrix
- Per-class performance
- Macro-averaged metrics
- Weighted-averaged metrics
- ROC-AUC where applicable

Class imbalance will be considered during model development and evaluation. Appropriate techniques will be investigated rather than blindly applying oversampling to every model.

---

## Binary Classification Analysis

For the primary intrusion detection task, the original multiclass labels are converted into two categories:

- `BENIGN` → BENIGN
- All attack labels → ATTACK

### Binary Distribution

| Binary Class | Records | Percentage |
|---|---:|---:|
| BENIGN | 2,148,386 | 83.4563% |
| ATTACK | 425,878 | 16.5437% |
| **Total** | **2,574,264** | **100%** |

### Observation

The binary dataset is imbalanced, with benign traffic representing approximately 83.46% of all network flows and malicious traffic representing approximately 16.54%.

Therefore, model evaluation will not rely on accuracy alone.

The binary NIDS evaluation will primarily consider:

- Precision
- Recall
- F1-score
- Confusion Matrix
- ROC-AUC
- PR-AUC where appropriate

Particular attention will be given to **attack recall**, because failing to detect malicious traffic is more significant for an intrusion detection system than incorrectly classifying some benign traffic as malicious.

Class-weighting, sampling strategies, and model-specific imbalance handling will be investigated during the model-training phase.