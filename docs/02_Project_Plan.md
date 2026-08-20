# Project Plan

## 1. Project Title

AI-Based Network Intrusion Detection System (NIDS)

## 2. Project Overview

The project aims to develop a machine-learning-based Network Intrusion Detection System capable of analyzing network traffic and identifying malicious activities.

The system will use the CICIDS2017 network traffic dataset and evaluate six machine learning algorithms that are outside the primary ML syllabus.

The system will support both binary intrusion detection and multiclass attack classification.

## 3. Problem Statement

Traditional network intrusion detection systems often rely on predefined signatures to identify known attacks. Such systems may struggle to detect new or evolving attack patterns.

This project aims to develop a machine-learning-based NIDS that learns patterns from network traffic and detects both normal and malicious network activity.

## 4. Objectives

### Primary Objectives

1. Develop a machine-learning-based Network Intrusion Detection System.
2. Preprocess and analyze the CICIDS2017 network traffic dataset.
3. Detect benign and malicious network traffic.
4. Classify malicious traffic into different attack categories.
5. Compare the performance of six machine learning algorithms.
6. Identify the best-performing model for intrusion detection.
7. Develop a prediction interface for detecting network traffic.

### Secondary Objectives

1. Analyze class imbalance in network traffic.
2. Compare supervised classification with anomaly detection.
3. Evaluate models using multiple performance metrics.
4. Provide visualizations of model performance.
5. Maintain a reproducible machine learning pipeline.

## 5. Machine Learning Algorithms

The following six algorithms will be evaluated:

1. LightGBM
2. CatBoost
3. Extra Trees Classifier
4. Histogram Gradient Boosting
5. Passive Aggressive Classifier
6. Isolation Forest

### Supervised Models

The following models will be evaluated for supervised intrusion classification:

- LightGBM
- CatBoost
- Extra Trees Classifier
- Histogram Gradient Boosting
- Passive Aggressive Classifier

### Anomaly Detection

Isolation Forest will be evaluated separately as an anomaly detection model.

It will learn the characteristics of normal traffic and identify anomalous network activity.

## 6. Detection Tasks

### 6.1 Binary Classification

The system will determine whether network traffic is:

- BENIGN
- ATTACK

### 6.2 Multiclass Classification

The system will identify the specific category of network traffic.

The original CICIDS2017 attack labels will be analyzed and appropriately grouped during preprocessing.

## 7. Dataset

The primary dataset is CICIDS2017.

Dataset characteristics:

- 8 CSV files
- 2,830,743 network-flow records
- 79 columns
- 78 traffic features
- 1 label column

The dataset contains benign traffic and multiple attack categories.

Raw dataset files will not be modified.

## 8. Functional Requirements

### FR1 — Dataset Loading

The system shall load network traffic data from the processed CICIDS2017 dataset.

### FR2 — Data Preprocessing

The system shall:

- Clean column names.
- Handle missing values.
- Handle infinite values.
- Remove duplicate records where appropriate.
- Validate feature types.
- Encode target labels.
- Prepare features for machine learning.

### FR3 — Feature Processing

The system shall prepare network traffic features for the selected machine learning algorithms.

Where required, feature scaling shall be applied.

### FR4 — Model Training

The system shall train the six selected algorithms using the prepared dataset.

### FR5 — Binary Detection

The system shall classify network traffic as benign or malicious.

### FR6 — Multiclass Detection

The system shall classify network traffic into appropriate attack categories.

### FR7 — Anomaly Detection

The system shall use Isolation Forest to identify anomalous network traffic.

### FR8 — Model Evaluation

The system shall evaluate models using:

- Accuracy
- Precision
- Recall
- F1-score
- Confusion Matrix
- ROC-AUC where applicable

### FR9 — Model Comparison

The system shall compare the six algorithms based on predictive performance and computational performance.

### FR10 — Prediction

The system shall accept network traffic feature values and produce a prediction.

### FR11 — Results Visualization

The system shall provide visualizations such as:

- Confusion matrices
- Class distributions
- Model performance comparison
- ROC curves where applicable
- Feature importance where supported

### FR12 — Web Interface

The system shall provide a user interface through which a user can submit network traffic features and obtain an intrusion prediction.

## 9. Non-Functional Requirements

### Performance

The system should process large network traffic datasets efficiently.

### Reliability

The preprocessing and prediction pipelines should produce consistent results for the same input.

### Maintainability

The project shall use modular Python code organized into separate components.

### Reproducibility

Dataset processing, model training, and evaluation procedures should be reproducible.

### Usability

The prediction interface should be simple enough for a user to understand the result.

### Security

Sensitive credentials and environment variables shall not be stored in the repository.

## 10. Scope

### Included

- CICIDS2017 dataset
- Network traffic preprocessing
- Exploratory data analysis
- Feature processing
- Binary intrusion detection
- Multiclass intrusion classification
- Anomaly detection
- Six machine learning algorithms
- Model evaluation
- Model comparison
- Prediction system
- Web-based interface
- Documentation

### Not Included

- Real-time packet capture from production networks
- Deployment on enterprise network infrastructure
- Automated firewall configuration
- Automated attack response
- Packet-level deep packet inspection
- Production-scale distributed deployment

## 11. Expected Output

The completed system is expected to provide:

1. Cleaned network traffic datasets.
2. Trained machine learning models.
3. Performance comparison of six algorithms.
4. Binary intrusion predictions.
5. Multiclass attack predictions.
6. Anomaly detection results.
7. Evaluation visualizations.
8. A working prediction interface.
9. Complete project documentation.

## 12. Project Workflow

The overall workflow will be:

Dataset
    ↓
Data Verification
    ↓
Data Preprocessing
    ↓
Exploratory Data Analysis
    ↓
Feature Engineering
    ↓
Train/Test Split
    ↓
Model Training
    ↓
Model Evaluation
    ↓
Model Comparison
    ↓
Model Selection
    ↓
Prediction System
    ↓
Web Interface
    ↓
Testing
    ↓
Final Documentation

---

# 13. Development Phases and Sprints

The project will be developed incrementally using short, well-defined sprints.

Each sprint will produce a measurable deliverable. After completing a task or sprint, the responsible team member will commit and push the changes to GitHub so that the next team member can continue from the latest version.

## Phase 1 — Project Foundation

### Sprint 1.1 — Dataset Verification
- Select CICIDS2017 dataset.
- Download the ML CSV files.
- Store raw files under `data/raw/`.
- Verify the number of files.
- Verify columns and labels.
- Create the dataset verification script.
- Document the dataset.

**Status:** Completed

### Sprint 1.2 — Project Requirements
- Define the problem statement.
- Define project objectives.
- Define project scope.
- Define functional requirements.
- Define non-functional requirements.
- Define project deliverables.

**Status:** Completed

---

# Phase 2 — Data Preprocessing

## Sprint 2.1 — Data Cleaning

Tasks:

- Load all raw CSV files.
- Normalize column names.
- Remove duplicate records where appropriate.
- Detect missing values.
- Detect infinite values.
- Handle invalid numerical values.
- Normalize attack-label encoding.
- Save cleaned data to `data/processed/`.

**Deliverable:**

Cleaned and validated dataset.

## Sprint 2.2 — Exploratory Data Analysis

Tasks:

- Analyze dataset dimensions.
- Analyze class distributions.
- Visualize benign vs attack traffic.
- Analyze attack categories.
- Analyze feature distributions.
- Identify highly correlated features.
- Identify potentially redundant features.
- Analyze class imbalance.

**Deliverable:**

EDA notebook and visualizations.

## Sprint 2.3 — Feature Preparation

Tasks:

- Select useful features.
- Remove unsuitable features.
- Prepare target labels.
- Prepare binary target.
- Prepare multiclass target.
- Determine scaling requirements.
- Prepare train/test datasets.

**Deliverable:**

Model-ready datasets.

---

# Phase 3 — Machine Learning Models

## Sprint 3.1 — LightGBM

Tasks:

- Implement LightGBM.
- Train binary classifier.
- Train multiclass classifier.
- Generate predictions.
- Evaluate performance.
- Save trained model.

**Deliverable:**

LightGBM model and evaluation results.

## Sprint 3.2 — CatBoost

Tasks:

- Implement CatBoost.
- Train binary classifier.
- Train multiclass classifier.
- Generate predictions.
- Evaluate performance.
- Save trained model.

**Deliverable:**

CatBoost model and evaluation results.

## Sprint 3.3 — Extra Trees

Tasks:

- Implement Extra Trees.
- Train binary classifier.
- Train multiclass classifier.
- Generate predictions.
- Evaluate performance.
- Save trained model.

**Deliverable:**

Extra Trees model and evaluation results.

## Sprint 3.4 — Histogram Gradient Boosting

Tasks:

- Implement Histogram Gradient Boosting.
- Train binary classifier.
- Train multiclass classifier.
- Generate predictions.
- Evaluate performance.
- Save trained model.

**Deliverable:**

Histogram Gradient Boosting model and evaluation results.

## Sprint 3.5 — Passive Aggressive

Tasks:

- Implement Passive Aggressive classifier.
- Prepare scaled features.
- Train binary classifier.
- Train multiclass classifier.
- Generate predictions.
- Evaluate performance.
- Save trained model.

**Deliverable:**

Passive Aggressive model and evaluation results.

## Sprint 3.6 — Isolation Forest

Tasks:

- Prepare normal traffic for anomaly detection.
- Train Isolation Forest.
- Detect anomalous traffic.
- Map anomalies against known labels for evaluation.
- Evaluate anomaly detection performance.
- Save trained model.

**Deliverable:**

Isolation Forest model and evaluation results.

---

# Phase 4 — Model Evaluation and Comparison

## Sprint 4.1 — Evaluation

Evaluate the models using:

- Accuracy
- Precision
- Recall
- F1-score
- Confusion Matrix
- ROC-AUC where applicable

## Sprint 4.2 — Model Comparison

Compare:

- Detection performance
- Training time
- Prediction time
- Memory requirements
- Model complexity
- Handling of class imbalance
- Suitability for NIDS

**Deliverable:**

Complete model comparison report.

---

# Phase 5 — Prediction System

## Sprint 5.1 — Prediction Pipeline

Tasks:

- Load trained model.
- Load preprocessing configuration.
- Accept network traffic features.
- Apply identical preprocessing.
- Generate prediction.
- Return attack category and confidence where applicable.

**Deliverable:**

Reusable prediction pipeline.

## Sprint 5.2 — Web Application

Tasks:

- Develop prediction interface.
- Create input form.
- Display prediction.
- Display attack category.
- Display model information.
- Add basic result visualization.

**Deliverable:**

Working NIDS web interface.

---

# Phase 6 — Testing

## Sprint 6.1 — Unit Testing

Test:

- Data loading
- Preprocessing
- Feature processing
- Model loading
- Prediction
- API functionality

## Sprint 6.2 — Integration Testing

Verify:

```text
Input
 ↓
Preprocessing
 ↓
Model
 ↓
Prediction
 ↓
Interface