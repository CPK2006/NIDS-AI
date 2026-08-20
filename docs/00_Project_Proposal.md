# Project Proposal

## 1. Project Title

AI-Based Network Intrusion Detection System (NIDS)

## 2. Introduction

Network security is an important aspect of modern computing systems because network infrastructure is continuously exposed to malicious activities. An Intrusion Detection System (IDS) monitors network activity and identifies suspicious or malicious behavior.

This project proposes the development of a machine-learning-based Network Intrusion Detection System capable of identifying malicious network traffic and classifying different types of network attacks.

The system will use the CICIDS2017 dataset and evaluate six machine learning algorithms that are outside the primary algorithms covered in the team's ML syllabus.

## 3. Aim

The main aim of the project is to develop and evaluate an AI-based Network Intrusion Detection System capable of detecting malicious network traffic and identifying different attack categories.

## 4. Objectives

The project objectives are:

1. Obtain and analyze the CICIDS2017 network traffic dataset.
2. Develop a reliable data preprocessing pipeline.
3. Perform exploratory analysis of network traffic.
4. Prepare features for machine learning.
5. Develop binary intrusion detection.
6. Develop multiclass intrusion classification.
7. Implement anomaly detection.
8. Train six selected machine learning algorithms.
9. Compare their performance using multiple evaluation metrics.
10. Develop a prediction interface for the final system.
11. Document the complete development and evaluation process.

## 5. Algorithms

The project will evaluate the following six algorithms:

### Supervised Learning

1. LightGBM
2. CatBoost
3. Extra Trees Classifier
4. Histogram Gradient Boosting
5. Passive Aggressive Classifier

### Anomaly Detection

6. Isolation Forest

These algorithms were selected because they are outside the primary machine learning algorithms covered in the team's syllabus and provide different approaches to network intrusion detection.

## 6. Dataset

The project will use the CICIDS2017 dataset developed by the Canadian Institute for Cybersecurity.

The dataset contains approximately 2.83 million network-flow records with 78 traffic features and one label column.

The dataset contains both benign traffic and multiple attack categories.

## 7. Scope

### 7.1 Included in Scope

The project will include:

- CICIDS2017 dataset analysis
- Data cleaning
- Missing and infinite value handling
- Duplicate analysis
- Feature analysis
- Exploratory data analysis
- Label processing
- Binary classification
- Multiclass classification
- Anomaly detection
- Training of six machine learning algorithms
- Model evaluation
- Model comparison
- Prediction functionality
- Visualization of results
- Web-based prediction interface
- Project documentation

### 7.2 Outside Scope

The following are outside the scope of the current project:

- Live enterprise network deployment
- Real-time packet capture from production networks
- Automated attack prevention
- Automated firewall configuration
- Automated blocking of attackers
- Deep packet inspection
- Distributed production deployment
- Enterprise-scale security monitoring

## 8. System Workflow

The proposed system will follow this workflow:

CICIDS2017 Dataset
        ↓
Data Verification
        ↓
Data Cleaning
        ↓
Exploratory Data Analysis
        ↓
Feature Processing
        ↓
Train/Test Split
        ↓
Model Training
        ↓
Model Evaluation
        ↓
Model Comparison
        ↓
Best Model Selection
        ↓
Prediction System
        ↓
Web Interface

## 9. Expected Deliverables

The project will produce:

1. Complete source code.
2. Dataset verification and preprocessing pipeline.
3. Exploratory data analysis.
4. Six trained machine learning approaches.
5. Binary classification results.
6. Multiclass classification results.
7. Anomaly detection results.
8. Model performance comparison.
9. Evaluation visualizations.
10. Prediction interface.
11. Technical documentation.
12. Final project report.

## 10. Expected Benefits

The project will demonstrate the practical application of machine learning to cybersecurity.

It will provide:

- Automated network traffic classification.
- Detection of malicious network activity.
- Comparison of different machine learning approaches.
- Anomaly detection capability.
- A reproducible machine learning pipeline.
- A foundation for future real-time NIDS development.

## 11. Future Enhancements

Possible future improvements include:

- Real-time network packet capture.
- Streaming-based intrusion detection.
- Online model updating.
- Deployment on cloud infrastructure.
- Integration with firewall systems.
- Automated alert generation.
- Real-time dashboards.
- Detection of previously unseen attacks.