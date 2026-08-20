# Problem Statement

## Title

AI-Based Network Intrusion Detection System (NIDS)

## Background

Computer networks are continuously exposed to various security threats, including denial-of-service attacks, scanning activities, brute-force attacks, botnet activity, web-based attacks, and other malicious behavior.

Traditional intrusion detection systems commonly depend on predefined signatures or rules. Although signature-based detection can effectively identify known attacks, it may have difficulty identifying previously unseen or evolving attack patterns.

Machine learning provides an alternative approach by learning patterns from network traffic and identifying traffic that differs from normal behavior.

## Problem

The objective of this project is to develop a machine-learning-based Network Intrusion Detection System that can analyze network traffic and identify malicious activity.

The system will use the CICIDS2017 dataset, which contains labeled network-flow records representing benign and multiple types of malicious traffic.

The project will evaluate six machine learning algorithms that are outside the primary algorithms covered in the team's ML syllabus:

1. LightGBM
2. CatBoost
3. Extra Trees Classifier
4. Histogram Gradient Boosting
5. Passive Aggressive Classifier
6. Isolation Forest

The system will investigate both supervised intrusion classification and anomaly detection.

## Proposed Solution

The proposed system will process network-flow data through a structured machine learning pipeline:

Network Traffic Dataset
        ↓
Data Verification
        ↓
Data Cleaning
        ↓
Feature Processing
        ↓
Exploratory Data Analysis
        ↓
Train/Test Data
        ↓
Machine Learning Models
        ↓
Model Evaluation
        ↓
Prediction
        ↓
NIDS Interface

The first five algorithms will be used for supervised classification, while Isolation Forest will be investigated as an anomaly detection approach.

## Detection Objectives

The system will perform two primary detection tasks.

### Binary Intrusion Detection

Determine whether a network flow is:

- BENIGN
- ATTACK

### Multiclass Intrusion Detection

Determine the category of the network traffic, such as:

- BENIGN
- DoS
- DDoS
- PortScan
- Bot
- Brute Force
- Web Attack
- Infiltration
- Other applicable attack categories

The exact multiclass grouping will be finalized after exploratory data analysis and preprocessing.

## Expected Outcome

The project is expected to produce a working NIDS that:

- Detects malicious network traffic.
- Classifies different attack categories.
- Detects anomalous network behavior.
- Compares six machine learning algorithms.
- Identifies the most suitable model for the intended detection task.
- Provides quantitative evaluation using standard machine learning metrics.
- Provides a user-facing prediction interface.

## Project Significance

The project demonstrates how machine learning can be applied to cybersecurity and network traffic analysis.

It also provides a comparison between several modern machine learning approaches and an anomaly detection technique, allowing the strengths and limitations of different algorithms to be studied in the context of intrusion detection.