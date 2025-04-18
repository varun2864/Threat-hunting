# Threat-hunting
using trained ML to identify anomalies in enterprise network traffic and deploy countermeasures

# Adaptive Threat Hunting Using Federated Machine Learning

This repository contains the implementation of a real-time adaptive threat hunting system. The system uses a custom-built network data collection tool and applies federated machine learning to detect anomalies and intrusions efficiently while preserving data privacy.

# Project Overview

The goal of this project is to move beyond traditional centralized approaches for network intrusion detection. Instead, it leverages federated learning and a custom raw packet analysis tool to:

-Maintain data privacy by keeping training data local.

-Eliminate the need for third-party tools like Zeek by generating datasets through a purpose-built collection tool.

-Periodically retrain the detection model to adapt to evolving network threats.

# Features

-Raw Network Packet Capture: Collects Ethernet frames using raw sockets directly from the network interface.

-Feature Extraction: Extracts structured features such as source/destination IP and MAC addresses, packet size, and protocol type.

-Federated Learning: Distributes model training across nodes using TensorFlow and Scikit-Learn, allowing local model updates without centralizing raw data.

-Model Evaluation: Compares multiple algorithms and selects the highest-performing model for deployment.

-Adaptive Retraining: Regular model updates improve accuracy over time as new data is collected.

#Technologies Used

-Python 3

-TensorFlow (federated learning)

-Scikit-Learn

-Linux raw socket programming

-CSV for storing structured network logs
