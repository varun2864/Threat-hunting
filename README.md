# Hybrid Network Threat Hunter  

A real-time threat hunting system that captures and analyzes raw traffic, extracts structured features, and detects anomalies using both rule-based thresholds and machine learning. Rule-based detection focuses on SYN floods, ICMP floods, and port scans, with automated countermeasures like real-time IP blocking, with machine learning being used for more complex patterns.

## Current Capabilities  
- **Packet Capture**: Sniffs and logs live network traffic.  
- **Feature Extraction**: Records IPs, ports, packet size, protocol, and TCP flags.  
- **Rule-Based Detection**: Detects SYN floods, ICMP floods, and port scans.
- **Machine Learning Mode**: Optionally integrates a trained ML model for anomaly detection.  
- **Automated Countermeasures**: Blocks and later unblocks malicious IPs using firewall rules.  
- **CSV Logging**: Maintains structured logs for further analysis and model training.  

## Machine Learning Model
- **Model**: Random Forest Classifier

- **Training Data**: CIC-IDS2018 dataset

- **Approach**: The model was trained on the entire dataset to handle a full range of network flow features. This provides a robust alternative to simple rule-based detection for complex, non-signature-based attacks.

- **Performance**: Achieved an overall accuracy of 98% on the test set. The model shows high precision and recall on common attack types but a lower performance on rare, imbalanced classes like FTP-Bruteforce and SQL Injection.

## Future Plans  
- **Adaptive Learning**: Periodically retrain models on new traffic data.
- **Enhanced Telemetry**: Provide richer reporting and real-time dashboards.
- **User Interface**: Provide user-friendly UI for ease of use.
