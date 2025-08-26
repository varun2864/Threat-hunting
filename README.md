# Hybrid Network Threat Hunter  

This project implements a real-time threat hunting system that captures and analyzes raw network traffic. It extracts structured features from packets and applies both rule-based detection and machine learning to identify anomalies, with a primary focus on SYN flood attacks. Detected threats trigger automated countermeasures, such as blocking malicious IPs in real time.  

## Current Capabilities  
- **Packet Capture**: Sniffs and logs live network traffic.  
- **Feature Extraction**: Records IPs, ports, packet size, protocol, and TCP flags.  
- **Rule-Based Detection**: Identifies SYN flood patterns using thresholds and ratios.  
- **Machine Learning Mode**: Optionally integrates a trained ML model for anomaly detection.  
- **Automated Countermeasures**: Blocks and later unblocks malicious IPs using firewall rules.  
- **CSV Logging**: Maintains structured logs for further analysis and model training.  

## Future Plans  
- **Extended Attack Detection**: Expand detection beyond SYN floods to cover other network threats.  
- **Improved ML Models**: Train and integrate advanced algorithms for higher accuracy.  
- **Adaptive Learning**: Periodically retrain models on new traffic data.  
- **Enhanced Telemetry**: Provide richer reporting and real-time dashboards.  
