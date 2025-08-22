# hybridscanner.py
import scapy.all as scapy
import time
import joblib
from collections import defaultdict
from datetime import datetime
import os
import csv

#initial configuration
INTERFACE = None
USE_ML = False
MODEL_PATH = "model.joblib"
FEATURE_ORDER = ["timestamp", "src_ip", "dest_ip", "src_port", "dest_port", "packet_size", "protocol", "tcp_flags", "label"]

# Rule-based SYN flood parameters
MONITOR_WINDOW = 5
SYN_THRESHOLD = 10 
ACK_RATIO_LIMIT = 0.2
BLOCK_DURATION = 60

# global variables
syn_counts = defaultdict(int)
handshakes = defaultdict(lambda: {"syn": 0, "ack": 0})
first_seen = {}
blocked_ips = {}
ml_model = None

LOG_FILE = "packet_log.csv"

#check for ML mode 
if USE_ML:
    ml_model = joblib.load(MODEL_PATH)


def init_csv(): # Initialize CSV file for logging
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, mode="w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(FEATURE_ORDER)


def log_packet_to_csv(src_ip, dest_ip, features, label="benign"): # appends packet data to the CSV log file
    with open(LOG_FILE, mode="a", newline="") as f:
        writer = csv.writer(f)
        row = [datetime.now().isoformat(), src_ip, dest_ip] + features + [label]
        writer.writerow(row)

## block and unblock IPs

def block_ip(ip): # blocks an IP address based on SYN flood detection
    if ip not in blocked_ips:
        print(f"[!] Blocking IP: {ip}")
        import subprocess
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        blocked_ips[ip] = datetime.now()

def unblock_expired_ips(): # unblocks IPs that have been blocked for more than 60 seconds
    now = datetime.now()
    expired = [ip for ip, t in blocked_ips.items() if (now - t).seconds > BLOCK_DURATION]
    for ip in expired:
        print(f"[+] Unblocking IP: {ip}")
        import subprocess
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
        del blocked_ips[ip]


# This function extracts features from the packet
# It returns a list of features including source port, destination port, packet size, protocol type
# and TCP flags. 
def extract_features(packet):
    src_port = None
    dest_port = None
    protocol = None
    tcp_flags = 0

    if scapy.TCP in packet:
        src_port = packet[scapy.TCP].sport
        dest_port = packet[scapy.TCP].dport
        tcp_flags = packet[scapy.TCP].flags
        protocol = 6  # TCP
    elif scapy.UDP in packet:
        src_port = packet[scapy.UDP].sport
        dest_port = packet[scapy.UDP].dport
        protocol = 17  # UDP
    elif scapy.ICMP in packet:
        protocol = 1  # ICMP

    packet_size = len(packet)

    return [src_port or 0, dest_port or 0, packet_size, protocol or 0, int(tcp_flags)]

# Packet handler function
# This function processes each captured packet
# it extracts features, applies rule-based detection, and logs the packet.
def packet_handler(packet):
    if scapy.IP in packet:
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        features = extract_features(packet)

        label = "benign"

        if USE_ML and ml_model:
            prediction = ml_model.predict([features])[0]
            label = prediction
            if prediction != "benign":
                print(f"[ML DETECTED] {prediction} from {ip_src}")
                block_ip(ip_src)
        else:
            if scapy.TCP in packet:
                label = rule_based_detection(ip_src, packet[scapy.TCP].flags)

        log_packet_to_csv(ip_src, ip_dst, features, label)


# Rule-based detection function
# This function implements a simple SYN flood detection mechanism
# It counts SYN packets and checks if the ratio of SYN to ACK packets exceeds a threshold.
# If it does, it blocks the source IP address.
def rule_based_detection(ip_src, tcp_flags):
    """Simple SYN flood detection."""
    now = time.time()

    if tcp_flags == "S":
        if ip_src not in first_seen:
            first_seen[ip_src] = now
            syn_counts[ip_src] = 1
        else:
            if now - first_seen[ip_src] <= MONITOR_WINDOW:
                syn_counts[ip_src] += 1
            else:
                first_seen[ip_src] = now
                syn_counts[ip_src] = 1
        handshakes[ip_src]["syn"] += 1

    elif "A" in tcp_flags:
        handshakes[ip_src]["ack"] += 1

    syns = handshakes[ip_src]["syn"]
    acks = handshakes[ip_src]["ack"]
    if syn_counts[ip_src] >= SYN_THRESHOLD and acks < syns * ACK_RATIO_LIMIT:
        block_ip(ip_src)
        return "syn_flood"
    return "benign"


#main 

init_csv()
print("Starting sniffer...")
sniffer = scapy.AsyncSniffer(iface=INTERFACE, prn=packet_handler, store=False)
sniffer.start()

try:
    while True:
        time.sleep(1)
        unblock_expired_ips()
except KeyboardInterrupt:
    print("\nStopping...")
    sniffer.stop()
