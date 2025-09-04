# simplified unified scanner with all features
# Features: CSV logging, ML mode, SYN flood (handshake-based), ICMP flood, Port scan, block/unblock

import scapy.all as scapy
import time
import joblib
import subprocess
import os
import csv
from collections import defaultdict
from datetime import datetime
from threading import Thread

# ==============================
# CONFIG
# ==============================
INTERFACE = "enp0s3"   # change if needed
USE_ML = False
MODEL_PATH = "model.joblib"
LOG_FILE = "packet_log.csv"

FEATURE_ORDER = ["timestamp", "src_ip", "dest_ip", "src_port", "dest_port",
                 "packet_size", "protocol", "tcp_flags_str", "label"]

# Thresholds
MONITOR_WINDOW = 5
SYN_THRESHOLD = 10
ACK_RATIO_LIMIT = 0.2
BLOCK_DURATION = 60
THRESHOLD_ICMP = 50
THRESHOLD_PORTSCAN = 20

# ==============================
# STATE
# ==============================
syn_counts = defaultdict(int)
handshakes = defaultdict(lambda: {"syn": 0, "ack": 0})
first_seen = {}
blocked_ips = {}

icmp_counter = defaultdict(int)
portscan_tracker = defaultdict(set)

ml_model = joblib.load(MODEL_PATH) if USE_ML else None

# ==============================
# LOGGING
# ==============================
def init_csv():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as f:
            csv.writer(f).writerow(FEATURE_ORDER)

def log_packet(src_ip, dest_ip, features, label="benign"):
    with open(LOG_FILE, "a", newline="") as f:
        row = [datetime.now().isoformat(), src_ip, dest_ip] + features + [label]
        csv.writer(f).writerow(row)

# ==============================
# BLOCKING
# ==============================
def block_ip(ip):
    if ip not in blocked_ips:
        print(f"[!] Blocking {ip}")
        try:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            blocked_ips[ip] = datetime.now()
        except Exception as e:
            print(f"iptables error: {e}")

def unblock_expired_ips():
    now = datetime.now()
    expired = [ip for ip, t in blocked_ips.items() if (now - t).seconds > BLOCK_DURATION]
    for ip in expired:
        print(f"[!] Unblocking {ip}")
        try:
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            del blocked_ips[ip]
        except Exception as e:
            print(f"iptables error: {e}")

# ==============================
# DETECTION
# ==============================
def extract_features(pkt):
    src_port = dest_port = 0
    protocol, tcp_flags = 0, ""

    if scapy.TCP in pkt:
        src_port, dest_port = pkt[scapy.TCP].sport, pkt[scapy.TCP].dport
        tcp_flags = pkt[scapy.TCP].sprintf("%TCP.flags%")
        protocol = 6
    elif scapy.UDP in pkt:
        src_port, dest_port = pkt[scapy.UDP].sport, pkt[scapy.UDP].dport
        protocol = 17
    elif scapy.ICMP in pkt:
        protocol = 1

    return [src_port, dest_port, len(pkt), protocol, tcp_flags]

def detect_syn(ip, flags):
    now = time.time()
    if "S" in flags:
        if now - first_seen.get(ip, 0) > MONITOR_WINDOW:
            first_seen[ip] = now
            syn_counts[ip] = 0
        syn_counts[ip] += 1
        handshakes[ip]["syn"] += 1
    if "A" in flags:
        handshakes[ip]["ack"] += 1

    syns, acks = handshakes[ip]["syn"], handshakes[ip]["ack"]
    if syn_counts[ip] >= SYN_THRESHOLD and acks < syns * ACK_RATIO_LIMIT:
        block_ip(ip)
        return "syn_flood"
    return "benign"

# ==============================
# HANDLERS
# ==============================
def packet_handler(pkt):
    if not pkt.haslayer(scapy.IP):
        return
    src, dst = pkt[scapy.IP].src, pkt[scapy.IP].dst
    features = extract_features(pkt)
    label = "benign"

    if USE_ML and ml_model:
        label = ml_model.predict([features])[0]
        if label != "benign":
            print(f"[ML DETECTED] {label} from {src}")
            block_ip(src)
    else:
        if pkt.haslayer(scapy.TCP):
            label = detect_syn(src, features[-1])
            portscan_tracker[src].add(pkt[scapy.TCP].dport)
        if pkt.haslayer(scapy.ICMP) and pkt[scapy.ICMP].type == 8:
            icmp_counter[src] += 1

    log_packet(src, dst, features, label)

def monitor():
    while True:
        time.sleep(5)
        for ip, count in list(icmp_counter.items()):
            if count > THRESHOLD_ICMP:
                print(f"[!] ICMP Flood from {ip} ({count} packets)")
                block_ip(ip)
            icmp_counter[ip] = 0
        for ip, ports in list(portscan_tracker.items()):
            if len(ports) > THRESHOLD_PORTSCAN:
                print(f"[!] Port Scan from {ip} ({len(ports)} ports)")
                block_ip(ip)
            portscan_tracker[ip].clear()

# ==============================
# MAIN
# ==============================
if __name__ == "__main__":
    init_csv()
    print("[*] Scanner started...")
    Thread(target=monitor, daemon=True).start()
    sniffer = scapy.AsyncSniffer(iface=INTERFACE, prn=packet_handler, store=False)
    sniffer.start()
    try:
        while True:
            time.sleep(1)
            unblock_expired_ips()
    except KeyboardInterrupt:
        print("\n[!] Stopping...")
        sniffer.stop()
