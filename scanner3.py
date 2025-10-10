# Features: CSV logging, ML mode, SYN flood, ICMP flood, Port scan, block/unblock

import scapy.all as scapy
import time
import joblib
import subprocess
import csv
from collections import defaultdict
from datetime import datetime
from threading import Thread


INTERFACE = "enp2s0"
USE_ML = False
MODEL_PATH = "model.joblib"
LOG_FILE = "log.csv"

MONITOR_WINDOW = 5
SYN_THRESHOLD = 10
BLOCK_DURATION = 15
THRESHOLD_ICMP = 50
THRESHOLD_PORTSCAN = 20


syn_counts = defaultdict(int)
first_seen = {}
blocked_ips = {}
icmp_counter = defaultdict(int)
portscan_tracker = defaultdict(set)

ml_model = joblib.load(MODEL_PATH) if USE_ML else None


def log_packet(src_ip, dest_ip, features, label="benign"):
    with open(LOG_FILE, "a", newline="") as f:
        row = [datetime.now().isoformat(), src_ip, dest_ip] + features + [label]
        csv.writer(f).writerow(row)


def block_ip(ip, reason="unknown", metrics=""):
    if ip not in blocked_ips:
        print(f"[!] Blocking {ip} | Reason: {reason} | {metrics}")
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
        
        if syn_counts[ip] >= SYN_THRESHOLD:
            block_ip(ip, "SYN_FLOOD", f"SYN={syn_counts[ip]}")
            syn_counts[ip] = 0
            first_seen[ip] = now
            return "syn_flood"
    return "benign"


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
            block_ip(src, "ML_DETECTION", f"Type={label}")
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
                block_ip(ip, "ICMP_FLOOD", f"Packets={count}")
            icmp_counter[ip] = 0
        for ip, ports in list(portscan_tracker.items()):
            if len(ports) > THRESHOLD_PORTSCAN:
                block_ip(ip, "PORT_SCAN", f"Ports={len(ports)}")
            portscan_tracker[ip].clear()


if __name__ == "__main__":
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
