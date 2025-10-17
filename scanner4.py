# Features: CSV logging, ML mode with flow tracking, SYN flood, ICMP flood, Port scan, block/unblock

import scapy.all as scapy
import time
import joblib
import subprocess
import csv
import numpy as np
from collections import defaultdict
from datetime import datetime
from threading import Thread


INTERFACE = "wlan0"
USE_ML = False
MODEL_PATH = "model_top20.joblib"
LOG_FILE = "log.csv"

MONITOR_WINDOW = 5
SYN_THRESHOLD = 10
BLOCK_DURATION = 15
THRESHOLD_ICMP = 50
THRESHOLD_PORTSCAN = 20

FLOW_TIMEOUT = 120  # flows inactive for 2 minutes are expired


syn_counts = defaultdict(int)
first_seen = {}
blocked_ips = {}
icmp_counter = defaultdict(int)
portscan_tracker = defaultdict(set)

ml_model = joblib.load(MODEL_PATH) if USE_ML else None


# Flow tracking for ML
class Flow:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        
        self.start_time = time.time()
        self.last_seen = time.time()
        
        self.fwd_packets = []
        self.bwd_packets = []
        
        self.fwd_header_lengths = []
        self.bwd_header_lengths = []
        
        self.init_win_bytes = None
        
    def add_packet(self, pkt, direction='fwd'):
        self.last_seen = time.time()
        pkt_len = len(pkt)
        
        if direction == 'fwd':
            self.fwd_packets.append((time.time(), pkt_len))
            if scapy.IP in pkt:
                self.fwd_header_lengths.append(pkt[scapy.IP].ihl * 4)
            if self.init_win_bytes is None and scapy.TCP in pkt and pkt[scapy.TCP].flags & 0x02:
                self.init_win_bytes = pkt[scapy.TCP].window
        else:
            self.bwd_packets.append((time.time(), pkt_len))
            if scapy.IP in pkt:
                self.bwd_header_lengths.append(pkt[scapy.IP].ihl * 4)
    
    def calculate_features(self):
        features = {}
        
        # Flow duration
        duration = (self.last_seen - self.start_time) * 1000000  # microseconds
        features['Flow Duration'] = duration if duration > 0 else 1
        
        # Fwd packet lengths
        fwd_lengths = [pkt[1] for pkt in self.fwd_packets]
        features['Fwd Packets Length Total'] = sum(fwd_lengths) if fwd_lengths else 0
        features['Fwd Packet Length Max'] = max(fwd_lengths) if fwd_lengths else 0
        features['Fwd Packet Length Mean'] = np.mean(fwd_lengths) if fwd_lengths else 0
        features['Avg Fwd Segment Size'] = np.mean(fwd_lengths) if fwd_lengths else 0
        features['Fwd Seg Size Min'] = min(fwd_lengths) if fwd_lengths else 0
        
        # Bwd packet lengths
        bwd_lengths = [pkt[1] for pkt in self.bwd_packets]
        features['Bwd Packet Length Mean'] = np.mean(bwd_lengths) if bwd_lengths else 0
        features['Bwd Packet Length Std'] = np.std(bwd_lengths) if bwd_lengths else 0
        features['Avg Bwd Segment Size'] = np.mean(bwd_lengths) if bwd_lengths else 0
        
        # Header lengths
        features['Fwd Header Length'] = sum(self.fwd_header_lengths) if self.fwd_header_lengths else 0
        
        # Subflow
        features['Subflow Fwd Bytes'] = sum(fwd_lengths) if fwd_lengths else 0
        
        # TCP window
        features['Init Fwd Win Bytes'] = self.init_win_bytes if self.init_win_bytes else 0
        
        # Packets/s
        duration_sec = (self.last_seen - self.start_time)
        if duration_sec > 0:
            features['Flow Packets/s'] = (len(self.fwd_packets) + len(self.bwd_packets)) / duration_sec
            features['Fwd Packets/s'] = len(self.fwd_packets) / duration_sec
        else:
            features['Flow Packets/s'] = 0
            features['Fwd Packets/s'] = 0
        
        # IAT (Inter-Arrival Time) calculations
        fwd_iats = [self.fwd_packets[i][0] - self.fwd_packets[i-1][0] 
                    for i in range(1, len(self.fwd_packets))] if len(self.fwd_packets) > 1 else [0]
        
        all_packets = sorted(self.fwd_packets + self.bwd_packets, key=lambda x: x[0])
        flow_iats = [all_packets[i][0] - all_packets[i-1][0] 
                     for i in range(1, len(all_packets))] if len(all_packets) > 1 else [0]
        
        features['Fwd IAT Total'] = sum(fwd_iats) * 1000000 if fwd_iats else 0
        features['Fwd IAT Min'] = min(fwd_iats) * 1000000 if fwd_iats else 0
        features['Fwd IAT Max'] = max(fwd_iats) * 1000000 if fwd_iats else 0
        
        features['Flow IAT Mean'] = np.mean(flow_iats) * 1000000 if flow_iats else 0
        features['Flow IAT Min'] = min(flow_iats) * 1000000 if flow_iats else 0
        features['Flow IAT Max'] = max(flow_iats) * 1000000 if flow_iats else 0
        
        return features


flows = {}

def get_flow_key(src_ip, dst_ip, src_port, dst_port, protocol):
    return (src_ip, dst_ip, src_port, dst_port, protocol)

def get_or_create_flow(pkt):
    if not pkt.haslayer(scapy.IP):
        return None
    
    src_ip = pkt[scapy.IP].src
    dst_ip = pkt[scapy.IP].dst
    src_port = dst_port = 0
    protocol = pkt[scapy.IP].proto
    
    if scapy.TCP in pkt:
        src_port = pkt[scapy.TCP].sport
        dst_port = pkt[scapy.TCP].dport
    elif scapy.UDP in pkt:
        src_port = pkt[scapy.UDP].sport
        dst_port = pkt[scapy.UDP].dport
    
    fwd_key = get_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
    bwd_key = get_flow_key(dst_ip, src_ip, dst_port, src_port, protocol)
    
    if fwd_key in flows:
        flows[fwd_key].add_packet(pkt, 'fwd')
        return flows[fwd_key]
    elif bwd_key in flows:
        flows[bwd_key].add_packet(pkt, 'bwd')
        return flows[bwd_key]
    else:
        flows[fwd_key] = Flow(src_ip, dst_ip, src_port, dst_port, protocol)
        flows[fwd_key].add_packet(pkt, 'fwd')
        return flows[fwd_key]


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

    # Rule-based detection (always active)
    if pkt.haslayer(scapy.TCP):
        #label = detect_syn(src, features[-1])
        portscan_tracker[src].add(pkt[scapy.TCP].dport)
    if pkt.haslayer(scapy.ICMP) and pkt[scapy.ICMP].type == 8:
        icmp_counter[src] += 1

    # ML-based detection (if enabled)
    if USE_ML and ml_model:
        flow = get_or_create_flow(pkt)
        if flow and (len(flow.fwd_packets) + len(flow.bwd_packets)) >= 10:  # Wait for 10 packets
            flow_features = flow.calculate_features()
            
            # Order features as model expects
            feature_order = [
                'Init Fwd Win Bytes', 'Fwd Header Length', 'Fwd Seg Size Min',
                'Fwd Packets Length Total', 'Fwd Packet Length Max', 'Subflow Fwd Bytes',
                'Fwd Packet Length Mean', 'Bwd Packet Length Mean', 'Fwd IAT Total',
                'Fwd Packets/s', 'Flow IAT Mean', 'Bwd Packet Length Std',
                'Flow IAT Min', 'Fwd IAT Min', 'Flow Packets/s', 'Flow IAT Max',
                'Flow Duration', 'Avg Fwd Segment Size', 'Fwd IAT Max', 'Avg Bwd Segment Size'
            ]
            
            feature_vector = [flow_features.get(f, 0) for f in feature_order]
            prediction = ml_model.predict([feature_vector])[0]
            
            if prediction != "Benign":
                label = prediction
                print(f"[ML DETECTED] {label} from {src}")
                block_ip(src, "ML_DETECTION", f"Type={label}")

    log_packet(src, dst, features, label)

def monitor():
    while True:
        time.sleep(5)
        
        # Clean up old flows
        now = time.time()
        expired_flows = [k for k, v in flows.items() if now - v.last_seen > FLOW_TIMEOUT]
        for k in expired_flows:
            del flows[k]
        
        # Rule-based monitoring
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
    print(f"[*] ML mode: {'ENABLED' if USE_ML else 'DISABLED'}")
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
