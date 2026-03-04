#!/usr/bin/env python3
"""
Lightweight Network IDS
Detects: Port scans, SSH brute force, suspicious DNS, SYN floods
"""

from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
from collections import defaultdict
from datetime import datetime, timedelta
import json
import csv
import os
import sys

# ──────────────────────────────────────────────
# CONFIGURATION — tweak thresholds here
# ──────────────────────────────────────────────
CONFIG = {
    "interface": "enp0s1",        # change to match your VM's interface (check with `ip a`)
    "port_scan_threshold": 10,    # unique ports from 1 IP in the time window = port scan
    "port_scan_window": 60,       # seconds
    "brute_force_threshold": 5,   # SYN packets to SSH port in time window
    "brute_force_window": 30,     # seconds
    "syn_flood_threshold": 100,   # SYN packets from 1 IP in time window
    "syn_flood_window": 10,       # seconds
    "suspicious_domains": [       # flag DNS queries containing these
        "evil", "malware", "c2", "botnet", "hack"
    ],
    "alert_log": "alerts.json",
    "alert_csv": "alerts.csv",
}

# ──────────────────────────────────────────────
# TRACKING STATE
# ──────────────────────────────────────────────
# port_scan_tracker[ip] = {port: timestamp, ...}
port_scan_tracker = defaultdict(dict)
# ssh_tracker[ip] = [timestamp, ...]
ssh_tracker = defaultdict(list)
# syn_tracker[ip] = [timestamp, ...]
syn_tracker = defaultdict(list)

alert_count = 0


def log_alert(alert_type, src_ip, details):
    """Log alert to JSON file, CSV, and print to console."""
    global alert_count
    alert_count += 1

    alert = {
        "id": alert_count,
        "timestamp": datetime.now().isoformat(),
        "type": alert_type,
        "source_ip": src_ip,
        "details": details
    }

    # Print to console with color
    colors = {
        "PORT_SCAN": "\033[93m",       # yellow
        "SSH_BRUTE_FORCE": "\033[91m",  # red
        "SYN_FLOOD": "\033[91m",        # red
        "SUSPICIOUS_DNS": "\033[95m",   # purple
    }
    reset = "\033[0m"
    color = colors.get(alert_type, "")
    print(f"\n{color}[ALERT #{alert_count}] {alert_type}{reset}")
    print(f"  Time:   {alert['timestamp']}")
    print(f"  Source: {src_ip}")
    print(f"  Detail: {details}")

    # Append to JSON log
    try:
        if os.path.exists(CONFIG["alert_log"]):
            with open(CONFIG["alert_log"], "r") as f:
                alerts = json.load(f)
        else:
            alerts = []
        alerts.append(alert)
        with open(CONFIG["alert_log"], "w") as f:
            json.dump(alerts, f, indent=2)
    except Exception as e:
        print(f"  [!] JSON write error: {e}")

    # Append to CSV
    csv_exists = os.path.exists(CONFIG["alert_csv"])
    with open(CONFIG["alert_csv"], "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["id", "timestamp", "type", "source_ip", "details"])
        if not csv_exists:
            writer.writeheader()
        writer.writerow(alert)


def clean_old_entries(tracker_dict, window_seconds):
    """Remove entries older than the window from a defaultdict(list)."""
    cutoff = datetime.now() - timedelta(seconds=window_seconds)
    for ip in list(tracker_dict.keys()):
        tracker_dict[ip] = [t for t in tracker_dict[ip] if t > cutoff]
        if not tracker_dict[ip]:
            del tracker_dict[ip]


def detect_port_scan(pkt):
    """Detect when one IP hits many unique ports."""
    if not pkt.haslayer(TCP):
        return
    src_ip = pkt[IP].src
    dst_port = pkt[TCP].dport
    now = datetime.now()

    port_scan_tracker[src_ip][dst_port] = now

    # Clean old entries
    cutoff = now - timedelta(seconds=CONFIG["port_scan_window"])
    port_scan_tracker[src_ip] = {
        port: ts for port, ts in port_scan_tracker[src_ip].items()
        if ts > cutoff
    }

    unique_ports = len(port_scan_tracker[src_ip])
    if unique_ports >= CONFIG["port_scan_threshold"]:
        ports_hit = sorted(port_scan_tracker[src_ip].keys())
        log_alert(
            "PORT_SCAN", src_ip,
            f"{unique_ports} unique ports in {CONFIG['port_scan_window']}s: "
            f"{ports_hit[:20]}{'...' if len(ports_hit) > 20 else ''}"
        )
        # Reset to avoid repeated alerts
        port_scan_tracker[src_ip] = {}


def detect_ssh_brute_force(pkt):
    """Detect repeated SSH connection attempts."""
    if not pkt.haslayer(TCP):
        return
    if pkt[TCP].dport != 22 or not (pkt[TCP].flags & 0x02):  # SYN flag
        return

    src_ip = pkt[IP].src
    now = datetime.now()
    ssh_tracker[src_ip].append(now)
    clean_old_entries(ssh_tracker, CONFIG["brute_force_window"])

    if len(ssh_tracker[src_ip]) >= CONFIG["brute_force_threshold"]:
        log_alert(
            "SSH_BRUTE_FORCE", src_ip,
            f"{len(ssh_tracker[src_ip])} SSH SYN packets in "
            f"{CONFIG['brute_force_window']}s"
        )
        ssh_tracker[src_ip] = []


def detect_syn_flood(pkt):
    """Detect SYN flood from a single IP."""
    if not pkt.haslayer(TCP):
        return
    if not (pkt[TCP].flags & 0x02):  # SYN flag
        return

    src_ip = pkt[IP].src
    now = datetime.now()
    syn_tracker[src_ip].append(now)
    clean_old_entries(syn_tracker, CONFIG["syn_flood_window"])

    if len(syn_tracker[src_ip]) >= CONFIG["syn_flood_threshold"]:
        log_alert(
            "SYN_FLOOD", src_ip,
            f"{len(syn_tracker[src_ip])} SYN packets in "
            f"{CONFIG['syn_flood_window']}s"
        )
        syn_tracker[src_ip] = []


def detect_suspicious_dns(pkt):
    """Flag DNS queries to suspicious domains."""
    if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
        return
    query = pkt[DNSQR].qname.decode("utf-8", errors="ignore").lower()
    for keyword in CONFIG["suspicious_domains"]:
        if keyword in query:
            log_alert(
                "SUSPICIOUS_DNS", pkt[IP].src,
                f"DNS query for: {query}"
            )
            break


def process_packet(pkt):
    """Main packet handler — runs all detection modules."""
    if not pkt.haslayer(IP):
        return
    detect_port_scan(pkt)
    detect_ssh_brute_force(pkt)
    detect_syn_flood(pkt)
    detect_suspicious_dns(pkt)


def main():
    iface = CONFIG["interface"]
    print("=" * 60)
    print(f"  Network IDS Starting")
    print(f"  Interface: {iface}")
    print(f"  Time: {datetime.now().isoformat()}")
    print("=" * 60)
    print(f"  Detections enabled:")
    print(f"    - Port scan    ({CONFIG['port_scan_threshold']} ports / {CONFIG['port_scan_window']}s)")
    print(f"    - SSH brute    ({CONFIG['brute_force_threshold']} attempts / {CONFIG['brute_force_window']}s)")
    print(f"    - SYN flood    ({CONFIG['syn_flood_threshold']} SYNs / {CONFIG['syn_flood_window']}s)")
    print(f"    - Suspicious DNS queries")
    print("=" * 60)
    print("\nListening for traffic... (Ctrl+C to stop)\n")

    try:
        sniff(iface=iface, prn=process_packet, store=False)
    except KeyboardInterrupt:
        print(f"\n\nIDS stopped. Total alerts: {alert_count}")
        print(f"Logs saved to: {CONFIG['alert_log']} and {CONFIG['alert_csv']}")


if __name__ == "__main__":
    main()