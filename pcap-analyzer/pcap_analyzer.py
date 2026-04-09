#!/usr/bin/env python3
"""
Network Traffic Analyzer - Detects attacks from PCAP files
"""

from scapy.all import rdpcap, TCP, UDP, IP, ICMP
from collections import defaultdict
from datetime import datetime
import sys

# Detection thresholds
PORT_SCAN_THRESHOLD = 10      # Connections to different ports
BRUTE_FORCE_THRESHOLD = 5     # Connections to same port

def load_pcap(filepath):
    """Load packets from a PCAP file."""
    print(f"[*] Loading {filepath}...")
    try:
        packets = rdpcap(filepath)
        print(f"[+] Loaded {len(packets)} packets")
        return packets
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)

def analyze_packets(packets):
    """Analyze packets and extract connection data."""
    connections = defaultdict(lambda: defaultdict(int))

    for pkt in packets:
        if IP in pkt and TCP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            dst_port = pkt[TCP].dport

            # Track unique destination ports per source IP
            connections[src_ip][dst_port] += 1

    return connections

def detect_port_scan(connections, threshold):
    """Detect port scanning activity."""
    alerts = []

    for ip, ports in connections.items():
        if len(ports) >= threshold:
            alerts.append({
                'type': 'Port Scan',
                'ip': ip,
                'ports_scanned': len(ports),
                'top_ports': sorted(ports.keys())[:10]
            })

    return alerts

def detect_brute_force(connections, threshold):
    """Detect brute-force attempts (many connections to same port)."""
    alerts = []

    for ip, ports in connections.items():
        for port, count in ports.items():
            if count >= threshold and port in [21, 22, 23, 3306, 3389]:
                alerts.append({
                    'type': 'Brute-Force',
                    'ip': ip,
                    'port': port,
                    'connection_count': count
                })

    return alerts

def print_report(packets, connections, alerts):
    """Print analysis report."""
    print("\n" + "="*60)
    print("         NETWORK TRAFFIC ANALYSIS REPORT")
    print("="*60)
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

    # Summary
    print(f"\n[SUMMARY]")
    print(f"  Total packets: {len(packets)}")
    print(f"  Unique source IPs: {len(connections)}")
    print(f"  Alerts generated: {len(alerts)}")

    # Traffic breakdown
    print(f"\n[TRAFFIC BREAKDOWN]")
    for ip, ports in connections.items():
        total_conns = sum(ports.values())
        print(f"  {ip}: {total_conns} connections to {len(ports)} ports")

    # Alerts
    if alerts:
        print(f"\n[ALERTS]")
        print("-"*60)
        for alert in alerts:
            if alert['type'] == 'Port Scan':
                print(f"\n  ⚠️  {alert['type']}: {alert['ip']}")
                print(f"      Ports scanned: {alert['ports_scanned']}")
                print(f"      Sample ports: {alert['top_ports']}")
            elif alert['type'] == 'Brute-Force':
                print(f"\n  ⚠️  {alert['type']}: {alert['ip']}")
                print(f"      Target port: {alert['port']}")
                print(f"      Connections: {alert['connection_count']}")
    else:
        print(f"\n[OK] No suspicious activity detected.")

    print("\n" + "="*60)
    
def export_csv(alerts, filename="packet_alerts.csv"):
    """Export alerts to CSV file."""
    import csv
    if not alerts:
        return

    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Type', 'Source IP', 'Details'])
        for alert in alerts:
            if alert['type'] == 'Port Scan':
                details = f"Scanned {alert['ports_scanned']} ports"
            else:
                details = f"Port {alert['port']}: {alert['connection_count']} connections"
            writer.writerow([alert['type'], alert['ip'], details])

    print(f"\n[+] Alerts exported to {filename}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 pcap_analyzer.py <pcap_file>")
        print("Example: python3 pcap_analyzer.py attack_capture.pcap")
        sys.exit(1)

    pcap_file = sys.argv[1]

    # Load and analyze
    packets = load_pcap(pcap_file)
    connections = analyze_packets(packets)

    # Detect threats
    alerts = []
    alerts.extend(detect_port_scan(connections, PORT_SCAN_THRESHOLD))
    alerts.extend(detect_brute_force(connections, BRUTE_FORCE_THRESHOLD))

    # Report
    print_report(packets, connections, alerts)
    export_csv(alerts)


if __name__ == "__main__":
    main()
