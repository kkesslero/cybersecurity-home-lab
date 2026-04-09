# Network Traffic Analyzer

A Python tool that analyzes PCAP files to detect network attacks.

## Features

- Reads packet captures from tcpdump or Wireshark
- Detects port scanning activity
- Detects brute-force attacks (SSH, FTP, MySQL, RDP)
- Generates threat reports
- Exports alerts to CSV

## Usage

### Capture Traffic

On the target machine:

```bash
sudo tcpdump -i enp0s1 -w capture.pcap
```

### Analyze

```bash
source venv/bin/activate
python3 pcap_analyzer.py capture.pcap
```

### Sample Output

[SUMMARY]
Total packets: 658
Unique source IPs: 3
Alerts generated: 5
[ALERTS]
⚠️ Port Scan: 192.168.64.5
Ports scanned: 23
⚠️ Brute-Force: 192.168.64.6
Target port: 22
Connections: 133

## Requirements

- Python 3
- scapy

## Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install scapy
```
