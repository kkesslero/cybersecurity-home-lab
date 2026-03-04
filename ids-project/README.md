# Network Intrusion Detection System (IDS)

A lightweight Python-based IDS that monitors live network traffic and detects malicious activity in real-time.

## Detections

- **Port Scanning** — Flags when a single IP probes 10+ unique ports within 60 seconds
- **SSH Brute Force** — Detects repeated SSH connection attempts (5+ SYN packets to port 22 in 30s)
- **SYN Flood** — Identifies denial-of-service attacks (100+ SYN packets in 10s)
- **Suspicious DNS** — Flags DNS queries containing known malicious keywords (C2, malware, botnet, etc.)

## Features

- Real-time packet sniffing with Scapy
- Color-coded console alerts
- Alert rate limiting (30s cooldown per alert type/IP to prevent log spam)
- Dual logging to JSON and CSV for evidence collection
- Configurable thresholds for all detection modules

## Lab Environment

| Machine | IP | Role |
|---------|-----|------|
| lab-server | 192.168.64.5 | Target running IDS |
| attack-box | 192.168.64.6 | Attacker simulation |

## Requirements

- Python 3
- Scapy (`sudo pip3 install scapy --break-system-packages`)
- Root privileges (for packet capture)

## Usage
```bash
sudo python3 ids.py
```

## Sample Output
```
[ALERT #1] PORT_SCAN
  Time:   2026-03-04T19:57:37.291875
  Source: 192.168.64.6
  Detail: 10 unique ports in 60s: [21, 53, 111, 143, 445, 554, 587, 993, 5900, 8080]

[ALERT #2] SSH_BRUTE_FORCE
  Time:   2026-03-04T20:00:42.876216
  Source: 192.168.64.6
  Detail: 5 SSH SYN packets in 30s

[ALERT #3] SYN_FLOOD
  Time:   2026-03-04T20:17:49.022800
  Source: 192.168.64.6
  Detail: 100 SYN packets in 10s

[ALERT #4] SUSPICIOUS_DNS
  Time:   2026-03-04T20:01:47.495648
  Source: 192.168.64.6
  Detail: DNS query for: evil-c2-server.com.
```

## Skills Demonstrated

- Network traffic analysis and packet inspection
- Signature-based intrusion detection
- Python networking with Scapy
- Security event logging and evidence preservation