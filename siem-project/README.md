# Cybersecurity Home Lab

A virtualized security lab environment for practicing attack simulation, log analysis, and intrusion detection.

## Overview

This project simulates a small enterprise network with multiple services running on a target server, attacked from a separate machine. All traffic and authentication attempts are logged for security analysis.

## Architecture

```
┌─────────────────┐         ┌─────────────────┐
│   attack-box    │────────▶│  lab-server     │
│  192.168.64.6   │         │  192.168.64.5   │
│                 │         │                 │
│  Tools:         │         │  Services:      │
│  - nmap         │         │  - SSH (22)     │
│  - hydra        │         │  - HTTP (80)    │
│  - nikto        │         │  - FTP (21)     │
│                 │         │  - MySQL (3306) │
└─────────────────┘         └─────────────────┘
```

## Environment

| Component  | Details                   |
| ---------- | ------------------------- |
| Host       | MacBook Air M2, 16GB RAM  |
| Hypervisor | UTM (ARM virtualization)  |
| Target OS  | Ubuntu Server 24.04 ARM64 |
| Attack OS  | Ubuntu Server 24.04 ARM64 |

## Services Configured

### SSH (Port 22)

- OpenSSH server with password authentication enabled
- Logs: `/var/log/auth.log`
- Protected by fail2ban

### Apache HTTP (Port 80)

- Default Apache2 installation
- Logs: `/var/log/apache2/access.log`

### FTP (Port 21)

- vsftpd with local user authentication
- Logs: `/var/log/auth.log`

### MySQL (Port 3306)

- MySQL 8.x with remote connections enabled
- Test user configured for brute-force testing
- Logs: `/var/log/mysql/error.log`

## Attack Tools

| Tool  | Purpose                                        |
| ----- | ---------------------------------------------- |
| nmap  | Port scanning and service detection            |
| hydra | Brute-force password attacks (SSH, FTP, MySQL) |
| nikto | Web server vulnerability scanning              |

## Sample Attacks

### Port Scan

```bash
nmap -sV -p 21,22,80,3306 192.168.64.5
```

### SSH Brute-Force

```bash
hydra -l username -P /usr/share/wordlists/rockyou.txt ssh://192.168.64.5 -t 4 -V
```

### FTP Brute-Force

```bash
hydra -l username -P /usr/share/wordlists/rockyou.txt ftp://192.168.64.5 -t 4 -V
```

### Web Vulnerability Scan

```bash
nikto -h http://192.168.64.5
```

### MySQL Brute-Force

```bash
hydra -l testuser -P /usr/share/wordlists/rockyou.txt mysql://192.168.64.5 -t 4 -V
```

## SIEM Log Analyzer

A Python-based tool that parses authentication and web logs to detect attacks in real-time.

### Features

- Parses `/var/log/auth.log` for failed SSH login attempts
- Parses `/var/log/apache2/access.log` for web scanning activity
- Detects brute-force attacks and web scans based on configurable thresholds
- **Real-time monitoring mode** — watches logs continuously and alerts instantly
- Generates formatted security reports
- Exports alerts to CSV for evidence collection

### Usage

**One-time scan:**

```bash
sudo python3 log_analyzer.py
```

**Real-time monitoring:**

```bash
sudo python3 log_analyzer.py --watch
```

### Sample Output (One-Time Scan)

```
[SUMMARY]
  SSH: 1 IPs, 8 failed attempts
  Web: 1 IPs, 6282 requests
  Alerts generated: 2

[ALERTS]
  ⚠️  Web Scan: 192.168.64.6
      Count: 6282
      Suspicious paths: 1241

  ⚠️  SSH Brute-Force: 192.168.64.6
      Count: 8
      Users targeted: kkesslero
```

### Sample Output (Real-Time Mode)

```
[*] Starting real-time monitoring...
[*] Press Ctrl+C to stop

[SSH] Failed login from 192.168.64.6 (user: kkesslero) - Total: 1
[SSH] Failed login from 192.168.64.6 (user: kkesslero) - Total: 2
[SSH] Failed login from 192.168.64.6 (user: kkesslero) - Total: 3
[SSH] Failed login from 192.168.64.6 (user: kkesslero) - Total: 4
[SSH] Failed login from 192.168.64.6 (user: kkesslero) - Total: 5

============================================================
⚠️  REAL-TIME ALERT - 2026-01-13 22:18:45
============================================================
  Type: SSH Brute-Force
  IP: 192.168.64.6
  Count: 5
  Users targeted: kkesslero
============================================================
```

## Log Analysis Commands

### View SSH/FTP Failed Logins

```bash
sudo tail -50 /var/log/auth.log | grep -E "(Failed|authentication failure)"
```

### View Web Access Logs

```bash
sudo tail -50 /var/log/apache2/access.log
```

### Check fail2ban Status

```bash
sudo fail2ban-client status sshd
```

### Unban an IP

```bash
sudo fail2ban-client set sshd unbanip <IP_ADDRESS>
```

## Key Findings

- **fail2ban** successfully detected and blocked SSH brute-force attacks after multiple failed attempts
- **FTP** brute-force attacks logged in auth.log but not blocked by default fail2ban config
- **nikto** scan revealed missing security headers (X-Frame-Options) and server version disclosure
- **MySQL** connection attempts logged in error.log with source IP
- **SIEM analyzer** correctly identified attack patterns and generated actionable alerts
- **Real-time monitoring** detected brute-force attacks as they happened and triggered instant alerts

## Skills Demonstrated

- Linux server administration
- Network service configuration
- Security tool usage (offensive and defensive)
- Log analysis and monitoring
- Intrusion detection and prevention
- Python scripting for security automation
- Real-time event processing

## Future Enhancements

- [x] Build SIEM-style log analysis tool in Python
- [x] Add Apache log parsing for web attack detection
- [x] Add real-time monitoring mode
- [ ] Configure fail2ban for FTP and MySQL
- [ ] Add network traffic capture (tcpdump/Wireshark)
- [ ] Set up centralized logging
- [ ] Add email/Slack alerting

## Resources

- [UTM Virtualization](https://mac.getutm.app/)
- [fail2ban Documentation](https://www.fail2ban.org/)
- [nmap Reference](https://nmap.org/book/man.html)
- [Hydra GitHub](https://github.com/vanhauser-thc/thc-hydra)
