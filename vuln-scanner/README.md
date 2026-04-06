# Vulnerability Scanner

Scans targets for open services and queries the NIST NVD for known CVEs.

## Usage
```bash
python3 scanner.py <target> [output.json]
```

### Examples
```bash
# Basic scan with terminal output
python3 scanner.py 192.168.64.5

# Scan with JSON report
python3 scanner.py 192.168.64.5 report.json
```

## Requirements

- python3
- nmap
- python-nmap
- requests

### Install dependencies
```bash
sudo apt install nmap
pip3 install python-nmap requests --break-system-packages
```

## Features

- Service and version detection via nmap (-sV)
- Automatic CPE 2.2 to 2.3 format conversion
- CVE lookup via NIST NVD API
- Filters to HIGH/CRITICAL severity from the last 2 years
- Results sorted by CVSS score
- JSON report export

## How It Works

1. Runs nmap service scan against target
2. Extracts CPE identifiers for detected services
3. Queries NVD API for each CPE
4. Filters and sorts vulnerabilities by severity and date
5. Displays results and optionally saves JSON report
