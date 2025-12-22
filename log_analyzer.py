#!/usr/bin/env python3
"""
SIEM Log Analyzer - Detects brute-force attacks and web scans
"""

import re
import csv
from collections import defaultdict
from datetime import datetime

# Configuration
AUTH_LOG = "/var/log/auth.log"
APACHE_LOG = "/var/log/apache2/access.log"
ALERT_THRESHOLD = 5
WEB_SCAN_THRESHOLD = 50

def parse_auth_log(filepath):
    failed_attempts = defaultdict(list)
    pattern = r"(\d{4}-\d{2}-\d{2}T[\d:]+).*Failed password for (\w+) from ([\d.]+)"
    
    try:
        with open(filepath, 'r') as f:
            for line in f:
                match = re.search(pattern, line)
                if match:
                    timestamp, user, ip = match.groups()
                    failed_attempts[ip].append({
                        'timestamp': timestamp,
                        'user': user
                    })
    except FileNotFoundError:
        print(f"[!] File not found: {filepath}")
        return {}
    except PermissionError:
        print("[ERROR] Permission denied. Run with sudo.")
        return {}
    
    return failed_attempts

def parse_apache_log(filepath):
    requests = defaultdict(list)
    pattern = r'([\d.]+).*\[(.+?)\]\s+"(\w+)\s+(.+?)\s+HTTP'
    
    try:
        with open(filepath, 'r') as f:
            for line in f:
                match = re.search(pattern, line)
                if match:
                    ip, timestamp, method, path = match.groups()
                    requests[ip].append({
                        'timestamp': timestamp,
                        'method': method,
                        'path': path
                    })
    except FileNotFoundError:
        print(f"[!] File not found: {filepath}")
        return {}
    except PermissionError:
        print("[ERROR] Permission denied. Run with sudo.")
        return {}
    
    return requests

def detect_brute_force(failed_attempts, threshold):
    alerts = []
    
    for ip, attempts in failed_attempts.items():
        if len(attempts) >= threshold:
            alerts.append({
                'type': 'SSH Brute-Force',
                'ip': ip,
                'count': len(attempts),
                'details': f"Users targeted: {', '.join(set(a['user'] for a in attempts))}",
                'first_seen': attempts[0]['timestamp'],
                'last_seen': attempts[-1]['timestamp']
            })
    
    return alerts

def detect_web_scans(requests, threshold):
    alerts = []
    
    for ip, reqs in requests.items():
        if len(reqs) >= threshold:
            paths = [r['path'] for r in reqs]
            suspicious_paths = [p for p in paths if any(x in p.lower() for x in ['admin', 'wp-', 'phpmyadmin', '.env', 'config', 'backup', '..'])]
            
            alerts.append({
                'type': 'Web Scan',
                'ip': ip,
                'count': len(reqs),
                'details': f"Suspicious paths: {len(suspicious_paths)}",
                'first_seen': reqs[0]['timestamp'],
                'last_seen': reqs[-1]['timestamp']
            })
    
    return alerts

def print_report(alerts, failed_attempts, web_requests):
    print("\n" + "="*60)
    print("           SIEM LOG ANALYSIS REPORT")
    print("="*60)
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)
    
    # Summary
    total_ssh_ips = len(failed_attempts)
    total_ssh_attempts = sum(len(a) for a in failed_attempts.values())
    total_web_ips = len(web_requests)
    total_web_requests = sum(len(r) for r in web_requests.values())
    
    print(f"\n[SUMMARY]")
    print(f"  SSH: {total_ssh_ips} IPs, {total_ssh_attempts} failed attempts")
    print(f"  Web: {total_web_ips} IPs, {total_web_requests} requests")
    print(f"  Alerts generated: {len(alerts)}")
    
    # Alerts
    if alerts:
        print(f"\n[ALERTS]")
        print("-"*60)
        for alert in sorted(alerts, key=lambda x: x['count'], reverse=True):
            print(f"\n  ⚠️  {alert['type']}: {alert['ip']}")
            print(f"      Count: {alert['count']}")
            print(f"      {alert['details']}")
            print(f"      First seen: {alert['first_seen']}")
            print(f"      Last seen: {alert['last_seen']}")
    else:
        print(f"\n[OK] No attacks detected.")
    
    print("\n" + "="*60)

def export_csv(alerts, filename="alerts.csv"):
    if not alerts:
        return
    
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Type', 'IP', 'Count', 'Details', 'First Seen', 'Last Seen'])
        for alert in alerts:
            writer.writerow([
                alert['type'],
                alert['ip'],
                alert['count'],
                alert['details'],
                alert['first_seen'],
                alert['last_seen']
            ])
    print(f"\n[+] Alerts exported to {filename}")

def main():
    print("[*] Starting SIEM Log Analyzer...")
    
    # Parse logs
    failed_attempts = parse_auth_log(AUTH_LOG)
    web_requests = parse_apache_log(APACHE_LOG)
    
    # Detect attacks
    alerts = []
    alerts.extend(detect_brute_force(failed_attempts, ALERT_THRESHOLD))
    alerts.extend(detect_web_scans(web_requests, WEB_SCAN_THRESHOLD))
    
    # Generate report
    print_report(alerts, failed_attempts, web_requests)
    export_csv(alerts)

if __name__ == "__main__":
    main()
