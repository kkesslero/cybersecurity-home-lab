#!/usr/bin/env python3
"""
SIEM Log Analyzer - Detects brute-force attacks from auth.log
"""

import re
import csv
from collections import defaultdict
from datetime import datetime

# Configuration
AUTH_LOG = "/var/log/auth.log"
ALERT_THRESHOLD = 5

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
    except PermissionError:
        print("[ERROR] Permission denied. Run with sudo.")
        return {}
    
    return failed_attempts

def detect_brute_force(failed_attempts, threshold):
    alerts = []
    
    for ip, attempts in failed_attempts.items():
        if len(attempts) >= threshold:
            alerts.append({
                'ip': ip,
                'count': len(attempts),
                'users_targeted': list(set(a['user'] for a in attempts)),
                'first_seen': attempts[0]['timestamp'],
                'last_seen': attempts[-1]['timestamp']
            })
    
    return alerts

def print_report(alerts, failed_attempts):
    print("\n" + "="*60)
    print("           SIEM LOG ANALYSIS REPORT")
    print("="*60)
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Log file: {AUTH_LOG}")
    print(f"Alert threshold: {ALERT_THRESHOLD} failed attempts")
    print("="*60)
    
    total_ips = len(failed_attempts)
    total_attempts = sum(len(a) for a in failed_attempts.values())
    print(f"\n[SUMMARY]")
    print(f"  Total unique IPs with failures: {total_ips}")
    print(f"  Total failed login attempts: {total_attempts}")
    print(f"  Alerts generated: {len(alerts)}")
    
    if alerts:
        print(f"\n[ALERTS] - Potential Brute-Force Attacks")
        print("-"*60)
        for alert in sorted(alerts, key=lambda x: x['count'], reverse=True):
            print(f"\n  ⚠️  ALERT: {alert['ip']}")
            print(f"      Failed attempts: {alert['count']}")
            print(f"      Users targeted: {', '.join(alert['users_targeted'])}")
            print(f"      First seen: {alert['first_seen']}")
            print(f"      Last seen: {alert['last_seen']}")
    else:
        print(f"\n[OK] No brute-force attacks detected.")
    
    print("\n" + "="*60)

def export_csv(alerts, filename="alerts.csv"):
    if not alerts:
        return
    
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['IP', 'Failed Attempts', 'Users Targeted', 'First Seen', 'Last Seen'])
        for alert in alerts:
            writer.writerow([
                alert['ip'],
                alert['count'],
                ', '.join(alert['users_targeted']),
                alert['first_seen'],
                alert['last_seen']
            ])
    print(f"\n[+] Alerts exported to {filename}")

def main():
    print("[*] Starting SIEM Log Analyzer...")
    
    failed_attempts = parse_auth_log(AUTH_LOG)
    
    if not failed_attempts:
        print("[!] No failed login attempts found.")
        return
    
    alerts = detect_brute_force(failed_attempts, ALERT_THRESHOLD)
    print_report(alerts, failed_attempts)
    export_csv(alerts)

if __name__ == "__main__":
    main()
