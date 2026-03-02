#!/usr/bin/env python3
"""
SIEM Log Analyzer - Detects brute-force attacks and web scans
Supports real-time monitoring with --watch flag
"""

import re
import csv
import sys
import time
from collections import defaultdict
from datetime import datetime

# Configuration
AUTH_LOG = "/var/log/auth.log"
APACHE_LOG = "/var/log/apache2/access.log"
ALERT_THRESHOLD = 5
WEB_SCAN_THRESHOLD = 50

# Track alerts we've already seen (for real-time mode)
alerted_ips = {'ssh': set(), 'web': set()}

def parse_auth_line(line):
    """Parse a single auth.log line for failed SSH attempts."""
    pattern = r"(\d{4}-\d{2}-\d{2}T[\d:]+).*Failed password for (\w+) from ([\d.]+)"
    match = re.search(pattern, line)
    if match:
        timestamp, user, ip = match.groups()
        return {'timestamp': timestamp, 'user': user, 'ip': ip}
    return None

def parse_apache_line(line):
    """Parse a single Apache access.log line."""
    pattern = r'([\d.]+).*\[(.+?)\]\s+"(\w+)\s+(.+?)\s+HTTP'
    match = re.search(pattern, line)
    if match:
        ip, timestamp, method, path = match.groups()
        return {'ip': ip, 'timestamp': timestamp, 'method': method, 'path': path}
    return None

def parse_auth_log(filepath):
    """Parse entire auth.log file."""
    failed_attempts = defaultdict(list)
    try:
        with open(filepath, 'r') as f:
            for line in f:
                result = parse_auth_line(line)
                if result:
                    failed_attempts[result['ip']].append({
                        'timestamp': result['timestamp'],
                        'user': result['user']
                    })
    except FileNotFoundError:
        print(f"[!] File not found: {filepath}")
        return {}
    except PermissionError:
        print("[ERROR] Permission denied. Run with sudo.")
        return {}
    return failed_attempts

def parse_apache_log(filepath):
    """Parse entire Apache access.log file."""
    requests = defaultdict(list)
    try:
        with open(filepath, 'r') as f:
            for line in f:
                result = parse_apache_line(line)
                if result:
                    requests[result['ip']].append({
                        'timestamp': result['timestamp'],
                        'method': result['method'],
                        'path': result['path']
                    })
    except FileNotFoundError:
        print(f"[!] File not found: {filepath}")
        return {}
    except PermissionError:
        print("[ERROR] Permission denied. Run with sudo.")
        return {}
    return requests

def detect_brute_force(failed_attempts, threshold):
    """Identify IPs with failed attempts exceeding threshold."""
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
    """Identify IPs making excessive HTTP requests."""
    alerts = []
    for ip, reqs in requests.items():
        if len(reqs) >= threshold:
            paths = [r['path'] for r in reqs]
            suspicious_paths = [p for p in paths if any(x in p.lower() for x in
                ['admin', 'wp-', 'phpmyadmin', '.env', 'config', 'backup', '..'])]
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
    """Print formatted security report."""
    print("\n" + "="*60)
    print("           SIEM LOG ANALYSIS REPORT")
    print("="*60)
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

    total_ssh_ips = len(failed_attempts)
    total_ssh_attempts = sum(len(a) for a in failed_attempts.values())
    total_web_ips = len(web_requests)
    total_web_requests = sum(len(r) for r in web_requests.values())

    print(f"\n[SUMMARY]")
    print(f"  SSH: {total_ssh_ips} IPs, {total_ssh_attempts} failed attempts")
    print(f"  Web: {total_web_ips} IPs, {total_web_requests} requests")
    print(f"  Alerts generated: {len(alerts)}")

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
    """Export alerts to CSV file."""
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

def print_realtime_alert(alert_type, ip, count, details):
    """Print a real-time alert with timestamp."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"\n{'='*60}")
    print(f"⚠️  REAL-TIME ALERT - {timestamp}")
    print(f"{'='*60}")
    print(f"  Type: {alert_type}")
    print(f"  IP: {ip}")
    print(f"  Count: {count}")
    print(f"  {details}")
    print(f"{'='*60}\n")

def watch_logs():
    """
    Real-time monitoring mode.
    Watches log files and alerts on new attacks.
    """
    print("[*] Starting real-time monitoring...")
    print("[*] Press Ctrl+C to stop\n")
    print(f"[*] Watching:")
    print(f"    - {AUTH_LOG}")
    print(f"    - {APACHE_LOG}")
    print(f"\n[*] Thresholds:")
    print(f"    - SSH: {ALERT_THRESHOLD} failed attempts")
    print(f"    - Web: {WEB_SCAN_THRESHOLD} requests")
    print(f"\n{'='*60}")
    print("[*] Monitoring... (waiting for attacks)")
    print(f"{'='*60}\n")

    # Track failed attempts and requests per IP
    ssh_attempts = defaultdict(list)
    web_requests = defaultdict(list)

    try:
        # Open both log files
        auth_file = open(AUTH_LOG, 'r')
        apache_file = open(APACHE_LOG, 'r')

        # Jump to end of files (only watch new entries)
        auth_file.seek(0, 2)
        apache_file.seek(0, 2)

        while True:
            # Check auth.log for new lines
            auth_line = auth_file.readline()
            if auth_line:
                result = parse_auth_line(auth_line)
                if result:
                    ip = result['ip']
                    ssh_attempts[ip].append(result)
                    count = len(ssh_attempts[ip])

                    # Print each failed attempt
                    print(f"[SSH] Failed login from {ip} (user: {result['user']}) - Total: {count}")

                    # Alert if threshold reached and not already alerted
                    if count >= ALERT_THRESHOLD and ip not in alerted_ips['ssh']:
                        alerted_ips['ssh'].add(ip)
                        print_realtime_alert(
                            "SSH Brute-Force",
                            ip,
                            count,
                            f"Users targeted: {', '.join(set(a['user'] for a in ssh_attempts[ip]))}"
                        )

            # Check Apache log for new lines
            apache_line = apache_file.readline()
            if apache_line:
                result = parse_apache_line(apache_line)
                if result:
                    ip = result['ip']
                    web_requests[ip].append(result)
                    count = len(web_requests[ip])

                    # Print every 10th request to avoid spam
                    if count % 10 == 0:
                        print(f"[WEB] {ip} - {count} requests")

                    # Alert if threshold reached and not already alerted
                    if count >= WEB_SCAN_THRESHOLD and ip not in alerted_ips['web']:
                        alerted_ips['web'].add(ip)
                        paths = [r['path'] for r in web_requests[ip]]
                        suspicious = len([p for p in paths if any(x in p.lower() for x in
                            ['admin', 'wp-', 'phpmyadmin', '.env', 'config', 'backup', '..'])])
                        print_realtime_alert(
                            "Web Scan",
                            ip,
                            count,
                            f"Suspicious paths: {suspicious}"
                        )

            # Small delay to prevent CPU spinning
            if not auth_line and not apache_line:
                time.sleep(0.1)

    except FileNotFoundError as e:
        print(f"[ERROR] Log file not found: {e}")
        sys.exit(1)
    except PermissionError:
        print("[ERROR] Permission denied. Run with sudo.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n[*] Stopping real-time monitoring...")
        print(f"[*] Session summary:")
        print(f"    - SSH attempts tracked: {sum(len(a) for a in ssh_attempts.values())}")
        print(f"    - Web requests tracked: {sum(len(r) for r in web_requests.values())}")
        print(f"    - Alerts triggered: {len(alerted_ips['ssh']) + len(alerted_ips['web'])}")
        auth_file.close()
        apache_file.close()

def main():
    # Check for --watch flag
    if len(sys.argv) > 1 and sys.argv[1] == '--watch':
        watch_logs()
        return

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