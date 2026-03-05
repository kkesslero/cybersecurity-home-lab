#!/usr/bin/env python3


import json
import os
import urllib.request
import urllib.error
from collections import defaultdict, Counter
from datetime import datetime


# ──────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────

# Path to Cowrie's JSON log file
COWRIE_LOG = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"

# Where to save generated report
REPORT_FILE = "threat_report.json"


ABUSEIPDB_API_KEY = ""


# ──────────────────────────────────────────────
# STEP 1: PARSE COWRIE LOGS
# ──────────────────────────────────────────────

def parse_cowrie_logs(log_path):
    """
      - cowrie.session.connect    → someone connected to the honeypot
      - cowrie.login.success      → a login attempt that Cowrie accepted
      - cowrie.login.failed       → a login attempt that Cowrie rejected
      - cowrie.command.input      → a command the attacker typed
      - cowrie.session.file_download → attacker tried to download a file
    """
    # defaultdict creates a new attacker profile automatically
    # the first time we see a new IP address
    attackers = defaultdict(lambda: {
        "first_seen": None,
        "last_seen": None,
        "login_attempts": [],
        "commands": [],
        "sessions": 0,
        "downloaded_files": [],
        "client_versions": set()
    })

    if not os.path.exists(log_path):
        print(f"[!] Log file not found: {log_path}")
        print(f"    Make sure Cowrie is running and has received connections.")
        return attackers

    line_count = 0
    error_count = 0

    with open(log_path, "r") as f:
        for line in f:
            line_count += 1
            try:
                entry = json.loads(line.strip())
            except json.JSONDecodeError:
                error_count += 1
                continue

            # Every Cowrie log entry has a src_ip field
            # identifying who connected
            src_ip = entry.get("src_ip", "")
            if not src_ip:
                continue

            timestamp = entry.get("timestamp", "")
            event_id = entry.get("eventid", "")

            # Track when we first and last saw this attacker
            if attackers[src_ip]["first_seen"] is None:
                attackers[src_ip]["first_seen"] = timestamp
            attackers[src_ip]["last_seen"] = timestamp

            # ── Login attempts ──
            # These tell us what credentials attackers are trying.
            if event_id in ("cowrie.login.success", "cowrie.login.failed"):
                attackers[src_ip]["login_attempts"].append({
                    "username": entry.get("username", ""),
                    "password": entry.get("password", ""),
                    "success": event_id == "cowrie.login.success",
                    "timestamp": timestamp
                })

            # ── Commands executed ──
            # After "logging in", what does the attacker do?
            if event_id == "cowrie.command.input":
                attackers[src_ip]["commands"].append({
                    "input": entry.get("input", ""),
                    "timestamp": timestamp
                })

            # ── File downloads ──
            # If an attacker tries to wget/curl a file, Cowrie logs
            # the URL.
            if event_id == "cowrie.session.file_download":
                attackers[src_ip]["downloaded_files"].append({
                    "url": entry.get("url", ""),
                    "filename": entry.get("filename", ""),
                    "timestamp": timestamp
                })

            # ── Session tracking ──
            # Each new connection is a session.
            if event_id == "cowrie.session.connect":
                attackers[src_ip]["sessions"] += 1

            # ── Client fingerprinting ──
            # The SSH client version string can identify attack tools.
            if event_id == "cowrie.client.version":
                version = entry.get("version", "")
                if version:
                    attackers[src_ip]["client_versions"].add(version)

    print(f"  Parsed {line_count} log entries ({error_count} errors)")
    return attackers


# ──────────────────────────────────────────────
# STEP 2: ENRICH WITH THREAT INTELLIGENCE
# ──────────────────────────────────────────────

def check_abuseipdb(ip):
    if not ABUSEIPDB_API_KEY:
        return {"note": "No API key configured — skipping enrichment"}

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    req = urllib.request.Request(url, headers={
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    })

    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())["data"]
            return {
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode", "??"),
                "isp": data.get("isp", "Unknown"),
                "total_reports": data.get("totalReports", 0),
                "usage_type": data.get("usageType", "Unknown")
            }
    except urllib.error.URLError as e:
        return {"error": str(e)}


# ──────────────────────────────────────────────
# STEP 3: GENERATE THREAT REPORT
# ──────────────────────────────────────────────

def generate_report(attackers):
  
    report = {
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "total_unique_attackers": len(attackers),
            "total_login_attempts": sum(
                len(a["login_attempts"]) for a in attackers.values()
            ),
            "total_commands_executed": sum(
                len(a["commands"]) for a in attackers.values()
            ),
            "total_sessions": sum(
                a["sessions"] for a in attackers.values()
            ),
            "top_usernames": [],
            "top_passwords": [],
        },
        "attackers": {}
    }

    # ── Credential analysis ──
    # Aggregating all attempted usernames and passwords tells us
    # what's currently in botnet wordlists.
    all_usernames = Counter()
    all_passwords = Counter()
    for data in attackers.values():
        for attempt in data["login_attempts"]:
            all_usernames[attempt["username"]] += 1
            all_passwords[attempt["password"]] += 1

    report["summary"]["top_usernames"] = all_usernames.most_common(20)
    report["summary"]["top_passwords"] = all_passwords.most_common(20)

    # ── Enrich each attacker with threat intel ──
    for ip, data in attackers.items():
        print(f"  Enriching {ip}...")
        intel = check_abuseipdb(ip)

        # Convert sets to lists for JSON serialization
        attacker_data = dict(data)
        attacker_data["client_versions"] = list(data["client_versions"])

        report["attackers"][ip] = {
            **attacker_data,
            "threat_intel": intel
        }

    return report


# ──────────────────────────────────────────────
# STEP 4: DISPLAY RESULTS
# ──────────────────────────────────────────────

def print_summary(report):
    """Print a human-readable threat intelligence summary."""
    s = report["summary"]

    print("\n" + "=" * 60)
    print("  HONEYPOT THREAT INTELLIGENCE REPORT")
    print("=" * 60)
    print(f"  Generated:          {report['generated_at']}")
    print(f"  Unique Attackers:   {s['total_unique_attackers']}")
    print(f"  Total Sessions:     {s['total_sessions']}")
    print(f"  Login Attempts:     {s['total_login_attempts']}")
    print(f"  Commands Executed:  {s['total_commands_executed']}")

    # ── Top credentials ──
    # This section answers: "What are attackers trying right now?"
    print("\n  ── Top Usernames Attempted ──")
    for username, count in s["top_usernames"][:10]:
        bar = "█" * min(count, 30)
        print(f"    {username:20s} {count:4d}  {bar}")

    print("\n  ── Top Passwords Attempted ──")
    for password, count in s["top_passwords"][:10]:
        bar = "█" * min(count, 30)
        print(f"    {password:20s} {count:4d}  {bar}")

    # ── Attacker profiles ──
    # This section answers: "Who is attacking us and what are they doing?"
    print("\n  ── Attacker Profiles ──")
    for ip, data in report["attackers"].items():
        intel = data.get("threat_intel", {})

        print(f"\n  {'─' * 50}")
        print(f"  IP: {ip}")
        print(f"  Sessions: {data['sessions']}")
        print(f"  Login attempts: {len(data['login_attempts'])}")
        print(f"  Commands executed: {len(data['commands'])}")
        print(f"  First seen: {data['first_seen']}")
        print(f"  Last seen: {data['last_seen']}")

        # Show SSH client version (useful for identifying attack tools)
        if data.get("client_versions"):
            print(f"  SSH client: {', '.join(data['client_versions'])}")

        # Show threat intel enrichment
        if "abuse_score" in intel:
            score = intel["abuse_score"]
            # Color code the risk level
            if score >= 75:
                risk = "\033[91mHIGH RISK\033[0m"      # red
            elif score >= 25:
                risk = "\033[93mMEDIUM RISK\033[0m"     # yellow
            else:
                risk = "\033[92mLOW RISK\033[0m"        # green

            print(f"  Abuse Score: {score}/100 ({risk})")
            print(f"  Country: {intel['country']}")
            print(f"  ISP: {intel['isp']}")
            print(f"  Reports: {intel['total_reports']}")
        elif "note" in intel:
            print(f"  Threat Intel: {intel['note']}")

        # Show commands (attacker behavior analysis)
        if data["commands"]:
            print(f"  Commands:")
            for cmd in data["commands"][:15]:
                print(f"    > {cmd['input']}")

        # Show download attempts (critical IOCs)
        if data["downloaded_files"]:
            print(f"  \033[91m⚠ Download attempts:\033[0m")
            for dl in data["downloaded_files"]:
                print(f"    URL: {dl['url']}")

    print(f"\n{'=' * 60}")


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

def main():
    print("[*] Honeypot Threat Intelligence Correlator")
    print(f"[*] Reading logs from: {COWRIE_LOG}")
    print()

    # Step 1: Parse the honeypot logs
    print("[*] Step 1: Parsing Cowrie logs...")
    attackers = parse_cowrie_logs(COWRIE_LOG)

    if not attackers:
        print("[!] No attacker data found.")
        print("    Make sure Cowrie is running and has received connections.")
        print(f"    Log path: {COWRIE_LOG}")
        return

    print(f"[+] Found {len(attackers)} unique attacker(s)")

    # Step 2 & 3: Enrich with threat intel and generate report
    print("\n[*] Step 2: Enriching with threat intelligence...")
    report = generate_report(attackers)

    # Step 4: Display results
    print_summary(report)

    # Save full report to JSON
    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[*] Full report saved to {REPORT_FILE}")


if __name__ == "__main__":
    main()