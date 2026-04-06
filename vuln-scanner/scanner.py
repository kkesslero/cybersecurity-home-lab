import nmap
import requests
import sys
import json
from datetime import datetime

def cpe_22_to_23(cpe_22):
    if not cpe_22.startswith('cpe:/'):
        return None
    parts = cpe_22.replace('cpe:/', '').split(':')
    while len(parts) < 4:
        parts.append('*')
    return 'cpe:2.3:' + ':'.join(parts) + ':*' * (11 - len(parts))

def lookup_cves(cpe_23):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_23}"
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"    API error: {e}")
        return {'vulnerabilities': [], 'totalResults': 0}

def get_severity(cve):
    metrics = cve.get('metrics', {})
    if 'cvssMetricV31' in metrics:
        data = metrics['cvssMetricV31'][0]['cvssData']
        return data['baseSeverity'], data['baseScore']
    elif 'cvssMetricV2' in metrics:
        data = metrics['cvssMetricV2'][0]
        return data['baseSeverity'], data['cvssData']['baseScore']
    return 'UNKNOWN', 0.0

def get_year(cve):
    published = cve.get('published', '')
    if published:
        return int(published[:4])
    return 0

def get_description(cve):
    for desc in cve.get('descriptions', []):
        if desc.get('lang') == 'en':
            return desc.get('value', '')[:200]  # First 200 chars
    return 'No description available'

def scan_target(target):
    results = {
        'target': target,
        'scan_time': datetime.now().isoformat(),
        'services': []
    }
    
    nm = nmap.PortScanner()
    print(f"Scanning {target}...")
    
    try:
        nm.scan(target, arguments='-sV')
    except Exception as e:
        print(f"Scan error: {e}")
        return results
    
    if target not in nm.all_hosts():
        print("Host not found or no open ports")
        return results
    
    current_year = datetime.now().year
    
    for port in nm[target]['tcp']:
        service = nm[target]['tcp'][port]
        cpe_22 = service.get('cpe', '')
        
        service_info = {
            'port': port,
            'product': service.get('product', 'unknown'),
            'version': service.get('version', 'unknown'),
            'cpe': cpe_22,
            'vulnerabilities': []
        }
        
        if not cpe_22 or not cpe_22.startswith('cpe:/a:'):
            results['services'].append(service_info)
            continue
        
        cpe_23 = cpe_22_to_23(cpe_22)
        print(f"\n{'='*60}")
        print(f"Port {port}: {service_info['product']} {service_info['version']}")
        print(f"Querying NVD for {cpe_23}...")
        
        data = lookup_cves(cpe_23)
        
        # Filter: HIGH/CRITICAL and recent
        for vuln in data['vulnerabilities']:
            cve = vuln['cve']
            severity, score = get_severity(cve)
            year = get_year(cve)
            
            if severity in ['HIGH', 'CRITICAL'] and year >= current_year - 2:
                vuln_info = {
                    'id': cve['id'],
                    'severity': severity,
                    'score': score,
                    'year': year,
                    'description': get_description(cve)
                }
                service_info['vulnerabilities'].append(vuln_info)
        
        # Sort by score descending
        service_info['vulnerabilities'].sort(key=lambda x: x['score'], reverse=True)
        
        print(f"Found {len(service_info['vulnerabilities'])} recent high/critical CVEs")
        
        for v in service_info['vulnerabilities'][:5]:  # Top 5
            print(f"\n  [{v['severity']}] {v['id']} (Score: {v['score']})")
            print(f"    {v['description']}...")
        
        if len(service_info['vulnerabilities']) > 5:
            print(f"\n  ... and {len(service_info['vulnerabilities']) - 5} more")
        
        results['services'].append(service_info)
    
    return results

def save_report(results, filename):
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nReport saved to {filename}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 scanner.py <target> [output.json]")
        print("Example: python3 scanner.py 192.168.64.5")
        print("         python3 scanner.py 192.168.64.5 report.json")
        sys.exit(1)
    
    target = sys.argv[1]
    results = scan_target(target)
    
    # Save JSON report if filename provided
    if len(sys.argv) >= 3:
        save_report(results, sys.argv[2])
    
    print(f"\n{'='*60}")
    print("SCAN COMPLETE")
    print(f"{'='*60}")
