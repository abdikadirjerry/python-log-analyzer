import re
from collections import Counter
import sys
import os

LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) - - \[(?P<date>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>[^\s]+) [^"]+" (?P<status>\d{3}) (?P<size>\d+)'
)

def analyze_logs(file_path):
    if not os.path.exists(file_path):
        print(f"Error: Log file not found at {file_path}")
        sys.exit(1)

    ip_counter = Counter()
    status_counter = Counter()
    path_counter = Counter()
    anomalies = []

    with open(file_path, 'r') as f:
        for line in f:
            match = LOG_PATTERN.match(line.strip())
            if match:
                data = match.groupdict()
                ip = data['ip']
                status = data['status']
                path = data['path']

                ip_counter[ip] += 1
                status_counter[status] += 1
                path_counter[path] += 1

                # Flag potential security anomalies (e.g. 401 Unauthorized or 404 probes)
                if status in ['401', '403', '404']:
                    anomalies.append((ip, status, path))

    return ip_counter, status_counter, path_counter, anomalies

def main():
    log_file = 'data/access.log'
    print(f"[*] Analyzing log file: {log_file}\n")

    ips, statuses, paths, anomalies = analyze_logs(log_file)

    print("=== TOP IP ADDRESSES ===")
    for ip, count in ips.most_common(5):
        print(f"  {ip}: {count} requests")

    print("\n=== HTTP STATUS CODES ===")
    for status, count in statuses.items():
        print(f"  Status {status}: {count} occurrences")

    print("\n=== SECURITY ANOMALIES & PROBES ===")
    if anomalies:
        for ip, status, path in anomalies:
            print(f"  [ALERT] IP {ip} triggered Status {status} on sensitive path: {path}")
    else:
        print("  No anomalies detected.")

if __name__ == '__main__':
    main()