# Python Log Analyzer (`python-log-analyzer`)

A lightweight Python command-line utility for parsing web server access logs, generating frequency telemetry, and detecting security anomalies.

## Features

- **Regex Log Parsing:** Extracts IP addresses, timestamps, HTTP methods, paths, status codes, and payload sizes.
- **Statistical Summaries:** Computes top requesting IPs and HTTP status code distribution.
- **Security Alerting:** Flags unauthorized requests (401/403) and resource probes (404).

## Running the Script

Execute the analyzer from your terminal:

```bash
python3 src/analyzer.py
```
