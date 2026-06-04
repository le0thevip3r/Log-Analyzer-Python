# Python Log Analyzer & Threat Detector

A lightweight, automated Python security utility designed to parse authentication log files, track user activity metrics, and detect potential brute-force attacks by monitoring failed login thresholds from distinct IP addresses.

## 🛡️ Features
* **Regex Engine Parsing:** Extract usernames and source IP addresses precisely using optimized regular expressions.
* **Authentication Auditing:** Calculates total log entries alongside global successful and failed login metrics.
* **Brute-Force Threat Detection:** Flags suspicious IP addresses that exceed a customizable failed login threshold (Default: `5`).
* **Automated Reporting:** Generates a structured plain-text security report (`report.txt`) and exports data to a clean comma-separated value file (`analysis.csv`) for SIEM ingest or Excel viewing.

## 📊 Sample Log Format
To test the script, ensure you have a file named `security.log` in the same directory. The parser expects log lines containing `user=<username>` and `ip=<ip_address>` flags along with status markers (`login_success` or `login_failed`).

**Example `security.log` content:**
```text
2026-06-04 10:00:00 ip=192.168.1.50 user=admin status=login_failed
2026-06-04 10:01:05 ip=192.168.1.50 user=admin status=login_failed
2026-06-04 10:01:40 ip=192.168.1.50 user=admin status=login_failed
2026-06-04 10:02:12 ip=192.168.1.50 user=admin status=login_failed
2026-06-04 10:03:00 ip=192.168.1.50 user=admin status=login_failed
2026-06-04 10:04:15 ip=10.0.0.12 user=aswath status=login_success
