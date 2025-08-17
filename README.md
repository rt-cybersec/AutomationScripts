# AutomationScripts

A collection of automation and security scripts written in **Python**, **PowerShell**, and **Bash**.  
This repository is designed as a personal toolkit for everyday tasks, system administration, API integrations, and security automation.

---

## 📂 Repository Structure

```
AutomationScripts/
├── windows-automation/
│ └── checkServices.ps1 # PowerShell script to check running services against VirusTotal
├── linux-automation/ # (Coming soon) Linux automation scripts
├── api-integrations/ # (Coming soon) API integration scripts
├── miscellaneous-security/
│ └── portScanner.py # Python-based TCP port scanner with customizable arguments
```

## ⚡ Current Scripts

### 🔹 Windows Automation

- **checkServices.ps1**
  - Scans running services on a Windows system.
  - Cross-checks service executables against VirusTotal.
  - Useful for identifying potentially malicious services.

### 🔹 Miscellaneous Security

- **portScanner.py**

  - Simple TCP port scanner built in Python.
  - Accepts arguments for:
    - `--target` (required) → IP or hostname to scan
    - `--ports` (optional) → Port range (default: 1–1024)
    - `--timeout` (optional) → Timeout in seconds per connection (default: 1)
    - `--workers` (optional) → Number of threads (default: 100)
  - Validates input arguments to avoid runtime errors.
  - Example usage:

    ```bash
    python portScanner.py --target 192.168.1.10 --ports 20-100 --timeout 2 --workers 50
    ```

---

## 🚀 Planned Scripts

### 📂 windows-automation

Scripts focused on Active Directory, Windows security, and system monitoring.

- **checkADUsers.ps1** → Pull all AD users, highlight disabled/inactive accounts
- **checkADGroups.ps1** → List AD groups with high privileges (Domain Admins, Enterprise Admins)
- **passwordExpiryReport.ps1** → Get all users with passwords expiring in X days
- **riskyShares.ps1** → Enumerate SMB shares with Everyone/Anonymous access
- **startupPrograms.ps1** → List autorun entries that could be persistence mechanisms

---

### 📂 linux-automation

Bash/Python utilities for Linux security and hardening.

- **checkRunningProcesses.sh** → Compare processes against VirusTotal/Hybrid Analysis
- **sshBruteForceCheck.sh** → Parse `auth.log` for brute-force attempts and block IPs (fail2ban-lite)
- **patchStatus.sh** → Check if critical packages are outdated
- **suidFilesFinder.sh** → List all SUID binaries (common privilege escalation step)
- **openPorts.sh** → Wrapper around `ss`/`netstat` → JSON output

---

### 📂 api-integrations

Automation with popular security APIs.

- **virustotal-hashcheck.py** → Bulk scan hashes/files against VirusTotal
- **shodan-query.py** → Fetch exposed assets by org/ASN
- **censys-lookup.py** → Get TLS/host data for given IP/domain
- **haveibeenpwned-check.py** → Check if given email/username is breached
- **ip-reputation-check.py** → Integrate with AbuseIPDB

---

### 📂 miscellaneous-security

General-purpose security tools.

- **dirScanner.py** → Basic directory brute-forcer (Gobuster-lite)
- **httpHeaderCheck.py** → Analyze HTTP headers for security best practices (HSTS, CSP, etc.)
- **jwtValidator.py** → Parse and validate JWT tokens for weak signing
- **logAnalyzer.py** → Parse log files (Windows/Linux/Apache) for anomalies

---

## 🛠️ Requirements

- Python 3.8+
- PowerShell 5.1+ (for Windows scripts)
- Bash (for Linux scripts)
- Required Python libraries will be listed in `requirements.txt` (coming soon).

---

## 👨‍💻 Author

**Rishabh Trivedi**

---
