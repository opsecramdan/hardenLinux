<div align="center">

```
##:::::::'####:'##::: ##:'##::::'##:'##::::'##:
##:::::::. ##:: ###:: ##: ##:::: ##:. ##::'##::
##:::::::: ##:: ####: ##: ##:::: ##::. ##'##:::
##:::::::: ##:: ## ## ##: ##:::: ##:::. ###::::
##:::::::: ##:: ##. ####: ##:::: ##::: ## ##:::
##:::::::: ##:: ##:. ###: ##:::: ##:: ##:. ##::
########:'####: ##::. ##:. #######:: ##:::. ##:
........::....::..::::..:::.......:::..:::::..::
'##::::'##::::'###::::'########::'########::'########:'##::: ##:'####:'##::: ##::'######:::
 ##:::: ##:::'## ##::: ##.... ##: ##.... ##: ##.....:: ###:: ##:. ##:: ###:: ##:'##... ##::
 ##:::: ##::'##:. ##:: ##:::: ##: ##:::: ##: ##::::::: ####: ##:: ##:: ####: ##: ##:::..:::
 #########:'##:::. ##: ########:: ##:::: ##: ######::: ## ## ##:: ##:: ## ## ##: ##::'####:
 ##.... ##: #########: ##.. ##::: ##:::: ##: ##...:::: ##. ####:: ##:: ##. ####: ##::: ##::
 ##:::: ##: ##.... ##: ##::. ##:: ##:::: ##: ##::::::: ##:. ###:: ##:: ##:. ###: ##::: ##::
 ##:::: ##: ##:::: ##: ##:::. ##: ########:: ########: ##::. ##:'####: ##::. ##:. ######:::
..:::::..::..:::::..::..:::::..::........:::........::..::::..::....::..::::..:::......::::
```

# Linux Hardening Audit Tool

**Advanced Edition — 129+ Security Checks across 17 Modules**

[![Python](https://img.shields.io/badge/Python-3.6%2B-blue?style=flat-square&logo=python)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=flat-square&logo=linux)](https://kernel.org/)
[![Mode](https://img.shields.io/badge/Mode-Read--Only-green?style=flat-square)](#)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)
[![Author](https://img.shields.io/badge/Author-opsecramdan-red?style=flat-square)](https://github.com/opsecramdan)
[![Checks](https://img.shields.io/badge/Security%20Checks-129%2B-brightgreen?style=flat-square)](#modules)

> 🔐 A production-safe, read-only Linux security hardening audit tool inspired by Lynis.
> Performs 129+ automated checks, generates scored reports (0–100), and provides
> actionable remediation guidance. **No system modification. No package installation. Safe on production.**

</div>

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Modules](#-modules)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Sample Output](#-sample-output)
- [Output Files](#-output-files)
- [Security Score](#-security-score)
- [Supported Distributions](#-supported-distributions)
- [Disclaimer](#-disclaimer)
- [Author](#-author)

---

## 🔍 Overview

**Linux Hardening Audit Tool** is a lightweight, read-only CLI security scanner built for Linux system administrators, security engineers, and DevSecOps professionals.

It performs comprehensive security posture analysis across **17 security domains** — from SSH configuration and kernel sysctl hardening, to Docker container security, malware detection, PAM policies, and boot security — all without touching a single system configuration.

Designed to be used in:
- **Pre-deployment server hardening audits**
- **Regular compliance checks (CIS-aligned)**
- **Penetration testing reconnaissance (own systems)**
- **Security portfolio / DevSecOps tooling**
- **Incident response baseline assessment**

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔒 **Read-Only Mode** | Never modifies, installs, or changes anything on the system |
| ✅ **129+ Security Checks** | Comprehensive coverage across 17 security modules |
| 🎯 **Security Score (0–100)** | Weighted score with per-section breakdown |
| 🟢🟡🔴 **PASS / WARNING / FAIL** | Color-coded findings with risk levels (LOW / MEDIUM / HIGH / CRITICAL) |
| 🛠️ **Remediation Guidance** | Every finding includes a concrete fix command |
| 📄 **JSON Export** | Machine-readable report for integration with SIEM / dashboards |
| 🐧 **Multi-Distro Support** | Ubuntu, Debian, CentOS, Rocky Linux, AlmaLinux |
| 🧩 **Modular Architecture** | Each module is an independent function — easy to extend |
| ⚡ **Zero Dependencies** | Uses Python 3 standard library only |
| 🏭 **Production-Safe** | Tested to be safe on live production servers |

---

## 🧩 Modules

| # | Module | Checks | Description |
|---|---|:---:|---|
| 01 | 🖥️ System Information | 3 | OS, kernel version, disk usage, virtualization |
| 02 | 👤 User Security | 12 | UID 0, duplicates, home dir perms, shell access |
| 03 | 🔑 Password Policy | 8 | login.defs, pwquality, lockout, SHA-512 hashing |
| 04 | 🔐 SSH Security | 14 | Root login, ciphers, MACs, forwarding, banner |
| 05 | 🌐 Network Security | 8 | Open ports, NFS exports, DNS, TCP wrappers |
| 06 | 🛡️ Firewall Status | 6 | UFW, firewalld, iptables, ip6tables |
| 07 | ⚙️ Running Services | 8 | Legacy services, MTA, NFS, Samba detection |
| 08 | 📁 File System Security | 10 | SUID/SGID, world-writable, critical perms, /tmp |
| 09 | ⏰ Cron Security | 6 | Suspicious patterns, cron.allow, user crontabs |
| 10 | 🔓 Sudo Security | 6 | NOPASSWD, wildcards, logging, requiretty |
| 11 | 🧠 Kernel Security | 15 | sysctl parameters, ASLR, SYN cookies, IP fwd |
| 12 | 📋 Logging & Auditing | 8 | rsyslog, auditd, journald, log file permissions |
| 13 | 🔒 PAM Security | 6 | faillock, pwhistory, SHA-512, su restriction |
| 14 | 🐳 Container Security | 6 | Docker socket, TCP API, privileged containers |
| 15 | 🦠 Malware Detection | 4 | rkhunter, chkrootkit, ClamAV, suspicious procs |
| 16 | 📦 Package Security | 5 | Pending updates, security patches, debsums |
| 17 | 🥾 Boot Security | 4 | GRUB password, Secure Boot, single-user auth |
| | **TOTAL** | **129+** | |

---

## 📋 Requirements

- **Python 3.6+** (uses standard library only — no pip install needed)
- **Linux** (any systemd-based distribution)
- **Root / sudo privileges** recommended for full audit coverage

> Running without root will still execute most checks, but some modules
> (shadow file, sysctl, firewall, Docker) may produce incomplete results.

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/opsecramdan/hardenLinux.git

# Enter the directory
cd linux-hardening-audit

# Make executable
chmod +x linux_hardening_audit_advanced.py
```

No virtual environment or pip install required. Pure Python 3 standard library.

---

## 💻 Usage

### Basic Run

```bash
python3 linux_hardening_audit_advanced.py
```

### Full Audit (Recommended — Root Access)

```bash
sudo python3 linux_hardening_audit_advanced.py
```

### Save Terminal Output

```bash
sudo python3 linux_hardening_audit_advanced.py | tee audit_$(hostname)_$(date +%Y%m%d).txt
```

### View JSON Report

```bash
# JSON is auto-generated after every run
cat audit_YYYYMMDD_HHMMSS.json | python3 -m json.tool
```

---

## 📊 Sample Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🔐  [SSH SECURITY]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✔ PermitRootLogin [LOW]
    → PermitRootLogin is properly configured (no).
  ✘ PasswordAuthentication [MEDIUM]
    → PasswordAuthentication = 'yes'. Brute-force risk.
    Fix: Use SSH keys only. Set 'PasswordAuthentication no'.
  ✔ PermitEmptyPasswords [LOW]
    → PermitEmptyPasswords is disabled.
  ✘ SSH Weak Ciphers [HIGH]
    → Weak ciphers configured: aes128-cbc, 3des-cbc
    Fix: Remove weak ciphers from sshd_config Ciphers directive.
  ⚠ SSH Banner [LOW]
    → No SSH warning banner configured.
    Fix: Set 'Banner /etc/issue.net' with a legal warning.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🧠  [KERNEL SECURITY (sysctl)]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✔ net.ipv4.ip_forward [LOW]
    → net.ipv4.ip_forward = 0 ✓
  ✔ net.ipv4.tcp_syncookies [LOW]
    → net.ipv4.tcp_syncookies = 1 ✓
  ✘ kernel.randomize_va_space [HIGH]
    → kernel.randomize_va_space = 1 (expected 2). Full ASLR not enabled.
    Fix: sysctl -w kernel.randomize_va_space=2

════════════════════════════════════════════════════════════════
    LINUX SECURITY AUDIT — COMPREHENSIVE REPORT SUMMARY
════════════════════════════════════════════════════════════════
  Generated  : 2025-01-15 14:32:07
  Hostname   : prod-server-01
  Audited By : opsecramdan — Linux Hardening Audit Tool
────────────────────────────────────────────────────────────────
  Total Checks : 129
  PASS         : 87
  WARNING      : 28
  FAIL         : 14
────────────────────────────────────────────────────────────────

  SECURITY SCORE: 74/100  [GOOD ✅]
  0 [████████████████░░░░] 100

  SCORE BY SECTION:
  System Information        [██████████] 100%
  User Security             [████████░░]  83%
  Password Policy           [███████░░░]  75%
  SSH Security              [██████░░░░]  64%
  Network Security          [████████░░]  87%
  Firewall Status           [█████████░]  90%
  Running Services          [██████████] 100%
  File System Security      [███████░░░]  70%
  Kernel Security           [██████░░░░]  60%
  Logging & Auditing        [████████░░]  80%
```

---

## 📁 Output Files

Every run automatically generates a JSON report:

```
audit_20250115_143207.json
```

**JSON Structure:**

```json
{
  "meta": {
    "tool": "Linux Hardening Audit Tool - Advanced Edition",
    "author": "opsecramdan",
    "timestamp": "2025-01-15T14:32:07",
    "hostname": "prod-server-01",
    "score": 74,
    "total": 129,
    "pass": 87,
    "warning": 28,
    "fail": 14
  },
  "findings": [
    {
      "section": "SSH Security",
      "check": "PermitRootLogin",
      "status": "PASS",
      "risk": "LOW",
      "explanation": "PermitRootLogin is properly configured (no).",
      "recommendation": ""
    },
    {
      "section": "SSH Security",
      "check": "PasswordAuthentication",
      "status": "WARNING",
      "risk": "MEDIUM",
      "explanation": "PasswordAuthentication = 'yes'. Brute-force risk.",
      "recommendation": "Set 'PasswordAuthentication no' and use SSH keys."
    }
  ]
}
```

The JSON output can be integrated with:
- **SIEM platforms** (Splunk, Elastic, Wazuh)
- **Custom dashboards** (Grafana, custom web UI)
- **CI/CD pipelines** for automated compliance gates
- **Reporting tools** for PDF/HTML generation

---

## 🏆 Security Score

The security score (0–100) is calculated using a weighted formula:

```
Score = ((PASS × 1.0) + (WARNING × 0.5)) / Total Checks × 100
```

| Score Range | Rating | Meaning |
|---|---|---|
| 85 – 100 | 🏆 EXCELLENT | Strongly hardened system |
| 70 – 84 | ✅ GOOD | Well configured with minor gaps |
| 55 – 69 | ⚠️ FAIR | Moderate risk — remediation needed |
| 40 – 54 | 🔴 POOR | Significant security gaps |
| 0 – 39 | ☠️ CRITICAL | Severely misconfigured — act immediately |

---

## 🐧 Supported Distributions

| Distribution | Status |
|---|---|
| Ubuntu 20.04 / 22.04 / 24.04 | ✅ Fully Supported |
| Debian 11 / 12 | ✅ Fully Supported |
| CentOS 7 / 8 | ✅ Supported |
| Rocky Linux 8 / 9 | ✅ Supported |
| AlmaLinux 8 / 9 | ✅ Supported |
| Kali Linux | ✅ Supported |
| Fedora 36+ | ✅ Supported |

---

## ⚙️ Extending the Tool

The modular design makes it easy to add new checks:

```python
def my_custom_check():
    section_header("MY CUSTOM MODULE", "🔧")

    # Your check logic
    result = read_file("/etc/myconfig")

    if "secure_setting" in result:
        add_finding("Custom", "My Check", "PASS", "LOW",
                    "Setting is secure.", "")
    else:
        add_finding("Custom", "My Check", "FAIL", "HIGH",
                    "Setting is insecure.",
                    "Set secure_setting=yes in /etc/myconfig.")
```

Then register it in `main()`:

```python
modules = [
    ...
    ("My Custom Check", my_custom_check),
]
```

---

## ⚠️ Disclaimer

This tool is intended for use on systems you **own or have explicit written permission to audit**.

- ✅ Use on your own servers, VMs, and infrastructure
- ✅ Use in authorized penetration testing engagements
- ✅ Use for internal security compliance auditing
- ❌ Do not use on systems without authorization

The author is not responsible for any misuse of this tool.

---

## 👤 Author

**opsecramdan**

> Linux Security Engineer | DevSecOps | Red Team Tooling

- 🐙 GitHub: [@opsecramdan](https://github.com/opsecramdan)

---

## 📄 License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Made with 🔐 by opsecramdan**

*If this tool helped secure your systems, consider giving it a ⭐*

</div>
