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

**Advanced Edition — 180+ Security Checks across 19 Modules**

[![Python](https://img.shields.io/badge/Python-3.6%2B-blue?style=flat-square&logo=python)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=flat-square&logo=linux)](https://kernel.org/)
[![Mode](https://img.shields.io/badge/Mode-Read--Only-green?style=flat-square)](#)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)
[![Author](https://img.shields.io/badge/Author-opsecramdan-red?style=flat-square)](https://github.com/opsecramdan)
[![Checks](https://img.shields.io/badge/Security%20Checks-180%2B-brightgreen?style=flat-square)](#modules)
[![Modules](https://img.shields.io/badge/Modules-19-blue?style=flat-square)](#modules)

> 🔐 A production-safe, read-only Linux security hardening audit tool inspired by Lynis.
> Performs **180+ automated checks** across **19 security modules**, generates scored reports (0–100),
> and provides actionable remediation guidance.
> **No system modification. No package installation. Safe on production.**

</div>

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Modules](#-modules)
- [What Gets Checked](#-what-gets-checked)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Sample Output](#-sample-output)
- [Output Files](#-output-files)
- [Security Score](#-security-score)
- [Supported Distributions](#-supported-distributions)
- [Extending the Tool](#-extending-the-tool)
- [Disclaimer](#-disclaimer)
- [Author](#-author)

---

## 🔍 Overview

**Linux Hardening Audit Tool** is a lightweight, read-only CLI security scanner built for Linux system administrators, security engineers, and DevSecOps professionals.

It performs comprehensive security posture analysis across **19 security domains** — from SSH configuration and kernel sysctl hardening, to Docker container security, malware detection, PAM policies, advanced permission auditing, and executable/script security — all without touching a single system configuration.

Designed to be used in:
- **Pre-deployment server hardening audits**
- **Regular compliance checks (CIS-aligned)**
- **Penetration testing reconnaissance (own systems)**
- **Incident response baseline assessment**
- **Security portfolio / DevSecOps tooling**
- **CTF / lab environment security validation**

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔒 **Read-Only Mode** | Never modifies, installs, or changes anything on the system |
| ✅ **180+ Security Checks** | Comprehensive coverage across 19 security modules |
| 🎯 **Security Score (0–100)** | Weighted score with per-section breakdown bar |
| 🟢🟡🔴 **PASS / WARNING / FAIL** | Color-coded findings with risk levels (LOW / MEDIUM / HIGH / CRITICAL) |
| 🛠️ **Remediation Guidance** | Every finding includes a concrete fix command |
| 📄 **JSON Export** | Machine-readable report auto-saved after every run |
| 🐧 **Multi-Distro Support** | Ubuntu, Debian, CentOS, Rocky Linux, AlmaLinux, Kali, Parrot |
| 🧩 **Modular Architecture** | Each module is an independent function — easy to extend |
| ⚡ **Zero Dependencies** | Uses Python 3 standard library only — no pip install needed |
| 🏭 **Production-Safe** | Tested to be safe on live production servers |
| 🔍 **Script & Binary Audit** | Detects writable scripts, SUID shells, backdoors in /tmp |
| 🗂️ **Permission Deep Scan** | Checks SSH keys, cron scripts, systemd services, \$PATH binaries |

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
| 11 | 🧠 Kernel Security | 15 | sysctl parameters, ASLR, SYN cookies, IP forwarding |
| 12 | 📋 Logging & Auditing | 8 | rsyslog, auditd, journald, log file permissions |
| 13 | 🔒 PAM Security | 6 | faillock, pwhistory, SHA-512, su restriction |
| 14 | 🐳 Container Security | 6 | Docker socket, TCP API, privileged containers |
| 15 | 🦠 Malware Detection | 4 | rkhunter, chkrootkit, ClamAV, suspicious procs |
| 16 | 📦 Package Security | 5 | Pending updates, security patches, debsums |
| 17 | 🥾 Boot Security | 4 | GRUB password, Secure Boot, single-user auth |
| 18 | 🔑 Advanced Permission Audit | 30+ | Critical files, SSH keys, \$PATH, cron dirs, sudoers.d |
| 19 | 📜 Script & Executable Audit | 11 | Writable scripts, SUID shells, /tmp executables, symlinks |
| | **TOTAL** | **180+** | |

---

## 🔬 What Gets Checked

### Module 18 — Advanced Permission Audit
Checks for dangerous file permission misconfigurations that lead to real exploits:

| File / Directory | Risk if Wrong | Exploit |
|---|---|---|
| `/etc/passwd` writable | CRITICAL | Add UID 0 account without password |
| `/etc/shadow` readable | CRITICAL | Extract and crack password hashes |
| `/etc/sudoers` writable | CRITICAL | Grant self full root sudo access |
| `/etc/ssh/sshd_config` writable | CRITICAL | Insert SSH backdoor |
| `~/.ssh/authorized_keys` writable | CRITICAL | Inject attacker SSH public key |
| `~/.ssh/` directory writable | CRITICAL | Replace authorized_keys |
| `~/.bashrc` / `~/.profile` writable | HIGH | Inject backdoor on every login |
| `/etc/environment` writable | HIGH | Environment variable injection |
| `/etc/ld.so.conf` writable | HIGH | Library hijacking (LD_PRELOAD) |
| `$PATH` directories world-writable | CRITICAL | Binary hijacking |
| `/root` directory not 700 | HIGH | Root home accessible by others |
| `/etc/cron.d/` files writable | CRITICAL | Inject root cron job |
| `/etc/sudoers.d/` files writable | CRITICAL | Escalate to root via sudo |

### Module 19 — Script & Executable Audit
Detects dangerous script and binary permission issues:

| Check | Risk | Exploit |
|---|---|---|
| World-writable `.sh` `.py` `.pl` files | CRITICAL | Script content replacement |
| World-writable executable binaries | CRITICAL | Binary hijacking |
| Cron-executed scripts that are writable | CRITICAL | Root code execution via cron |
| Writable systemd `.service` files | CRITICAL | Persistent backdoor on reboot |
| Writable `ExecStart` binaries in services | CRITICAL | Service binary replacement |
| Writable `/etc/init.d/` scripts | CRITICAL | Boot-time backdoor injection |
| SUID set on shell scripts | CRITICAL | Direct privilege escalation |
| Executables found in `/tmp` or `/var/tmp` | HIGH | Malware staging detection |
| Symlinks pointing to `/tmp` in sensitive dirs | HIGH | Symlink attack |
| Group-writable binaries in `$PATH` | HIGH | PATH-based binary hijacking |
| Non-root owned files in `/usr/local/bin` | HIGH | Supply chain / binary tampering |

---

## 📋 Requirements

- **Python 3.6+** — standard library only, no pip install needed
- **Linux** — any systemd-based distribution
- **Root / sudo privileges** — recommended for full audit coverage

> Running without root will still execute most checks, but some modules
> (shadow file, sysctl, firewall, Docker, advanced permissions) may produce incomplete results.

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/opsecramdan/hardenLinux.git

# Enter the directory
cd hardenLinux

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

### Full Audit — Recommended (Root Access)
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
  📜  [SCRIPT & EXECUTABLE PERMISSION AUDIT]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✔ World-Writable Script Files [LOW]
    → No world-writable script files found ✓
  ✘ Executable Files in /tmp or /var/tmp [HIGH]
    → 2 executable file(s) in /tmp: /tmp/update.sh, /tmp/.x
    Fix: Investigate immediately — common malware staging location.
  ✔ Suspicious Symlinks in Sensitive Dirs [LOW]
    → No suspicious symlinks in sensitive directories ✓
  ✘ Writable Scripts Called by Cron [CRITICAL]
    → Cron-executed scripts that are writable: /opt/backup.sh (0o777)
    Fix: chmod 700 on cron scripts — writable cron script = root code execution!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🔑  [ADVANCED PERMISSION SECURITY]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✔ Perms: /etc/passwd [LOW]
    → /etc/passwd permissions 0o644 ✓
  ✔ Perms: /etc/shadow [LOW]
    → /etc/shadow permissions 0o640 ✓
  ✘ authorized_keys: ramdan [CRITICAL]
    → /home/ramdan/.ssh/authorized_keys is 0o644 — SSH key injection possible!
    Fix: chmod 600 /home/ramdan/.ssh/authorized_keys

════════════════════════════════════════════════════════════════
    LINUX SECURITY AUDIT — COMPREHENSIVE REPORT SUMMARY
════════════════════════════════════════════════════════════════
  Generated  : 2025-01-15 14:32:07
  Hostname   : prod-server-01
  Audited By : opsecramdan — Linux Hardening Audit Tool
────────────────────────────────────────────────────────────────
  Total Checks : 183
  PASS         : 141
  WARNING      : 28
  FAIL         : 14
────────────────────────────────────────────────────────────────

  SECURITY SCORE: 76/100  [GOOD ✅]
  0 [███████████████░░░░░] 100

  SCORE BY SECTION:
  System Information        [██████████] 100%
  User Security             [████████░░]  83%
  SSH Security              [██████░░░░]  64%
  Kernel Security           [██████░░░░]  60%
  Adv. Permission Audit     [████████░░]  82%
  Script & Exec Perms       [███████░░░]  72%
```

---

## 📁 Output Files

Every run automatically generates a timestamped JSON report:

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
    "score": 76,
    "total": 183,
    "pass": 141,
    "warning": 28,
    "fail": 14
  },
  "findings": [
    {
      "section": "Script Perms",
      "check": "Writable Scripts Called by Cron",
      "status": "FAIL",
      "risk": "CRITICAL",
      "explanation": "Cron-executed scripts that are writable: /opt/backup.sh (0o777)",
      "recommendation": "chmod 700 on cron scripts — writable cron script = root code execution!"
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
| Parrot OS | ✅ Supported |
| Fedora 36+ | ✅ Supported |

---

## ⚙️ Extending the Tool

The modular design makes it easy to add new checks. Each module follows the same pattern:

```python
def my_custom_check():
    section_header("MY CUSTOM MODULE", "🔧")

    result = read_file("/etc/myconfig")

    if "secure_setting" in result:
        add_finding("Custom", "My Check", "PASS", "LOW",
                    "Setting is secure ✓", "")
    else:
        add_finding("Custom", "My Check", "FAIL", "HIGH",
                    "Setting is insecure.",
                    "Set secure_setting=yes in /etc/myconfig.")
```

Register it in `main()`:

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
