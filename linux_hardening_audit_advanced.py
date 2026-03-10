#!/usr/bin/env python3
"""
Linux Server Hardening Audit Tool - ADVANCED EDITION (100+ Checks)
Created by: opsecramdan
Description: Read-only security audit script for Linux servers
             Safe to run on production systems.
"""

import os
import subprocess
import pwd
import grp
import stat
import re
import json
import sys
import socket
import platform
from datetime import datetime
from pathlib import Path

# ============================================================
# BANNER
# ============================================================

BANNER = r"""
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

    Linux Server Hardening Audit Tool  [ADVANCED EDITION - 100+ Checks]
    Created by  : opsecramdan
    Mode        : Read-Only | Non-Destructive | Production-Safe
    Purpose     : Comprehensive Security Posture Analysis
"""

# ============================================================
# COLORS
# ============================================================

class Color:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

def c(text, color):
    return f"{color}{text}{Color.RESET}"

# ============================================================
# GLOBAL REPORT STATE
# ============================================================

report_items  = []
total_checks  = 0
total_pass    = 0
total_warn    = 0
total_fail    = 0

def add_finding(section, check, status, risk, explanation, recommendation=""):
    global total_checks, total_pass, total_warn, total_fail
    total_checks += 1
    if status == "PASS":
        total_pass += 1
    elif status == "WARNING":
        total_warn += 1
    elif status == "FAIL":
        total_fail += 1

    report_items.append({
        "section": section, "check": check, "status": status,
        "risk": risk, "explanation": explanation, "recommendation": recommendation
    })

    status_color = {"PASS": Color.GREEN, "WARNING": Color.YELLOW, "FAIL": Color.RED}.get(status, Color.WHITE)
    risk_color   = {"LOW": Color.CYAN, "MEDIUM": Color.YELLOW, "HIGH": Color.RED,
                    "CRITICAL": Color.RED + Color.BOLD}.get(risk, Color.WHITE)

    prefix = {"PASS": "✔", "WARNING": "⚠", "FAIL": "✘"}.get(status, "?")
    print(f"  {c(prefix, status_color)} {c(check, Color.BOLD)} [{c(risk, risk_color)}]")
    print(f"    {c('→', Color.DIM)} {explanation}")
    if status != "PASS" and recommendation:
        print(f"    {c('Fix:', Color.CYAN)} {recommendation}")

def run_cmd(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.returncode
    except Exception:
        return "", 1

def file_contains(path, pattern):
    try:
        with open(path) as f:
            return bool(re.search(pattern, f.read(), re.MULTILINE | re.IGNORECASE))
    except Exception:
        return False

def read_file(path):
    try:
        with open(path) as f:
            return f.read()
    except Exception:
        return ""

def section_header(title, icon=""):
    print(f"\n{c('━' * 62, Color.BLUE)}")
    print(f"{c(f'  {icon}  [{title}]', Color.BOLD + Color.CYAN)}")
    print(f"{c('━' * 62, Color.BLUE)}")

# ============================================================
# MODULE 1 — SYSTEM INFORMATION
# ============================================================

def system_check():
    section_header("SYSTEM INFORMATION", "🖥")

    os_info,  _ = run_cmd("cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'")
    kernel,   _ = run_cmd("uname -r")
    arch,     _ = run_cmd("uname -m")
    uptime,   _ = run_cmd("uptime -p 2>/dev/null || uptime")
    virt,     _ = run_cmd("systemd-detect-virt 2>/dev/null || echo 'none'")
    last_boot,_ = run_cmd("who -b 2>/dev/null | awk '{print $3, $4}'")
    cpu_info, _ = run_cmd("grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2")
    mem_info, _ = run_cmd("free -h | grep Mem | awk '{print $2}'")
    disk_info,_ = run_cmd("df -h / | tail -1 | awk '{print $5}'")

    hostname = socket.gethostname()

    print(f"\n  {c('Hostname    :', Color.BOLD)} {hostname}")
    print(f"  {c('OS          :', Color.BOLD)} {os_info or 'Unknown'}")
    print(f"  {c('Kernel      :', Color.BOLD)} {kernel or 'Unknown'}")
    print(f"  {c('Architecture:', Color.BOLD)} {arch or 'Unknown'}")
    print(f"  {c('Uptime      :', Color.BOLD)} {uptime or 'Unknown'}")
    print(f"  {c('Last Boot   :', Color.BOLD)} {last_boot or 'Unknown'}")
    print(f"  {c('CPU         :', Color.BOLD)} {cpu_info.strip() or 'Unknown'}")
    print(f"  {c('Total RAM   :', Color.BOLD)} {mem_info or 'Unknown'}")
    print(f"  {c('Disk Usage /:', Color.BOLD)} {disk_info or 'Unknown'}")
    print(f"  {c('Virt        :', Color.BOLD)} {virt or 'none'}")

    # Check 1: Kernel version freshness (basic heuristic)
    kernel_major = re.search(r"^(\d+)\.(\d+)", kernel or "")
    if kernel_major:
        major = int(kernel_major.group(1))
        minor = int(kernel_major.group(2))
        if major >= 5 and minor >= 15:
            add_finding("System", "Kernel Version", "PASS", "LOW",
                        f"Kernel {kernel} appears modern.", "")
        else:
            add_finding("System", "Kernel Version", "WARNING", "MEDIUM",
                        f"Kernel {kernel} may be outdated.",
                        "Update kernel: 'apt update && apt upgrade' or 'yum update kernel'.")
    else:
        add_finding("System", "Kernel Version", "WARNING", "LOW",
                    "Could not parse kernel version.", "")

    # Check 2: Disk usage warning
    if disk_info:
        usage_pct = re.search(r"(\d+)%", disk_info)
        if usage_pct and int(usage_pct.group(1)) >= 90:
            add_finding("System", "Root Disk Usage", "FAIL", "HIGH",
                        f"Root partition is {disk_info} full — critical!",
                        "Free up disk space immediately.")
        elif usage_pct and int(usage_pct.group(1)) >= 75:
            add_finding("System", "Root Disk Usage", "WARNING", "MEDIUM",
                        f"Root partition is {disk_info} full.",
                        "Monitor and clean up disk space.")
        else:
            add_finding("System", "Root Disk Usage", "PASS", "LOW",
                        f"Root partition usage: {disk_info}.", "")

    # Check 3: Virtualization disclosure
    if virt and virt.lower() not in ("none", ""):
        add_finding("System", "Virtualization Detected", "WARNING", "LOW",
                    f"Running inside a virtualized environment: {virt}.",
                    "Ensure hypervisor security patches are applied by the provider.")
    else:
        add_finding("System", "Virtualization Detected", "PASS", "LOW",
                    "Bare-metal or virtualization not detected.", "")

# ============================================================
# MODULE 2 — USER SECURITY (12 checks)
# ============================================================

def user_check():
    section_header("USER SECURITY", "👤")

    all_users = pwd.getpwall()

    # Check 1: UID 0 non-root
    uid0 = [p.pw_name for p in all_users if p.pw_uid == 0 and p.pw_name != "root"]
    if uid0:
        add_finding("User Security", "Non-root UID 0 Accounts", "FAIL", "CRITICAL",
                    f"Accounts with UID 0: {', '.join(uid0)}",
                    "Remove or fix: 'usermod -u <newuid> <user>'.")
    else:
        add_finding("User Security", "Non-root UID 0 Accounts", "PASS", "LOW",
                    "No non-root accounts with UID 0.", "")

    # Check 2: Duplicate UIDs
    uids = [p.pw_uid for p in all_users]
    dup_uids = {u for u in uids if uids.count(u) > 1}
    if dup_uids:
        add_finding("User Security", "Duplicate UIDs", "WARNING", "MEDIUM",
                    f"Duplicate UIDs: {dup_uids}",
                    "Assign unique UIDs to all users.")
    else:
        add_finding("User Security", "Duplicate UIDs", "PASS", "LOW",
                    "All UIDs are unique.", "")

    # Check 3: Duplicate GIDs
    gids = [g.gr_gid for g in grp.getgrall()]
    dup_gids = {g for g in gids if gids.count(g) > 1}
    if dup_gids:
        add_finding("User Security", "Duplicate GIDs", "WARNING", "MEDIUM",
                    f"Duplicate GIDs: {dup_gids}",
                    "Assign unique GIDs to all groups.")
    else:
        add_finding("User Security", "Duplicate GIDs", "PASS", "LOW",
                    "All GIDs are unique.", "")

    # Check 4: Duplicate usernames
    usernames = [p.pw_name for p in all_users]
    dup_names = {n for n in usernames if usernames.count(n) > 1}
    if dup_names:
        add_finding("User Security", "Duplicate Usernames", "FAIL", "HIGH",
                    f"Duplicate usernames: {dup_names}",
                    "Remove duplicate entries from /etc/passwd.")
    else:
        add_finding("User Security", "Duplicate Usernames", "PASS", "LOW",
                    "No duplicate usernames.", "")

    # Check 5: Users with shell but no password (from /etc/shadow)
    try:
        with open("/etc/shadow") as f:
            shadow_lines = f.readlines()
        no_pass = []
        locked  = []
        for line in shadow_lines:
            parts = line.strip().split(":")
            if len(parts) < 2:
                continue
            user, pw = parts[0], parts[1]
            if pw in ("", "!!", ""):
                no_pass.append(user)
            elif pw.startswith("!") or pw.startswith("*"):
                locked.append(user)
        if no_pass:
            add_finding("User Security", "Empty Password Accounts", "FAIL", "CRITICAL",
                        f"Accounts with empty passwords: {', '.join(no_pass)}",
                        "Set passwords or lock: 'passwd -l <user>'.")
        else:
            add_finding("User Security", "Empty Password Accounts", "PASS", "LOW",
                        "No accounts with empty passwords.", "")

        add_finding("User Security", "Locked Accounts", "PASS", "LOW",
                    f"{len(locked)} account(s) properly locked (!, *).", "")
    except PermissionError:
        add_finding("User Security", "Shadow File Access", "WARNING", "MEDIUM",
                    "Cannot read /etc/shadow — run as root for full audit.",
                    "Re-run with sudo.")

    # Check 6: Users with interactive shell that shouldn't have one
    system_users_with_shell = [
        p.pw_name for p in all_users
        if p.pw_uid < 1000 and p.pw_uid != 0
        and p.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "")
        and p.pw_name not in ("sync", "shutdown", "halt")
    ]
    if system_users_with_shell:
        add_finding("User Security", "System Users With Login Shell", "WARNING", "MEDIUM",
                    f"System users with shell: {', '.join(system_users_with_shell[:5])}",
                    "Set shell to /usr/sbin/nologin for system accounts.")
    else:
        add_finding("User Security", "System Users With Login Shell", "PASS", "LOW",
                    "System accounts use nologin/false shells.", "")

    # Check 7: Root account path
    root_path, _ = run_cmd("grep '^root:' /etc/passwd | cut -d: -f6")
    if root_path == "/root":
        add_finding("User Security", "Root Home Directory", "PASS", "LOW",
                    "Root home is /root (standard).", "")
    else:
        add_finding("User Security", "Root Home Directory", "WARNING", "MEDIUM",
                    f"Root home is '{root_path}' (non-standard).",
                    "Verify root home directory is correct.")

    # Check 8: /etc/passwd permissions
    passwd_mode = stat.S_IMODE(os.stat("/etc/passwd").st_mode)
    if passwd_mode <= 0o644:
        add_finding("User Security", "/etc/passwd Permissions", "PASS", "LOW",
                    f"/etc/passwd permissions: {oct(passwd_mode)}.", "")
    else:
        add_finding("User Security", "/etc/passwd Permissions", "FAIL", "HIGH",
                    f"/etc/passwd has insecure permissions: {oct(passwd_mode)}.",
                    "chmod 644 /etc/passwd")

    # Check 9: /etc/shadow permissions
    if os.path.exists("/etc/shadow"):
        shadow_mode = stat.S_IMODE(os.stat("/etc/shadow").st_mode)
        if shadow_mode <= 0o640:
            add_finding("User Security", "/etc/shadow Permissions", "PASS", "LOW",
                        f"/etc/shadow permissions: {oct(shadow_mode)}.", "")
        else:
            add_finding("User Security", "/etc/shadow Permissions", "FAIL", "CRITICAL",
                        f"/etc/shadow has insecure permissions: {oct(shadow_mode)}.",
                        "chmod 640 /etc/shadow && chown root:shadow /etc/shadow")

    # Check 10: /etc/group permissions
    group_mode = stat.S_IMODE(os.stat("/etc/group").st_mode)
    if group_mode <= 0o644:
        add_finding("User Security", "/etc/group Permissions", "PASS", "LOW",
                    f"/etc/group permissions: {oct(group_mode)}.", "")
    else:
        add_finding("User Security", "/etc/group Permissions", "FAIL", "HIGH",
                    f"/etc/group has insecure permissions: {oct(group_mode)}.",
                    "chmod 644 /etc/group")

    # Check 11: Never-logged-in accounts
    lastlog_out, _ = run_cmd("lastlog 2>/dev/null | awk '$2==\"Never\" {print $1}'")
    never_logged = [u for u in lastlog_out.split("\n") if u and u != "Username"]
    if len(never_logged) > 5:
        add_finding("User Security", "Never-Logged-In Accounts", "WARNING", "MEDIUM",
                    f"{len(never_logged)} accounts have never logged in.",
                    "Disable unused accounts: 'usermod -L <user>'.")
    else:
        add_finding("User Security", "Never-Logged-In Accounts", "PASS", "LOW",
                    f"{len(never_logged)} account(s) never logged in — acceptable.", "")

    # Check 12: Home directory permissions
    bad_home = []
    for p in all_users:
        if p.pw_uid >= 1000 and os.path.isdir(p.pw_dir):
            mode = stat.S_IMODE(os.stat(p.pw_dir).st_mode)
            if mode & 0o022:
                bad_home.append(p.pw_name)
    if bad_home:
        add_finding("User Security", "World/Group-Writable Home Dirs", "WARNING", "MEDIUM",
                    f"Home dirs with loose permissions: {', '.join(bad_home[:5])}",
                    "chmod 750 /home/<user>")
    else:
        add_finding("User Security", "World/Group-Writable Home Dirs", "PASS", "LOW",
                    "All home directories have proper permissions.", "")

# ============================================================
# MODULE 3 — PASSWORD POLICY (8 checks)
# ============================================================

def password_policy_check():
    section_header("PASSWORD POLICY", "🔑")

    content = read_file("/etc/login.defs")

    def get_param(param):
        m = re.search(rf"^\s*{param}\s+(\S+)", content, re.MULTILINE)
        return m.group(1) if m else None

    # Check 1: PASS_MAX_DAYS
    val = get_param("PASS_MAX_DAYS")
    if val and int(val) <= 90:
        add_finding("Password Policy", "PASS_MAX_DAYS", "PASS", "LOW",
                    f"Password max age: {val} days.", "")
    elif val:
        add_finding("Password Policy", "PASS_MAX_DAYS", "WARNING", "MEDIUM",
                    f"PASS_MAX_DAYS is {val} (recommended ≤90).",
                    "Set PASS_MAX_DAYS 90 in /etc/login.defs.")
    else:
        add_finding("Password Policy", "PASS_MAX_DAYS", "FAIL", "HIGH",
                    "PASS_MAX_DAYS not configured.",
                    "Add 'PASS_MAX_DAYS 90' to /etc/login.defs.")

    # Check 2: PASS_MIN_LEN
    val = get_param("PASS_MIN_LEN")
    if val and int(val) >= 12:
        add_finding("Password Policy", "PASS_MIN_LEN", "PASS", "LOW",
                    f"Minimum password length: {val}.", "")
    elif val:
        add_finding("Password Policy", "PASS_MIN_LEN", "WARNING", "MEDIUM",
                    f"PASS_MIN_LEN is {val} (recommended ≥12).",
                    "Set PASS_MIN_LEN 12 in /etc/login.defs.")
    else:
        add_finding("Password Policy", "PASS_MIN_LEN", "FAIL", "HIGH",
                    "PASS_MIN_LEN not configured.",
                    "Add 'PASS_MIN_LEN 12' to /etc/login.defs.")

    # Check 3: PASS_MIN_DAYS
    val = get_param("PASS_MIN_DAYS")
    if val and int(val) >= 7:
        add_finding("Password Policy", "PASS_MIN_DAYS", "PASS", "LOW",
                    f"Minimum days between changes: {val}.", "")
    else:
        add_finding("Password Policy", "PASS_MIN_DAYS", "WARNING", "MEDIUM",
                    f"PASS_MIN_DAYS is '{val or 'not set'}' (recommended ≥7).",
                    "Set PASS_MIN_DAYS 7 in /etc/login.defs.")

    # Check 4: PASS_WARN_AGE
    val = get_param("PASS_WARN_AGE")
    if val and int(val) >= 7:
        add_finding("Password Policy", "PASS_WARN_AGE", "PASS", "LOW",
                    f"Password expiry warning: {val} days before.", "")
    else:
        add_finding("Password Policy", "PASS_WARN_AGE", "WARNING", "LOW",
                    f"PASS_WARN_AGE is '{val or 'not set'}' (recommended ≥7).",
                    "Set PASS_WARN_AGE 7 in /etc/login.defs.")

    # Check 5: pwquality / PAM complexity
    pam_pwq = os.path.exists("/etc/security/pwquality.conf")
    pam_pam = file_contains("/etc/pam.d/common-password", "pam_pwquality") or \
              file_contains("/etc/pam.d/system-auth", "pam_pwquality")
    if pam_pwq or pam_pam:
        add_finding("Password Policy", "PAM pwquality Module", "PASS", "LOW",
                    "pam_pwquality is configured for password complexity.", "")
    else:
        add_finding("Password Policy", "PAM pwquality Module", "WARNING", "MEDIUM",
                    "pam_pwquality not detected — no complexity enforcement.",
                    "Install libpam-pwquality and configure /etc/security/pwquality.conf.")

    # Check 6: pwquality minlen
    pwq = read_file("/etc/security/pwquality.conf")
    minlen_m = re.search(r"^\s*minlen\s*=\s*(\d+)", pwq, re.MULTILINE)
    if minlen_m and int(minlen_m.group(1)) >= 12:
        add_finding("Password Policy", "pwquality minlen", "PASS", "LOW",
                    f"pwquality minlen = {minlen_m.group(1)}.", "")
    elif minlen_m:
        add_finding("Password Policy", "pwquality minlen", "WARNING", "MEDIUM",
                    f"pwquality minlen = {minlen_m.group(1)} (recommended ≥12).",
                    "Set 'minlen = 12' in /etc/security/pwquality.conf.")
    else:
        add_finding("Password Policy", "pwquality minlen", "WARNING", "LOW",
                    "pwquality minlen not set.",
                    "Set 'minlen = 12' in /etc/security/pwquality.conf.")

    # Check 7: Account lockout (pam_tally2 or pam_faillock)
    has_lockout = (
        file_contains("/etc/pam.d/common-auth", "pam_tally") or
        file_contains("/etc/pam.d/common-auth", "pam_faillock") or
        file_contains("/etc/pam.d/system-auth", "pam_tally") or
        file_contains("/etc/pam.d/system-auth", "pam_faillock")
    )
    if has_lockout:
        add_finding("Password Policy", "Account Lockout Policy", "PASS", "LOW",
                    "Account lockout via pam_tally2 or pam_faillock is configured.", "")
    else:
        add_finding("Password Policy", "Account Lockout Policy", "FAIL", "HIGH",
                    "No account lockout policy detected — brute-force risk.",
                    "Configure pam_faillock in /etc/pam.d/common-auth.")

    # Check 8: Password hashing algorithm (SHA-512)
    encrypt_method = get_param("ENCRYPT_METHOD")
    if encrypt_method and "SHA512" in encrypt_method.upper():
        add_finding("Password Policy", "Password Hash Algorithm", "PASS", "LOW",
                    f"Password hashing uses {encrypt_method}.", "")
    else:
        add_finding("Password Policy", "Password Hash Algorithm", "WARNING", "MEDIUM",
                    f"ENCRYPT_METHOD is '{encrypt_method or 'not set'}' — SHA512 recommended.",
                    "Set 'ENCRYPT_METHOD SHA512' in /etc/login.defs.")

# ============================================================
# MODULE 4 — SSH SECURITY (14 checks)
# ============================================================

def ssh_check():
    section_header("SSH SECURITY", "🔐")

    sshd_config = "/etc/ssh/sshd_config"
    if not os.path.exists(sshd_config):
        add_finding("SSH Security", "sshd_config", "WARNING", "MEDIUM",
                    "sshd_config not found — SSH may not be installed.", "")
        return

    raw = read_file(sshd_config)

    def get_val(param):
        m = re.search(rf"^\s*{param}\s+(\S+)", raw, re.MULTILINE | re.IGNORECASE)
        return m.group(1) if m else None

    checks = [
        ("PermitRootLogin",       lambda v: v and v.lower() in ("no","prohibit-password","forced-commands-only"),
         "FAIL", "HIGH", "Root SSH login enabled.", "Set 'PermitRootLogin no'."),
        ("PasswordAuthentication",lambda v: v and v.lower() == "no",
         "WARNING", "MEDIUM", "Password auth enabled — brute-force risk.", "Use SSH keys only."),
        ("PermitEmptyPasswords",  lambda v: not v or v.lower() == "no",
         "FAIL", "CRITICAL", "Empty password SSH login is ENABLED!", "Set 'PermitEmptyPasswords no'."),
        ("X11Forwarding",         lambda v: not v or v.lower() == "no",
         "WARNING", "MEDIUM", "X11 forwarding is enabled.", "Set 'X11Forwarding no'."),
        ("AllowAgentForwarding",  lambda v: not v or v.lower() == "no",
         "WARNING", "LOW", "Agent forwarding enabled — lateral movement risk.", "Set 'AllowAgentForwarding no'."),
        ("AllowTcpForwarding",    lambda v: not v or v.lower() == "no",
         "WARNING", "MEDIUM", "TCP forwarding enabled — tunneling risk.", "Set 'AllowTcpForwarding no'."),
        ("UseDNS",                lambda v: not v or v.lower() == "no",
         "WARNING", "LOW", "UseDNS enabled — may slow login.", "Set 'UseDNS no'."),
    ]

    for param, is_ok, fail_status, fail_risk, fail_msg, fix in checks:
        val = get_val(param)
        if is_ok(val):
            add_finding("SSH Security", param, "PASS", "LOW",
                        f"{param} is properly configured ({val or 'default'}).", "")
        else:
            add_finding("SSH Security", param, fail_status, fail_risk,
                        f"{param} = '{val or 'not set'}'. {fail_msg}", fix)

    # MaxAuthTries
    val = get_val("MaxAuthTries")
    if val and int(val) <= 4:
        add_finding("SSH Security", "MaxAuthTries", "PASS", "LOW",
                    f"MaxAuthTries = {val}.", "")
    else:
        add_finding("SSH Security", "MaxAuthTries", "WARNING", "MEDIUM",
                    f"MaxAuthTries = '{val or '6 (default)'}' — lower recommended.",
                    "Set 'MaxAuthTries 3'.")

    # LoginGraceTime
    val = get_val("LoginGraceTime")
    if val and int(re.sub(r"[^0-9]", "", val)) <= 60:
        add_finding("SSH Security", "LoginGraceTime", "PASS", "LOW",
                    f"LoginGraceTime = {val}.", "")
    else:
        add_finding("SSH Security", "LoginGraceTime", "WARNING", "MEDIUM",
                    f"LoginGraceTime = '{val or '120 (default)'}' — reduce to limit exposure.",
                    "Set 'LoginGraceTime 30'.")

    # ClientAliveInterval
    val = get_val("ClientAliveInterval")
    if val and int(val) <= 300:
        add_finding("SSH Security", "ClientAliveInterval", "PASS", "LOW",
                    f"ClientAliveInterval = {val}s — idle timeout active.", "")
    else:
        add_finding("SSH Security", "ClientAliveInterval", "WARNING", "LOW",
                    f"ClientAliveInterval not configured — sessions may never timeout.",
                    "Set 'ClientAliveInterval 300' and 'ClientAliveCountMax 0'.")

    # Banner
    val = get_val("Banner")
    if val and val != "none":
        add_finding("SSH Security", "SSH Banner", "PASS", "LOW",
                    f"SSH login banner configured: {val}.", "")
    else:
        add_finding("SSH Security", "SSH Banner", "WARNING", "LOW",
                    "No SSH warning banner configured.",
                    "Set 'Banner /etc/issue.net' with a legal warning.")

    # Ciphers (weak cipher check)
    val = get_val("Ciphers")
    weak_ciphers = ["3des", "arcfour", "blowfish", "cast128", "aes128-cbc", "aes256-cbc"]
    if val:
        found_weak = [c for c in weak_ciphers if c in val.lower()]
        if found_weak:
            add_finding("SSH Security", "SSH Weak Ciphers", "FAIL", "HIGH",
                        f"Weak ciphers configured: {', '.join(found_weak)}",
                        "Remove weak ciphers from sshd_config Ciphers directive.")
        else:
            add_finding("SSH Security", "SSH Weak Ciphers", "PASS", "LOW",
                        "No weak ciphers detected in Ciphers directive.", "")
    else:
        add_finding("SSH Security", "SSH Weak Ciphers", "WARNING", "LOW",
                    "Ciphers not explicitly set — defaults apply.",
                    "Explicitly set strong ciphers in sshd_config.")

    # MACs (weak MAC check)
    val = get_val("MACs")
    weak_macs = ["hmac-md5", "hmac-sha1", "umac-64"]
    if val:
        found_weak = [m for m in weak_macs if m in val.lower()]
        if found_weak:
            add_finding("SSH Security", "SSH Weak MACs", "FAIL", "HIGH",
                        f"Weak MACs configured: {', '.join(found_weak)}",
                        "Remove weak MACs from sshd_config.")
        else:
            add_finding("SSH Security", "SSH Weak MACs", "PASS", "LOW",
                        "No weak MACs detected.", "")
    else:
        add_finding("SSH Security", "SSH Weak MACs", "WARNING", "LOW",
                    "MACs not explicitly set — defaults apply.",
                    "Explicitly restrict MACs to hmac-sha2-256, hmac-sha2-512.")

# ============================================================
# MODULE 5 — NETWORK SECURITY (8 checks)
# ============================================================

DANGEROUS_PORTS = {
    23: "Telnet", 21: "FTP", 69: "TFTP", 111: "RPC",
    2049: "NFS", 3306: "MySQL", 5432: "PostgreSQL",
    27017: "MongoDB", 6379: "Redis", 5984: "CouchDB",
    9200: "Elasticsearch", 8080: "HTTP-Alt/Dev", 8443: "HTTPS-Alt",
    2375: "Docker (unencrypted)", 4444: "Metasploit/backdoor",
    5555: "ADB/Android Debug", 4369: "RabbitMQ EPMD",
    11211: "Memcached", 9042: "Cassandra"
}

def network_check():
    section_header("NETWORK SECURITY", "🌐")

    out, rc = run_cmd("ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null")
    if rc != 0 or not out:
        add_finding("Network", "Open Ports", "WARNING", "MEDIUM",
                    "Could not retrieve open ports.", "Install iproute2.")
        return

    dangerous_found = []
    public_services  = []

    for line in out.split("\n")[1:]:
        port_m = re.search(r":(\d+)\s", line)
        if port_m:
            port = int(port_m.group(1))
            if port in DANGEROUS_PORTS:
                # Check if bound to 0.0.0.0 or :: (public)
                if "0.0.0.0" in line or ":::" in line or "*:" in line:
                    dangerous_found.append(f"Port {port} ({DANGEROUS_PORTS[port]})")
                else:
                    public_services.append(f"Port {port} ({DANGEROUS_PORTS[port]}) - localhost only")

    # Check 1: Dangerous public ports
    if dangerous_found:
        add_finding("Network", "Publicly Exposed Sensitive Ports", "FAIL", "HIGH",
                    f"Sensitive services on public interfaces: {', '.join(dangerous_found)}",
                    "Bind services to localhost or restrict with firewall rules.")
    else:
        add_finding("Network", "Publicly Exposed Sensitive Ports", "PASS", "LOW",
                    "No sensitive ports exposed on public interfaces.", "")

    # Check 2: Localhost-only services
    if public_services:
        add_finding("Network", "Sensitive Ports (localhost only)", "PASS", "LOW",
                    f"Sensitive services bound to localhost: {', '.join(public_services)}", "")

    # Check 3: IPv6 status
    ipv6_out, _ = run_cmd("sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null")
    if "= 1" in ipv6_out:
        add_finding("Network", "IPv6 Status", "PASS", "LOW",
                    "IPv6 is disabled system-wide.", "")
    else:
        add_finding("Network", "IPv6 Status", "WARNING", "LOW",
                    "IPv6 is enabled — ensure it is intentional and secured.",
                    "Disable if not needed: 'sysctl -w net.ipv6.conf.all.disable_ipv6=1'.")

    # Check 4: Network interface count
    ifaces, _ = run_cmd("ip link show | grep '^[0-9]' | awk -F: '{print $2}' | tr -d ' '")
    iface_list = [i for i in ifaces.split("\n") if i and i != "lo"]
    if len(iface_list) > 2:
        add_finding("Network", "Network Interfaces", "WARNING", "LOW",
                    f"Multiple interfaces detected: {', '.join(iface_list)} — review if needed.",
                    "Disable unused interfaces.")
    else:
        add_finding("Network", "Network Interfaces", "PASS", "LOW",
                    f"Network interfaces: {', '.join(iface_list)}.", "")

    # Check 5: /etc/hosts.allow and hosts.deny (TCP Wrappers)
    hosts_allow = os.path.exists("/etc/hosts.allow")
    hosts_deny  = os.path.exists("/etc/hosts.deny")
    if hosts_allow and hosts_deny:
        add_finding("Network", "TCP Wrappers (hosts.allow/deny)", "PASS", "LOW",
                    "TCP Wrappers files exist (hosts.allow, hosts.deny).", "")
    else:
        add_finding("Network", "TCP Wrappers (hosts.allow/deny)", "WARNING", "LOW",
                    "TCP Wrappers not fully configured.",
                    "Create /etc/hosts.deny with 'ALL: ALL' as default deny.")

    # Check 6: /etc/hosts integrity
    hosts_content = read_file("/etc/hosts")
    suspicious_hosts = re.findall(r"^\s*\d+\.\d+\.\d+\.\d+\s+(?!localhost|ip6)(\S+)", hosts_content, re.MULTILINE)
    if len(suspicious_hosts) > 5:
        add_finding("Network", "/etc/hosts Entries", "WARNING", "MEDIUM",
                    f"{len(suspicious_hosts)} custom /etc/hosts entries — review for hijacking.",
                    "Audit /etc/hosts for unauthorized entries.")
    else:
        add_finding("Network", "/etc/hosts Entries", "PASS", "LOW",
                    f"/etc/hosts has {len(suspicious_hosts)} custom entries — normal.", "")

    # Check 7: resolv.conf DNS servers
    resolv = read_file("/etc/resolv.conf")
    nameservers = re.findall(r"^nameserver\s+(\S+)", resolv, re.MULTILINE)
    if nameservers:
        add_finding("Network", "DNS Nameservers", "PASS", "LOW",
                    f"DNS servers configured: {', '.join(nameservers)}", "")
    else:
        add_finding("Network", "DNS Nameservers", "WARNING", "MEDIUM",
                    "No nameservers configured in /etc/resolv.conf.",
                    "Configure DNS servers in /etc/resolv.conf.")

    # Check 8: NFS exports
    exports = read_file("/etc/exports")
    if exports and "*" in exports:
        add_finding("Network", "NFS Wildcard Exports", "FAIL", "HIGH",
                    "NFS exports with wildcard (*) found — all hosts can mount!",
                    "Restrict NFS exports to specific IP ranges in /etc/exports.")
    elif exports:
        add_finding("Network", "NFS Exports", "WARNING", "MEDIUM",
                    "NFS exports configured — verify they are necessary.",
                    "Review /etc/exports and restrict access.")
    else:
        add_finding("Network", "NFS Exports", "PASS", "LOW",
                    "No NFS exports configured.", "")

# ============================================================
# MODULE 6 — FIREWALL (6 checks)
# ============================================================

def firewall_check():
    section_header("FIREWALL STATUS", "🛡")

    # Check 1: UFW
    ufw_out, ufw_rc = run_cmd("ufw status verbose 2>/dev/null")
    if ufw_rc == 0 and "active" in ufw_out.lower():
        add_finding("Firewall", "UFW Status", "PASS", "LOW", "UFW is active.", "")

        # Check 2: UFW default policy
        if "deny (incoming)" in ufw_out.lower():
            add_finding("Firewall", "UFW Default Incoming Policy", "PASS", "LOW",
                        "UFW default incoming policy: DENY.", "")
        else:
            add_finding("Firewall", "UFW Default Incoming Policy", "FAIL", "HIGH",
                        "UFW default incoming policy is not DENY.",
                        "Set: 'ufw default deny incoming'.")
        return

    # Check 3: firewalld
    fw_out, fw_rc = run_cmd("firewall-cmd --state 2>/dev/null")
    if fw_rc == 0 and "running" in fw_out.lower():
        add_finding("Firewall", "firewalld Status", "PASS", "LOW", "firewalld is running.", "")

        # Default zone
        zone_out, _ = run_cmd("firewall-cmd --get-default-zone 2>/dev/null")
        add_finding("Firewall", "firewalld Default Zone", "PASS", "LOW",
                    f"Default zone: {zone_out or 'unknown'}.", "")
        return

    # Check 4: iptables
    ipt_out, ipt_rc = run_cmd("iptables -L -n 2>/dev/null | head -50")
    if ipt_rc == 0 and ipt_out:
        drop_found   = "DROP" in ipt_out or "REJECT" in ipt_out
        policy_input = re.search(r"Chain INPUT.*policy (\w+)", ipt_out)

        if drop_input := policy_input:
            policy = drop_input.group(1)
            if policy == "DROP":
                add_finding("Firewall", "iptables INPUT Policy", "PASS", "LOW",
                            "iptables INPUT chain policy: DROP.", "")
            else:
                add_finding("Firewall", "iptables INPUT Policy", "WARNING", "MEDIUM",
                            f"iptables INPUT chain policy: {policy} (should be DROP).",
                            "Set: 'iptables -P INPUT DROP'.")

        if drop_found:
            add_finding("Firewall", "iptables Rules", "PASS", "LOW",
                        "iptables has blocking rules configured.", "")
        else:
            add_finding("Firewall", "iptables Rules", "WARNING", "MEDIUM",
                        "iptables present but no blocking rules found.",
                        "Configure proper iptables rules.")
    else:
        add_finding("Firewall", "Firewall Status", "FAIL", "HIGH",
                    "No active firewall detected (UFW, firewalld, iptables).",
                    "Install and enable: 'apt install ufw && ufw enable'.")

    # Check 5: ip6tables
    ip6_out, ip6_rc = run_cmd("ip6tables -L -n 2>/dev/null | head -10")
    if ip6_rc == 0 and "DROP" in (ip6_out or ""):
        add_finding("Firewall", "ip6tables IPv6 Rules", "PASS", "LOW",
                    "ip6tables has blocking rules for IPv6.", "")
    else:
        add_finding("Firewall", "ip6tables IPv6 Rules", "WARNING", "MEDIUM",
                    "No ip6tables IPv6 blocking rules found.",
                    "Configure ip6tables rules or disable IPv6.")

# ============================================================
# MODULE 7 — RUNNING SERVICES (8 checks)
# ============================================================

LEGACY_SERVICES = {
    "telnet": "CRITICAL", "rsh": "CRITICAL", "rlogin": "CRITICAL",
    "tftp": "HIGH", "talk": "MEDIUM", "ntalk": "MEDIUM",
    "finger": "MEDIUM", "rpcbind": "MEDIUM", "ypserv": "HIGH",
    "cups": "LOW", "avahi-daemon": "LOW", "inetd": "HIGH",
    "xinetd": "HIGH", "chargen": "MEDIUM", "daytime": "LOW",
    "echo": "LOW", "discard": "LOW", "rstatd": "MEDIUM",
    "rusersd": "MEDIUM", "rwalld": "MEDIUM"
}

def service_check():
    section_header("RUNNING SERVICES", "⚙")

    out, rc = run_cmd("systemctl list-units --type=service --state=running --no-pager 2>/dev/null")
    if rc != 0 or not out:
        add_finding("Services", "Active Services", "WARNING", "MEDIUM",
                    "Could not list running services.", "")
        return

    # Check 1: Legacy services
    found_legacy = {svc: risk for svc, risk in LEGACY_SERVICES.items() if svc in out.lower()}
    if found_legacy:
        for svc, risk in found_legacy.items():
            add_finding("Services", f"Legacy Service: {svc}", "FAIL", risk,
                        f"Legacy/unnecessary service running: {svc}",
                        f"Disable: 'systemctl disable --now {svc}'.")
    else:
        add_finding("Services", "Legacy Services", "PASS", "LOW",
                    "No legacy or unnecessary services detected.", "")

    # Check 2: cron running
    cron_running = "cron" in out.lower() or "crond" in out.lower()
    add_finding("Services", "Cron Daemon", "PASS" if cron_running else "WARNING", "LOW",
                "Cron daemon is running." if cron_running else "Cron daemon not running — scheduled tasks may fail.", "")

    # Check 3: SSH running
    ssh_running = "ssh" in out.lower() or "sshd" in out.lower()
    add_finding("Services", "SSH Daemon", "PASS" if ssh_running else "WARNING", "LOW",
                "SSH daemon is running." if ssh_running else "SSH daemon not running.", "")

    # Check 4: Unnecessary mail server
    mail_running = any(m in out.lower() for m in ["postfix", "sendmail", "exim", "qmail"])
    if mail_running:
        add_finding("Services", "Mail Server (MTA)", "WARNING", "MEDIUM",
                    "A mail server (MTA) is running — needed?",
                    "If not a mail server, disable the MTA service.")
    else:
        add_finding("Services", "Mail Server (MTA)", "PASS", "LOW",
                    "No MTA/mail server running.", "")

    # Check 5: NFS server
    nfs_running = "nfs-server" in out.lower() or "nfsd" in out.lower()
    if nfs_running:
        add_finding("Services", "NFS Server", "WARNING", "MEDIUM",
                    "NFS server is running — ensure exports are restricted.",
                    "Review /etc/exports and restrict to known hosts.")
    else:
        add_finding("Services", "NFS Server", "PASS", "LOW",
                    "NFS server not running.", "")

    # Check 6: Samba
    samba_running = any(s in out.lower() for s in ["smbd", "nmbd", "samba"])
    if samba_running:
        add_finding("Services", "Samba Service", "WARNING", "MEDIUM",
                    "Samba is running — file sharing exposed.",
                    "Restrict Samba to specific hosts in smb.conf.")
    else:
        add_finding("Services", "Samba Service", "PASS", "LOW",
                    "Samba not running.", "")

# ============================================================
# MODULE 8 — FILE SYSTEM SECURITY (10 checks)
# ============================================================

def filesystem_check():
    section_header("FILE SYSTEM SECURITY", "📁")

    # Check 1: SUID files
    suid_out, _ = run_cmd("find / -xdev -perm -4000 -type f 2>/dev/null")
    suid_files = [f for f in suid_out.split("\n") if f]
    if len(suid_files) > 15:
        add_finding("File System", "SUID Files", "WARNING", "MEDIUM",
                    f"Found {len(suid_files)} SUID files — review unusual ones.",
                    "Remove unnecessary SUID bits: 'chmod u-s <file>'.")
    else:
        add_finding("File System", "SUID Files", "PASS", "LOW",
                    f"{len(suid_files)} SUID files — within normal range.", "")

    # Check 2: SGID files
    sgid_out, _ = run_cmd("find / -xdev -perm -2000 -type f 2>/dev/null")
    sgid_files = [f for f in sgid_out.split("\n") if f]
    if len(sgid_files) > 15:
        add_finding("File System", "SGID Files", "WARNING", "MEDIUM",
                    f"Found {len(sgid_files)} SGID files.",
                    "Remove unnecessary SGID bits: 'chmod g-s <file>'.")
    else:
        add_finding("File System", "SGID Files", "PASS", "LOW",
                    f"{len(sgid_files)} SGID files — normal range.", "")

    # Check 3: World-writable files
    ww_out, _ = run_cmd(
        "find / -xdev -path /proc -prune -o -path /sys -prune -o -perm -0002 -type f -print 2>/dev/null | head -30"
    )
    ww_files = [f for f in ww_out.split("\n") if f and "/proc" not in f and "/sys" not in f]
    if ww_files:
        add_finding("File System", "World-Writable Files", "WARNING", "MEDIUM",
                    f"{len(ww_files)} world-writable files found: {', '.join(ww_files[:3])}...",
                    "Remove world-write permission: 'chmod o-w <file>'.")
    else:
        add_finding("File System", "World-Writable Files", "PASS", "LOW",
                    "No world-writable files found.", "")

    # Check 4: World-writable directories (not sticky)
    wwd_out, _ = run_cmd(
        "find / -xdev -path /proc -prune -o -path /sys -prune -o -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | head -20"
    )
    wwd = [f for f in wwd_out.split("\n") if f and "/proc" not in f]
    if wwd:
        add_finding("File System", "World-Writable Dirs Without Sticky Bit", "WARNING", "HIGH",
                    f"{len(wwd)} world-writable dirs without sticky bit: {', '.join(wwd[:3])}",
                    "Add sticky bit: 'chmod +t <dir>'.")
    else:
        add_finding("File System", "World-Writable Dirs Without Sticky Bit", "PASS", "LOW",
                    "All world-writable dirs have sticky bit set.", "")

    # Check 5-9: Critical file permissions
    critical_files = {
        "/etc/passwd":   (0o644, "644"),
        "/etc/shadow":   (0o640, "640"),
        "/etc/sudoers":  (0o440, "440"),
        "/etc/group":    (0o644, "644"),
        "/etc/gshadow":  (0o640, "640"),
    }
    for filepath, (max_mode, mode_str) in critical_files.items():
        if not os.path.exists(filepath):
            continue
        actual = stat.S_IMODE(os.stat(filepath).st_mode)
        if actual <= max_mode:
            add_finding("File System", f"Perms: {filepath}", "PASS", "LOW",
                        f"{filepath} permissions: {oct(actual)} (OK).", "")
        else:
            add_finding("File System", f"Perms: {filepath}", "FAIL", "HIGH",
                        f"{filepath} permissions {oct(actual)} — too permissive.",
                        f"chmod {mode_str} {filepath}")

    # Check 10: /tmp is noexec
    mount_out, _ = run_cmd("mount | grep ' /tmp '")
    if mount_out and "noexec" in mount_out:
        add_finding("File System", "/tmp noexec Mount Option", "PASS", "LOW",
                    "/tmp is mounted with noexec.", "")
    else:
        add_finding("File System", "/tmp noexec Mount Option", "WARNING", "MEDIUM",
                    "/tmp may not have noexec — scripts can execute from /tmp.",
                    "Add 'noexec,nosuid,nodev' to /tmp in /etc/fstab.")

# ============================================================
# MODULE 9 — CRON SECURITY (6 checks)
# ============================================================

SUSPICIOUS_CRON_PATTERNS = [
    (r"curl\s+http", "curl download in cron"),
    (r"wget\s+http", "wget download in cron"),
    (r"bash\s+-[ic]", "bash with -i/-c flag"),
    (r"nc\s+-", "netcat usage"),
    (r"python.*http\.server", "Python HTTP server"),
    (r"chmod\s+777", "chmod 777 in cron"),
    (r"/tmp/\S+\.(sh|py|pl|rb)", "script execution from /tmp"),
    (r"base64\s+-d", "base64 decode in cron"),
    (r"eval\s*\(", "eval() in cron"),
    (r"mkfifo", "FIFO pipe creation"),
]

def cron_check():
    section_header("CRON SECURITY", "⏰")

    cron_paths = [
        "/etc/crontab", "/etc/cron.d/", "/etc/cron.daily/",
        "/etc/cron.hourly/", "/etc/cron.weekly/", "/etc/cron.monthly/",
        "/var/spool/cron/", "/var/spool/cron/crontabs/"
    ]

    all_content = ""
    for path in cron_paths:
        if os.path.isfile(path):
            all_content += read_file(path) + "\n"
        elif os.path.isdir(path):
            for fname in os.listdir(path):
                fpath = os.path.join(path, fname)
                if os.path.isfile(fpath):
                    all_content += read_file(fpath) + "\n"

    # Check 1: Suspicious patterns
    found_suspicious = []
    for pattern, desc in SUSPICIOUS_CRON_PATTERNS:
        if re.search(pattern, all_content, re.IGNORECASE):
            found_suspicious.append(desc)

    if found_suspicious:
        add_finding("Cron", "Suspicious Cron Patterns", "FAIL", "HIGH",
                    f"Suspicious cron patterns: {', '.join(found_suspicious)}",
                    "Review all cron jobs and remove unauthorized entries.")
    else:
        add_finding("Cron", "Suspicious Cron Patterns", "PASS", "LOW",
                    "No suspicious patterns in cron jobs.", "")

    # Check 2: /etc/cron.allow
    if os.path.exists("/etc/cron.allow"):
        add_finding("Cron", "/etc/cron.allow", "PASS", "LOW",
                    "cron.allow exists — only listed users can schedule cron jobs.", "")
    else:
        add_finding("Cron", "/etc/cron.allow", "WARNING", "MEDIUM",
                    "cron.allow does not exist — any user may create cron jobs.",
                    "Create /etc/cron.allow with only authorized users.")

    # Check 3: /etc/cron.deny
    if os.path.exists("/etc/cron.deny"):
        add_finding("Cron", "/etc/cron.deny", "PASS", "LOW",
                    "cron.deny exists.", "")
    else:
        add_finding("Cron", "/etc/cron.deny", "WARNING", "LOW",
                    "cron.deny does not exist.",
                    "Create /etc/cron.deny to blacklist unauthorized users.")

    # Check 4: User crontabs
    crontab_out, _ = run_cmd("ls /var/spool/cron/crontabs/ 2>/dev/null || ls /var/spool/cron/ 2>/dev/null")
    users_with_cron = [u for u in crontab_out.split("\n") if u]
    if len(users_with_cron) > 2:
        add_finding("Cron", "User Crontabs", "WARNING", "MEDIUM",
                    f"Multiple users with crontabs: {', '.join(users_with_cron)}",
                    "Review each user crontab for unauthorized jobs.")
    else:
        add_finding("Cron", "User Crontabs", "PASS", "LOW",
                    f"{len(users_with_cron)} user crontab(s) found — normal.", "")

    # Check 5: /etc/crontab permissions
    if os.path.exists("/etc/crontab"):
        cron_mode = stat.S_IMODE(os.stat("/etc/crontab").st_mode)
        if cron_mode <= 0o640:
            add_finding("Cron", "/etc/crontab Permissions", "PASS", "LOW",
                        f"/etc/crontab permissions: {oct(cron_mode)}.", "")
        else:
            add_finding("Cron", "/etc/crontab Permissions", "WARNING", "MEDIUM",
                        f"/etc/crontab permissions: {oct(cron_mode)} — too permissive.",
                        "chmod 600 /etc/crontab")

    # Check 6: at.allow
    if os.path.exists("/etc/at.allow"):
        add_finding("Cron", "/etc/at.allow", "PASS", "LOW",
                    "at.allow exists — restricts 'at' job scheduling.", "")
    else:
        add_finding("Cron", "/etc/at.allow", "WARNING", "LOW",
                    "at.allow not found — any user can schedule 'at' jobs.",
                    "Create /etc/at.allow with authorized users only.")

# ============================================================
# MODULE 10 — SUDO SECURITY (6 checks)
# ============================================================

def sudo_check():
    section_header("SUDO SECURITY", "🔓")

    sudoers_content = read_file("/etc/sudoers")
    sudoers_dir = "/etc/sudoers.d/"
    if os.path.isdir(sudoers_dir):
        for f in os.listdir(sudoers_dir):
            sudoers_content += read_file(os.path.join(sudoers_dir, f))

    # Check 1: NOPASSWD
    nopasswd = re.findall(r"^[^#].*NOPASSWD.*", sudoers_content, re.MULTILINE)
    if nopasswd:
        add_finding("Sudo", "NOPASSWD Rules", "WARNING", "HIGH",
                    f"{len(nopasswd)} NOPASSWD sudo rule(s) found.",
                    "Require password for all sudo operations where possible.")
    else:
        add_finding("Sudo", "NOPASSWD Rules", "PASS", "LOW",
                    "No NOPASSWD sudo rules detected.", "")

    # Check 2: ALL=(ALL) ALL
    all_rules = re.findall(r"^[^#].+ALL\s*=\s*\(ALL\)\s*ALL", sudoers_content, re.MULTILINE)
    if len(all_rules) > 1:
        add_finding("Sudo", "Overly Broad Sudo Rules", "WARNING", "MEDIUM",
                    f"{len(all_rules)} wildcard ALL=(ALL) ALL rules found.",
                    "Restrict sudo to specific commands.")
    elif all_rules:
        add_finding("Sudo", "Overly Broad Sudo Rules", "PASS", "LOW",
                    "Root sudo access exists — verify it is intended.", "")
    else:
        add_finding("Sudo", "Overly Broad Sudo Rules", "PASS", "LOW",
                    "No wildcard sudo rules found.", "")

    # Check 3: Sudo logging
    sudo_log = re.search(r"Defaults.*logfile|Defaults.*syslog", sudoers_content, re.IGNORECASE)
    if sudo_log:
        add_finding("Sudo", "Sudo Logging", "PASS", "LOW",
                    "Sudo logging configured in sudoers.", "")
    else:
        add_finding("Sudo", "Sudo Logging", "WARNING", "MEDIUM",
                    "Sudo logging not explicitly configured.",
                    "Add 'Defaults logfile=/var/log/sudo.log' to /etc/sudoers.")

    # Check 4: requiretty
    req_tty = re.search(r"Defaults.*requiretty", sudoers_content, re.IGNORECASE)
    if req_tty:
        add_finding("Sudo", "Sudo requiretty", "PASS", "LOW",
                    "requiretty is set — prevents sudo from non-TTY sessions.", "")
    else:
        add_finding("Sudo", "Sudo requiretty", "WARNING", "LOW",
                    "requiretty not set in sudoers.",
                    "Add 'Defaults requiretty' to /etc/sudoers.")

    # Check 5: sudo timestamp timeout
    timeout_m = re.search(r"Defaults.*timestamp_timeout\s*=\s*(-?\d+)", sudoers_content)
    if timeout_m:
        timeout = int(timeout_m.group(1))
        if timeout <= 5:
            add_finding("Sudo", "Sudo Timestamp Timeout", "PASS", "LOW",
                        f"Sudo timestamp timeout: {timeout} min.", "")
        else:
            add_finding("Sudo", "Sudo Timestamp Timeout", "WARNING", "LOW",
                        f"Sudo timestamp timeout is {timeout} min (recommended ≤5).",
                        "Set 'Defaults timestamp_timeout=5' in /etc/sudoers.")
    else:
        add_finding("Sudo", "Sudo Timestamp Timeout", "WARNING", "LOW",
                    "Sudo timestamp timeout not explicitly set (default 5 min).",
                    "Explicitly set 'Defaults timestamp_timeout=5'.")

    # Check 6: visudo syntax
    _, visudo_rc = run_cmd("visudo -c 2>/dev/null")
    if visudo_rc == 0:
        add_finding("Sudo", "sudoers Syntax", "PASS", "LOW",
                    "sudoers file syntax is valid.", "")
    else:
        add_finding("Sudo", "sudoers Syntax", "FAIL", "CRITICAL",
                    "sudoers file has syntax errors — sudo may not work!",
                    "Fix with: 'visudo' to edit and validate sudoers.")

# ============================================================
# MODULE 11 — KERNEL SECURITY (15 checks)
# ============================================================

KERNEL_PARAMS = [
    ("net.ipv4.ip_forward",                     "0",  "HIGH",   "IP forwarding should be disabled on workstations/servers."),
    ("net.ipv4.tcp_syncookies",                  "1",  "HIGH",   "SYN cookies protect against SYN flood DoS attacks."),
    ("net.ipv4.conf.all.accept_source_route",    "0",  "MEDIUM", "Source routing allows packet path manipulation."),
    ("net.ipv4.conf.default.accept_source_route","0",  "MEDIUM", "Source routing should be disabled on all interfaces."),
    ("net.ipv4.conf.all.accept_redirects",       "0",  "MEDIUM", "ICMP redirects can be used for MITM attacks."),
    ("net.ipv4.conf.default.accept_redirects",   "0",  "MEDIUM", "ICMP redirects should be disabled."),
    ("net.ipv4.conf.all.send_redirects",         "0",  "MEDIUM", "Sending ICMP redirects should be disabled."),
    ("net.ipv4.conf.all.log_martians",           "1",  "LOW",    "Logging martian packets helps detect spoofing."),
    ("net.ipv4.conf.all.rp_filter",              "1",  "MEDIUM", "Reverse path filtering prevents IP spoofing."),
    ("kernel.randomize_va_space",                "2",  "HIGH",   "Full ASLR should be enabled (value=2)."),
    ("fs.suid_dumpable",                         "0",  "MEDIUM", "SUID core dumps should be disabled."),
    ("kernel.dmesg_restrict",                    "1",  "LOW",    "Restrict dmesg to root."),
    ("kernel.kptr_restrict",                     "2",  "MEDIUM", "Restrict kernel pointer exposure."),
    ("net.ipv6.conf.all.accept_redirects",       "0",  "MEDIUM", "IPv6 ICMP redirects should be disabled."),
    ("kernel.core_uses_pid",                     "1",  "LOW",    "Core dumps should use PID in filename."),
]

def kernel_check():
    section_header("KERNEL SECURITY (sysctl)", "🧠")

    for param, expected, risk, desc in KERNEL_PARAMS:
        actual, rc = run_cmd(f"sysctl -n {param} 2>/dev/null")
        actual = actual.strip()
        if actual == expected:
            add_finding("Kernel", param, "PASS", "LOW",
                        f"{param} = {actual} ✓", "")
        elif actual:
            add_finding("Kernel", param, "FAIL", risk,
                        f"{param} = {actual} (expected {expected}). {desc}",
                        f"sysctl -w {param}={expected} && add to /etc/sysctl.conf")
        else:
            add_finding("Kernel", param, "WARNING", "LOW",
                        f"{param} not found.",
                        f"Add '{param} = {expected}' to /etc/sysctl.conf.")

# ============================================================
# MODULE 12 — LOGGING (8 checks)
# ============================================================

def logging_check():
    section_header("LOGGING & AUDITING", "📋")

    services = {
        "rsyslog":    ("FAIL",    "HIGH",   "rsyslog not running — system logs disabled!",
                       "systemctl enable --now rsyslog"),
        "auditd":     ("WARNING", "MEDIUM", "auditd not running — no kernel-level audit trail.",
                       "apt install auditd && systemctl enable --now auditd"),
        "syslog":     ("WARNING", "LOW",    "syslog not running.", ""),
    }

    for svc, (fail_status, risk, msg, fix) in services.items():
        out, _ = run_cmd(f"systemctl is-active {svc} 2>/dev/null")
        if out.strip() == "active":
            add_finding("Logging", f"{svc} Status", "PASS", "LOW",
                        f"{svc} is active.", "")
        else:
            add_finding("Logging", f"{svc} Status", fail_status, risk, msg, fix)

    # Check 4: logrotate
    logrotate = os.path.exists("/etc/logrotate.conf") or os.path.isdir("/etc/logrotate.d/")
    add_finding("Logging", "logrotate", "PASS" if logrotate else "WARNING",
                "LOW" if logrotate else "MEDIUM",
                "logrotate configured." if logrotate else "logrotate not found.",
                "" if logrotate else "apt install logrotate")

    # Check 5: /var/log/auth.log or secure exists
    auth_log = os.path.exists("/var/log/auth.log") or os.path.exists("/var/log/secure")
    add_finding("Logging", "Auth Log File", "PASS" if auth_log else "FAIL",
                "LOW" if auth_log else "HIGH",
                "Auth log file exists." if auth_log else "No auth log found — login activity not logged!",
                "" if auth_log else "Ensure rsyslog is running and auth.log exists.")

    # Check 6: audit rules configured
    if os.path.exists("/etc/audit/audit.rules"):
        audit_rules = read_file("/etc/audit/audit.rules")
        rule_count = len([l for l in audit_rules.split("\n") if l.strip().startswith("-a") or l.strip().startswith("-w")])
        if rule_count >= 5:
            add_finding("Logging", "Audit Rules", "PASS", "LOW",
                        f"{rule_count} audit rules configured.", "")
        else:
            add_finding("Logging", "Audit Rules", "WARNING", "MEDIUM",
                        f"Only {rule_count} audit rules configured — may be insufficient.",
                        "Add comprehensive audit rules to /etc/audit/audit.rules.")
    else:
        add_finding("Logging", "Audit Rules", "WARNING", "MEDIUM",
                    "No audit rules file found.",
                    "Configure /etc/audit/audit.rules with appropriate rules.")

    # Check 7: /var/log permissions
    log_mode = stat.S_IMODE(os.stat("/var/log").st_mode)
    if log_mode <= 0o755:
        add_finding("Logging", "/var/log Permissions", "PASS", "LOW",
                    f"/var/log permissions: {oct(log_mode)}.", "")
    else:
        add_finding("Logging", "/var/log Permissions", "WARNING", "MEDIUM",
                    f"/var/log has permissive mode: {oct(log_mode)}.",
                    "chmod 755 /var/log")

    # Check 8: journald persistent logging
    journald = read_file("/etc/systemd/journald.conf")
    if "Storage=persistent" in journald:
        add_finding("Logging", "journald Persistent Storage", "PASS", "LOW",
                    "journald configured with persistent storage.", "")
    else:
        add_finding("Logging", "journald Persistent Storage", "WARNING", "LOW",
                    "journald not set to persistent storage — logs may be lost on reboot.",
                    "Set 'Storage=persistent' in /etc/systemd/journald.conf.")

# ============================================================
# MODULE 13 — PAM SECURITY (6 checks)
# ============================================================

def pam_check():
    section_header("PAM SECURITY", "🔒")

    pam_files = [
        "/etc/pam.d/common-auth",
        "/etc/pam.d/common-password",
        "/etc/pam.d/system-auth",
        "/etc/pam.d/password-auth",
    ]

    pam_content = ""
    for f in pam_files:
        pam_content += read_file(f)

    # Check 1: pam_faillock or pam_tally2
    has_lockout = bool(re.search(r"pam_(faillock|tally2)", pam_content))
    add_finding("PAM", "Account Lockout (faillock/tally2)",
                "PASS" if has_lockout else "FAIL",
                "LOW" if has_lockout else "HIGH",
                "Account lockout configured via pam_faillock/tally2." if has_lockout else "No account lockout policy!",
                "" if has_lockout else "Configure pam_faillock in /etc/pam.d/common-auth.")

    # Check 2: pam_pwhistory (password history)
    has_history = "pam_pwhistory" in pam_content
    add_finding("PAM", "Password History (pam_pwhistory)",
                "PASS" if has_history else "WARNING",
                "LOW" if has_history else "MEDIUM",
                "Password history enforced via pam_pwhistory." if has_history else "Password history not enforced.",
                "" if has_history else "Add pam_pwhistory.so remember=5 to PAM config.")

    # Check 3: pam_unix with sha512
    has_sha512 = "sha512" in pam_content
    add_finding("PAM", "Password Hashing SHA-512",
                "PASS" if has_sha512 else "WARNING",
                "LOW" if has_sha512 else "MEDIUM",
                "SHA-512 hashing in PAM." if has_sha512 else "SHA-512 not explicitly configured in PAM.",
                "" if has_sha512 else "Add 'sha512' to pam_unix.so in common-password.")

    # Check 4: pam_securetty
    securetty = os.path.exists("/etc/securetty")
    add_finding("PAM", "/etc/securetty",
                "PASS" if securetty else "WARNING",
                "LOW",
                "/etc/securetty exists — limits root login to secure TTYs." if securetty else "/etc/securetty not found.",
                "" if securetty else "Create /etc/securetty to restrict root console access.")

    # Check 5: su restriction
    su_pam = read_file("/etc/pam.d/su")
    su_restricted = "pam_wheel" in su_pam
    add_finding("PAM", "su Restricted to wheel Group",
                "PASS" if su_restricted else "WARNING",
                "LOW" if su_restricted else "MEDIUM",
                "su is restricted via pam_wheel." if su_restricted else "su not restricted to wheel group.",
                "" if su_restricted else "Enable pam_wheel.so in /etc/pam.d/su.")

    # Check 6: /etc/pam.d/ permissions
    pam_d_mode = stat.S_IMODE(os.stat("/etc/pam.d").st_mode)
    if pam_d_mode <= 0o755:
        add_finding("PAM", "/etc/pam.d Permissions", "PASS", "LOW",
                    f"/etc/pam.d permissions: {oct(pam_d_mode)}.", "")
    else:
        add_finding("PAM", "/etc/pam.d Permissions", "WARNING", "MEDIUM",
                    f"/etc/pam.d has loose permissions: {oct(pam_d_mode)}.",
                    "chmod 755 /etc/pam.d")

# ============================================================
# MODULE 14 — CONTAINER SECURITY (6 checks)
# ============================================================

def container_check():
    section_header("CONTAINER SECURITY", "🐳")

    # Check 1: Docker installed
    docker_out, docker_rc = run_cmd("docker --version 2>/dev/null")
    if docker_rc != 0 or not docker_out:
        add_finding("Container", "Docker Installation", "PASS", "LOW",
                    "Docker not installed — no container attack surface.", "")
        return

    add_finding("Container", "Docker Installation", "WARNING", "LOW",
                f"Docker installed: {docker_out}",
                "Ensure Docker daemon is properly hardened.")

    # Check 2: Docker socket permissions
    if os.path.exists("/var/run/docker.sock"):
        sock_mode = stat.S_IMODE(os.stat("/var/run/docker.sock").st_mode)
        if sock_mode & 0o002:
            add_finding("Container", "Docker Socket Permissions", "FAIL", "CRITICAL",
                        "Docker socket is world-readable/writable — anyone can control Docker!",
                        "chmod 660 /var/run/docker.sock")
        else:
            add_finding("Container", "Docker Socket Permissions", "PASS", "LOW",
                        f"Docker socket permissions: {oct(sock_mode)}.", "")

    # Check 3: Docker TCP socket (unencrypted)
    tcp_docker, _ = run_cmd("ss -tlnp 2>/dev/null | grep ':2375'")
    if tcp_docker:
        add_finding("Container", "Docker TCP Port (2375)", "FAIL", "CRITICAL",
                    "Docker API exposed on TCP port 2375 (unencrypted)!",
                    "Disable TCP Docker API or use TLS on port 2376.")
    else:
        add_finding("Container", "Docker TCP Port (2375)", "PASS", "LOW",
                    "Docker TCP API port 2375 not exposed.", "")

    # Check 4: Privileged containers
    priv_out, _ = run_cmd("docker ps --quiet 2>/dev/null | xargs -I{} docker inspect --format '{{.Name}} {{.HostConfig.Privileged}}' {} 2>/dev/null | grep 'true'")
    if priv_out:
        add_finding("Container", "Privileged Containers", "FAIL", "CRITICAL",
                    f"Privileged containers found: {priv_out[:200]}",
                    "Never run containers with --privileged unless absolutely required.")
    else:
        add_finding("Container", "Privileged Containers", "PASS", "LOW",
                    "No privileged containers detected.", "")

    # Check 5: Docker info – userns-remap
    docker_info, _ = run_cmd("docker info 2>/dev/null")
    if "userns" in docker_info.lower():
        add_finding("Container", "Docker User Namespace Remapping", "PASS", "LOW",
                    "User namespace remapping is enabled.", "")
    else:
        add_finding("Container", "Docker User Namespace Remapping", "WARNING", "MEDIUM",
                    "User namespace remapping not enabled — containers run as root.",
                    "Enable userns-remap in /etc/docker/daemon.json.")

    # Check 6: Docker daemon.json
    daemon_json = read_file("/etc/docker/daemon.json")
    if daemon_json:
        add_finding("Container", "Docker daemon.json", "PASS", "LOW",
                    "Docker daemon.json configured.", "")
    else:
        add_finding("Container", "Docker daemon.json", "WARNING", "LOW",
                    "Docker daemon.json not found — using defaults.",
                    "Create /etc/docker/daemon.json with security options.")

# ============================================================
# MODULE 15 — MALWARE & ROOTKIT DETECTION (4 checks)
# ============================================================

def malware_check():
    section_header("MALWARE & ROOTKIT DETECTION", "🦠")

    # Check 1: rkhunter
    rkh_out, rkh_rc = run_cmd("which rkhunter 2>/dev/null")
    if rkh_rc == 0:
        add_finding("Malware", "rkhunter Installed", "PASS", "LOW",
                    "rkhunter is installed for rootkit detection.", "")
        # Run rkhunter check (read-only)
        rkh_check, _ = run_cmd("rkhunter --check --sk --rwo 2>/dev/null | head -30")
        warnings = [l for l in rkh_check.split("\n") if "Warning" in l or "INFECTED" in l]
        if warnings:
            add_finding("Malware", "rkhunter Findings", "FAIL", "HIGH",
                        f"rkhunter warnings: {len(warnings)} issue(s) found.",
                        "Review: 'rkhunter --check --sk' for full details.")
        else:
            add_finding("Malware", "rkhunter Findings", "PASS", "LOW",
                        "rkhunter found no obvious issues.", "")
    else:
        add_finding("Malware", "rkhunter Installed", "WARNING", "MEDIUM",
                    "rkhunter not installed.",
                    "Install: 'apt install rkhunter && rkhunter --update'.")

    # Check 2: chkrootkit
    chk_out, chk_rc = run_cmd("which chkrootkit 2>/dev/null")
    if chk_rc == 0:
        add_finding("Malware", "chkrootkit Installed", "PASS", "LOW",
                    "chkrootkit is installed.", "")
    else:
        add_finding("Malware", "chkrootkit Installed", "WARNING", "MEDIUM",
                    "chkrootkit not installed.",
                    "Install: 'apt install chkrootkit'.")

    # Check 3: ClamAV
    clam_out, clam_rc = run_cmd("which clamscan 2>/dev/null || which clamav 2>/dev/null")
    if clam_rc == 0:
        add_finding("Malware", "ClamAV Installed", "PASS", "LOW",
                    "ClamAV antivirus is installed.", "")
    else:
        add_finding("Malware", "ClamAV Installed", "WARNING", "LOW",
                    "ClamAV not installed.",
                    "Install: 'apt install clamav && freshclam'.")

    # Check 4: Suspicious processes (simple heuristic)
    ps_out, _ = run_cmd("ps aux 2>/dev/null")
    suspicious_procs = []
    suspicious_keywords = ["nc -l", "bash -i", "python.*reverse", "socat.*exec", "/tmp/.", "cryptominer"]
    for kw in suspicious_keywords:
        if re.search(kw, ps_out, re.IGNORECASE):
            suspicious_procs.append(kw)

    if suspicious_procs:
        add_finding("Malware", "Suspicious Processes", "FAIL", "CRITICAL",
                    f"Suspicious process patterns detected: {', '.join(suspicious_procs)}",
                    "Investigate immediately with 'ps aux' and 'lsof -p <pid>'.")
    else:
        add_finding("Malware", "Suspicious Processes", "PASS", "LOW",
                    "No obviously suspicious processes detected.", "")

# ============================================================
# MODULE 16 — SYSTEM PACKAGES & UPDATES (5 checks)
# ============================================================

def package_check():
    section_header("PACKAGE & UPDATE SECURITY", "📦")

    # Check 1: Unattended upgrades
    unattended = (
        os.path.exists("/etc/apt/apt.conf.d/50unattended-upgrades") or
        os.path.exists("/etc/yum/yum.conf")
    )
    add_finding("Packages", "Automatic Security Updates",
                "PASS" if unattended else "WARNING",
                "LOW" if unattended else "MEDIUM",
                "Automatic security updates configured." if unattended else "Automatic updates not configured.",
                "" if unattended else "Install: 'apt install unattended-upgrades && dpkg-reconfigure unattended-upgrades'.")

    # Check 2: Pending updates (apt)
    apt_out, apt_rc = run_cmd("apt list --upgradable 2>/dev/null | grep -c upgradable")
    if apt_rc == 0 and apt_out.isdigit():
        count = int(apt_out)
        if count == 0:
            add_finding("Packages", "Pending Updates (apt)", "PASS", "LOW",
                        "System is up to date.", "")
        elif count < 10:
            add_finding("Packages", "Pending Updates (apt)", "WARNING", "MEDIUM",
                        f"{count} package updates pending.",
                        "Run: 'apt update && apt upgrade'.")
        else:
            add_finding("Packages", "Pending Updates (apt)", "FAIL", "HIGH",
                        f"{count} package updates pending — system may be vulnerable.",
                        "Run: 'apt update && apt upgrade' immediately.")

    # Check 3: Security updates specifically
    apt_sec, _ = run_cmd("apt list --upgradable 2>/dev/null | grep -i security | wc -l")
    if apt_sec.isdigit() and int(apt_sec) > 0:
        add_finding("Packages", "Pending Security Updates", "FAIL", "HIGH",
                    f"{apt_sec} security updates pending!",
                    "Apply immediately: 'apt upgrade'.")
    else:
        add_finding("Packages", "Pending Security Updates", "PASS", "LOW",
                    "No pending security-specific updates.", "")

    # Check 4: Package integrity (dpkg)
    debsums_out, debsums_rc = run_cmd("which debsums 2>/dev/null")
    if debsums_rc == 0:
        add_finding("Packages", "debsums Package Integrity", "PASS", "LOW",
                    "debsums is installed for package integrity verification.", "")
    else:
        add_finding("Packages", "debsums Package Integrity", "WARNING", "LOW",
                    "debsums not installed — cannot verify package file integrity.",
                    "Install: 'apt install debsums' and run 'debsums -c'.")

    # Check 5: apt-get source list integrity
    sources_list = read_file("/etc/apt/sources.list")
    if "https://" in sources_list:
        add_finding("Packages", "APT HTTPS Repositories", "PASS", "LOW",
                    "APT repositories using HTTPS.", "")
    elif "http://" in sources_list:
        add_finding("Packages", "APT HTTPS Repositories", "WARNING", "MEDIUM",
                    "Some APT repositories using plain HTTP.",
                    "Update sources to use HTTPS where possible.")
    else:
        add_finding("Packages", "APT Sources", "WARNING", "LOW",
                    "Could not verify APT source URLs.", "")

# ============================================================
# MODULE 17 — BOOT SECURITY (4 checks)
# ============================================================

def boot_check():
    section_header("BOOT SECURITY", "🥾")

    # Check 1: GRUB password
    grub_cfg = read_file("/boot/grub/grub.cfg") + read_file("/boot/grub2/grub.cfg")
    has_grub_password = "password_pbkdf2" in grub_cfg or "set superusers" in grub_cfg
    add_finding("Boot", "GRUB Bootloader Password",
                "PASS" if has_grub_password else "WARNING",
                "LOW" if has_grub_password else "MEDIUM",
                "GRUB bootloader password is set." if has_grub_password else "No GRUB password detected.",
                "" if has_grub_password else "Set GRUB password to prevent unauthorized boot modification.")

    # Check 2: GRUB config permissions
    for grub_path in ["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"]:
        if os.path.exists(grub_path):
            mode = stat.S_IMODE(os.stat(grub_path).st_mode)
            if mode <= 0o600:
                add_finding("Boot", "GRUB Config Permissions", "PASS", "LOW",
                            f"{grub_path} permissions: {oct(mode)}.", "")
            else:
                add_finding("Boot", "GRUB Config Permissions", "WARNING", "MEDIUM",
                            f"{grub_path} has loose permissions: {oct(mode)}.",
                            f"chmod og-rwx {grub_path}")
            break

    # Check 3: Secure Boot
    sb_out, _ = run_cmd("mokutil --sb-state 2>/dev/null || bootctl status 2>/dev/null | grep 'Secure Boot'")
    if "enabled" in sb_out.lower():
        add_finding("Boot", "Secure Boot", "PASS", "LOW",
                    "Secure Boot is enabled.", "")
    else:
        add_finding("Boot", "Secure Boot", "WARNING", "MEDIUM",
                    "Secure Boot status unknown or disabled.",
                    "Enable Secure Boot in BIOS/UEFI settings.")

    # Check 4: Single-user mode password
    su_mode = read_file("/etc/inittab") + read_file("/usr/lib/systemd/system/rescue.service")
    if "sulogin" in su_mode or "ExecStart" in su_mode:
        add_finding("Boot", "Single-User Mode Authentication", "PASS", "LOW",
                    "Single-user mode requires authentication.", "")
    else:
        add_finding("Boot", "Single-User Mode Authentication", "WARNING", "MEDIUM",
                    "Could not verify single-user mode authentication.",
                    "Ensure rescue/single-user mode requires root password.")

# ============================================================
# FINAL REPORT & SCORE
# ============================================================

def calculate_score():
    if total_checks == 0:
        return 0
    score = ((total_pass * 1.0) + (total_warn * 0.5)) / total_checks * 100
    return round(score)

def print_summary():
    score = calculate_score()

    print(f"\n\n{c('═' * 64, Color.BOLD)}")
    print(c("    LINUX SECURITY AUDIT — COMPREHENSIVE REPORT SUMMARY", Color.BOLD + Color.CYAN))
    print(f"{c('═' * 64, Color.BOLD)}")
    print(f"  {c('Generated  :', Color.BOLD)} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {c('Hostname   :', Color.BOLD)} {socket.gethostname()}")
    print(f"  {c('Audited By :', Color.BOLD)} opsecramdan — Linux Hardening Audit Tool")
    print(f"{c('─' * 64, Color.DIM)}")
    print(f"  {c('Total Checks :', Color.BOLD)} {total_checks}")
    print(f"  {c('PASS', Color.GREEN + Color.BOLD)}         : {total_pass}")
    print(f"  {c('WARNING', Color.YELLOW + Color.BOLD)}      : {total_warn}")
    print(f"  {c('FAIL', Color.RED + Color.BOLD)}         : {total_fail}")
    print(f"{c('─' * 64, Color.DIM)}")

    # Score
    if score >= 85:
        sc, rating = Color.GREEN, "EXCELLENT 🏆"
    elif score >= 70:
        sc, rating = Color.GREEN, "GOOD ✅"
    elif score >= 55:
        sc, rating = Color.YELLOW, "FAIR ⚠️"
    elif score >= 40:
        sc, rating = Color.RED, "POOR 🔴"
    else:
        sc, rating = Color.RED + Color.BOLD, "CRITICAL ☠️"

    print(f"\n  {c('SECURITY SCORE:', Color.BOLD)} {c(f'{score}/100  [{rating}]', sc)}")
    filled = int(score / 5)
    bar = "█" * filled + "░" * (20 - filled)
    print(f"  0 [{c(bar, sc)}] 100\n")

    # Section-by-section score
    print(f"{c('  SCORE BY SECTION:', Color.BOLD + Color.CYAN)}")
    sections = {}
    for item in report_items:
        sec = item["section"]
        if sec not in sections:
            sections[sec] = {"pass": 0, "warn": 0, "fail": 0, "total": 0}
        sections[sec]["total"] += 1
        if item["status"] == "PASS":
            sections[sec]["pass"] += 1
        elif item["status"] == "WARNING":
            sections[sec]["warn"] += 1
        else:
            sections[sec]["fail"] += 1

    for sec, data in sections.items():
        sec_score = round(((data["pass"] + data["warn"] * 0.5) / data["total"]) * 100)
        color = Color.GREEN if sec_score >= 75 else Color.YELLOW if sec_score >= 50 else Color.RED
        bar_f = int(sec_score / 10)
        mini_bar = "▓" * bar_f + "░" * (10 - bar_f)
        print(f"  {sec:<25} [{c(mini_bar, color)}] {c(str(sec_score) + '%', color)}")

    # Critical failures
    fails = [i for i in report_items if i["status"] == "FAIL"]
    if fails:
        print(f"\n{c('─' * 64, Color.RED)}")
        print(c(f"  ⚠  TOP CRITICAL FINDINGS ({len(fails)} items):", Color.RED + Color.BOLD))
        print(f"{c('─' * 64, Color.RED)}")
        for item in fails[:10]:
            print(f"  {c('✘', Color.RED)} [{item['risk']}] {item['check']}")
            print(f"    {c('→', Color.DIM)} {item['recommendation']}")

    print(f"\n{c('═' * 64, Color.BOLD)}\n")

def export_json(fname=None):
    fname = fname or f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    data = {
        "meta": {
            "tool": "Linux Hardening Audit Tool - Advanced Edition",
            "author": "opsecramdan",
            "timestamp": datetime.now().isoformat(),
            "hostname": socket.gethostname(),
            "score": calculate_score(),
            "total": total_checks, "pass": total_pass,
            "warning": total_warn, "fail": total_fail
        },
        "findings": report_items
    }
    with open(fname, "w") as f:
        json.dump(data, f, indent=2)
    return fname

# ============================================================
# MAIN
# ============================================================

def main():
    print(c(BANNER, Color.CYAN))
    print(c(f"  [ Audit Start: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ]", Color.BOLD))
    print(c(f"  [ Running as : {os.getenv('USER', 'unknown')} ]", Color.DIM))
    if os.geteuid() != 0:
        print(c("  ⚠  WARNING: Not running as root — some checks will be skipped.", Color.YELLOW + Color.BOLD))
    print()

    modules = [
        ("System Information",    system_check),
        ("User Security",         user_check),
        ("Password Policy",       password_policy_check),
        ("SSH Security",          ssh_check),
        ("Network Security",      network_check),
        ("Firewall Status",       firewall_check),
        ("Running Services",      service_check),
        ("File System Security",  filesystem_check),
        ("Cron Security",         cron_check),
        ("Sudo Security",         sudo_check),
        ("Kernel Security",       kernel_check),
        ("Logging & Auditing",    logging_check),
        ("PAM Security",          pam_check),
        ("Container Security",    container_check),
        ("Malware Detection",     malware_check),
        ("Package Security",      package_check),
        ("Boot Security",         boot_check),
    ]

    for name, fn in modules:
        try:
            fn()
        except Exception as e:
            print(f"  {c('[ERROR]', Color.RED)} Module '{name}' failed: {e}")

    print_summary()

    # Export
    json_file = export_json()
    print(f"  {c('📄 JSON report saved:', Color.CYAN)} {json_file}")
    print(f"  {c('✅ Audit complete!', Color.GREEN + Color.BOLD)} Total checks: {total_checks}\n")

if __name__ == "__main__":
    main()
