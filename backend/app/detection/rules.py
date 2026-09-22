"""Rule-based detection. Each rule takes a Context and returns a list of Detection objects.

These rules are deliberately simple and explainable: every detection lists the exact
event_ids that triggered it and a plain-English reason. The AI agents (Phases 5-6)
investigate on top of these findings; they do not replace them.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from .common import (Context, Detection, fmt_duration, is_external, process_name,
                     sev_name, sev_score, uniq_sorted)
from .config import DetectionConfig

# ==========================================================================
# Rule 1 - Brute force
# ==========================================================================
def _has_dense_window(cluster, ctx, window, threshold) -> bool:
    left = 0
    for right in range(len(cluster)):
        while ctx.t(cluster[right]) - ctx.t(cluster[left]) > window:
            left += 1
        if right - left + 1 >= threshold:
            return True
    return False


def detect_brute_force(ctx: Context, cfg: DetectionConfig) -> list[Detection]:
    window = timedelta(minutes=cfg.brute_force_window_minutes)
    success_window = timedelta(minutes=cfg.success_after_failure_minutes)

    failures_by_ip = defaultdict(list)
    for e in ctx.events:
        if e["event_type"] == "LOGIN" and e["status"] == "FAILED" and e["source_ip"]:
            failures_by_ip[e["source_ip"]].append(e)
    successes = [e for e in ctx.events if e["event_type"] == "LOGIN" and e["status"] == "SUCCESS"]

    detections = []
    for ip, fails in failures_by_ip.items():
        i = 0
        while i < len(fails):
            # A cluster is a run of failures where each is within `window` of the previous one
            j = i
            while j + 1 < len(fails) and ctx.t(fails[j + 1]) - ctx.t(fails[j]) <= window:
                j += 1
            cluster = fails[i:j + 1]
            i = j + 1
            if not _has_dense_window(cluster, ctx, window, cfg.brute_force_threshold):
                continue

            users = uniq_sorted(e["username"] for e in cluster)
            first, last = ctx.t(cluster[0]), ctx.t(cluster[-1])
            success = next(
                (s for s in successes
                 if s["source_ip"] == ip
                 and last < ctx.t(s) <= last + success_window
                 and (not users or s["username"] in users)),
                None,
            )

            score = 2 + (1 if len(cluster) >= 25 else 0) + (1 if success else 0)
            score = min(score, sev_score("HIGH"))  # only a correlated chain reaches CRITICAL
            duration = (last - first).total_seconds()
            who = ", ".join(f"'{u}'" for u in users) or "unknown accounts"
            reason = (f"{len(cluster)} failed login attempts from {ip} against {who} within "
                      f"{fmt_duration(duration)} (rule: at least {cfg.brute_force_threshold} "
                      f"in {cfg.brute_force_window_minutes} min).")
            if success:
                gap = (ctx.t(success) - last).total_seconds()
                reason += (f" A successful login from the same IP followed {fmt_duration(gap)} "
                           f"after the last failure.")

            event_ids = [e["event_id"] for e in cluster] + ([success["event_id"]] if success else [])
            detections.append(Detection(
                rule_id="BRUTE_FORCE",
                title=f"Repeated failed logins from {ip}",
                severity=sev_name(score),
                first_seen=first.isoformat(),
                last_seen=(ctx.t(success) if success else last).isoformat(),
                reason=reason,
                event_ids=ctx.order_ids(event_ids),
                source_ips=[ip],
                usernames=uniq_sorted(users + ([success["username"]] if success else [])),
                hostnames=uniq_sorted(e["hostname"] for e in cluster),
                destination_ips=uniq_sorted(e["destination_ip"] for e in cluster),
                details={
                    "failed_attempts": len(cluster),
                    "targeted_users": users,
                    "threshold": cfg.brute_force_threshold,
                    "window_minutes": cfg.brute_force_window_minutes,
                    "duration_seconds": duration,
                    "followed_by_success": success is not None,
                    "success_event_id": success["event_id"] if success else None,
                    "success_time": ctx.t(success).isoformat() if success else None,
                    "success_user": success["username"] if success else None,
                },
            ))
    return detections


# ==========================================================================
# Rule 2 - Suspicious PowerShell
# ==========================================================================
PS_NAMES = {"powershell", "powershell.exe", "pwsh", "pwsh.exe", "powershell_ise.exe"}
_PS_IN_CMD = re.compile(r"\b(powershell|pwsh)(\.exe)?\b", re.I)

_ENCODED = re.compile(r"\s-(?:e|ec|enc|encodedcommand)\s+[a-z0-9+/=]{16,}", re.I)
_CRADLE = re.compile(r"downloadstring|downloadfile|net\.webclient|invoke-webrequest|\biwr\b|"
                     r"invoke-restmethod|start-bitstransfer|invoke-expression|\biex\b", re.I)
_OFFICE_PARENT = re.compile(r"parent process:\s*(winword|excel|outlook|powerpnt|onenote)\.exe", re.I)
_HIDDEN = re.compile(r"\s-w(?:indowstyle)?\s+hidden", re.I)
_BYPASS = re.compile(r"\s-(?:ep|executionpolicy)\s+bypass", re.I)
_NOPROFILE = re.compile(r"\s-nop(?:rofile)?\b", re.I)

STRONG_PS = (("encoded_command", _ENCODED), ("download_cradle", _CRADLE),
             ("office_parent", _OFFICE_PARENT))
WEAK_PS = (("hidden_window", _HIDDEN), ("policy_bypass", _BYPASS), ("no_profile", _NOPROFILE))

PS_LABELS = {
    "encoded_command": "encoded command",
    "download_cradle": "download-and-execute pattern",
    "office_parent": "launched by an Office application",
    "follows_bruteforce_login": "ran shortly after a login that followed repeated failures",
    "hidden_window": "hidden window",
    "policy_bypass": "execution-policy bypass",
    "no_profile": "profile loading disabled",
}


def _is_powershell(e) -> bool:
    if e["event_type"] != "PROCESS":
        return False
    return process_name(e) in PS_NAMES or bool(_PS_IN_CMD.search(e["command_line"] or ""))


def detect_suspicious_powershell(ctx: Context, cfg: DetectionConfig,
                                 brute_detections: list[Detection]) -> list[Detection]:
    post_login = timedelta(minutes=cfg.post_login_powershell_minutes)
    compromised_logins = [
        (d.details["success_user"], d.source_ips[0], d.details["success_time"])
        for d in brute_detections if d.details["followed_by_success"]
    ]

    flagged = []  # (event, strong, weak)
    for e in ctx.events:
        if not _is_powershell(e):
            continue
        text = f" {e['command_line'] or ''} {e['message'] or ''} "
        strong = [name for name, rx in STRONG_PS if rx.search(text)]
        weak = [name for name, rx in WEAK_PS if rx.search(text)]
        for user, ip, when in compromised_logins:
            login_time = datetime.fromisoformat(when)
            if (e["username"] == user and e["source_ip"] == ip
                    and timedelta(0) <= ctx.t(e) - login_time <= post_login):
                strong.append("follows_bruteforce_login")
                break
        if strong or len(weak) >= 2:
            flagged.append((e, strong, weak))

    # Group by (host, user); a new group starts after a long gap
    groups = defaultdict(list)
    for item in flagged:
        groups[(item[0]["hostname"], item[0]["username"])].append(item)

    gap = timedelta(minutes=cfg.powershell_group_gap_minutes)
    detections = []
    for (_host, _user), items in groups.items():
        chunks, current = [], [items[0]]
        for item in items[1:]:
            if ctx.t(item[0]) - ctx.t(current[-1][0]) <= gap:
                current.append(item)
            else:
                chunks.append(current)
                current = [item]
        chunks.append(current)

        for chunk in chunks:
            events = [c[0] for c in chunk]
            strong_all = sorted({s for c in chunk for s in c[1]})
            weak_all = sorted({w for c in chunk for w in c[2]})
            high = len(strong_all) >= 2 or (strong_all and weak_all)
            labels = [PS_LABELS[x] for x in strong_all + weak_all]
            user = events[0]["username"] or "unknown user"
            host = events[0]["hostname"] or "unknown host"
            detections.append(Detection(
                rule_id="SUSPICIOUS_POWERSHELL",
                title=f"Suspicious PowerShell activity on {host}",
                severity="HIGH" if high else "MEDIUM",
                first_seen=ctx.t(events[0]).isoformat(),
                last_seen=ctx.t(events[-1]).isoformat(),
                reason=(f"{len(events)} PowerShell execution(s) by '{user}' on {host} showed: "
                        + "; ".join(labels) + "."),
                event_ids=ctx.order_ids(e["event_id"] for e in events),
                source_ips=uniq_sorted(e["source_ip"] for e in events),
                usernames=uniq_sorted(e["username"] for e in events),
                hostnames=uniq_sorted(e["hostname"] for e in events),
                details={
                    "strong_indicators": strong_all,
                    "weak_indicators": weak_all,
                    "events": [{"event_id": c[0]["event_id"], "strong": c[1], "weak": c[2]}
                               for c in chunk],
                },
            ))
    return detections


# ==========================================================================
# Rule 3 - Unusual login
# ==========================================================================
def detect_unusual_login(ctx: Context, cfg: DetectionConfig) -> list[Detection]:
    activity = Counter()          # (user, ip) -> number of events
    user_total = Counter()        # user -> number of events
    for e in ctx.events:
        if e["username"] and e["source_ip"]:
            activity[(e["username"], e["source_ip"])] += 1
            user_total[e["username"]] += 1

    flagged = defaultdict(list)   # (user, ip) -> [(event, signals)]
    for e in ctx.events:
        if not (e["event_type"] == "LOGIN" and e["status"] == "SUCCESS"
                and e["username"] and e["source_ip"]):
            continue
        signals = []
        if is_external(e["source_ip"]):
            signals.append("external_source_ip")
        total = user_total[e["username"]]
        if (total >= cfg.rare_source_min_events
                and activity[(e["username"], e["source_ip"])] / total < cfg.rare_source_share):
            signals.append("rarely_seen_source_for_user")
        hour = ctx.t(e).hour
        if not (cfg.business_hours_start <= hour < cfg.business_hours_end):
            signals.append("outside_business_hours")
        if len(signals) >= cfg.unusual_login_min_signals:
            flagged[(e["username"], e["source_ip"])].append((e, signals))

    labels = {
        "external_source_ip": "source IP is outside the internal network",
        "rarely_seen_source_for_user": "source IP is rarely used by this account",
        "outside_business_hours": "login happened outside business hours",
    }
    detections = []
    for (user, ip), items in flagged.items():
        events = [i[0] for i in items]
        signals = sorted({s for i in items for s in i[1]})
        best = max(len(i[1]) for i in items)
        detections.append(Detection(
            rule_id="UNUSUAL_LOGIN",
            title=f"Unusual successful login for '{user}' from {ip}",
            severity="HIGH" if best >= 3 else "MEDIUM",
            first_seen=ctx.t(events[0]).isoformat(),
            last_seen=ctx.t(events[-1]).isoformat(),
            reason=(f"Successful login for '{user}' from {ip}: "
                    + "; ".join(labels[s] for s in signals) + "."),
            event_ids=ctx.order_ids(e["event_id"] for e in events),
            source_ips=[ip],
            usernames=[user],
            hostnames=uniq_sorted(e["hostname"] for e in events),
            destination_ips=uniq_sorted(e["destination_ip"] for e in events),
            details={"signals": signals,
                     "events": [{"event_id": i[0]["event_id"], "signals": i[1]} for i in items],
                     "business_hours": f"{cfg.business_hours_start:02d}:00-{cfg.business_hours_end:02d}:00"},
        ))
    return detections


# ==========================================================================
# Rule 4 - Suspicious outbound connection
# ==========================================================================
SCRIPTING_PROCESSES = {"powershell.exe", "pwsh.exe", "powershell", "pwsh", "cmd.exe",
                       "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
                       "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}
SUSPICIOUS_PORTS = {4444, 1337, 31337, 6666, 9001, 5555}


def detect_suspicious_outbound(ctx: Context, cfg: DetectionConfig) -> list[Detection]:
    groups = defaultdict(list)
    for e in ctx.events:
        if e["event_type"] != "NETWORK" or not is_external(e["destination_ip"]):
            continue
        proc = process_name(e)
        if proc in SCRIPTING_PROCESSES or e["destination_port"] in SUSPICIOUS_PORTS:
            groups[(e["username"], e["hostname"], e["destination_ip"])].append(e)

    detections = []
    for (user, host, dest), events in groups.items():
        procs = uniq_sorted(process_name(e) for e in events)
        ports = sorted({e["destination_port"] for e in events if e["destination_port"]})
        risky_port = any(p in SUSPICIOUS_PORTS for p in ports)
        risky_proc = any(p in SCRIPTING_PROCESSES for p in procs)

        beacon_like = False
        if len(events) >= 3:
            gaps = [(ctx.t(b) - ctx.t(a)).total_seconds() for a, b in zip(events, events[1:])]
            mean = sum(gaps) / len(gaps)
            beacon_like = mean > 0 and (max(gaps) - min(gaps)) / mean <= 0.2

        reason = (f"{len(events)} outbound connection(s) from {host or 'unknown host'} "
                  f"(user '{user or 'unknown'}') to external address {dest}")
        if ports:
            reason += f" on port(s) {', '.join(map(str, ports))}"
        reason += f" by {', '.join(procs) or 'an unknown process'}."
        if beacon_like:
            reason += " The connections repeat at near-regular intervals (beaconing-like pattern)."

        detections.append(Detection(
            rule_id="SUSPICIOUS_OUTBOUND",
            title=f"Suspicious outbound connection to {dest}",
            severity="HIGH" if (risky_port or risky_proc) else "MEDIUM",
            first_seen=ctx.t(events[0]).isoformat(),
            last_seen=ctx.t(events[-1]).isoformat(),
            reason=reason,
            event_ids=[e["event_id"] for e in events],
            source_ips=uniq_sorted(e["source_ip"] for e in events),
            usernames=uniq_sorted(e["username"] for e in events),
            hostnames=uniq_sorted(e["hostname"] for e in events),
            destination_ips=[dest],
            details={"connections": len(events), "ports": ports, "processes": procs,
                     "risky_port": risky_port, "scripting_process": risky_proc,
                     "beacon_like": beacon_like},
        ))
    return detections


# ==========================================================================
# Rule 5 - Suspicious commands (discovery / persistence / download tools)
# ==========================================================================
COMMAND_PATTERNS = (
    # (category, name, regex, severity)
    ("persistence", "scheduled task created", re.compile(r"schtasks(\.exe)?\s+/create", re.I), "MEDIUM"),
    ("persistence", "registry run key", re.compile(r"reg(\.exe)?\s+add\s+.*\\run", re.I), "MEDIUM"),
    ("persistence", "local account created", re.compile(r"\bnet\s+user\s+\S+\s+\S+\s+/add", re.I), "MEDIUM"),
    ("persistence", "service created", re.compile(r"\bsc(\.exe)?\s+create\b", re.I), "MEDIUM"),
    ("download", "download via system utility", re.compile(r"certutil.*-urlcache|bitsadmin.*/transfer", re.I), "MEDIUM"),
    ("discovery", "account discovery (whoami)", re.compile(r"\bwhoami\b", re.I), "LOW"),
    ("discovery", "account/group listing (net user/group)", re.compile(r"\bnet\s+(user|group|localgroup|view)\b", re.I), "LOW"),
    ("discovery", "network configuration discovery", re.compile(r"\bipconfig\s+/all\b", re.I), "LOW"),
    ("discovery", "system information discovery", re.compile(r"\bsysteminfo\b|\bnltest\b", re.I), "LOW"),
)


def detect_suspicious_commands(ctx: Context, cfg: DetectionConfig) -> list[Detection]:
    gap = timedelta(minutes=cfg.powershell_group_gap_minutes)
    matches = defaultdict(list)  # (host, user) -> [(event, category, name, severity)]
    for e in ctx.events:
        if e["event_type"] != "PROCESS" or not e["command_line"]:
            continue
        for category, name, rx, severity in COMMAND_PATTERNS:  # first (most severe) match wins
            if rx.search(e["command_line"]):
                matches[(e["hostname"], e["username"])].append((e, category, name, severity))
                break

    detections = []
    for (host, user), items in matches.items():
        chunks, current = [], [items[0]]
        for item in items[1:]:
            if ctx.t(item[0]) - ctx.t(current[-1][0]) <= gap:
                current.append(item)
            else:
                chunks.append(current)
                current = [item]
        chunks.append(current)

        for chunk in chunks:
            events = [c[0] for c in chunk]
            categories = sorted({c[1] for c in chunk})
            names = sorted({c[2] for c in chunk})
            top = max(sev_score(c[3]) for c in chunk)
            detections.append(Detection(
                rule_id="SUSPICIOUS_COMMAND",
                title=f"Suspicious commands on {host or 'unknown host'}",
                severity=sev_name(top),
                first_seen=ctx.t(events[0]).isoformat(),
                last_seen=ctx.t(events[-1]).isoformat(),
                reason=(f"{len(events)} command(s) by '{user or 'unknown'}' matched: "
                        + "; ".join(names) + "."),
                event_ids=[e["event_id"] for e in events],
                source_ips=uniq_sorted(e["source_ip"] for e in events),
                usernames=uniq_sorted(e["username"] for e in events),
                hostnames=uniq_sorted(e["hostname"] for e in events),
                details={"categories": categories,
                         "matches": [{"event_id": c[0]["event_id"], "category": c[1],
                                      "pattern": c[2], "command_line": c[0]["command_line"]}
                                     for c in chunk]},
            ))
    return detections
