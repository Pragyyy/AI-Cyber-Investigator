"""Turn individual detections into incidents.

Two detections belong to the same incident when they share a username or a source IP
AND happen within `correlation_gap_minutes` of each other. An incident is only created
when it is worth an analyst's time: at least MEDIUM severity, or two or more detections.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from .common import Context, Detection, sev_name, sev_score, uniq_sorted
from .config import DetectionConfig

# When an incident contains several rules, the first one in this list names its type.
TYPE_PRECEDENCE = [
    ("BRUTE_FORCE", "brute_force"),
    ("UNUSUAL_LOGIN", "suspicious_authentication"),
    ("SUSPICIOUS_POWERSHELL", "suspicious_powershell"),
    ("SUSPICIOUS_OUTBOUND", "suspicious_outbound"),
    ("SUSPICIOUS_COMMAND", "suspicious_command"),
]
POST_COMPROMISE = {"SUSPICIOUS_POWERSHELL", "SUSPICIOUS_OUTBOUND", "SUSPICIOUS_COMMAND"}


def _linked(a: Detection, b: Detection, gap: timedelta) -> bool:
    shares_actor = bool(
        {u.lower() for u in a.usernames} & {u.lower() for u in b.usernames}
        or set(a.source_ips) & set(b.source_ips)
    )
    if not shares_actor:
        return False
    a1, a2 = datetime.fromisoformat(a.first_seen), datetime.fromisoformat(a.last_seen)
    b1, b2 = datetime.fromisoformat(b.first_seen), datetime.fromisoformat(b.last_seen)
    return max(a1, b1) - min(a2, b2) <= gap


def _group(detections: list[Detection], gap: timedelta) -> list[list[Detection]]:
    parent = list(range(len(detections)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for i in range(len(detections)):
        for j in range(i + 1, len(detections)):
            if _linked(detections[i], detections[j], gap):
                parent[find(i)] = find(j)

    groups: dict[int, list[Detection]] = {}
    for i, d in enumerate(detections):
        groups.setdefault(find(i), []).append(d)
    return list(groups.values())


def _classify(group: list[Detection]) -> tuple[str, str]:
    rules = {d.rule_id for d in group}
    brute_with_success = any(d.rule_id == "BRUTE_FORCE" and d.details["followed_by_success"]
                             for d in group)
    if len(rules) >= 3 or (brute_with_success and rules & POST_COMPROMISE):
        return "attack_chain", "Multi-Stage Attack Chain"

    for rule_id, incident_type in TYPE_PRECEDENCE:
        if rule_id in rules:
            break
    if incident_type == "brute_force":
        title = ("Brute-Force Attack with Successful Login" if brute_with_success
                 else "Possible Brute-Force Attack")
    elif incident_type == "suspicious_authentication":
        title = ("Suspicious Authentication Followed by Endpoint Activity" if len(rules) > 1
                 else "Suspicious Authentication")
    else:
        title = {"suspicious_powershell": "Suspicious PowerShell Activity",
                 "suspicious_outbound": "Suspicious Outbound Connection",
                 "suspicious_command": "Suspicious Command Execution"}[incident_type]
    return incident_type, title


def build_incidents(detections: list[Detection], ctx: Context,
                    cfg: DetectionConfig) -> list[dict]:
    gap = timedelta(minutes=cfg.correlation_gap_minutes)
    incidents = []
    for group in _group(detections, gap):
        top = max(sev_score(d.severity) for d in group)
        if top < sev_score("MEDIUM") and len(group) < 2:
            continue  # a lone low-severity detection is not worth an incident

        incident_type, title = _classify(group)
        score = min(top + (1 if incident_type == "attack_chain" else 0), sev_score("CRITICAL"))
        group.sort(key=lambda d: d.first_seen)
        event_ids = ctx.order_ids(i for d in group for i in d.event_ids)
        source_ips = uniq_sorted(ip for d in group for ip in d.source_ips)
        usernames = uniq_sorted(u for d in group for u in d.usernames)
        hostnames = uniq_sorted(h for d in group for h in d.hostnames)
        first = min(d.first_seen for d in group)
        last = max(d.last_seen for d in group)
        rules = [rule for rule, _ in TYPE_PRECEDENCE if any(d.rule_id == rule for d in group)]

        incidents.append({
            "incident_type": incident_type,
            "title": title,
            "severity": sev_name(score),
            "severity_score": score,
            "status": "open",
            "first_seen": first,
            "last_seen": last,
            "source_ips": source_ips,
            "usernames": usernames,
            "hostnames": hostnames,
            "destination_ips": uniq_sorted(ip for d in group for ip in d.destination_ips),
            "rules": rules,
            "detections": [d.to_dict() for d in group],
            "event_ids": event_ids,
            "event_count": len(event_ids),
            "summary": (f"{len(group)} detection(s) from {len(rules)} rule(s) between "
                        f"{first.replace('T', ' ')} and {last.replace('T', ' ')}; "
                        f"user(s): {', '.join(usernames) or 'n/a'}; "
                        f"source IP(s): {', '.join(source_ips) or 'n/a'}; "
                        f"host(s): {', '.join(hostnames) or 'n/a'}."),
        })

    incidents.sort(key=lambda i: (i["first_seen"], i["title"]))
    for n, incident in enumerate(incidents, start=1):
        incident["incident_id"] = f"INC-{n:03d}"
    return incidents
