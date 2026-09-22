"""Build a structured, traceable evidence package for one incident.

Every evidence item lists the exact event_ids that support it, so the final report can
always answer "why did the system reach this conclusion?" This module only states
facts found in the logs - it does not interpret them (no MITRE mapping, no verdict).
That happens in the Threat Intelligence and Investigation agents (Phases 5-6).
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from ..detection.common import Context, fmt_duration, uniq_sorted

RELATED_EVENT_WINDOW_MINUTES = 5

CATEGORY_LABELS = {
    "authentication": "Authentication",
    "process_execution": "Process Execution",
    "network": "Network Activity",
    "file": "File Artifact",
    "discovery": "Discovery",
    "persistence": "Persistence",
}

_COMMAND_CATEGORY_TO_EVIDENCE = {"discovery": "discovery", "persistence": "persistence",
                                 "download": "network"}


class _Counter:
    """Assigns EV-001, EV-002, ... in the order items are added."""

    def __init__(self):
        self.n = 0

    def next_id(self) -> str:
        self.n += 1
        return f"EV-{self.n:03d}"


def _item(counter, category, statement, event_ids, ctx, **extra):
    ids = ctx.order_ids(event_ids)
    return {
        "evidence_id": counter.next_id(),
        "category": category,
        "category_label": CATEGORY_LABELS[category],
        "statement": statement,
        "event_ids": ids,
        "event_count": len(ids),
        "first_seen": ctx.by_id[ids[0]]["timestamp"] if ids else None,
        "last_seen": ctx.by_id[ids[-1]]["timestamp"] if ids else None,
        **extra,
    }


# --------------------------------------------------------------------------
# Per-rule evidence builders. Each takes (detection_dict, ctx, counter) and
# returns a list of evidence items.
# --------------------------------------------------------------------------
def _from_brute_force(det, ctx, counter):
    items = []
    d = det["details"]
    fail_ids = [i for i in det["event_ids"] if i != d.get("success_event_id")]
    who = ", ".join(f"'{u}'" for u in d["targeted_users"]) or "the target account(s)"
    items.append(_item(
        counter, "authentication",
        f"{d['failed_attempts']} failed authentication attempts against {who} from "
        f"{det['source_ips'][0]} within {fmt_duration(d['duration_seconds'])}.",
        fail_ids, ctx,
    ))
    if d["followed_by_success"]:
        login_time = datetime.fromisoformat(d["success_time"])
        last_fail_time = ctx.by_id[fail_ids[-1]]["timestamp"]
        gap = (login_time - datetime.fromisoformat(last_fail_time)).total_seconds()
        items.append(_item(
            counter, "authentication",
            f"Successful authentication as '{d['success_user']}' from {det['source_ips'][0]} "
            f"followed {fmt_duration(gap)} after the last failed attempt.",
            [d["success_event_id"]], ctx,
        ))
    return items


def _from_powershell(det, ctx, counter):
    by_signal = defaultdict(list)
    for entry in det["details"]["events"]:
        for signal in entry["strong"] or entry["weak"] or ["unclassified"]:
            by_signal[signal].append(entry["event_id"])

    labels = {
        "encoded_command": "PowerShell executed with a base64-encoded command",
        "download_cradle": "PowerShell used a download-and-execute pattern "
                           "(e.g. DownloadString / Invoke-WebRequest / IEX)",
        "office_parent": "PowerShell was launched by an Office application, not interactively",
        "follows_bruteforce_login": "PowerShell executed shortly after a login that followed "
                                    "repeated authentication failures",
        "hidden_window": "PowerShell executed with a hidden window",
        "policy_bypass": "PowerShell executed with the execution policy bypassed",
        "no_profile": "PowerShell executed with profile loading disabled",
    }
    items = []
    for signal, ids in by_signal.items():
        items.append(_item(counter, "process_execution", labels.get(signal, signal) + ".",
                           ids, ctx))
    return items


def _from_unusual_login(det, ctx, counter):
    labels = {
        "external_source_ip": lambda ip: f"Successful login from external IP address {ip}.",
        "rarely_seen_source_for_user": lambda ip: f"Source IP {ip} is rarely used by this account.",
        "outside_business_hours": lambda ip: "Login occurred outside normal business hours.",
    }
    by_signal = defaultdict(list)
    for entry in det["details"]["events"]:
        for signal in entry["signals"]:
            by_signal[signal].append(entry["event_id"])
    ip = det["source_ips"][0] if det["source_ips"] else "unknown IP"
    return [_item(counter, "authentication", labels[s](ip) + f" (account: '{det['usernames'][0]}')",
                  ids, ctx)
            for s, ids in by_signal.items()]


def _from_outbound(det, ctx, counter):
    d = det["details"]
    dest = det["destination_ips"][0] if det["destination_ips"] else "an external host"
    ports = f" on port(s) {', '.join(map(str, d['ports']))}" if d["ports"] else ""
    statement = (f"{d['connections']} outbound connection(s) to external address {dest}{ports} "
                f"by {', '.join(d['processes']) or 'an unknown process'}.")
    items = [_item(counter, "network", statement, det["event_ids"], ctx,
                   destination_ip=dest, ports=d["ports"])]
    if d["beacon_like"]:
        items.append(_item(
            counter, "network",
            f"Connections to {dest} repeat at near-regular intervals, consistent with "
            f"command-and-control beaconing.",
            det["event_ids"], ctx,
        ))
    return items


def _from_commands(det, ctx, counter):
    by_pattern = defaultdict(list)
    pattern_category = {}
    example_cmd = {}
    for m in det["details"]["matches"]:
        by_pattern[m["pattern"]].append(m["event_id"])
        pattern_category[m["pattern"]] = m["category"]
        example_cmd.setdefault(m["pattern"], m["command_line"])

    items = []
    for pattern, ids in by_pattern.items():
        category = _COMMAND_CATEGORY_TO_EVIDENCE.get(pattern_category[pattern], "discovery")
        n = len(ids)
        plural = "s" if n != 1 else ""
        items.append(_item(
            counter, category,
            f"{n} command{plural} matching '{pattern}' observed "
            f"(example: {example_cmd[pattern]!r}).",
            ids, ctx, pattern=pattern,
        ))
    return items


_BUILDERS = {
    "BRUTE_FORCE": _from_brute_force,
    "SUSPICIOUS_POWERSHELL": _from_powershell,
    "UNUSUAL_LOGIN": _from_unusual_login,
    "SUSPICIOUS_OUTBOUND": _from_outbound,
    "SUSPICIOUS_COMMAND": _from_commands,
}


# --------------------------------------------------------------------------
# Related events: same actor, near the incident window, not already cited as evidence
# --------------------------------------------------------------------------
def _find_related_events(incident, ctx, covered_ids):
    window = timedelta(minutes=RELATED_EVENT_WINDOW_MINUTES)
    start = datetime.fromisoformat(incident["first_seen"]) - window
    end = datetime.fromisoformat(incident["last_seen"]) + window
    actors = (set(incident["source_ips"]) | set(incident["usernames"])
             | set(incident["hostnames"]))
    if not actors:
        return []

    related = []
    for e in ctx.events:
        if e["event_id"] in covered_ids:
            continue
        if not (start <= ctx.t(e) <= end):
            continue
        if not ({e["source_ip"], e["username"], e["hostname"]} & actors):
            continue
        related.append(e)
    return related


def _file_artifact_items(related_events, ctx, counter, covered_ids):
    items = []
    for e in related_events:
        if e["event_type"] != "FILE":
            continue
        path = e["command_line"] or e["message"] or "an unnamed file"
        hash_part = f" (SHA-256: {e['file_hash']})" if e["file_hash"] else ""
        items.append(_item(
            counter, "file",
            f"File artifact created on {e['hostname'] or 'unknown host'}: {path}{hash_part}.",
            [e["event_id"]], ctx,
        ))
        covered_ids.add(e["event_id"])
    return items


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------
def build_evidence(incident: dict, all_events: list[dict]) -> dict:
    """Build the evidence package for one incident.

    `all_events` should be every normalized event of the upload (not just the
    incident's own event_ids), so related context events can be found.
    """
    ctx = Context(all_events)
    counter = _Counter()
    covered_ids = set(incident["event_ids"])

    items = []
    for det in incident["detections"]:
        builder = _BUILDERS.get(det["rule_id"])
        if builder:
            items.extend(builder(det, ctx, counter))

    related_events = _find_related_events(incident, ctx, covered_ids)
    items.extend(_file_artifact_items(related_events, ctx, counter, covered_ids))
    remaining_related = [e for e in related_events if e["event_id"] not in covered_ids]

    all_cited_ids = uniq_sorted(i for item in items for i in item["event_ids"])
    cited_events = [ctx.by_id[i] for i in all_cited_ids]

    indicators = {
        "source_ips": uniq_sorted(incident["source_ips"]),
        "destination_ips": uniq_sorted(
            incident["destination_ips"] + [e["destination_ip"] for e in cited_events]
        ),
        "usernames": uniq_sorted(incident["usernames"]),
        "hostnames": uniq_sorted(incident["hostnames"]),
        "processes": uniq_sorted(
            (e["process"] or "") for e in cited_events if e["event_type"] == "PROCESS"
        ),
        "file_hashes": uniq_sorted(e["file_hash"] for e in cited_events),
        "destination_ports": sorted({e["destination_port"] for e in cited_events
                                     if e["destination_port"]}),
    }

    return {
        "incident_id": incident["incident_id"],
        "evidence_items": items,
        "indicators": indicators,
        "related_events": [
            {"event_id": e["event_id"], "timestamp": e["timestamp"],
             "event_type": e["event_type"], "message": e["message"]}
            for e in remaining_related
        ],
        "total_cited_events": len(all_cited_ids),
        "traceable": all(i in ctx.by_id for i in all_cited_ids),
    }
