"""Shared helpers: severity levels, the Detection record, event context, small utilities."""
from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field
from datetime import datetime

LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def sev_score(name: str) -> int:
    return LEVELS.index(name) + 1


def sev_name(score: int) -> str:
    return LEVELS[max(1, min(score, len(LEVELS))) - 1]


@dataclass
class Detection:
    """One rule firing. `event_ids` point back to the original log rows."""
    rule_id: str
    title: str
    severity: str
    first_seen: str
    last_seen: str
    reason: str
    event_ids: list
    source_ips: list = field(default_factory=list)
    usernames: list = field(default_factory=list)
    hostnames: list = field(default_factory=list)
    destination_ips: list = field(default_factory=list)
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


class Context:
    """Events sorted by time, with fast id and timestamp lookup."""

    def __init__(self, events: list[dict]):
        self.events = sorted(events, key=lambda e: (e["timestamp"], e["row_number"]))
        self.by_id = {e["event_id"]: e for e in self.events}
        self._times = {e["event_id"]: datetime.fromisoformat(e["timestamp"]) for e in self.events}

    def t(self, event: dict) -> datetime:
        return self._times[event["event_id"]]

    def order_ids(self, ids) -> list[str]:
        return sorted(set(ids), key=lambda i: (self.by_id[i]["timestamp"], self.by_id[i]["row_number"]))


# Internal ranges only. We deliberately do NOT use ipaddress.is_private, because Python
# also counts the documentation ranges (198.51.100.0/24, 203.0.113.0/24) as private,
# and our simulated "external" hosts live there.
_INTERNAL = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
)]


def parse_ip(value):
    try:
        return ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None


def is_external(value) -> bool:
    """True only for a valid IP that is outside internal ranges (hostnames -> False)."""
    ip = parse_ip(value)
    return ip is not None and not any(ip in net for net in _INTERNAL)


GENERIC_ACTIONS = {"process_start", "process_create", "execute", "executed", "start",
                   "create", "process"}


def process_name(event: dict) -> str:
    """Lower-case executable name. Falls back to `action` for PROCESS events, because the
    brief's example format puts the process name ("powershell") in the action column."""
    name = event.get("process")
    if not name and event.get("event_type") == "PROCESS":
        action = event.get("action")
        if action and action.lower() not in GENERIC_ACTIONS:
            name = action
    if not name:
        return ""
    return name.replace("/", "\\").split("\\")[-1].lower()


def fmt_duration(seconds: float) -> str:
    seconds = int(round(seconds))
    if seconds < 60:
        return f"{seconds} seconds"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes} min {sec} s" if sec else f"{minutes} min"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} h {minutes} min"


def uniq_sorted(values) -> list:
    return sorted({v for v in values if v})
