"""Tunable thresholds for the detection engine.

Everything the rules treat as a "magic number" lives here so it can be explained in
the report, changed per run, and tested.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class DetectionConfig:
    # Brute force: >= threshold failed logins from one source IP within the window
    brute_force_threshold: int = 10
    brute_force_window_minutes: int = 10
    # A successful login from the same IP this soon after the failures is "followed by success"
    success_after_failure_minutes: int = 30

    # Unusual login: flagged when at least this many signals fire
    # (external source IP, rarely-seen source for that user, outside business hours)
    unusual_login_min_signals: int = 2
    business_hours_start: int = 7    # inclusive, 24h clock, in the log's own timezone
    business_hours_end: int = 19     # exclusive
    rare_source_share: float = 0.25  # source IP is < 25% of the user's activity
    rare_source_min_events: int = 5  # need this much history to call anything "rare"

    # PowerShell run by the same user on the same host within this gap is one detection
    powershell_group_gap_minutes: int = 30
    # PowerShell this soon after a post-brute-force login is treated as suspicious
    post_login_powershell_minutes: int = 15

    # Detections are merged into one incident when they share a user or source IP
    # and are no more than this many minutes apart
    correlation_gap_minutes: int = 60
