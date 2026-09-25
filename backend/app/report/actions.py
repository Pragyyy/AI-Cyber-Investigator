"""Deterministic recommended-action lists, keyed by detection rule.

Recommended actions are operational guidance with real consequences if wrong, so - like
the detection and evidence layers - they come from a fixed, reviewed lookup table
rather than an LLM's improvisation. This mirrors the same "evidence-based, not
invented" principle used throughout the rest of the pipeline, applied to the one part
of the report where getting it wrong could actually cause harm.
"""
from __future__ import annotations

RECOMMENDED_ACTIONS_BY_RULE = {
    "BRUTE_FORCE": [
        "Disable or force a password reset on the targeted account(s) immediately.",
        "Block or rate-limit the source IP at the firewall or identity provider.",
        "Review what the account did immediately after any successful login.",
        "Enable or verify multi-factor authentication on the account going forward.",
    ],
    "UNUSUAL_LOGIN": [
        "Verify the login with the account owner through an out-of-band channel.",
        "Review the account's recent activity for anything inconsistent with normal use.",
        "Consider forcing a session or password reset if the login cannot be confirmed "
        "as legitimate.",
    ],
    "SUSPICIOUS_POWERSHELL": [
        "Decode and review any base64-encoded command to determine what it actually "
        "executed.",
        "Identify the parent process; if it is an Office application, treat this as "
        "likely phishing or macro-based initial access.",
        "Isolate the host pending review if the command shows a download-and-execute "
        "pattern.",
    ],
    "SUSPICIOUS_OUTBOUND": [
        "Block the destination IP/port at the network perimeter.",
        "Isolate the affected host from the network pending review.",
        "Capture and preserve network traffic logs for the affected timeframe.",
    ],
    "SUSPICIOUS_COMMAND": [
        "Review any newly created scheduled tasks, services, or accounts for "
        "legitimacy and remove them if unauthorized.",
        "Correlate discovery commands with the login or process that preceded them to "
        "confirm the scope of access.",
    ],
}

UNIVERSAL_CLOSING_ACTIONS = [
    "Preserve the original logs and this report as evidence.",
    "Document findings and actions taken for the incident record.",
]


def get_recommended_actions(incident: dict) -> list[str]:
    """Actions for every rule that fired in this incident, in the incident's own rule
    order, deduplicated (an action shared by two rules is listed once), followed by two
    universal closing actions that apply to every incident."""
    seen: set[str] = set()
    actions: list[str] = []
    for rule_id in incident["rules"]:
        for action in RECOMMENDED_ACTIONS_BY_RULE.get(rule_id, []):
            if action not in seen:
                seen.add(action)
                actions.append(action)
    for action in UNIVERSAL_CLOSING_ACTIONS:
        if action not in seen:
            seen.add(action)
            actions.append(action)
    return actions
