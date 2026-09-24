"""Builds a deterministic attack-phase timeline from an incident's detections.

This is pure, testable logic with no LLM involved - it's the factual skeleton the
Investigation agent's narrative is built on top of. One phase per detection (each
detection is already a grouped, time-bounded cluster of related events from the
detection engine), labeled by MITRE tactic where a validated technique covers it,
otherwise by a generic rule-based label.
"""
from __future__ import annotations

from datetime import datetime

RULE_PHASE_LABELS = {
    "BRUTE_FORCE": "Initial Access (Credential Access)",
    "UNUSUAL_LOGIN": "Initial Access",
    "SUSPICIOUS_POWERSHELL": "Execution",
    "SUSPICIOUS_OUTBOUND": "Command and Control",
}

COMMAND_CATEGORY_LABELS = {"discovery": "Discovery", "persistence": "Persistence",
                          "download": "Command and Control"}

# A gap this long (seconds) between consecutive phases is worth flagging as an
# unexplained silence rather than treated as continuous activity.
NOTABLE_GAP_SECONDS = 120


def _phase_label(detection: dict, tactic_by_evidence: dict[str, str]) -> str:
    """Prefer a validated MITRE tactic (from threat_intel) that covers this
    detection's evidence, since that's more precise than a generic rule label."""
    for eid in detection.get("event_ids", []):
        tactic = tactic_by_evidence.get(eid)
        if tactic:
            return tactic.split(",")[0].strip()  # a technique may list several tactics

    if detection["rule_id"] == "SUSPICIOUS_COMMAND":
        categories = detection.get("details", {}).get("categories", [])
        labels = sorted({COMMAND_CATEGORY_LABELS.get(c, c.title()) for c in categories})
        return " / ".join(labels) if labels else "Discovery"

    return RULE_PHASE_LABELS.get(detection["rule_id"], detection["rule_id"].replace("_", " ").title())


def _tactic_by_evidence(threat_intel: dict | None) -> dict[str, str]:
    """Map each evidence ID to the tactic of the technique it best supports (verdict
    'supported' takes priority over 'potential' if both cite the same evidence)."""
    if not threat_intel:
        return {}
    priority = {"supported": 0, "potential": 1, "weak": 2}
    result: dict[str, tuple[int, str]] = {}
    for t in threat_intel.get("techniques", []):
        rank = priority.get(t.get("verdict"), 3)
        for eid in t.get("evidence_ids", []):
            if eid not in result or rank < result[eid][0]:
                result[eid] = (rank, t.get("tactic") or t.get("technique_name", ""))
    return {eid: tactic for eid, (_, tactic) in result.items()}


def build_timeline(incident: dict, threat_intel: dict | None = None) -> list[dict]:
    """One phase per detection, ordered by time, with gaps between phases computed."""
    tactic_by_evidence = _tactic_by_evidence(threat_intel)
    phases = []
    for i, d in enumerate(sorted(incident["detections"], key=lambda d: d["first_seen"]), start=1):
        phases.append({
            "step": i,
            "phase": _phase_label(d, tactic_by_evidence),
            "rule_id": d["rule_id"],
            "first_seen": d["first_seen"],
            "last_seen": d["last_seen"],
            "event_ids": d["event_ids"],
            "description": d["reason"],
            "gap_before_seconds": None,
        })

    for prev, cur in zip(phases, phases[1:]):
        prev_end = datetime.fromisoformat(prev["last_seen"])
        cur_start = datetime.fromisoformat(cur["first_seen"])
        cur["gap_before_seconds"] = max((cur_start - prev_end).total_seconds(), 0.0)

    return phases


def notable_gaps(timeline: list[dict]) -> list[dict]:
    """Phases preceded by a gap long enough to be worth calling out explicitly."""
    return [
        {"before_phase": p["phase"], "gap_seconds": p["gap_before_seconds"]}
        for p in timeline
        if p["gap_before_seconds"] is not None and p["gap_before_seconds"] >= NOTABLE_GAP_SECONDS
    ]
