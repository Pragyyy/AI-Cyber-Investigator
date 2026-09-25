"""Assembles a normalized, rendering-ready report data structure from everything the
earlier phases already produced. No new analysis happens here - this module only
organizes and formats what Phases 2-6 already computed, plus the deterministic
recommended actions (see actions.py). This same structure backs both the PDF export
and (later, Phase 8) a dashboard "report" view, so it's built once and reused.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .actions import get_recommended_actions

VERDICT_ORDER = {"supported": 0, "potential": 1, "weak": 2}
VERDICT_LABELS = {
    "supported": "Technique supported by observed evidence",
    "potential": "Potential technique",
    "weak": "Weak / low-confidence match",
}


def _fmt_time(iso_timestamp: str | None) -> str:
    if not iso_timestamp:
        return "unknown"
    try:
        return datetime.fromisoformat(iso_timestamp).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return iso_timestamp


def build_report_data(incident: dict, evidence: dict, investigation_result: dict,
                      rag_result: dict | None = None) -> dict:
    """`investigation_result` is the combined output of run_investigation() (or the
    /investigate endpoint's cached response): detection_analysis, evidence_summary,
    threat_intel (validated techniques), timeline, investigation, trace. `rag_result`
    is the raw retrieval output (has supporting_guidance) - optional, since it may not
    always be cached; the report's "RAG Sources" section is simply omitted without it.
    """
    detection_analysis = investigation_result.get("detection_analysis") or {}
    evidence_summary = investigation_result.get("evidence_summary") or {}
    agent_threat_intel = investigation_result.get("threat_intel") or {"techniques": []}
    timeline = investigation_result.get("timeline") or []
    final_investigation = investigation_result.get("investigation") or {}
    trace = investigation_result.get("trace") or []

    techniques = sorted(
        agent_threat_intel.get("techniques", []),
        key=lambda t: (VERDICT_ORDER.get(t.get("verdict"), 3), -t.get("score", 0) if "score" in t else 0,
                       t.get("technique_id", "")),
    )

    timeline_rows = [
        {
            "step": p["step"],
            "phase": p["phase"],
            "time_range": f"{_fmt_time(p['first_seen'])} - {_fmt_time(p['last_seen'])}",
            "description": p["description"],
            "gap_note": (
                f"Preceded by a gap of about {round(p['gap_before_seconds'] / 60, 1)} "
                f"min with no observed activity."
                if p.get("gap_before_seconds") and p["gap_before_seconds"] >= 120 else None
            ),
        }
        for p in timeline
    ]

    return {
        "report_title": "Cybersecurity Incident Report",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),

        "incident_id": incident["incident_id"],
        "incident_type": incident["incident_type"],
        "title": incident["title"],
        "severity": incident["severity"],
        "status": incident["status"],
        "detection_time": _fmt_time(incident["first_seen"]),
        "last_activity_time": _fmt_time(incident["last_seen"]),
        "affected_users": incident["usernames"],
        "affected_hosts": incident["hostnames"],
        "source_ips": incident["source_ips"],
        "destination_ips": incident["destination_ips"],
        "rules_fired": incident["rules"],
        "event_count": incident["event_count"],

        "executive_summary": final_investigation.get("investigation_summary")
                             or detection_analysis.get("reasoning", ""),
        "initial_hypothesis": detection_analysis.get("initial_hypothesis", ""),
        "detection_confidence": detection_analysis.get("confidence", ""),
        "recommended_priority": final_investigation.get("recommended_priority")
                                or incident["severity"].lower(),

        "timeline": timeline_rows,
        "attack_sequence_narrative": final_investigation.get("attack_sequence_narrative", ""),
        "affected_scope": final_investigation.get("affected_scope", ""),
        "gaps_and_uncertainty": final_investigation.get("gaps_and_uncertainty", ""),

        "evidence_items": [
            {"evidence_id": i["evidence_id"], "category": i["category_label"],
             "statement": i["statement"]}
            for i in evidence["evidence_items"]
        ],
        "indicators": evidence["indicators"],
        "evidence_narrative": evidence_summary.get("narrative", ""),

        "mitre_techniques": [
            {"technique_id": t["technique_id"], "technique_name": t["technique_name"],
             "verdict": t["verdict"], "verdict_label": VERDICT_LABELS.get(t["verdict"], t["verdict"]),
             "justification": t["justification"]}
            for t in techniques
        ],
        "rag_sources": [
            {"title": g["title"], "source": g["source"]}
            for g in (rag_result or {}).get("supporting_guidance", [])
        ],

        "recommended_actions": get_recommended_actions(incident),

        "llm_provider": investigation_result.get("llm_provider", "unknown"),
        "graph_backend": investigation_result.get("graph_backend", "unknown"),
        "agent_trace": [
            {"agent": t["agent"], "generated_by": t["generated_by"]} for t in trace
        ],
    }
