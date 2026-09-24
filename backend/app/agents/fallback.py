"""Deterministic, data-only fallback outputs for each agent.

These serve two purposes: they're what MockProvider returns by default (so the whole
pipeline works with zero configuration), and they're what a real provider falls back to
if its API call fails for any reason (see llm/providers.py). Either way, the caller can
tell the difference via the "generated_by" field nodes.py attaches - "llm" vs
"fallback" - so the UI/report can be honest about which agents actually reasoned and
which used the deterministic stand-in.
"""
from __future__ import annotations

SEVERITY_CONFIDENCE = {"LOW": "low", "MEDIUM": "low", "HIGH": "medium", "CRITICAL": "high"}


def fallback_detection_analysis(incident: dict) -> dict:
    reasons = [d["reason"] for d in incident["detections"]]
    who = ", ".join(f"'{u}'" for u in incident["usernames"]) or "an unidentified account"
    where = ", ".join(incident["hostnames"]) or "an unidentified host"
    return {
        "headline": incident["title"],
        "reasoning": " ".join(reasons) or "No detection reasons were recorded.",
        "initial_hypothesis": (
            f"Rule-based detection classified this as {incident['incident_type']} "
            f"({incident['severity']}) involving {who} on {where}, based on "
            f"{len(incident['detections'])} rule(s): {', '.join(incident['rules'])}."
        ),
        "confidence": SEVERITY_CONFIDENCE.get(incident["severity"], "low"),
    }


def fallback_evidence_summary(evidence: dict) -> dict:
    items = evidence["evidence_items"]
    narrative = " ".join(f"{i['statement']} ({i['evidence_id']})" for i in items)
    # Prioritize authentication and network evidence first (usually the most decisive),
    # then everything else, in the order it was extracted.
    priority = {"authentication": 0, "network": 1}
    ranked = sorted(items, key=lambda i: priority.get(i["category"], 2))
    return {
        "narrative": narrative or "No evidence items were extracted for this incident.",
        "key_evidence_ids": [i["evidence_id"] for i in ranked[:6]],
    }


def fallback_threat_intel(rag_result: dict) -> list[dict]:
    results = []
    for t in rag_result["candidate_techniques"]:
        results.append({
            "technique_id": t["technique_id"],
            "technique_name": t["technique_name"],
            "verdict": t["confidence"],  # "supported" | "potential" | "weak"
            "justification": (
                f"Retrieved by semantic similarity (score {t['score']}) from evidence "
                f"{', '.join(t['matched_evidence'])}. Technique summary: {t['excerpt'][:180]}"
            ),
            "evidence_ids": [e for e in t["matched_evidence"] if e.startswith("EV-")],
        })
    return results


PRIORITY_FROM_SEVERITY = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high", "CRITICAL": "critical"}


def fallback_investigation(incident: dict, timeline: list[dict],
                           threat_intel: dict) -> dict:
    sequence_parts = []
    for p in timeline:
        gap_note = ""
        if p["gap_before_seconds"] and p["gap_before_seconds"] >= 120:
            minutes = round(p["gap_before_seconds"] / 60, 1)
            gap_note = f" (after a gap of about {minutes} min with no observed activity)"
        sequence_parts.append(f"{p['phase']}{gap_note}: {p['description']}")
    attack_sequence_narrative = " Then, ".join(sequence_parts) or "No timeline phases were available."

    who = ", ".join(f"'{u}'" for u in incident["usernames"]) or "an unidentified account"
    where = ", ".join(incident["hostnames"]) or "an unidentified host"
    affected_scope = f"Affected account(s): {who}. Affected host(s): {where}."

    techniques = threat_intel.get("techniques", [])
    confirmed = [t for t in techniques if t.get("verdict") == "supported"]
    investigation_summary = (
        f"{incident['title']} ({incident['severity']}) involving {who} on {where}, "
        f"spanning {len(timeline)} correlated phase(s)."
        + (f" Techniques with strong evidentiary support: "
           f"{', '.join(t['technique_id'] for t in confirmed)}." if confirmed else "")
    )

    weak_or_potential = [t for t in techniques if t.get("verdict") in ("potential", "weak")]
    uncertainty_parts = []
    if weak_or_potential:
        uncertainty_parts.append(
            "Not fully confirmed: " +
            ", ".join(f"{t['technique_id']} ({t['verdict']})" for t in weak_or_potential) + "."
        )
    notable = [p for p in timeline if p["gap_before_seconds"] and p["gap_before_seconds"] >= 120]
    if notable:
        uncertainty_parts.append(
            f"There {'is' if len(notable) == 1 else 'are'} {len(notable)} unexplained "
            f"timing gap(s) in the observed activity that may hide additional, "
            f"unlogged attacker actions."
        )
    if not uncertainty_parts:
        uncertainty_parts.append("No significant gaps or low-confidence mappings were identified.")

    return {
        "attack_sequence_narrative": attack_sequence_narrative,
        "affected_scope": affected_scope,
        "investigation_summary": investigation_summary,
        "gaps_and_uncertainty": " ".join(uncertainty_parts),
        "recommended_priority": PRIORITY_FROM_SEVERITY.get(incident["severity"], "medium"),
    }
