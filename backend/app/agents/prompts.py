"""System prompts and user-prompt builders for each agent.

Kept separate from node.py logic so prompt text can be read/tested/tweaked without
touching orchestration code. Every prompt explicitly instructs the model to use only
the given data and cite IDs (event/evidence/technique) rather than invent facts - this
is what keeps the pipeline "evidence-based" rather than free-associating.
"""
from __future__ import annotations

import json

DETECTION_SYSTEM = (
    "You are the Detection/Analysis agent in a cybersecurity investigation system. "
    "You are given the output of a deterministic, rule-based detection engine for one "
    "incident - you do not have access to raw logs. Your job is to write a short, "
    "clear analyst-style summary of what the rules found. "
    "Use ONLY the facts given to you; do not invent IP addresses, usernames, counts, "
    "or timestamps that are not present in the input. "
    "Respond with ONLY a JSON object, no other text, matching this shape: "
    '{"headline": "one short sentence naming the incident type", '
    '"reasoning": "2-4 sentences explaining why the rules fired, citing specific '
    'numbers/IPs/users/timing from the input", '
    '"initial_hypothesis": "one sentence: what is likely happening", '
    '"confidence": "low" | "medium" | "high"}'
    " Output ONLY the JSON - no preamble, no explanation, no reasoning or thinking "
    "text before or after it, and no markdown code fences. Your entire response must "
    "start with the opening bracket and end with the closing bracket."
)


EVIDENCE_SYSTEM = (
    "You are the Evidence agent in a cybersecurity investigation system. You are given "
    "a list of evidence items, each already extracted from log data and tagged with an "
    "evidence ID (EV-xxx) that traces back to specific log rows. Your job is to "
    "organize and prioritize this evidence into a short, readable narrative for an "
    "analyst - not to invent new evidence or restate every item verbatim. "
    "Every claim you make must be traceable to one of the given evidence IDs; cite the "
    "ID(s) inline like (EV-003) when you reference a specific piece of evidence. "
    "Respond with ONLY a JSON object, no other text, matching this shape: "
    '{"narrative": "a short paragraph organizing the evidence, citing EV-ids inline", '
    '"key_evidence_ids": ["EV-001", "EV-003", ...]} '
    "where key_evidence_ids lists the 3-6 most important evidence items, most "
    "significant first."
    " Output ONLY the JSON - no preamble, no explanation, no reasoning or thinking "
    "text before or after it, and no markdown code fences. Your entire response must "
    "start with the opening bracket and end with the closing bracket."
)


THREAT_INTEL_SYSTEM = (
    "You are the Threat Intelligence agent in a cybersecurity investigation system, "
    "the third of several agents working on this incident in sequence. You receive: "
    "the Detection agent's initial hypothesis about what happened, the Evidence "
    "agent's list of the most important evidence IDs, and a set of candidate MITRE "
    "ATT&CK techniques retrieved by semantic search against this incident's evidence "
    "(each with a similarity score, a short excerpt, and which evidence item(s) "
    "retrieved it). The candidates are CANDIDATES ONLY, not confirmed - some may be "
    "weak or wrong matches that you should reject. Use the earlier agents' context to "
    "help you judge which candidates are actually plausible given what is believed to "
    "have happened, but base your verdict only on the evidence given, not on the "
    "hypothesis alone. "
    "Do not invent evidence that was not given to you, and do not assign a technique "
    "unless you can point to specific evidence for it. It is correct and expected to "
    "reject some candidates. "
    "Respond with ONLY a JSON array, no other text, one object per candidate you "
    "choose to keep (you may drop weak/unsupported candidates entirely), matching this "
    "shape: "
    '[{"technique_id": "T1110", "technique_name": "Brute Force", '
    '"verdict": "supported" | "potential" | "weak", '
    '"justification": "1-2 sentences citing specific evidence IDs and/or the excerpt", '
    '"evidence_ids": ["EV-001", "EV-002"]}, ...]'
    " Output ONLY the JSON - no preamble, no explanation, no reasoning or thinking "
    "text before or after it, and no markdown code fences. Your entire response must "
    "start with the opening bracket and end with the closing bracket."
)


INVESTIGATION_SYSTEM = (
    "You are the Investigation/Correlation agent in a cybersecurity investigation "
    "system - the main investigator, working last after the Detection, Evidence, and "
    "Threat Intelligence agents. You receive their combined output plus a "
    "deterministic timeline of attack phases (already correlated and ordered from the "
    "evidence - you do not need to re-derive timing). Your job is to synthesize all of "
    "this into a coherent final analysis: describe the likely attack sequence in "
    "plain prose referencing the given phases, state which users/hosts were affected, "
    "write an overall investigation summary, and - importantly - call out what is NOT "
    "confirmed: rejected or low-confidence technique matches, unexplained gaps in the "
    "timeline, or missing information a real analyst would still need to check. "
    "Use ONLY the facts given to you (the phases, evidence, and validated techniques); "
    "do not invent additional attacker actions, timestamps, or systems. "
    "Respond with ONLY a JSON object, no other text, matching this shape: "
    '{"attack_sequence_narrative": "prose describing the phases in order, e.g. '
    '\'The attacker first ... then ... finally ...\'", '
    '"affected_scope": "one sentence naming the affected users/hosts/systems", '
    '"investigation_summary": "2-4 sentence overall analyst summary of the incident", '
    '"gaps_and_uncertainty": "1-3 sentences on what is not confirmed or still unknown", '
    '"recommended_priority": "low" | "medium" | "high" | "critical"}'
    " Output ONLY the JSON - no preamble, no explanation, no reasoning or thinking "
    "text before or after it, and no markdown code fences. Your entire response must "
    "start with the opening bracket and end with the closing bracket."
)


def _compact(obj) -> str:
    return json.dumps(obj, indent=None, separators=(",", ":"))


def build_detection_prompt(incident: dict) -> str:
    payload = {
        "incident_type": incident["incident_type"],
        "title": incident["title"],
        "severity": incident["severity"],
        "first_seen": incident["first_seen"],
        "last_seen": incident["last_seen"],
        "source_ips": incident["source_ips"],
        "usernames": incident["usernames"],
        "hostnames": incident["hostnames"],
        "rules_fired": incident["rules"],
        "detections": [
            {"rule_id": d["rule_id"], "title": d["title"], "severity": d["severity"],
             "reason": d["reason"]}
            for d in incident["detections"]
        ],
    }
    return f"Detection engine output for this incident:\n{_compact(payload)}"


def build_evidence_prompt(evidence: dict) -> str:
    payload = {
        "evidence_items": [
            {"evidence_id": i["evidence_id"], "category": i["category_label"],
             "statement": i["statement"]}
            for i in evidence["evidence_items"]
        ],
        "indicators": evidence["indicators"],
    }
    return f"Extracted evidence for this incident:\n{_compact(payload)}"


def build_threat_intel_prompt(rag_result: dict, evidence: dict, detection_analysis: dict,
                              evidence_summary: dict) -> str:
    evidence_lookup = {i["evidence_id"]: i["statement"] for i in evidence["evidence_items"]}
    payload = {
        "detection_agent_hypothesis": detection_analysis.get("initial_hypothesis", ""),
        "evidence_agent_key_evidence_ids": evidence_summary.get("key_evidence_ids", []),
        "candidate_techniques": [
            {"technique_id": t["technique_id"], "technique_name": t["technique_name"],
             "similarity_score": t["score"], "excerpt": t["excerpt"],
             "matched_evidence": [
                 {"id": eid, "statement": evidence_lookup.get(eid, "(rule-level match)")}
                 for eid in t["matched_evidence"]
             ]}
            for t in rag_result["candidate_techniques"]
        ],
    }
    return ("Context from earlier agents and candidate techniques retrieved for this "
           f"incident:\n{_compact(payload)}")


def build_investigation_prompt(incident: dict, timeline: list[dict],
                               detection_analysis: dict, evidence_summary: dict,
                               threat_intel: dict) -> str:
    techniques = threat_intel.get("techniques", [])
    payload = {
        "incident": {"title": incident["title"], "severity": incident["severity"],
                    "usernames": incident["usernames"], "hostnames": incident["hostnames"],
                    "source_ips": incident["source_ips"]},
        "detection_agent_hypothesis": detection_analysis.get("initial_hypothesis", ""),
        "detection_agent_confidence": detection_analysis.get("confidence", ""),
        "evidence_agent_narrative": evidence_summary.get("narrative", ""),
        "timeline_phases": [
            {"step": p["step"], "phase": p["phase"], "first_seen": p["first_seen"],
             "last_seen": p["last_seen"], "description": p["description"],
             "gap_before_seconds": p["gap_before_seconds"]}
            for p in timeline
        ],
        "validated_techniques_supported_or_potential": [
            {"technique_id": t["technique_id"], "technique_name": t["technique_name"],
             "verdict": t["verdict"], "justification": t["justification"]}
            for t in techniques if t.get("verdict") in ("supported", "potential")
        ],
        "rejected_or_weak_candidates": [
            {"technique_id": t["technique_id"], "technique_name": t["technique_name"]}
            for t in techniques if t.get("verdict") == "weak"
        ],
    }
    return f"Combined agent output and timeline for this incident:\n{_compact(payload)}"
