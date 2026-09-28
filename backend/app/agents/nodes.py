"""Node functions for the multi-agent graph. Each node reads AgentState, calls its
agent's LLM step (with a deterministic fallback), and returns the state updates for
that agent - this is the shape both the LangGraph runner and the dependency-light
SequentialRunner expect (see graph.py).
"""
from __future__ import annotations

import json
import time

from ..llm import LLMProvider, parse_json_response
from ..llm.config import llm_config
from . import fallback, prompts
from .timeline import build_timeline

DETECTION_MAX_TOKENS = 1000
EVIDENCE_MAX_TOKENS = 1400
THREAT_INTEL_MAX_TOKENS = 2800
INVESTIGATION_MAX_TOKENS = 2500


def _throttle(provider: LLMProvider) -> None:
    """Sleep LLM_REQUEST_DELAY_SECONDS before a real provider call, to stay under
    free-tier per-minute rate limits (Groq et al. enforce tight ones - see
    llm/providers.py's retry-on-429 for the reactive half of handling this). Skipped
    entirely for the mock provider, so local development and the test suite - which
    calls these nodes dozens of times - stay fast regardless of this setting.
    """
    if provider.name != "mock" and llm_config.request_delay_seconds > 0:
        time.sleep(llm_config.request_delay_seconds)


def _run_json_step(provider: LLMProvider, system: str, user: str, fallback_value,
                   max_tokens: int) -> tuple[object, str, str | None]:
    """Call the provider, parse its JSON, and report whether the fallback was used.

    Returns (parsed_value, generated_by, debug_note). generated_by is "llm", "fallback"
    (provider itself used the fallback - no key configured, or the real call failed),
    or "fallback_parse_error" (a real call returned text that didn't parse as JSON, so
    we fell back after the fact rather than risk garbage data downstream). debug_note
    is None except for fallback_parse_error, where it holds a preview of the raw
    response and the parse error - without this, a parse failure is a silent mystery,
    which is exactly what happened when this went untracked.
    """
    fallback_text = json.dumps(fallback_value)
    raw = provider.complete(system, user, max_tokens=max_tokens,
                            mock_response=lambda: fallback_text)
    if raw.strip() == fallback_text:
        return fallback_value, "fallback", None
    try:
        return parse_json_response(raw), "llm", None
    except ValueError as exc:
        preview = raw[:300] + ("..." if len(raw) > 300 else "")
        debug_note = f"{exc}. Raw response ({len(raw)} chars) started with: {preview!r}"
        return fallback_value, "fallback_parse_error", debug_note


def _trace_entry(agent: str, generated_by: str, debug_note: str | None = None) -> dict:
    entry = {"agent": agent, "generated_by": generated_by}
    if debug_note:
        entry["debug_note"] = debug_note
    return entry


def node_detection(state: dict, provider: LLMProvider) -> dict:
    incident = state["incident"]
    _throttle(provider)
    system, user = prompts.DETECTION_SYSTEM, prompts.build_detection_prompt(incident)
    result, generated_by, debug_note = _run_json_step(
        provider, system, user, fallback.fallback_detection_analysis(incident),
        DETECTION_MAX_TOKENS,
    )
    return {
        "detection_analysis": result,
        "trace": state.get("trace", []) +
                [_trace_entry("detection_analysis", generated_by, debug_note)],
    }


def node_evidence(state: dict, provider: LLMProvider) -> dict:
    evidence = state["evidence"]
    _throttle(provider)
    system, user = prompts.EVIDENCE_SYSTEM, prompts.build_evidence_prompt(evidence)
    result, generated_by, debug_note = _run_json_step(
        provider, system, user, fallback.fallback_evidence_summary(evidence),
        EVIDENCE_MAX_TOKENS,
    )
    return {
        "evidence_summary": result,
        "trace": state.get("trace", []) +
                [_trace_entry("evidence_summary", generated_by, debug_note)],
    }


def node_threat_intel(state: dict, provider: LLMProvider) -> dict:
    rag_result, evidence = state["rag_result"], state["evidence"]
    debug_note = None
    if not rag_result.get("candidate_techniques"):
        # Nothing retrieved (e.g. min_score filtered everything) - no LLM call needed.
        result, generated_by = [], "fallback"
    else:
        system = prompts.THREAT_INTEL_SYSTEM
        # Genuine agent-to-agent handoff: this prompt is built from what the Detection
        # and Evidence agents already produced, not just the original inputs.
        user = prompts.build_threat_intel_prompt(
            rag_result, evidence,
            detection_analysis=state["detection_analysis"],
            evidence_summary=state["evidence_summary"],
        )
        _throttle(provider)
        result, generated_by, debug_note = _run_json_step(
            provider, system, user, fallback.fallback_threat_intel(rag_result),
            THREAT_INTEL_MAX_TOKENS,
        )
    return {
        "threat_intel": {"techniques": result},
        "trace": state.get("trace", []) +
                [_trace_entry("threat_intel", generated_by, debug_note)],
    }


def node_investigation(state: dict, provider: LLMProvider) -> dict:
    incident = state["incident"]
    threat_intel = state["threat_intel"]
    timeline = build_timeline(incident, threat_intel)

    system = prompts.INVESTIGATION_SYSTEM
    user = prompts.build_investigation_prompt(
        incident, timeline, state["detection_analysis"], state["evidence_summary"],
        threat_intel,
    )
    _throttle(provider)
    result, generated_by, debug_note = _run_json_step(
        provider, system, user,
        fallback.fallback_investigation(incident, timeline, threat_intel),
        INVESTIGATION_MAX_TOKENS,
    )
    return {
        "timeline": timeline,
        "investigation": result,
        "trace": state.get("trace", []) +
                [_trace_entry("investigation", generated_by, debug_note)],
    }
