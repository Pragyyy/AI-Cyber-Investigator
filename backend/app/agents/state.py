"""Shared state that flows through the multi-agent graph. Each node reads what earlier
agents produced and adds its own piece - this is the "controlled agent-to-agent
communication" the project brief asks LangGraph for, made explicit as a typed dict."""
from __future__ import annotations

from typing import TypedDict


class AgentState(TypedDict, total=False):
    # Inputs (set before the graph runs)
    incident: dict
    evidence: dict
    rag_result: dict  # output of rag.retrieve_for_incident()

    # Agent 1 - Detection/Analysis
    detection_analysis: dict

    # Agent 2 - Evidence
    evidence_summary: dict

    # Agent 3 - Threat Intelligence
    threat_intel: dict

    # Agent 4 - Investigation/Correlation
    timeline: list
    investigation: dict

    # Bookkeeping
    trace: list  # [{"agent": ..., "generated_by": "llm"|"fallback", "note": ...}, ...]
    errors: list
