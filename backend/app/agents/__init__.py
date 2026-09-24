"""Multi-agent investigation workflow: Detection/Analysis -> Evidence -> Threat
Intelligence agents, orchestrated by LangGraph (or a lighter sequential fallback).
"""
from __future__ import annotations

from ..llm import LLMProvider, get_provider_safe, llm_config
from .config import AgentConfig, agent_config
from .graph import get_runner_safe
from .state import AgentState

__all__ = ["run_investigation", "AgentConfig", "agent_config", "AgentState"]


def run_investigation(incident: dict, evidence: dict, rag_result: dict,
                      provider: LLMProvider | None = None,
                      graph_backend: str | None = None) -> dict:
    """Run the Detection -> Evidence -> Threat Intelligence agent chain for one
    incident and return their combined output.

    `provider` defaults to the configured LLM provider (falling back to the mock
    provider if it can't be constructed - e.g. no API key set yet). `graph_backend`
    defaults to the configured graph backend (falling back to the dependency-light
    sequential runner if langgraph isn't installed).
    """
    provider = provider or get_provider_safe(llm_config)
    runner = get_runner_safe(graph_backend or agent_config.graph_backend, provider)

    initial_state: AgentState = {
        "incident": incident, "evidence": evidence, "rag_result": rag_result,
        "trace": [],
    }
    final_state = runner.invoke(initial_state)

    return {
        "incident_id": incident["incident_id"],
        "llm_provider": provider.name,
        "graph_backend": runner.backend,
        "detection_analysis": final_state.get("detection_analysis"),
        "evidence_summary": final_state.get("evidence_summary"),
        "threat_intel": final_state.get("threat_intel"),
        "timeline": final_state.get("timeline"),
        "investigation": final_state.get("investigation"),
        "trace": final_state.get("trace", []),
    }
