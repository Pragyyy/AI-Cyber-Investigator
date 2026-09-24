"""Agent graph configuration."""
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AgentConfig:
    # "langgraph" is the project brief's recommended orchestration. "sequential" is a
    # dependency-light fallback with identical agent logic - used automatically if
    # langgraph isn't installed, and by this project's own test suite.
    graph_backend: str = os.getenv("AGENT_GRAPH_BACKEND", "langgraph")


agent_config = AgentConfig()
