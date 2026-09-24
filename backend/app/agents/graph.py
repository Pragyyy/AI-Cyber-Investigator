"""Builds and runs the agent graph: Detection -> Evidence -> Threat Intelligence.

Two interchangeable runners, both exposing `.invoke(initial_state) -> final_state`:

- LangGraphRunner: the project brief's recommended orchestration (LangGraph
  StateGraph), used by default.
- SequentialRunner: a small dependency-light fallback with identical node logic and
  ordering, used when langgraph isn't installed and by this project's own test suite
  (so the agent logic itself is fully tested without needing the langgraph package).

Node order matters here beyond just style: node_threat_intel reads
state["detection_analysis"] and state["evidence_summary"], so it genuinely depends on
the other two agents having already run - this is real agent-to-agent handoff via
shared state, not three independent calls run in sequence for show.
"""
from __future__ import annotations

from ..llm import LLMProvider
from .nodes import node_detection, node_evidence, node_threat_intel
from .state import AgentState

NODE_ORDER = [("detection", node_detection), ("evidence", node_evidence),
             ("threat_intel", node_threat_intel)]


class SequentialRunner:
    """No external dependency. Runs each node in order, merging its returned dict into
    the shared state - the same update-merge semantics LangGraph uses."""
    backend = "sequential"

    def __init__(self, provider: LLMProvider):
        self.provider = provider

    def invoke(self, initial_state: AgentState) -> AgentState:
        state = dict(initial_state)
        for _name, node_fn in NODE_ORDER:
            updates = node_fn(state, self.provider)
            state.update(updates)
        return state


class LangGraphRunner:
    """The project brief's recommended orchestration."""
    backend = "langgraph"

    def __init__(self, provider: LLMProvider):
        try:
            from langgraph.graph import END, START, StateGraph
        except ImportError as exc:
            raise RuntimeError(
                "langgraph is not installed. Run `pip install langgraph` on the "
                "machine hosting the backend, or set AGENT_GRAPH_BACKEND=sequential "
                "for a lighter mode with identical agent logic."
            ) from exc

        self.provider = provider
        graph = StateGraph(AgentState)
        for name, node_fn in NODE_ORDER:
            graph.add_node(name, self._wrap(node_fn))
        graph.add_edge(START, NODE_ORDER[0][0])
        for (name, _), (next_name, _) in zip(NODE_ORDER, NODE_ORDER[1:]):
            graph.add_edge(name, next_name)
        graph.add_edge(NODE_ORDER[-1][0], END)
        self._compiled = graph.compile()

    def _wrap(self, node_fn):
        def run(state):
            return node_fn(state, self.provider)
        return run

    def invoke(self, initial_state: AgentState) -> AgentState:
        return self._compiled.invoke(initial_state)


def get_runner(backend: str, provider: LLMProvider):
    if backend == "sequential":
        return SequentialRunner(provider)
    if backend == "langgraph":
        return LangGraphRunner(provider)
    raise ValueError(f"Unknown agent graph backend '{backend}'. "
                     f"Choose from ['langgraph', 'sequential'].")


def get_runner_safe(backend: str, provider: LLMProvider):
    """Never raises: falls back to SequentialRunner (with a warning) if the configured
    backend can't be constructed - e.g. langgraph isn't installed yet."""
    try:
        return get_runner(backend, provider)
    except Exception as exc:  # noqa: BLE001
        print(f"[agents] Falling back to the sequential graph runner: {exc}")
        return SequentialRunner(provider)
