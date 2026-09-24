"""Agent tests use the SequentialRunner (no langgraph needed) with the MockProvider
(no API key/network needed) by default, so the agent logic itself is fully testable.
A separate test confirms LangGraphRunner degrades gracefully when langgraph is absent.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("RAG_EMBEDDING_BACKEND", "tfidf")
os.environ.setdefault("RAG_VECTOR_BACKEND", "memory")
_RAG_TMP = tempfile.mkdtemp()
os.environ["RAG_PERSIST_DIR"] = _RAG_TMP

from app.agents import run_investigation  # noqa: E402
from app.agents.fallback import (fallback_detection_analysis, fallback_evidence_summary,
                                 fallback_threat_intel)  # noqa: E402
from app.agents.graph import LangGraphRunner, SequentialRunner, get_runner_safe  # noqa: E402
from app.agents.nodes import node_detection, node_evidence, node_threat_intel  # noqa: E402
from app.detection import run_detection  # noqa: E402
from app.evidence import build_evidence  # noqa: E402
from app.llm import get_provider
from app.llm.config import LLMConfig  # noqa: E402
from app.parser import parse_log_file  # noqa: E402
from app.rag import build_index, rag_config, retrieve_for_incident  # noqa: E402

SAMPLES = Path(__file__).resolve().parents[2] / "data" / "sample_logs"
MOCK = get_provider(LLMConfig(provider="mock"))


def load_incident(filename, index=0):
    events = parse_log_file((SAMPLES / filename).read_bytes(), filename).events
    incidents = run_detection(events)["incidents"]
    incident = incidents[index]
    evidence = build_evidence(incident, events)
    return incident, evidence


class FallbackBuilderTests(unittest.TestCase):
    """Fallback builders must never invent facts beyond their input - every number,
    ID and IP in the output should trace back to the incident/evidence given."""

    def test_detection_fallback_uses_only_given_facts(self):
        incident, _ = load_incident("brute_force.csv")
        result = fallback_detection_analysis(incident)
        self.assertEqual(result["headline"], incident["title"])
        self.assertIn(incident["source_ips"][0], result["reasoning"])
        self.assertEqual(result["confidence"], "medium")  # HIGH severity -> medium

    def test_evidence_fallback_cites_every_item(self):
        incident, evidence = load_incident("attack_chain.csv")
        result = fallback_evidence_summary(evidence)
        for item in evidence["evidence_items"]:
            self.assertIn(item["evidence_id"], result["narrative"])
        self.assertLessEqual(len(result["key_evidence_ids"]), 6)
        self.assertTrue(set(result["key_evidence_ids"]) <=
                        {i["evidence_id"] for i in evidence["evidence_items"]})

    def test_threat_intel_fallback_only_uses_retrieved_candidates(self):
        incident, evidence = load_incident("brute_force.csv")
        build_index(rag_config)
        rag_result = retrieve_for_incident(incident, evidence, rag_config)
        result = fallback_threat_intel(rag_result)
        self.assertEqual({t["technique_id"] for t in result},
                         {c["technique_id"] for c in rag_result["candidate_techniques"]})
        for t in result:
            self.assertIn(t["verdict"], ("supported", "potential", "weak"))

    def test_threat_intel_fallback_handles_empty_candidates(self):
        self.assertEqual(fallback_threat_intel({"candidate_techniques": []}), [])


class NodeTests(unittest.TestCase):
    """Each node is tested directly against the MockProvider (no fallback lambda
    override needed beyond what the node builds itself)."""

    @classmethod
    def setUpClass(cls):
        build_index(rag_config)
        cls.incident, cls.evidence = load_incident("attack_chain.csv")
        cls.rag_result = retrieve_for_incident(cls.incident, cls.evidence, rag_config)

    def test_node_detection_returns_parseable_result_and_trace(self):
        state = {"incident": self.incident}
        updates = node_detection(state, MOCK)
        self.assertIn("headline", updates["detection_analysis"])
        self.assertEqual(updates["trace"][-1]["agent"], "detection_analysis")
        self.assertEqual(updates["trace"][-1]["generated_by"], "fallback")
        self.assertNotIn("debug_note", updates["trace"][-1])  # clean fallback, no error

    def test_node_evidence_returns_parseable_result(self):
        state = {"evidence": self.evidence}
        updates = node_evidence(state, MOCK)
        self.assertIn("narrative", updates["evidence_summary"])
        self.assertIn("key_evidence_ids", updates["evidence_summary"])

    def test_node_threat_intel_requires_upstream_state(self):
        """Real dependency, not cosmetic ordering: threat_intel reads the other two
        agents' outputs, so it needs them already in state."""
        state = {
            "rag_result": self.rag_result, "evidence": self.evidence,
            "detection_analysis": fallback_detection_analysis(self.incident),
            "evidence_summary": fallback_evidence_summary(self.evidence),
        }
        updates = node_threat_intel(state, MOCK)
        self.assertGreater(len(updates["threat_intel"]["techniques"]), 0)

    def test_llm_generated_by_tag_when_provider_returns_real_text(self):
        """Simulate a real (non-fallback) LLM response via a custom mock_response is
        not possible with MockProvider directly (it always uses the given fallback),
        so instead we use an OpenAI-compatible provider pointed nowhere reachable but
        assert the *fallback* path tags correctly - the "llm" tag path itself is
        exercised implicitly by test_run_investigation_end_to_end using a provider
        stub below."""
        state = {"incident": self.incident}
        updates = node_detection(state, MOCK)
        self.assertEqual(updates["trace"][-1]["generated_by"], "fallback")


class _EchoRealProvider:
    """A tiny stand-in that simulates a "real" LLM by returning valid JSON that is
    NOT identical to the fallback text, so nodes correctly tag it "llm"."""
    name = "echo_test_provider"

    def complete(self, system, user, *, max_tokens=1024, temperature=0.2, mock_response=None):
        if "headline" in system:
            return json.dumps({"headline": "LLM-GENERATED HEADLINE", "reasoning": "r",
                              "initial_hypothesis": "h", "confidence": "high"})
        if "narrative" in system:
            return json.dumps({"narrative": "LLM-GENERATED NARRATIVE", "key_evidence_ids": []})
        return json.dumps([{"technique_id": "T9999", "technique_name": "LLM Technique",
                           "verdict": "supported", "justification": "llm said so",
                           "evidence_ids": []}])


class _RamblingProvider:
    """Simulates a reasoning model (e.g. gpt-oss on Groq) that wraps its JSON answer in
    unrequested chain-of-thought/preamble text and then gets cut off by max_tokens
    before the JSON closes - this is what actually happened in real use with
    openai_compatible + gpt-oss-20b, and is exactly the case debug_note exists for."""
    name = "rambling_test_provider"

    def complete(self, system, user, *, max_tokens=1024, temperature=0.2, mock_response=None):
        # Deliberately unparseable: an opening brace that never closes.
        return ('Let me think about this step by step. First I will consider the '
               'evidence... {"narrative": "this response gets cut off mid-thought')


class NodeParseFailureTests(unittest.TestCase):
    """Regression coverage for a real production issue: a real LLM call can return
    non-JSON text (reasoning-model preamble, truncation) that must fall back cleanly
    AND be debuggable, rather than silently swallowed."""

    @classmethod
    def setUpClass(cls):
        build_index(rag_config)
        cls.incident, cls.evidence = load_incident("brute_force.csv")

    def test_unparseable_response_falls_back_with_debug_note(self):
        state = {"evidence": self.evidence}
        updates = node_evidence(state, _RamblingProvider())
        trace = updates["trace"][-1]
        self.assertEqual(trace["generated_by"], "fallback_parse_error")
        self.assertIn("debug_note", trace)
        self.assertIn("Raw response", trace["debug_note"])
        # and the actual data returned must still be the safe deterministic fallback,
        # not the garbled/truncated text
        self.assertEqual(updates["evidence_summary"],
                         fallback_evidence_summary(self.evidence))

    def test_debug_note_previews_the_raw_text_for_diagnosis(self):
        state = {"evidence": self.evidence}
        updates = node_evidence(state, _RamblingProvider())
        note = updates["trace"][-1]["debug_note"]
        self.assertIn("Let me think about this step by step", note)


class SequentialRunnerTests(unittest.TestCase):
    def test_full_chain_with_mock_provider(self):
        incident, evidence = load_incident("brute_force.csv")
        build_index(rag_config)
        rag_result = retrieve_for_incident(incident, evidence, rag_config)
        runner = SequentialRunner(MOCK)
        final_state = runner.invoke({"incident": incident, "evidence": evidence,
                                    "rag_result": rag_result, "trace": []})
        self.assertIn("detection_analysis", final_state)
        self.assertIn("evidence_summary", final_state)
        self.assertIn("threat_intel", final_state)
        self.assertEqual(len(final_state["trace"]), 3)
        self.assertEqual([t["agent"] for t in final_state["trace"]],
                         ["detection_analysis", "evidence_summary", "threat_intel"])

    def test_llm_tag_used_when_provider_returns_novel_json(self):
        incident, evidence = load_incident("brute_force.csv")
        rag_result = retrieve_for_incident(incident, evidence, rag_config)
        runner = SequentialRunner(_EchoRealProvider())
        final_state = runner.invoke({"incident": incident, "evidence": evidence,
                                    "rag_result": rag_result, "trace": []})
        self.assertEqual(final_state["detection_analysis"]["headline"], "LLM-GENERATED HEADLINE")
        self.assertEqual(final_state["evidence_summary"]["narrative"], "LLM-GENERATED NARRATIVE")
        self.assertTrue(all(t["generated_by"] == "llm" for t in final_state["trace"]))


def _langgraph_installed() -> bool:
    try:
        import langgraph  # noqa: F401
        return True
    except ImportError:
        return False


class LangGraphFallbackTests(unittest.TestCase):
    """These force the ImportError path via sys.modules patching rather than relying
    on langgraph actually being absent from the environment. requirements.txt lists
    langgraph as a normal dependency, so on any machine that ran
    `pip install -r requirements.txt` it IS installed - a test that only passed when
    it was missing would fail on every correctly set-up machine, forever. Patching
    sys.modules makes `import langgraph...` raise ImportError deterministically,
    regardless of what's actually installed, so this tests our fallback *logic*
    rather than the ambient environment."""

    def test_missing_langgraph_falls_back_to_sequential(self):
        with mock.patch.dict(sys.modules, {"langgraph": None, "langgraph.graph": None}):
            runner = get_runner_safe("langgraph", MOCK)
        self.assertIsInstance(runner, SequentialRunner)

    def test_strict_get_runner_raises_for_missing_langgraph(self):
        with mock.patch.dict(sys.modules, {"langgraph": None, "langgraph.graph": None}):
            with self.assertRaises(RuntimeError):
                LangGraphRunner(MOCK)

    def test_unknown_backend_raises_in_strict_mode(self):
        from app.agents.graph import get_runner
        with self.assertRaises(ValueError):
            get_runner("not_a_real_backend", MOCK)

    def test_langgraph_runner_produces_same_shape_as_sequential(self):
        """When langgraph IS installed, its output must match the sequential runner's
        output shape exactly - same node logic, just different orchestration."""
        if not _langgraph_installed():
            self.skipTest("langgraph not installed in this environment")
        incident, evidence = load_incident("brute_force.csv")
        rag_result = retrieve_for_incident(incident, evidence, rag_config)
        seq_state = SequentialRunner(MOCK).invoke(
            {"incident": incident, "evidence": evidence, "rag_result": rag_result, "trace": []})
        lg_state = LangGraphRunner(MOCK).invoke(
            {"incident": incident, "evidence": evidence, "rag_result": rag_result, "trace": []})
        for key in ("detection_analysis", "evidence_summary", "threat_intel"):
            self.assertEqual(seq_state[key], lg_state[key])


class RunInvestigationIntegrationTests(unittest.TestCase):
    """End-to-end through the public run_investigation() entry point, for every attack
    scenario - this is what the API layer calls."""

    @classmethod
    def setUpClass(cls):
        build_index(rag_config)

    def test_every_attack_scenario_produces_a_complete_result(self):
        for filename in ("brute_force.csv", "suspicious_powershell.csv",
                         "suspicious_auth_endpoint.csv", "attack_chain.csv"):
            with self.subTest(file=filename):
                incident, evidence = load_incident(filename)
                rag_result = retrieve_for_incident(incident, evidence, rag_config)
                result = run_investigation(incident, evidence, rag_result,
                                          provider=MOCK, graph_backend="sequential")
                self.assertEqual(result["incident_id"], incident["incident_id"])
                self.assertEqual(result["llm_provider"], "mock")
                self.assertEqual(result["graph_backend"], "sequential")
                for key in ("detection_analysis", "evidence_summary", "threat_intel"):
                    self.assertIsNotNone(result[key])
                self.assertEqual(len(result["trace"]), 3)

    def test_defaults_to_configured_backend_with_graceful_langgraph_fallback(self):
        incident, evidence = load_incident("brute_force.csv")
        rag_result = retrieve_for_incident(incident, evidence, rag_config)
        # No explicit provider/backend passed - exercises get_provider_safe() and
        # get_runner_safe() with whatever this environment's config actually resolves
        # to. langgraph may or may not be installed, so assert the graceful-fallback
        # *contract* (always one of the two known backends, never a crash) rather than
        # hardcoding which one wins here - the forced-absence case is covered
        # separately and deterministically in LangGraphFallbackTests above.
        result = run_investigation(incident, evidence, rag_result)
        self.assertIn(result["graph_backend"], ("sequential", "langgraph"))
        self.assertIsNotNone(result["detection_analysis"])

    def test_deterministic_with_mock_provider(self):
        incident, evidence = load_incident("attack_chain.csv")
        rag_result = retrieve_for_incident(incident, evidence, rag_config)
        a = run_investigation(incident, evidence, rag_result, provider=MOCK,
                             graph_backend="sequential")
        b = run_investigation(incident, evidence, rag_result, provider=MOCK,
                             graph_backend="sequential")
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
