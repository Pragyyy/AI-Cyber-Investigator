"""Report generation tests. PDF rendering is actually executed (not mocked) and its
output is verified by extracting text back out with pypdf - so these tests catch real
rendering bugs (like the & escaping issue found during development), not just "did it
throw an exception"."""
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RAG_EMBEDDING_BACKEND", "tfidf")
os.environ.setdefault("RAG_VECTOR_BACKEND", "memory")
_RAG_TMP = tempfile.mkdtemp()
os.environ["RAG_PERSIST_DIR"] = _RAG_TMP

from app.agents import run_investigation  # noqa: E402
from app.detection import run_detection  # noqa: E402
from app.evidence import build_evidence  # noqa: E402
from app.parser import parse_log_file  # noqa: E402
from app.rag import build_index, rag_config, retrieve_for_incident  # noqa: E402
from app.report import build_report_data, get_recommended_actions, render_pdf  # noqa: E402
from app.report.actions import RECOMMENDED_ACTIONS_BY_RULE, UNIVERSAL_CLOSING_ACTIONS

SAMPLES = Path(__file__).resolve().parents[2] / "data" / "sample_logs"

try:
    from pypdf import PdfReader
    HAVE_PYPDF = True
except ImportError:
    HAVE_PYPDF = False


def full_pipeline(filename, index=0):
    events = parse_log_file((SAMPLES / filename).read_bytes(), filename).events
    incident = run_detection(events)["incidents"][index]
    evidence = build_evidence(incident, events)
    build_index(rag_config)
    rag_result = retrieve_for_incident(incident, evidence, rag_config)
    investigation = run_investigation(incident, evidence, rag_result, graph_backend="sequential")
    return incident, evidence, investigation, rag_result


class RecommendedActionsTests(unittest.TestCase):
    def test_actions_only_from_rules_actually_present(self):
        incident, _, _, _ = full_pipeline("brute_force.csv")
        actions = get_recommended_actions(incident)
        for action in RECOMMENDED_ACTIONS_BY_RULE["BRUTE_FORCE"]:
            self.assertIn(action, actions)
        for action in RECOMMENDED_ACTIONS_BY_RULE["SUSPICIOUS_POWERSHELL"]:
            self.assertNotIn(action, actions)  # brute force incident has no PowerShell

    def test_universal_actions_always_included(self):
        incident, _, _, _ = full_pipeline("brute_force.csv")
        actions = get_recommended_actions(incident)
        for action in UNIVERSAL_CLOSING_ACTIONS:
            self.assertIn(action, actions)

    def test_multi_rule_incident_combines_and_dedupes(self):
        incident, _, _, _ = full_pipeline("attack_chain.csv")  # 4 rules
        actions = get_recommended_actions(incident)
        self.assertEqual(len(actions), len(set(actions)))  # no duplicates
        # every rule that fired should contribute at least one action
        for rule_id in incident["rules"]:
            rule_actions = RECOMMENDED_ACTIONS_BY_RULE.get(rule_id, [])
            self.assertTrue(any(a in actions for a in rule_actions) or not rule_actions)

    def test_deterministic(self):
        incident, _, _, _ = full_pipeline("attack_chain.csv")
        self.assertEqual(get_recommended_actions(incident), get_recommended_actions(incident))


class ReportDataBuilderTests(unittest.TestCase):
    def test_core_incident_fields_present(self):
        incident, evidence, investigation, rag_result = full_pipeline("attack_chain.csv")
        report = build_report_data(incident, evidence, investigation, rag_result)
        self.assertEqual(report["incident_id"], incident["incident_id"])
        self.assertEqual(report["severity"], "CRITICAL")
        self.assertEqual(report["affected_users"], incident["usernames"])
        self.assertEqual(report["affected_hosts"], incident["hostnames"])

    def test_timeline_rows_match_phase_count(self):
        incident, evidence, investigation, rag_result = full_pipeline("attack_chain.csv")
        report = build_report_data(incident, evidence, investigation, rag_result)
        self.assertEqual(len(report["timeline"]), len(investigation["timeline"]))

    def test_gap_note_only_on_notable_gaps(self):
        incident, evidence, investigation, rag_result = full_pipeline("attack_chain.csv")
        report = build_report_data(incident, evidence, investigation, rag_result)
        gap_notes = [row["gap_note"] for row in report["timeline"]]
        self.assertTrue(any(g is not None for g in gap_notes))
        self.assertTrue(any(g is None for g in gap_notes))

    def test_evidence_items_carry_ids(self):
        incident, evidence, investigation, rag_result = full_pipeline("attack_chain.csv")
        report = build_report_data(incident, evidence, investigation, rag_result)
        report_ids = {i["evidence_id"] for i in report["evidence_items"]}
        source_ids = {i["evidence_id"] for i in evidence["evidence_items"]}
        self.assertEqual(report_ids, source_ids)

    def test_mitre_techniques_sorted_supported_first(self):
        incident, evidence, investigation, rag_result = full_pipeline("attack_chain.csv")
        report = build_report_data(incident, evidence, investigation, rag_result)
        verdict_order = {"supported": 0, "potential": 1, "weak": 2}
        scores = [verdict_order[t["verdict"]] for t in report["mitre_techniques"]]
        self.assertEqual(scores, sorted(scores))

    def test_missing_rag_result_omits_sources_without_crashing(self):
        incident, evidence, investigation, _ = full_pipeline("brute_force.csv")
        report = build_report_data(incident, evidence, investigation, rag_result=None)
        self.assertEqual(report["rag_sources"], [])

    def test_recommended_actions_included(self):
        incident, evidence, investigation, rag_result = full_pipeline("brute_force.csv")
        report = build_report_data(incident, evidence, investigation, rag_result)
        self.assertGreater(len(report["recommended_actions"]), 0)

    def test_agent_trace_carried_through(self):
        incident, evidence, investigation, rag_result = full_pipeline("brute_force.csv")
        report = build_report_data(incident, evidence, investigation, rag_result)
        self.assertEqual(len(report["agent_trace"]), 4)


@unittest.skipUnless(HAVE_PYPDF, "pypdf not installed")
class PdfRenderingTests(unittest.TestCase):
    """These actually render a PDF and read the text back out - not just checking that
    render_pdf() doesn't throw."""

    @classmethod
    def setUpClass(cls):
        incident, evidence, investigation, rag_result = full_pipeline("attack_chain.csv")
        cls.report_data = build_report_data(incident, evidence, investigation, rag_result)
        cls.tmp_dir = tempfile.mkdtemp()
        cls.pdf_path = os.path.join(cls.tmp_dir, "report.pdf")
        render_pdf(cls.report_data, cls.pdf_path)
        cls.text = "\n".join(p.extract_text() for p in PdfReader(cls.pdf_path).pages)

    def test_file_was_created_with_content(self):
        self.assertTrue(os.path.exists(self.pdf_path))
        self.assertGreater(os.path.getsize(self.pdf_path), 1000)

    def test_key_incident_facts_appear_in_rendered_text(self):
        self.assertIn(self.report_data["incident_id"], self.text)
        self.assertIn("CRITICAL", self.text)
        self.assertIn("192.168.1.50", self.text)
        self.assertIn("admin", self.text)

    def test_mitre_heading_renders_correctly_not_corrupted(self):
        """Regression test for the & escaping bug: this exact heading rendered as
        'MITRE ATT&CK; Mapping' (corrupted) before the fix."""
        self.assertIn("MITRE ATT&CK Mapping", self.text)
        self.assertNotIn("ATT&CK;", self.text)

    def test_evidence_ids_appear(self):
        for item in self.report_data["evidence_items"][:3]:
            self.assertIn(item["evidence_id"], self.text)

    def test_recommended_actions_appear(self):
        for action in self.report_data["recommended_actions"][:2]:
            # Long strings may wrap across lines in extracted text; check a distinctive
            # substring instead of the full sentence.
            self.assertIn(action.split(".")[0][:30], self.text)

    def test_ampersand_and_angle_brackets_survive_intact(self):
        """Stress test: inject characters that break naive reportlab markup if not
        escaped, and confirm they come back out exactly as given."""
        import copy
        data = copy.deepcopy(self.report_data)
        data["gaps_and_uncertainty"] = ("Confidence < 50% & > 10% uncertain; A&B not "
                                        "ruled out. <script>alert(1)</script>")
        path = os.path.join(self.tmp_dir, "stress.pdf")
        render_pdf(data, path)
        text = "\n".join(p.extract_text() for p in PdfReader(path).pages)
        self.assertIn("Confidence < 50% & > 10% uncertain; A&B not ruled out.", text)
        self.assertIn("<script>alert(1)</script>", text)

    def test_multi_page(self):
        self.assertGreaterEqual(len(PdfReader(self.pdf_path).pages), 3)


if __name__ == "__main__":
    unittest.main()
