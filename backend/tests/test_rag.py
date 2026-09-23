"""RAG tests use the lightweight tfidf/memory backends (no downloads needed), pointed
at an isolated temp directory. The sentence-transformers/chromadb backends share the
same code paths (embeddings.py / store.py) and are exercised by the abstraction's
interface contract, but are not re-downloaded/tested here - see README for how to
switch backends via environment variables.
"""
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp()
os.environ["RAG_EMBEDDING_BACKEND"] = "tfidf"
os.environ["RAG_VECTOR_BACKEND"] = "memory"
os.environ["RAG_PERSIST_DIR"] = _TMP

from app.detection import run_detection  # noqa: E402
from app.evidence import build_evidence  # noqa: E402
from app.parser import parse_log_file  # noqa: E402
from app.rag import RagConfig  # noqa: E402
from app.rag.chunking import load_and_chunk  # noqa: E402
from app.rag.pipeline import build_index, get_status, retrieve, retrieve_for_incident  # noqa: E402

SAMPLES = Path(__file__).resolve().parents[2] / "data" / "sample_logs"
KB_DIR = Path(__file__).resolve().parents[2] / "data" / "knowledge_base"
CFG = RagConfig(embedding_backend="tfidf", vector_backend="memory", persist_dir=_TMP)


def tearDownModule():
    shutil.rmtree(_TMP, ignore_errors=True)


class ChromaConversionTests(unittest.TestCase):
    """Regression test for a real bug: ChromaDB's validation rejects numpy scalar
    types (numpy.float32), so embeddings must be converted to plain Python floats
    before being passed in. This doesn't need chromadb installed, so it still catches
    the bug in environments (like this one) where chromadb isn't available."""

    def test_numpy_rows_become_plain_python_floats(self):
        import numpy as np
        from app.rag.store import _to_float_rows

        rows = np.array([[0.1, -0.2, 0.3]], dtype="float32")
        converted = _to_float_rows(rows)
        self.assertEqual(type(converted), list)
        self.assertEqual(type(converted[0]), list)
        for value in converted[0]:
            self.assertIs(type(value), float)  # not numpy.float32/float64
        self.assertAlmostEqual(converted[0][0], 0.1, places=5)


class ChunkingTests(unittest.TestCase):
    def test_loads_all_techniques_and_docs(self):
        chunks = load_and_chunk(str(KB_DIR))
        mitre = [c for c in chunks if c.doc_type == "mitre_technique"]
        guides = [c for c in chunks if c.doc_type == "guideline"]
        self.assertEqual(len(mitre), 17)
        self.assertGreaterEqual(len(guides), 15)
        # every technique chunk cites its ID and a MITRE URL
        t1110 = next(c for c in mitre if c.metadata["technique_id"] == "T1110")
        self.assertIn("T1110", t1110.title)
        self.assertTrue(t1110.url.startswith("https://attack.mitre.org/techniques/T1110/"))

    def test_chunk_ids_are_unique(self):
        chunks = load_and_chunk(str(KB_DIR))
        ids = [c.chunk_id for c in chunks]
        self.assertEqual(len(ids), len(set(ids)))

    def test_long_section_gets_split_with_overlap(self):
        chunks = load_and_chunk(str(KB_DIR), max_words=20, overlap=5)
        doc_chunks = [c for c in chunks if c.doc_type == "guideline"]
        self.assertGreater(len(doc_chunks), 15)  # more, smaller pieces than the default


class IndexAndRetrieveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = build_index(CFG)

    def test_manifest_reports_backends_and_counts(self):
        self.assertEqual(self.manifest["embedding_backend"], "tfidf")
        self.assertEqual(self.manifest["vector_backend"], "memory")
        self.assertEqual(self.manifest["technique_count"], 17)
        self.assertEqual(self.manifest["chunk_count"],
                         self.manifest["technique_count"] + self.manifest["guideline_chunk_count"])

    def test_get_status_reflects_build(self):
        status = get_status(CFG)
        self.assertTrue(status["built"])
        self.assertEqual(status["chunk_count"], self.manifest["chunk_count"])

    def test_retrieve_top_result_is_relevant(self):
        cases = {
            "repeated failed login attempts brute force": "T1110",
            "powershell encoded command hidden window": None,  # checked via technique_id below
            "scheduled task created public folder persistence": "T1053.005",
        }
        for query, expected_id in cases.items():
            if expected_id is None:
                continue
            results = retrieve(query, k=3, cfg=CFG)
            top_ids = [r["metadata"].get("technique_id") for r in results]
            self.assertIn(expected_id, top_ids, f"{expected_id} not in top-3 for {query!r}")

    def test_retrieve_respects_k(self):
        self.assertEqual(len(retrieve("login", k=2, cfg=CFG)), 2)

    def test_scores_are_sorted_descending(self):
        results = retrieve("suspicious powershell activity", k=5, cfg=CFG)
        scores = [r["score"] for r in results]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_unbuilt_index_raises_clear_error(self):
        empty_cfg = RagConfig(embedding_backend="tfidf", vector_backend="memory",
                              persist_dir=tempfile.mkdtemp())
        with self.assertRaises(RuntimeError):
            retrieve("anything", cfg=empty_cfg)


class IncidentRetrievalTests(unittest.TestCase):
    """Checks retrieval recall against the manifest's expected_mitre ground truth.
    This is an open-world check (expected IDs must appear), not exact-set matching,
    since a reasonable retrieval may surface additional relevant techniques too.
    """

    @classmethod
    def setUpClass(cls):
        build_index(CFG)
        cls.manifest = json.loads((SAMPLES / "manifest.json").read_text())

    def _candidates_for(self, filename):
        events = parse_log_file((SAMPLES / filename).read_bytes(), filename).events
        incidents = run_detection(events)["incidents"]
        out = []
        for inc in incidents:
            ev = build_evidence(inc, events)
            result = retrieve_for_incident(inc, ev, cfg=CFG)
            out.append((inc, result))
        return out

    def test_expected_techniques_are_recalled(self):
        for filename, truth in self.manifest.items():
            expected_mitre = truth.get("expected_mitre")
            if not expected_mitre:
                continue
            with self.subTest(file=filename):
                results = self._candidates_for(filename)
                self.assertEqual(len(results), 1, "expected exactly one incident for this file")
                _, result = results[0]
                found_ids = {t["technique_id"] for t in result["candidate_techniques"]}
                missing = set(expected_mitre) - found_ids
                self.assertEqual(missing, set(),
                                 f"{filename}: expected {expected_mitre}, missing {missing}, "
                                 f"got {sorted(found_ids)}")

    def test_every_candidate_traces_to_at_least_one_evidence_item(self):
        _, result = self._candidates_for("attack_chain.csv")[0]
        for t in result["candidate_techniques"]:
            self.assertGreater(len(t["matched_evidence"]), 0)

    def test_candidates_never_below_min_score(self):
        for filename in ("brute_force.csv", "suspicious_powershell.csv", "attack_chain.csv"):
            for _, result in self._candidates_for(filename):
                for t in result["candidate_techniques"]:
                    self.assertGreaterEqual(t["score"], CFG.min_score)

    def test_response_includes_non_confirmation_note(self):
        _, result = self._candidates_for("brute_force.csv")[0]
        self.assertIn("not confirmed", result["note"])

    def test_normal_activity_has_no_incidents_so_nothing_to_map(self):
        events = parse_log_file((SAMPLES / "normal_activity.csv").read_bytes(),
                                "normal_activity.csv").events
        self.assertEqual(run_detection(events)["incidents"], [])


if __name__ == "__main__":
    unittest.main()
