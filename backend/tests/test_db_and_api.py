import os
import tempfile
import unittest
from pathlib import Path

# Point the app at a throwaway database BEFORE importing it.
_TMP = tempfile.mkdtemp()
os.environ["DB_PATH"] = str(Path(_TMP) / "test.db")
os.environ["RAG_EMBEDDING_BACKEND"] = "tfidf"
os.environ["RAG_VECTOR_BACKEND"] = "memory"
os.environ["RAG_PERSIST_DIR"] = str(Path(_TMP) / "rag_index")

from app import db  # noqa: E402
from app.parser import parse_log_file  # noqa: E402

SAMPLES = Path(__file__).resolve().parents[2] / "data" / "sample_logs"


class DbTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.init_db()
        data = (SAMPLES / "attack_chain.csv").read_bytes()
        cls.upload = db.save_upload("attack_chain.csv", parse_log_file(data, "attack_chain.csv"))

    def test_upload_summary(self):
        u = self.upload
        self.assertEqual(u["event_count"], 88)
        self.assertEqual(u["summary"]["event_type_counts"]["LOGIN"] > 25, True)
        self.assertLess(u["summary"]["time_start"], u["summary"]["time_end"])

    def test_query_filters_and_paging(self):
        uid = self.upload["upload_id"]
        total, rows = db.query_events(uid, source_ip="192.168.1.50", status="failed")
        self.assertEqual((total, len(rows)), (25, 25))
        total, rows = db.query_events(uid, limit=10, offset=5)
        self.assertEqual(len(rows), 10)
        total, rows = db.query_events(uid, search="schtasks")
        self.assertEqual(total, 1)
        self.assertEqual(rows[0]["raw"]["process"], "schtasks.exe")

    def test_incident_storage_stats_and_replace(self):
        from app.detection import run_detection
        data = (SAMPLES / "security_logs.csv").read_bytes()
        u = db.save_upload("combined.csv", parse_log_file(data, "combined.csv"))
        uid = u["upload_id"]
        incidents = run_detection(db.get_all_events(uid))["incidents"]
        db.replace_incidents(uid, incidents)
        db.replace_incidents(uid, incidents)  # re-running must replace, not duplicate
        stored = db.list_incidents(uid)
        self.assertEqual(len(stored), 4)
        self.assertEqual(stored[0]["severity"], "CRITICAL")   # most severe first
        self.assertEqual(db.get_incident(uid, "INC-003")["incident_type"], "attack_chain")
        self.assertIsNone(db.get_incident(uid, "INC-999"))
        stats = db.dashboard_stats(uid)
        self.assertEqual(stats["total_events"], 130)
        self.assertEqual(stats["active_incidents"], 4)
        self.assertEqual(stats["high_severity_incidents"], 4)
        self.assertGreater(stats["suspicious_events"], 60)

    def test_evidence_cache_and_rebuild(self):
        from app.evidence import build_evidence
        data = (SAMPLES / "attack_chain.csv").read_bytes()
        u = db.save_upload("ac.csv", parse_log_file(data, "ac.csv"))
        uid = u["upload_id"]
        incidents = run_detection = __import__("app.detection", fromlist=["run_detection"]).run_detection
        incs = incidents(db.get_all_events(uid))["incidents"]
        db.replace_incidents(uid, incs)
        self.assertIsNone(db.get_evidence(uid, "INC-001"))
        ev = build_evidence(incs[0], db.get_all_events(uid))
        db.save_evidence(uid, "INC-001", ev)
        cached = db.get_evidence(uid, "INC-001")
        self.assertEqual(cached, ev)
        # re-running detection must clear stale evidence
        db.replace_incidents(uid, incs)
        self.assertIsNone(db.get_evidence(uid, "INC-001"))

    def test_delete_cascades(self):
        data = (SAMPLES / "brute_force.csv").read_bytes()
        u = db.save_upload("b.csv", parse_log_file(data, "b.csv"))
        self.assertTrue(db.delete_upload(u["upload_id"]))
        self.assertEqual(db.query_events(u["upload_id"])[0], 0)
        self.assertFalse(db.delete_upload(u["upload_id"]))


try:
    from fastapi.testclient import TestClient
    from app.main import app
    HAVE_API = True
except ImportError:  # fastapi / httpx not installed
    HAVE_API = False


@unittest.skipUnless(HAVE_API, "fastapi/httpx not installed")
class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.client.__enter__()  # runs the lifespan (creates tables)

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)

    def test_health(self):
        self.assertEqual(self.client.get("/api/health").json()["status"], "ok")

    def test_upload_then_fetch_events(self):
        data = (SAMPLES / "security_logs.csv").read_bytes()
        r = self.client.post("/api/uploads", files={"file": ("security_logs.csv", data)})
        self.assertEqual(r.status_code, 201)
        uid = r.json()["upload_id"]
        r = self.client.get(f"/api/uploads/{uid}/events", params={"event_type": "network", "limit": 5})
        body = r.json()
        self.assertEqual(len(body["events"]), 5)
        self.assertGreater(body["total"], 5)

    def test_bad_upload_returns_400_with_message(self):
        r = self.client.post("/api/uploads", files={"file": ("x.csv", b"user,action\nbob,login\n")})
        self.assertEqual(r.status_code, 400)
        self.assertIn("timestamp", r.json()["detail"])

    def test_upload_auto_detects_and_incident_endpoints(self):
        data = (SAMPLES / "security_logs.csv").read_bytes()
        up = self.client.post("/api/uploads", files={"file": ("security_logs.csv", data)}).json()
        self.assertEqual(up["incident_count"], 4)
        uid = up["upload_id"]
        incidents = self.client.get(f"/api/uploads/{uid}/incidents").json()
        self.assertEqual(len(incidents), 4)
        one = self.client.get(f"/api/uploads/{uid}/incidents/{incidents[0]['incident_id']}")
        self.assertEqual(one.status_code, 200)
        self.assertEqual(self.client.get(f"/api/uploads/{uid}/incidents/INC-999").status_code, 404)
        self.assertEqual(self.client.get(f"/api/uploads/{uid}/stats").json()["total_events"], 130)

    def test_rerun_detection_with_custom_threshold(self):
        data = (SAMPLES / "spec_example_no_header.csv").read_bytes()
        up = self.client.post("/api/uploads", files={"file": ("spec.csv", data)}).json()
        self.assertEqual(up["incident_count"], 0)
        r = self.client.post(f"/api/uploads/{up['upload_id']}/detect",
                             params={"brute_force_threshold": 3})
        self.assertEqual(r.json()["incident_count"], 1)

    def test_evidence_endpoint(self):
        data = (SAMPLES / "attack_chain.csv").read_bytes()
        up = self.client.post("/api/uploads", files={"file": ("ac.csv", data)}).json()
        uid = up["upload_id"]
        incidents = self.client.get(f"/api/uploads/{uid}/incidents").json()
        iid = incidents[0]["incident_id"]
        r = self.client.get(f"/api/uploads/{uid}/incidents/{iid}/evidence")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertTrue(body["traceable"])
        self.assertGreater(len(body["evidence_items"]), 0)
        # second call should be served from cache and be identical
        r2 = self.client.get(f"/api/uploads/{uid}/incidents/{iid}/evidence")
        self.assertEqual(r.json(), r2.json())
        r3 = self.client.get(f"/api/uploads/{uid}/incidents/{iid}/evidence", params={"refresh": "true"})
        self.assertEqual(r3.json(), r.json())
        self.assertEqual(
            self.client.get(f"/api/uploads/{uid}/incidents/INC-999/evidence").status_code, 404)

    def test_rag_status_search_and_threat_intel(self):
        status = self.client.get("/api/rag/status").json()
        self.assertTrue(status["built"])  # built automatically on startup (lifespan)
        results = self.client.get("/api/rag/search", params={"q": "brute force", "k": 3}).json()
        self.assertLessEqual(len(results), 3)

        data = (SAMPLES / "attack_chain.csv").read_bytes()
        up = self.client.post("/api/uploads", files={"file": ("ac.csv", data)}).json()
        uid = up["upload_id"]
        iid = self.client.get(f"/api/uploads/{uid}/incidents").json()[0]["incident_id"]
        r = self.client.get(f"/api/uploads/{uid}/incidents/{iid}/threat-intel")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertGreater(len(body["candidate_techniques"]), 0)
        r2 = self.client.get(f"/api/uploads/{uid}/incidents/{iid}/threat-intel")
        self.assertEqual(r.json(), r2.json())  # served from cache
        self.assertEqual(
            self.client.get(f"/api/uploads/{uid}/incidents/INC-999/threat-intel").status_code, 404)

    def test_rag_reindex(self):
        r = self.client.post("/api/rag/reindex")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["chunk_count"] > 0)

    def test_root_redirects_to_docs(self):
        r = self.client.get("/", follow_redirects=False)
        self.assertIn(r.status_code, (302, 307))

    def test_unknown_upload_is_404(self):
        self.assertEqual(self.client.get("/api/uploads/UPL-nope").status_code, 404)

    def test_sample_loading_and_traversal_blocked(self):
        names = [s["name"] for s in self.client.get("/api/samples").json()]
        self.assertIn("attack_chain.csv", names)
        self.assertNotIn("manifest.json", names)
        self.assertEqual(self.client.post("/api/samples/attack_chain.csv/load").status_code, 201)
        self.assertEqual(self.client.post("/api/samples/..%2F..%2F.env/load").status_code, 404)


if __name__ == "__main__":
    unittest.main()
