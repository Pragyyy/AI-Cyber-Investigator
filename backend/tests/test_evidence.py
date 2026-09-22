import unittest
from pathlib import Path

from app.detection import run_detection
from app.evidence import build_evidence
from app.parser import parse_log_file

SAMPLES = Path(__file__).resolve().parents[2] / "data" / "sample_logs"


def evidence_for(filename, incident_index=0):
    events = parse_log_file((SAMPLES / filename).read_bytes(), filename).events
    incidents = run_detection(events)["incidents"]
    return build_evidence(incidents[incident_index], events), incidents[incident_index], events


class TraceabilityTests(unittest.TestCase):
    """The core requirement: every evidence item must point back to real log rows."""

    def _check(self, filename):
        for idx in range(len(run_detection(
                parse_log_file((SAMPLES / filename).read_bytes(), filename).events)["incidents"])):
            with self.subTest(file=filename, incident=idx):
                ev, inc, events = evidence_for(filename, idx)
                by_id = {e["event_id"] for e in events}
                self.assertTrue(ev["traceable"])
                self.assertGreater(len(ev["evidence_items"]), 0)
                for item in ev["evidence_items"]:
                    self.assertGreater(len(item["event_ids"]), 0)
                    for eid in item["event_ids"]:
                        self.assertIn(eid, by_id, f"{item['evidence_id']} cites unknown event {eid}")
                    # every statement should be a real sentence with supporting numbers/text
                    self.assertTrue(item["statement"].strip())

    def test_all_scenarios_are_traceable(self):
        for filename in ("brute_force.csv", "suspicious_powershell.csv",
                         "suspicious_auth_endpoint.csv", "attack_chain.csv"):
            self._check(filename)

    def test_evidence_ids_are_sequential_and_unique(self):
        ev, _, _ = evidence_for("attack_chain.csv")
        ids = [i["evidence_id"] for i in ev["evidence_items"]]
        self.assertEqual(ids, [f"EV-{n:03d}" for n in range(1, len(ids) + 1)])


class ContentTests(unittest.TestCase):
    def test_brute_force_evidence_matches_spec_example_style(self):
        ev, inc, _ = evidence_for("brute_force.csv")
        stmts = [i["statement"] for i in ev["evidence_items"]]
        self.assertTrue(any("30 failed authentication attempts" in s for s in stmts))
        self.assertTrue(any("192.168.1.77" in s for s in stmts))
        # no success in this scenario -> no "Successful authentication" item
        self.assertFalse(any("Successful authentication" in s for s in stmts))

    def test_attack_chain_evidence_covers_full_kill_chain(self):
        ev, inc, _ = evidence_for("attack_chain.csv")
        categories = {i["category"] for i in ev["evidence_items"]}
        self.assertEqual(categories, {"authentication", "process_execution", "discovery",
                                      "persistence", "network", "file"})
        stmts = " | ".join(i["statement"] for i in ev["evidence_items"])
        self.assertIn("25 failed authentication attempts", stmts)
        self.assertIn("Successful authentication", stmts)
        self.assertIn("encoded", stmts.lower())
        self.assertIn("beaconing", stmts.lower())
        self.assertIn("scheduled task", stmts.lower())
        self.assertIn("whoami", stmts.lower())

    def test_file_artifact_found_even_though_no_rule_flags_it(self):
        """FILE events aren't matched by any detection rule directly - evidence
        extraction should still pick up the dropped file via related-event context."""
        ev, inc, events = evidence_for("attack_chain.csv")
        file_items = [i for i in ev["evidence_items"] if i["category"] == "file"]
        self.assertEqual(len(file_items), 1)
        self.assertIn("SHA-256", file_items[0]["statement"])
        self.assertIn("update.exe", file_items[0]["statement"])
        # and it must not still be sitting in "related_events" once it's been promoted
        self.assertNotIn(file_items[0]["event_ids"][0],
                         [r["event_id"] for r in ev["related_events"]])

    def test_indicators_are_deduplicated_and_include_context(self):
        ev, inc, _ = evidence_for("attack_chain.csv")
        ind = ev["indicators"]
        self.assertEqual(ind["source_ips"], ["192.168.1.50"])
        self.assertEqual(ind["usernames"], ["admin"])
        self.assertIn("powershell.exe", ind["processes"])
        self.assertIn("schtasks.exe", ind["processes"])
        self.assertEqual(len(ind["file_hashes"]), 1)
        self.assertIn(4444, ind["destination_ports"])
        self.assertIn("198.51.100.23", ind["destination_ips"])  # C2 destination, not just source

    def test_unusual_login_produces_one_item_per_signal(self):
        ev, inc, _ = evidence_for("suspicious_auth_endpoint.csv")
        auth_items = [i for i in ev["evidence_items"] if i["category"] == "authentication"]
        self.assertGreaterEqual(len(auth_items), 2)  # external IP + outside business hours

    def test_powershell_evidence_names_each_technique_separately(self):
        ev, inc, _ = evidence_for("suspicious_powershell.csv")
        stmts = [i["statement"] for i in ev["evidence_items"]]
        self.assertTrue(any("encoded" in s.lower() for s in stmts))
        self.assertTrue(any("download-and-execute" in s.lower() for s in stmts))
        self.assertTrue(any("office" in s.lower() for s in stmts))


class DeterminismTests(unittest.TestCase):
    def test_same_incident_gives_same_evidence(self):
        a, _, _ = evidence_for("attack_chain.csv")
        b, _, _ = evidence_for("attack_chain.csv")
        self.assertEqual(a, b)

    def test_normal_activity_has_no_incidents_to_evidence(self):
        events = parse_log_file((SAMPLES / "normal_activity.csv").read_bytes(),
                                "normal_activity.csv").events
        self.assertEqual(run_detection(events)["incidents"], [])


if __name__ == "__main__":
    unittest.main()
