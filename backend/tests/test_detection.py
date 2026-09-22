import json
import unittest
from dataclasses import replace
from pathlib import Path

from app.detection import DetectionConfig, run_detection
from app.detection.common import is_external, process_name
from app.parser import parse_log_file

SAMPLES = Path(__file__).resolve().parents[2] / "data" / "sample_logs"


def detect(name, cfg=None):
    r = parse_log_file((SAMPLES / name).read_bytes(), name)
    return run_detection(r.events, cfg)


def make_event(n, ts, **fields):
    base = {"event_id": f"EVT-{n:06d}", "row_number": n, "timestamp": ts, "username": None,
            "source_ip": None, "destination_ip": None, "destination_port": None,
            "event_type": None, "action": None, "status": None, "hostname": None,
            "process": None, "command_line": None, "file_hash": None, "message": None}
    base.update(fields)
    return base


class ScenarioTests(unittest.TestCase):
    def test_normal_activity_has_no_false_positives(self):
        out = detect("normal_activity.csv")
        self.assertEqual(out["detections"], [])
        self.assertEqual(out["incidents"], [])

    def test_brute_force(self):
        (inc,) = detect("brute_force.csv")["incidents"]
        self.assertEqual((inc["incident_type"], inc["severity"]), ("brute_force", "HIGH"))
        (det,) = inc["detections"]
        self.assertEqual(det["details"]["failed_attempts"], 30)
        self.assertFalse(det["details"]["followed_by_success"])

    def test_suspicious_powershell(self):
        (inc,) = detect("suspicious_powershell.csv")["incidents"]
        self.assertEqual(inc["incident_type"], "suspicious_powershell")
        self.assertEqual(inc["rules"], ["SUSPICIOUS_POWERSHELL", "SUSPICIOUS_OUTBOUND"])
        ps = next(d for d in inc["detections"] if d["rule_id"] == "SUSPICIOUS_POWERSHELL")
        self.assertIn("encoded_command", ps["details"]["strong_indicators"])
        self.assertIn("download_cradle", ps["details"]["strong_indicators"])

    def test_suspicious_authentication_then_endpoint_activity(self):
        (inc,) = detect("suspicious_auth_endpoint.csv")["incidents"]
        self.assertEqual(inc["incident_type"], "suspicious_authentication")
        login = next(d for d in inc["detections"] if d["rule_id"] == "UNUSUAL_LOGIN")
        self.assertIn("external_source_ip", login["details"]["signals"])
        self.assertIn("outside_business_hours", login["details"]["signals"])

    def test_attack_chain(self):
        (inc,) = detect("attack_chain.csv")["incidents"]
        self.assertEqual((inc["incident_type"], inc["severity"]), ("attack_chain", "CRITICAL"))
        self.assertEqual(len(inc["rules"]), 4)
        brute = next(d for d in inc["detections"] if d["rule_id"] == "BRUTE_FORCE")
        self.assertEqual(brute["details"]["failed_attempts"], 25)
        self.assertTrue(brute["details"]["followed_by_success"])
        self.assertIn(brute["details"]["success_event_id"], inc["event_ids"])
        out = next(d for d in inc["detections"] if d["rule_id"] == "SUSPICIOUS_OUTBOUND")
        self.assertTrue(out["details"]["beacon_like"])

    def test_combined_dataset_finds_exactly_the_four_attacks(self):
        incidents = detect("security_logs.csv")["incidents"]
        self.assertEqual(sorted(i["incident_type"] for i in incidents),
                         ["attack_chain", "brute_force", "suspicious_authentication",
                          "suspicious_powershell"])
        self.assertEqual([i["incident_id"] for i in incidents], ["INC-001", "INC-002", "INC-003", "INC-004"])

    def test_csv_and_json_give_same_result(self):
        a = detect("security_logs.csv")["incidents"]
        b = detect("security_logs.json")["incidents"]
        self.assertEqual([(i["incident_type"], i["event_ids"]) for i in a],
                         [(i["incident_type"], i["event_ids"]) for i in b])

    def test_deterministic(self):
        self.assertEqual(detect("security_logs.csv"), detect("security_logs.csv"))


class ManifestTests(unittest.TestCase):
    """Ground truth written by the sample generator must match what the engine finds."""

    def test_every_manifest_entry(self):
        manifest = json.loads((SAMPLES / "manifest.json").read_text())
        for filename, truth in manifest.items():
            expected = truth["expected_incidents"]
            if not isinstance(expected, list):
                continue
            with self.subTest(file=filename):
                incidents = detect(filename)["incidents"]
                self.assertEqual(len(incidents), len(expected))
                for exp in expected:
                    match = [i for i in incidents if i["incident_type"] == exp["type"]]
                    self.assertEqual(len(match), 1, f"no incident of type {exp['type']}")
                    inc = match[0]
                    if "source_ip" in exp:
                        self.assertIn(exp["source_ip"], inc["source_ips"])
                    if "user" in exp:
                        self.assertIn(exp["user"], inc["usernames"])
                    if "host" in exp:
                        self.assertIn(exp["host"], inc["hostnames"])


class BriefExampleTests(unittest.TestCase):
    """The tiny 5-line example from the project brief."""

    def setUp(self):
        self.events = parse_log_file((SAMPLES / "spec_example_no_header.csv").read_bytes(),
                                     "x.csv").events

    def test_default_thresholds_ignore_only_three_failures(self):
        self.assertEqual(run_detection(self.events)["incidents"], [])

    def test_lower_threshold_finds_chain(self):
        cfg = replace(DetectionConfig(), brute_force_threshold=3)
        (inc,) = run_detection(self.events, cfg)["incidents"]
        self.assertEqual(inc["incident_type"], "attack_chain")
        ps = next(d for d in inc["detections"] if d["rule_id"] == "SUSPICIOUS_POWERSHELL")
        self.assertIn("follows_bruteforce_login", ps["details"]["strong_indicators"])


class RuleEdgeCaseTests(unittest.TestCase):
    def test_slow_trickle_of_failures_is_not_brute_force(self):
        events = [make_event(i, f"2026-09-14T{8 + i:02d}:00:00", username="a", source_ip="1.2.3.4",
                             event_type="LOGIN", status="FAILED") for i in range(1, 11)]
        self.assertEqual(run_detection(events)["detections"], [])

    def test_ten_fast_failures_is_brute_force(self):
        events = [make_event(i, f"2026-09-14T09:00:{i:02d}", username="a", source_ip="1.2.3.4",
                             event_type="LOGIN", status="FAILED") for i in range(1, 11)]
        (det,) = run_detection(events)["detections"]
        self.assertEqual(det["rule_id"], "BRUTE_FORCE")

    def test_benign_powershell_not_flagged(self):
        e = make_event(1, "2026-09-14T10:00:00", event_type="PROCESS", process="powershell.exe",
                       command_line="powershell.exe Get-Process | Sort-Object CPU", username="admin")
        self.assertEqual(run_detection([e])["detections"], [])

    def test_lone_discovery_command_creates_no_incident(self):
        e = make_event(1, "2026-09-14T10:00:00", event_type="PROCESS", process="cmd.exe",
                       command_line="cmd.exe /c whoami", username="admin", hostname="H")
        out = run_detection([e])
        self.assertEqual(len(out["detections"]), 1)
        self.assertEqual(out["incidents"], [])

    def test_external_login_alone_in_business_hours_not_flagged(self):
        events = [make_event(1, "2026-09-14T10:00:00", username="a", source_ip="203.0.113.5",
                             event_type="LOGIN", status="SUCCESS")]
        self.assertEqual(run_detection(events)["detections"], [])

    def test_helpers(self):
        self.assertTrue(is_external("203.0.113.77"))      # documentation range counts as external here
        self.assertFalse(is_external("192.168.1.50"))
        self.assertFalse(is_external("server"))            # hostnames are not IPs
        self.assertEqual(process_name({"process": None, "event_type": "PROCESS",
                                       "action": "powershell"}), "powershell")
        self.assertEqual(process_name({"process": "C:\\Windows\\System32\\CMD.EXE",
                                       "event_type": "PROCESS", "action": None}), "cmd.exe")


if __name__ == "__main__":
    unittest.main()
