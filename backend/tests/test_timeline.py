import unittest
from pathlib import Path

from app.agents.timeline import build_timeline, notable_gaps
from app.detection import run_detection
from app.evidence import build_evidence
from app.parser import parse_log_file

SAMPLES = Path(__file__).resolve().parents[2] / "data" / "sample_logs"


def load_incident(filename, index=0):
    events = parse_log_file((SAMPLES / filename).read_bytes(), filename).events
    return run_detection(events)["incidents"][index]


class TimelineOrderingTests(unittest.TestCase):
    def test_one_phase_per_detection_ordered_by_time(self):
        incident = load_incident("attack_chain.csv")
        timeline = build_timeline(incident)
        self.assertEqual(len(timeline), len(incident["detections"]))
        times = [p["first_seen"] for p in timeline]
        self.assertEqual(times, sorted(times))
        self.assertEqual([p["step"] for p in timeline], list(range(1, len(timeline) + 1)))

    def test_single_detection_incident_has_no_gap(self):
        incident = load_incident("brute_force.csv")
        timeline = build_timeline(incident)
        self.assertEqual(len(timeline), 1)
        self.assertIsNone(timeline[0]["gap_before_seconds"])

    def test_every_event_id_traces_back_to_the_incident(self):
        incident = load_incident("attack_chain.csv")
        timeline = build_timeline(incident)
        incident_ids = set(incident["event_ids"])
        for phase in timeline:
            for eid in phase["event_ids"]:
                self.assertIn(eid, incident_ids)


class PhaseLabelTests(unittest.TestCase):
    def test_brute_force_labeled_initial_access(self):
        incident = load_incident("brute_force.csv")
        timeline = build_timeline(incident)
        self.assertIn("Initial Access", timeline[0]["phase"])

    def test_suspicious_command_labeled_by_category(self):
        incident = load_incident("attack_chain.csv")
        timeline = build_timeline(incident)
        command_phase = next(p for p in timeline if p["rule_id"] == "SUSPICIOUS_COMMAND")
        self.assertIn(command_phase["phase"], ("Discovery", "Persistence", "Discovery / Persistence"))

    def test_validated_technique_tactic_overrides_generic_label(self):
        """When a threat_intel technique covers a phase's evidence, its MITRE tactic
        should be used as the phase label instead of the generic rule-based one."""
        incident = load_incident("attack_chain.csv")
        outbound_detection = next(d for d in incident["detections"]
                                  if d["rule_id"] == "SUSPICIOUS_OUTBOUND")
        fake_threat_intel = {"techniques": [
            {"technique_id": "T1071.001", "tactic": "Command and Control",
             "verdict": "supported", "evidence_ids": outbound_detection["event_ids"][:1]},
        ]}
        timeline = build_timeline(incident, fake_threat_intel)
        outbound_phase = next(p for p in timeline if p["rule_id"] == "SUSPICIOUS_OUTBOUND")
        self.assertEqual(outbound_phase["phase"], "Command and Control")

    def test_no_threat_intel_falls_back_to_generic_labels(self):
        incident = load_incident("attack_chain.csv")
        timeline = build_timeline(incident, threat_intel=None)
        self.assertTrue(all(p["phase"] for p in timeline))  # every phase still gets a label


class GapDetectionTests(unittest.TestCase):
    def test_attack_chain_has_a_notable_gap_before_execution(self):
        incident = load_incident("attack_chain.csv")
        timeline = build_timeline(incident)
        gaps = notable_gaps(timeline)
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0]["before_phase"], "Execution")
        self.assertGreaterEqual(gaps[0]["gap_seconds"], 120)

    def test_gaps_never_negative_even_for_overlapping_phases(self):
        incident = load_incident("attack_chain.csv")
        timeline = build_timeline(incident)
        for p in timeline:
            if p["gap_before_seconds"] is not None:
                self.assertGreaterEqual(p["gap_before_seconds"], 0)

    def test_normal_activity_has_no_incidents_so_no_timeline_to_build(self):
        events = parse_log_file((SAMPLES / "normal_activity.csv").read_bytes(),
                                "normal_activity.csv").events
        self.assertEqual(run_detection(events)["incidents"], [])


if __name__ == "__main__":
    unittest.main()
