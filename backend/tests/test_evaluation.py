"""Regression guard for the randomized evaluation (backend/evaluation/). Uses a small N
so it runs fast as part of the normal suite; the full-scale report is generated
separately by scripts/evaluate_detection.py.

These are NOT "detection should have zero false positives" tests - that would assert
something false about the current engine (see docs/EVALUATION.md). They assert the
properties that should always hold (attacks are found, structure is well-formed) and
pin today's false-positive behavior as a known baseline, so a large unexplained swing
in either direction gets caught rather than silently drifting.
"""
import random
import unittest

from evaluation import scenarios as sc
from evaluation.run import analyze, evaluate

SEED = 123
N_SMALL = 15


class AttackDetectionRegressionTests(unittest.TestCase):
    """Every randomized instance of every attack type must still be found and
    correctly classified. This is the property the whole engine exists for."""

    def test_every_attack_type_detected_and_classified(self):
        results = evaluate(seed=SEED, n_normal=1, n_tricky=1, n_per_attack=N_SMALL)
        for name, stats in results["attacks"].items():
            with self.subTest(attack=name):
                self.assertEqual(stats["detected"], stats["n"],
                                 f"{name}: missed {stats['n'] - stats['detected']}/{stats['n']}")
                self.assertEqual(stats["type_correct"], stats["n"],
                                 f"{name}: misclassified {stats['n'] - stats['type_correct']}/{stats['n']}")
                self.assertEqual(stats["fragmented"], 0,
                                 f"{name}: {stats['fragmented']} instance(s) split across incidents")

    def test_deterministic_for_a_given_seed(self):
        a = evaluate(seed=SEED, n_normal=5, n_tricky=0, n_per_attack=5)
        b = evaluate(seed=SEED, n_normal=5, n_tricky=0, n_per_attack=5)
        self.assertEqual(a["attacks"], b["attacks"])
        self.assertEqual(a["normal"], b["normal"])


class ThresholdBoundaryTests(unittest.TestCase):
    """The brute-force rule's documented threshold (10 within 10 minutes) must be exact,
    with no off-by-one drift."""

    def test_nine_failures_not_detected_ten_are(self):
        self.assertEqual(analyze(sc.threshold_sweep_rows(9)), [])
        self.assertEqual(len(analyze(sc.threshold_sweep_rows(10))), 1)


class KnownEvasionCasesTests(unittest.TestCase):
    """Pins the engine's documented blind spots (see docs/EVALUATION.md) as explicit,
    named tests - if one of these starts passing, the rule changed and the docs need
    updating; if a NEW evasion is found, add it here."""

    def test_low_and_slow_brute_force_is_not_detected(self):
        self.assertEqual(analyze(sc.evasion_low_and_slow()), [])

    def test_distributed_brute_force_is_not_detected(self):
        self.assertEqual(analyze(sc.evasion_distributed()), [])

    def test_beaconing_over_standard_port_by_generic_process_is_not_detected(self):
        self.assertEqual(analyze(sc.evasion_beacon_standard_port()), [])

    def test_password_spraying_one_ip_many_accounts_is_detected(self):
        incidents = analyze(sc.spray_positive())
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["incident_type"], "brute_force")

    def test_locked_out_legitimate_user_is_flagged_like_a_successful_brute_force(self):
        """Documented, expected ambiguity - not a bug. A real user locked out and then
        succeeding is indistinguishable from a successful attack using only these
        fields, so this SHOULD be flagged; the response process is what tells them
        apart, not the detection rule."""
        incidents = analyze(sc.locked_out_legitimate_user())
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["incident_type"], "brute_force")

    def test_same_user_unrelated_login_and_powershell_merge_without_losing_evidence(self):
        """Regression test for a specific finding in docs/EVALUATION.md: when an
        unrelated UNUSUAL_LOGIN detection and a SUSPICIOUS_POWERSHELL detection share a
        username within the correlation window, they merge into one incident - titled
        after the rule engine's naming precedence, which may not match either
        detection alone, but must never drop one of the two underlying detections."""
        internal_ip = "10.0.1.55"
        # UNUSUAL_LOGIN needs >= rare_source_min_events (5) total (user, source_ip) events
        # for "rarely seen source" to evaluate at all, with the login's source under 25%
        # of them - four ordinary internal-IP events plus the one external login gives
        # exactly that, alongside the external-IP signal itself (2 signals >= threshold).
        filler_rows = [
            sc.row(sc.at(8, m), "mallory", internal_ip, "", "PROCESS", "process_start",
                  "EXECUTED", "WS-MALLORY", process="chrome.exe", msg="chrome.exe started")
            for m in (5, 10, 15, 20)
        ]
        login_rows = [
            sc.row(sc.at(9), "mallory", "203.0.113.50", "10.0.0.10", "LOGIN",
                  "authentication", "SUCCESS", "SRV-APP01", msg="Interactive logon"),
        ]
        # A fixed timestamp 10 minutes after the login - well inside the 60-minute
        # correlation window - rather than attack_powershell()'s own randomized time
        # (10:00-16:00), which would usually land too far away to merge.
        ps_rows = [
            sc.row(sc.at(9, 10), "mallory", internal_ip, "", "PROCESS", "process_start",
                  "EXECUTED", "WS-MALLORY", process="powershell.exe",
                  cmd=f"powershell.exe -NoProfile -EncodedCommand {sc.ENCODED}",
                  msg="Spawned by user session"),
        ]
        incidents = analyze(filler_rows + login_rows + ps_rows)
        self.assertEqual(len(incidents), 1)
        rule_ids = {d["rule_id"] for d in incidents[0]["detections"]}
        self.assertIn("UNUSUAL_LOGIN", rule_ids)
        self.assertIn("SUSPICIOUS_POWERSHELL", rule_ids)


class FalsePositiveBaselineTests(unittest.TestCase):
    """Characterization tests, not correctness tests: they pin the CURRENT measured
    false-positive rate as a baseline so a large unexplained change (in either
    direction) is caught in review, rather than silently drifting. A rate landing in
    this range is not "passing" in the sense of being good - see
    docs/EVALUATION.md's root-cause analysis of UNUSUAL_LOGIN. If detection logic
    changes on purpose, update these bounds deliberately alongside that change.
    """

    @classmethod
    def setUpClass(cls):
        cls.results = evaluate(seed=SEED, n_normal=60, n_tricky=60, n_per_attack=1)

    def test_ordinary_day_false_positive_rate_within_known_range(self):
        r = self.results["normal"]
        rate = r["days_with_false_incident"] / r["days"]
        self.assertGreater(rate, 0.10, "rate dropped well below the documented baseline - "
                           "if a real fix landed, update this bound")
        self.assertLess(rate, 0.65, "rate rose well above the documented baseline - "
                        "investigate before shipping")

    def test_ordinary_day_false_positives_are_exclusively_unusual_login(self):
        """The specific, documented mechanism: on a plain working day, every false
        incident traces to UNUSUAL_LOGIN (remote-login IP rarity), never brute force,
        PowerShell, outbound, or command rules misfiring on benign activity."""
        for rules in self.results["normal"]["by_rules"]:
            self.assertEqual(rules, "UNUSUAL_LOGIN",
                             f"unexpected false-positive rule combination: {rules}")

    def test_tricky_admin_day_false_positive_rate_is_high(self):
        """Legitimate IT-admin activity (scheduled tasks, service installs, discovery
        commands across hosts) looks very similar to early attack stages by design -
        this is the headline finding: expect it to be high, not low."""
        r = self.results["tricky_benign"]
        rate = r["days_with_false_incident"] / r["days"]
        self.assertGreater(rate, 0.5)


if __name__ == "__main__":
    unittest.main()
