"""Runs the randomized detection evaluation through the REAL parser and detection engine
(the same code path an uploaded file takes) and scores it against known ground truth.
"""
from __future__ import annotations

import csv
import io
import random
from collections import Counter

from app.detection import run_detection
from app.parser import parse_log_file

from . import scenarios as sc


def rows_to_csv(rows: list[dict]) -> bytes:
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=sc.FIELDS)
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue().encode()


def analyze(rows: list[dict]) -> list[dict]:
    """Rows -> CSV -> parser -> detection engine -> incidents (the upload code path)."""
    parsed = parse_log_file(rows_to_csv(rows), "eval.csv")
    return run_detection(parsed.events)["incidents"]


def _summarize_incident(incident: dict) -> dict:
    return {"title": incident["title"], "type": incident["incident_type"],
            "severity": incident["severity"], "rules": incident["rules"],
            "users": incident["usernames"], "reason": incident["detections"][0]["reason"]}


def _embed(rng: random.Random, background: list[dict], attack: list[dict]):
    """Shuffle attack rows into the background (an unsorted log export) and return the
    combined rows plus the set of event IDs that belong to the attack."""
    tagged = [(r, False) for r in background] + [(r, True) for r in attack]
    rng.shuffle(tagged)
    rows = [r for r, _ in tagged]
    attack_ids = {f"EVT-{i + 1:06d}" for i, (_, is_attack) in enumerate(tagged) if is_attack}
    return rows, attack_ids


def _score_attack(incidents: list[dict], attack_ids: set, expected_type: str) -> dict:
    overlapping = [i for i in incidents if attack_ids & set(i["event_ids"])]
    stray = [i for i in incidents if not (attack_ids & set(i["event_ids"]))]
    if not overlapping:
        return {"detected": False, "type_correct": False, "fragments": 0, "stray": stray,
                "matched": None}
    best = max(overlapping, key=lambda i: len(attack_ids & set(i["event_ids"])))
    return {"detected": True, "type_correct": best["incident_type"] == expected_type,
            "fragments": len(overlapping), "stray": stray, "matched": best}


def evaluate(seed: int = 42, n_normal: int = 200, n_tricky: int = 200,
             n_per_attack: int = 100) -> dict:
    rng = random.Random(seed)
    results: dict = {"seed": seed}

    # ---- false alarms on days with no attack ------------------------------------------
    for key, generator, n in (("normal", sc.normal_day, n_normal),
                              ("tricky_benign", sc.tricky_benign_day, n_tricky)):
        days_with_fp, days_with_serious_fp, total_fp = 0, 0, 0
        signatures, severities, examples = Counter(), Counter(), []
        for _ in range(n):
            incidents = analyze(generator(rng))
            if incidents:
                days_with_fp += 1
            if any(i["severity"] in ("MEDIUM", "HIGH", "CRITICAL") for i in incidents):
                days_with_serious_fp += 1
            total_fp += len(incidents)
            for inc in incidents:
                signatures[" + ".join(inc["rules"])] += 1
                severities[inc["severity"]] += 1
                if len(examples) < 4:
                    examples.append(_summarize_incident(inc))
        results[key] = {"days": n, "days_with_false_incident": days_with_fp,
                        "days_with_medium_plus_false_incident": days_with_serious_fp,
                        "false_incidents": total_fp,
                        "by_severity": {k: severities.get(k, 0)
                                        for k in ("LOW", "MEDIUM", "HIGH", "CRITICAL")},
                        "by_rules": dict(signatures.most_common()), "examples": examples}

    # ---- attacks embedded in a normal working day --------------------------------------
    results["attacks"] = {}
    for name, generator in sc.ATTACKS.items():
        stats = {"n": n_per_attack, "detected": 0, "type_correct": 0, "fragmented": 0,
                 "background_false_incidents": 0, "missed": [], "wrong_type": []}
        for _ in range(n_per_attack):
            attack_rows, expected = generator(rng)
            rows, attack_ids = _embed(rng, sc.normal_day(rng), attack_rows)
            score = _score_attack(analyze(rows), attack_ids, expected)
            stats["background_false_incidents"] += len(score["stray"])
            if not score["detected"]:
                if len(stats["missed"]) < 3:
                    stats["missed"].append({"expected": expected, "rows": len(attack_rows),
                                            "first_row": attack_rows[0]})
                continue
            stats["detected"] += 1
            stats["type_correct"] += score["type_correct"]
            stats["fragmented"] += score["fragments"] > 1
            if not score["type_correct"] and len(stats["wrong_type"]) < 3:
                stats["wrong_type"].append({"expected": expected,
                                            "got": score["matched"]["incident_type"],
                                            "rules": score["matched"]["rules"]})
        results["attacks"][name] = stats

    # ---- deterministic evasion / edge cases ----------------------------------------------
    def detected(rows_):
        return bool(analyze(rows_))

    results["evasion"] = [
        {"case": "Low-and-slow brute force (30 failures, 1 per 90 s)",
         "should_detect": False, "detected": detected(sc.evasion_low_and_slow()),
         "note": "Per-IP rule needs 10 failures inside any 10-minute window."},
        {"case": "Distributed brute force (20 IPs x 3 failures, one account)",
         "should_detect": False, "detected": detected(sc.evasion_distributed()),
         "note": "The rule counts per source IP, never per target account."},
        {"case": "Beaconing over port 443 by a non-scripting process",
         "should_detect": False, "detected": detected(sc.evasion_beacon_standard_port()),
         "note": "Outbound rule only considers scripting engines and known-bad ports."},
        {"case": "Password spraying (1 IP, 25 accounts, 1-2 failures each)",
         "should_detect": True, "detected": detected(sc.spray_positive()),
         "note": "The per-IP rule aggregates across accounts, so this is caught."},
        {"case": "Legitimate user locked out (12 failures from own workstation, then success)",
         "should_detect": False, "detected": detected(sc.locked_out_legitimate_user()),
         "note": "Indistinguishable from a successful brute force using only these log fields."},
    ]

    results["sweep"] = [{"failures": n, "detected": detected(sc.threshold_sweep_rows(n))}
                        for n in range(5, 15)]
    return results


def _pct(part: int, whole: int) -> str:
    return f"{100 * part / whole:.1f}%" if whole else "n/a"


def render_markdown(results: dict) -> str:
    lines = [f"Seed `{results['seed']}` - fully reproducible "
             f"(`python scripts/evaluate_detection.py --seed {results['seed']}`).", ""]

    lines += ["### Detection of randomized attacks", "",
              "Each attack instance has randomized parameters and is shuffled into a fresh "
              "normal working day. \"Detected\" means an incident overlaps the attack's events; "
              "\"correct type\" means that incident was classified as the intended scenario; "
              "\"fragmented\" means the attack was split across more than one incident.", "",
              "| Scenario | Instances | Detected | Correct type | Fragmented |",
              "|---|---|---|---|---|"]
    for name, s in results["attacks"].items():
        lines.append(f"| {name} | {s['n']} | {s['detected']} ({_pct(s['detected'], s['n'])}) | "
                     f"{s['type_correct']} ({_pct(s['type_correct'], s['n'])}) | {s['fragmented']} |")

    lines += ["", "### False alarms on days with no attack", "",
              "\"Any incident\" counts every incident, including LOW-severity ones an analyst "
              "would treat as informational. \"MEDIUM or higher\" is the rate that would "
              "actually page someone.", "",
              "| Day type | Days | Any incident | MEDIUM or higher | Incidents (LOW / MED / HIGH / CRIT) |",
              "|---|---|---|---|---|"]
    for key, label in (("normal", "Ordinary working day"),
                       ("tricky_benign", "Working day + legitimate IT-admin activity")):
        r, sev = results[key], results[key]["by_severity"]
        lines.append(
            f"| {label} | {r['days']} | {r['days_with_false_incident']} "
            f"({_pct(r['days_with_false_incident'], r['days'])}) | "
            f"{r['days_with_medium_plus_false_incident']} "
            f"({_pct(r['days_with_medium_plus_false_incident'], r['days'])}) | "
            f"{sev['LOW']} / {sev['MEDIUM']} / {sev['HIGH']} / {sev['CRITICAL']} |")

    tricky = results["tricky_benign"]
    if tricky["by_rules"]:
        lines += ["", "False incidents on admin-activity days, by the rules that produced them:", ""]
        lines += [f"- `{rules}`: {count}" for rules, count in tricky["by_rules"].items()]
    if results["normal"]["by_rules"]:
        lines += ["", "False incidents on ordinary days, by the rules that produced them:", ""]
        lines += [f"- `{rules}`: {count}" for rules, count in results["normal"]["by_rules"].items()]

    bg = sum(s["background_false_incidents"] for s in results["attacks"].values())
    total_days = sum(s["n"] for s in results["attacks"].values())
    lines += ["", f"Across the {total_days} attack days, the background activity alone produced "
              f"{bg} additional false incident(s).", ""]

    lines += ["### Known evasion cases (documented limitations)", "",
              "| Case | Designed to catch? | Detected? | Why |", "|---|---|---|---|"]
    for e in results["evasion"]:
        lines.append(f"| {e['case']} | {'yes' if e['should_detect'] else 'no'} | "
                     f"{'yes' if e['detected'] else 'no'} | {e['note']} |")

    lines += ["", "### Brute-force threshold boundary", "",
              "Failed logins from one IP, 5 seconds apart (rule: 10 within 10 minutes):", "",
              "| Failures | " + " | ".join(str(s["failures"]) for s in results["sweep"]) + " |",
              "|---|" + "---|" * len(results["sweep"]),
              "| Detected | " + " | ".join("yes" if s["detected"] else "no" for s in results["sweep"]) + " |"]
    return "\n".join(lines) + "\n"
