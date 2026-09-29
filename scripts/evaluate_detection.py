#!/usr/bin/env python3
"""Run the randomized detection evaluation and print (or save) a markdown report.

    python scripts/evaluate_detection.py
    python scripts/evaluate_detection.py --seed 7 --per-attack 200 --markdown docs/EVAL.md

Deterministic for a given seed. Uses the real parser and detection engine - the same code
path an uploaded file takes - against synthetic data with known ground truth.
"""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from evaluation.run import evaluate, render_markdown  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--normal", type=int, default=200, help="ordinary days (no attack)")
    ap.add_argument("--tricky", type=int, default=200, help="days with legitimate admin activity")
    ap.add_argument("--per-attack", type=int, default=100, help="instances of each attack type")
    ap.add_argument("--markdown", help="write the report to this file")
    ap.add_argument("--json", help="write raw results to this file")
    args = ap.parse_args()

    start = time.time()
    results = evaluate(args.seed, args.normal, args.tricky, args.per_attack)
    report = render_markdown(results)
    print(report)
    print(f"(evaluated in {time.time() - start:.1f}s)")
    if args.markdown:
        Path(args.markdown).parent.mkdir(parents=True, exist_ok=True)
        Path(args.markdown).write_text(report, encoding="utf-8")
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")


if __name__ == "__main__":
    main()
