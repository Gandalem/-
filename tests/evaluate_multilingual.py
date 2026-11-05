"""Evaluate the active guard.py against 40 English/Korean/Chinese test cases.
Only one classifier is evaluated. No API keys or prompts are written to reports.
"""
import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
import guard

import evaluate_guard as core


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=40)
    args = parser.parse_args()
    os.environ["CLAUDE_ENABLED"] = "0"
    if not os.getenv("NCP_API_KEY"):
        print("ERROR: NCP_API secret not available", flush=True)
        return 2

    records = json.loads((HERE / "multilingual_cases.json").read_text(encoding="utf-8"))["cases"]
    cases = [(x["id"], x["category"], x["expected"], x["prompt"]) for x in records]
    selected = cases[:max(1, min(args.limit, len(cases)))]

    print(f"Evaluating current guard.py: {len(selected)} prompts; Claude off; NCP timeout 30s", flush=True)
    core.guard = guard
    rows = core.evaluate(selected, require_live=True)
    api_failures = core.report(rows, len(selected), "results/multilingual_guard.json")

    allow_rows = [r for r in rows if r["expected"] == "ALLOW"]
    block_rows = [r for r in rows if r["expected"] == "BLOCK"]
    bar = sum(r["correct"] for r in allow_rows) / len(allow_rows) if allow_rows else 0.
    abr = sum(r["correct"] for r in block_rows) / len(block_rows) if block_rows else 0.
    harmonic = 2 * abr * bar / (abr + bar) if abr + bar else 0.
    result = {
        "model": "guard.py",
        "cases": len(rows),
        "abr": round(abr, 4),
        "bar": round(bar, 4),
        "harmonic_mean": round(harmonic, 4),
        "api_failures": api_failures,
        "wrong_ids": [r["id"] for r in rows if not r["correct"]],
        "note": "Self-authored cases, not official competition scores"
    }
    Path("results/multilingual_summary.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print("LATEST GUARD RESULT: " + json.dumps(result, ensure_ascii=False), flush=True)
    return 2 if api_failures or len(rows) != len(selected) else 0


if __name__ == "__main__":
    raise SystemExit(main())
