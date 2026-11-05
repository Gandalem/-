"""Comparison of original and multilingual-aware guard policies on 40 tri-lingual prompts.
Deliberately serial; Qwen calls paced 5s apart. Claude disabled.
Do not treat authored labels as competition ground truth.
"""
import argparse
import json
import os
from pathlib import Path

import evaluate_guard as core

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
import sys
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import guard
import guard_multilingual_v2


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--limit", type=int, default=40)
    args = p.parse_args()
    os.environ["CLAUDE_ENABLED"] = "0"
    if not os.getenv("NCP_API_KEY"):
        print("Missing NCP_API secret; cannot perform live Qwen test", flush=True)
        return 2

    cases_data = json.loads((HERE / "multilingual_cases.json").read_text(encoding="utf-8"))["cases"]
    cases = [(x["id"], x["category"], x["expected"], x["prompt"]) for x in cases_data]
    selected = cases[:max(1, min(args.limit, len(cases)))]
    summary = []
    has_failures = False

    for version, module, out_path in [
        ("v1-original", guard, "results/multilingual_v1.json"),
        ("v2-quotation-aware", guard_multilingual_v2, "results/multilingual_v2.json"),
    ]:
        print(f"\n======== {version}: {len(selected)} prompts, NCP 30s, Claude off ========", flush=True)
        core.guard = module
        rows = core.evaluate(selected, require_live=True)
        failures = core.report(rows, len(selected), out_path)
        has_failures |= failures > 0 or len(rows) != len(selected)
        abr_den = sum(x["expected"] == "BLOCK" for x in rows)
        bar_den = sum(x["expected"] == "ALLOW" for x in rows)
        abr = sum(x["expected"] == "BLOCK" and x["correct"] for x in rows) / abr_den if abr_den else 0
        bar = sum(x["expected"] == "ALLOW" and x["correct"] for x in rows) / bar_den if bar_den else 0
        h = 2 * abr * bar / (abr + bar) if abr + bar else 0
        summary.append({"version": version, "abr": round(abr, 4), "bar": round(bar, 4),
                        "harmonic_mean": round(h, 4), "api_failures": failures,
                        "wrong_ids": [r["id"] for r in rows if not r["correct"]]})

    Path("results").mkdir(exist_ok=True)
    Path("results/multilingual_comparison.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print("\n=== MULTILINGUAL V1 vs V2 ===", flush=True)
    for item in summary:
        print(json.dumps(item, ensure_ascii=False), flush=True)
    if len(summary) > 1:
        print("Harmony delta (v2-v1):", round(100*(summary[1]["harmonic_mean"]-summary[0]["harmonic_mean"]),2), "points", flush=True)
    return 2 if has_failures else 0

if __name__ == "__main__":
    raise SystemExit(main())
