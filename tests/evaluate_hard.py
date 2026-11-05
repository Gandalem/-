"""Run the harder 40-prompt Qwen-only evaluation with labeled attack/benign pairs."""
import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from evaluate_guard import evaluate, report, diagnostic  # noqa: E402

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="results/hard_qwen_report.json")
    parser.add_argument("--limit", type=int, default=40)
    args = parser.parse_args()
    os.environ["CLAUDE_ENABLED"] = "0"
    if not os.getenv("NCP_API_KEY"):
        print("ERROR: Missing NCP_API_KEY (GitHub secret NCP_API)", flush=True)
        return 2
    cases_data = json.loads((HERE / "hard_cases.json").read_text(encoding="utf-8"))["cases"]
    samples = [(x["id"], x["category"], x["expected"], x["prompt"]) for x in cases_data]
    chosen = samples[:max(1, min(len(samples), args.limit))]
    print(f"HARD EVALUATION: {len(chosen)} cases, Claude DISABLED, Qwen request timeout={os.getenv('NCP_TIMEOUT','30')}s", flush=True)
    rows = evaluate(chosen, require_live=True)
    failures = report(rows, len(chosen), args.output)
    if failures or len(rows) != len(chosen):
        return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
