"""Benchmark three validated NCP Guard APIs. Standard library only.
Prompts and credentials are NEVER logged or saved to generated reports.
"""
import argparse
import concurrent.futures
import json
import os
import statistics
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT))
from evaluate_guard import CASES as BASIC_CASES

BASE = os.getenv("NCP_GUARD_BASE", "https://223.130.136.240").rstrip("/")
SECRET = os.getenv("NCP_API_V2", "")
MODEL_PATHS = {
    "prompt": "/guard/prompt/classify",
    "qwen": "/guard/qwen/classify",
    "granite": "/guard/granite/classify",
}
TIMEOUT = float(os.getenv("NCP_GUARD_TIMEOUT", "30"))


def load_cases(dataset):
    if dataset in ("hard", "both"):
        raw = json.loads((ROOT / "tests/hard_cases.json").read_text(encoding="utf-8"))["cases"]
        hard = [(x["id"], x["category"], x["expected"], x["prompt"]) for x in raw]
    else:
        hard = []
    basic = list(BASIC_CASES) if dataset in ("basic", "both") else []
    return hard + basic


def infer_label(obj):
    if not isinstance(obj, dict):
        return None
    value = obj.get("decision")
    if isinstance(value, str) and value.strip().upper() in ("ALLOW", "BLOCK"):
        return value.strip().upper()
    return None


def request(model, prompt):
    payload = json.dumps({"text": prompt}, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        BASE + MODEL_PATHS[model], data=payload,
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + SECRET},
        method="POST"
    )
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            raw = response.read(120000)
            status = response.status
        value = json.loads(raw)
        decision = infer_label(value)
        meta = {}
        if model == "prompt":
            score = value.get("score") if isinstance(value, dict) else None
            if isinstance(score, (float, int)):
                meta["score"] = round(score, 6)
        return {"label": decision, "seconds": round(time.monotonic()-start, 3), "http": status, "meta": meta}
    except urllib.error.HTTPError as e:
        return {"label": None, "seconds": round(time.monotonic()-start, 3), "http": e.code}
    except Exception as e:
        return {"label": None, "seconds": round(time.monotonic()-start, 3), "error_type": type(e).__name__}


def request_retry(model, prompt):
    result = None
    for attempt in range(3):
        result = request(model, prompt)
        if result.get("http") not in (429, 502, 503, 504) or attempt == 2:
            break
        time.sleep(6*(attempt+1))
    return result


def summarize(rows):
    valid = [x for x in rows if x["actual"] in ("ALLOW", "BLOCK")]
    benign = [x for x in valid if x["expected"] == "ALLOW"]
    attack = [x for x in valid if x["expected"] == "BLOCK"]
    correct = sum(x["correct"] for x in valid)
    bar = sum(x["correct"] for x in benign)/len(benign) if benign else 0.
    abr = sum(x["correct"] for x in attack)/len(attack) if attack else 0.
    harmonic = 2*abr*bar/(abr+bar) if abr+bar else 0.
    timings = sorted(x["seconds"] for x in valid)
    def pct(p):
        if not timings:
            return None
        idx = round((len(timings)-1)*p)
        return timings[idx]
    return {
        "total": len(rows), "valid": len(valid), "errors": len(rows)-len(valid),
        "correct": correct,
        "accuracy_on_valid": round(correct/len(valid), 4) if valid else None,
        "abr_on_valid": round(abr, 4), "bar_on_valid": round(bar, 4),
        "harmonic_on_valid": round(harmonic, 4),
        "p50_seconds": pct(.50), "p95_seconds": pct(.95),
        "avg_seconds": round(statistics.mean(timings), 3) if timings else None,
        "wrong_ids": [x["id"] for x in valid if not x["correct"]],
        "error_ids": [x["id"] for x in rows if x["actual"] is None],
        "note": "Hand-authored expected labels, not an official competition score",
    }


def benchmark(model, dataset, limit):
    cases = load_cases(dataset)[:limit]
    results = []
    interval = float(os.getenv("NCP_GUARD_INTERVAL_SECONDS", "1"))
    prior = None
    for idx, (case_id, category, expected, prompt) in enumerate(cases, 1):
        if prior is not None:
            elapsed = time.monotonic()-prior
            if elapsed < interval:
                time.sleep(interval-elapsed)
        prior = time.monotonic()
        r = request_retry(model, prompt)
        row = {
            "id": case_id, "category": category, "expected": expected,
            "actual": r["label"], "correct": r["label"] == expected,
            "seconds": r["seconds"], "http": r.get("http"), "error_type": r.get("error_type"),
        }
        if "score" in r.get("meta", {}):
            row["score"] = r["meta"]["score"]
        results.append(row)
        print(f"{model} {idx:02d}/{len(cases):02d} {case_id} expected={expected} "
              f"actual={r['label'] or 'ERROR'} match={row['correct']} seconds={r['seconds']} http={r.get('http')}", flush=True)
    summary = summarize(results)
    print("MODEL SUMMARY", model, json.dumps(summary, ensure_ascii=False), flush=True)
    return {"model": model, "dataset": dataset, "summary": summary, "cases": results}


def concurrency_test():
    # Keep legitimate and adversarial examples; compare identical inputs.
    cases = load_cases("hard")
    selected = [cases[i] for i in (0, 1, 4, 5, 8, 9)]
    records = []
    for case_id, category, expected, prompt in selected:
        individual = {}
        t0 = time.monotonic()
        for model in MODEL_PATHS:
            individual[model] = request_retry(model, prompt)
        serial_wall = round(time.monotonic()-t0, 3)
        time.sleep(2)
        t1 = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            futures = {m:pool.submit(request_retry, m, prompt) for m in MODEL_PATHS}
            concurrent = {m:futures[m].result() for m in MODEL_PATHS}
        parallel_wall = round(time.monotonic()-t1, 3)
        record = {
            "id": case_id, "expected": expected, "serial_wall_seconds":serial_wall,
            "parallel_wall_seconds":parallel_wall,
            "serial": {m: {"decision":r["label"], "seconds":r["seconds"], "http":r.get("http")} for m,r in individual.items()},
            "parallel": {m: {"decision":r["label"], "seconds":r["seconds"], "http":r.get("http")} for m,r in concurrent.items()}
        }
        records.append(record)
        print(f"PARALLEL {case_id}: serial={serial_wall}s parallel={parallel_wall}s "
              f"status={','.join(str(concurrent[m].get('http')) for m in MODEL_PATHS)}", flush=True)
        time.sleep(3)
    serial = [x["serial_wall_seconds"] for x in records]
    parallel = [x["parallel_wall_seconds"] for x in records]
    return {
        "cases": records, "serial_average_seconds": round(statistics.mean(serial), 3),
        "parallel_average_seconds": round(statistics.mean(parallel), 3),
        "observed_wall_speedup": round(statistics.mean(serial)/statistics.mean(parallel), 3),
        "warning": "Serial vs parallel timings use separate calls and shared CPU resources; repeat before production",
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--model", choices=MODEL_PATHS, help="Benchmark one endpoint")
    p.add_argument("--dataset", choices=["hard","basic","both"], default="hard")
    p.add_argument("--limit", type=int, default=40)
    p.add_argument("--parallel", action="store_true")
    args = p.parse_args()
    if not SECRET:
        print("ERROR: NCP_API_V2 secret missing", flush=True)
        return 2
    if not (args.parallel or args.model):
        p.error("--model or --parallel required")
    result = concurrency_test() if args.parallel else benchmark(args.model, args.dataset, args.limit)
    Path("results").mkdir(exist_ok=True)
    name = "parallel" if args.parallel else args.model+"_"+args.dataset
    file = Path("results") / ("guard_benchmark_"+name+".json")
    file.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print("RESULT FILE", str(file), flush=True)
    if not args.parallel and result["summary"]["errors"]:
        return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
