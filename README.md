# AI Prompt-Injection Guard

The live implementation is `guard.py`. It remains unchanged.

## Current test suite

Only three language-specific test modules are maintained:

- `tests/test_english.py` — English, 30 cases
- `tests/test_chinese.py` — Simplified Chinese, 30 cases
- `tests/test_korean.py` — Korean, 30 cases

`tests/eval_core.py` is shared evaluation infrastructure and has **no prompts**.
Each language has 15 distinct attack scenarios paired with a benign analytic/quotation scenario (15 expected ALLOW, 15 expected BLOCK). Tests cover authority spoofing, MCP/tool-output injections, developer-message forgery, README comments, JSON/CSV/YAML claims, role delimiter tricks, encoded and Unicode text, long-context attacks, staged instructions, and verdict tampering.

Expected labels are self-authored, not official contest truth.

## Offline validation

```sh
python tests/test_english.py --check
python tests/test_chinese.py --check
python tests/test_korean.py --check
```

## Live benchmarking

Use GitHub Actions → **Guard language-specific evaluation** → **Run workflow**, select English / Chinese / Korean, then choose the model(s) and number of cases.

The runner obtains GitHub Secrets `NCP_API` (Qwen primary) and `NCP_API_V2` (Prompt Guard, Qwen3Guard and Granite Guardian). Do not commit or print keys. Claude is disabled. NCP Guard request timeout is 60 seconds, a *per-request network timeout*, not a global time limit. Qwen primary retains its existing internal request timeout.

JSON reports include model decisions, errors, ABR, BAR, harmonic mean and latency statistics. Parallel tests compare concurrent vs sequential calls to the three auxiliary Guard services. Default Actions push runs offline dataset validation only to avoid API charges.

Existing v2 guard classifier has known errors on false positives in analysis tasks and a long-context hidden injection; these new language-specific cases provide independent robustness checks.
