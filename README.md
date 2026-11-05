# AI Prompt Injection Guardrail — current guard.py

This repository contains one active prompt-injection classifier: **`guard.py`**, promoted from the former multilingual v2 experimental implementation. The earlier v1 policy is no longer the active code. The duplicate experimental file has been deleted from `main`.

## What it does

- Classifies input text as exactly `ALLOW` or `BLOCK`.
- Uses Python standard library only, plus the existing NCP vLLM model `Qwen/Qwen3.8-27B-FP8`.
- Recognizes intent differences between direct prompt-injection instructions and legitimate discussions, translations, or reviews of attack text.
- Handles mixed English, Korean, and Chinese.
- Keeps an optional Claude review path in code, **disabled by default** (`CLAUDE_ENABLED=0`). GitHub Actions tests do **not** call Claude.
- Qwen API request timeout defaults to 30 seconds, with calls paced 5 seconds apart in the test runner to avoid HTTP 429.

## Environment and API secrets

The GitHub Actions secret is called **`NCP_API`** and is mapped to `NCP_API_KEY` for the Python process. Do not commit keys.

```bash
export NCP_API_KEY="your-key"  # set locally only, never in Git
export NCP_BASE_URL="https://223.130.136.240/v1"
export NCP_MODEL="Qwen/Qwen3.8-27B-FP8"
export NCP_TIMEOUT="30"
export CLAUDE_ENABLED="0"
python3 -m unittest -v test_guard.py
printf '%s' '안녕하세요. 请解释 what is HTTP.' | python3 guard.py
```

## Tests

- `python3 -m unittest -v test_guard.py`: 12 mocked/offline tests.
- `python3 tests/evaluate_multilingual.py`: 40 trilingual, paired attack/benign cases in `tests/multilingual_cases.json` using the **current** `guard.py` only.
- `python3 tests/evaluate_hard.py`: separate 40-case hard evaluation.
- `python3 tests/evaluate_guard.py`: separate 48-case baseline evaluation.
- The multilingual GitHub Actions workflow runs automatically for guard or test input changes. The original 48-case workflow is manual-only to prevent overlapping API calls and rate limiting.

## Previous performance and known limitations

On the previous 40-case tri-lingual evaluation of the identical v2 logic (Nov 5, 2026): **37/40 correct**, ABR 95%, BAR 90%, harmonic mean 92.4%, with zero provider failures. The errors were MLB05 (false BLOCK), MLB17 (false BLOCK), and MLM19 (missed long-context attack). These are self-authored expected labels, **not official competition results**. GitHub Actions must be rerun after promotion to confirm current behavior.

The long input sampler currently inspects only bounded portions of long texts; hidden attacks in an omitted segment may be missed. The runtime may also lack external network access or environment-provided keys. The official contest `guard.py` callable interface is not yet known, so adapt it only after organizers provide the requirements.

## References

OWASP LLM Prompt Injection Prevention Cheat Sheet; IBM Prevent Prompt Injection; USENIX StruQ; Microsoft Spotlighting; PINT and BIPIA.
