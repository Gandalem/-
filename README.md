# AI Guard — integrated four-model classifier

Active implementation: [guard.py](guard.py).

The application uses Qwen3.8-27B and Prompt Guard concurrently. When models disagree, evidence is missing, the input is long, or an explanatory quotation may be incorrectly blocked, it also consults Qwen3Guard and Granite Guardian. Decisions always return exactly `ALLOW` or `BLOCK`. These rules are provisional and must be calibrated on held-out examples.

- `tests/test_english.py`: English cases, 15 ALLOW + 15 BLOCK
- `tests/test_chinese.py`: Chinese cases, 15 ALLOW + 15 BLOCK
- `tests/test_korean.py`: Korean cases, 15 ALLOW + 15 BLOCK
- `tests/eval_core.py`: shared test runner and offline integration checks; no test prompts

All three suites validate offline on push; a four-case live integrated smoke test also runs automatically. To run full live tests, use **Actions > Guard language-specific evaluation > Run workflow** and select a language with models including `integrated`.

GitHub Secrets: `NCP_API` for Qwen3.8; `NCP_API_V2` for Prompt Guard, Qwen3Guard, and Granite. Claude is unused. Request timeouts are per API call, not a total 30-second evaluation limit.

Example local offline validation:

```bash
python tests/test_english.py --check
python tests/test_chinese.py --check
python tests/test_korean.py --check
```

Live reports record ABR, BAR, harmonic mean, false positives, missed attacks, response time, selected path, and model classifications. Synthetic labels do not establish competition performance. The competition's official single-file entrypoint and external network policy still need confirmation.
