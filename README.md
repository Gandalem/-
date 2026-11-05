# AI Prompt Injection Guardrail - Contest Draft v1

2026 AI 보안 해커톤 준비용. **최종 제출은 운영진이 공개하는 인터페이스를 반영한 `팀명_guard.py` 단일 파일**입니다. 현재 파일은 사전 개발용입니다.

## Architecture

1. Python stdlib normalizes and detects bounded attack indicators (not automatic blanket bans).
2. NCP vLLM Qwen3.8-27B-FP8 produces `ALLOW` / `BLOCK`.
3. Anthropic Claude optionally performs an independent review when Qwen's classification conflicts with observed signals, Qwen blocks a likely explanatory example, or Qwen is unavailable.
4. Python validates the final output and handles errors.

The models receive the suspicious prompt as **untrusted data**; the code never gives the models tool execution or filesystem privileges.

## Requirements

- Python 3.10+, standard library only.
- Existing NCP vLLM server and optional Anthropic API credentials.
- No GPU changes; no pretrained model downloads.

## Local tests

```bash
python3 -m unittest -v test_guard.py
echo "파이썬 리스트 정렬 방법" | python3 guard.py
```

## Provider configuration

```bash
export NCP_BASE_URL="https://223.130.136.240/v1"
export NCP_MODEL="Qwen/Qwen3.8-27B-FP8"
read -rsp "NCP API Key: " NCP_API_KEY; echo; export NCP_API_KEY
read -rsp "Claude API Key: " ANTHROPIC_API_KEY; echo; export ANTHROPIC_API_KEY
export CLAUDE_ENABLED=1
```

No keys should be committed. Do not disable TLS certificate verification. Default Claude model is configurable via `CLAUDE_MODEL` and should be set to an identifier available to your API account. Both provider integrations need live connectivity tests before competition.

## Limitations / competition day checklist

- Official `guard.py` function signature, permitted environment variables, dependency restrictions and network access are **not yet confirmed**.
- The offline fallback is heuristic and has **not** been validated for ABR/BAR on contest data.
- The current bounded input sampling can miss attacks hidden in omitted portions of very long prompts.
- Normalized/encoded content may lead to false positives, particularly when the user is quoting an attack for analysis.
- Claude only runs when `CLAUDE_ENABLED=1`; selectivity and disagreement rules require tuning with public and held-out samples.
- Only `ALLOW` / `BLOCK` should be returned or printed by the final adapter.
- Never commit or print real API keys, hidden policies, or private prompts.

## Research anchors

- OWASP LLM Prompt Injection Prevention Cheat Sheet
- IBM: https://www.ibm.com/kr-ko/think/insights/prevent-prompt-injection
- StruQ (USENIX Security 2025)
- Spotlighting (Microsoft Research)
- PINT benchmark / BIPIA
