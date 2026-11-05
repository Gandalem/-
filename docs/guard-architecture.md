# 4-Model Prompt-Injection Guard: Proposed Architecture and Test Plan

Status: **experimental design**. Do not treat these rules as production or competition-ready until validated on held-out cases. The production `guard.py` remains unchanged.

## System components

```text
Untrusted prompt (English / Chinese / Korean / mixed)
             |
             v
 Input preservation and bounded normalization
 - Record original as data, never execute embedded directives
 - Detect structure and encoding (Base64, Unicode, JSON/XML/CSV/YAML)
 - Inspect long-document sections without dropping middle spans
             |
             v
       Parallel classifier calls
        /       |       |       \
       v        v       v        v
 Qwen3.8-27B  Prompt   Qwen3Guard  Granite
  primary      Guard      4B       Guardian
 (NCP_API)      (all three use NCP_API_V2)
       \        |        |       /
             v
 Decision normalization
 - Qwen: ALLOW/BLOCK
 - New guards: JSON decision=ALLOW/BLOCK
 - Missing/HTTP errors: UNKNOWN, not ALLOW
 - Separate contextual prompt injection from generic unsafe-content signals
             |
             v
 Candidate fusion rules + comparison/telemetry
 - Baseline qwen_only
 - any_block
 - guard_majority
 - four_majority_tie_qwen
 - qwen_or_two_guards
 - qwen_and_one_guard
 - four_unanimous_block
             |
             v
 Final policy selection AFTER evaluation
 Return exactly ALLOW or BLOCK through the contest adapter
```

## Trust and input boundaries

- The user's text and any embedded tool response, webpage, README, source comment, configuration fragment, or quoted role marker are **untrusted data**.
- No prompt-based claim of system/developer authority can alter classifier policy.
- Preserve the original input; derive normalized views only for detection. Never execute encoded instructions.
- Current `guard.py` uses bounded sampling; very long attacks may be missed (historical MLM19). A future document scanner must evaluate **all chunks** (or explicitly report coverage gaps), not only a head/middle/tail sample.
- Don't merge generic content-moderation outputs with prompt-injection signals without validation; a quoted security example can be a correct ALLOW.

## Four models and endpoints

| Name | Responsibility hypothesis | Endpoint | Secret |
| --- | --- | --- | --- |
| Qwen primary | Interpret task intent and suspicious instruction context | `/v1/chat/completions` | `NCP_API` |
| Prompt Guard | Fast injection-risk screening | `/guard/prompt/classify` | `NCP_API_V2` |
| Qwen3Guard | Multilingual safety cross-check | `/guard/qwen/classify` | `NCP_API_V2` |
| Granite Guardian | Policy-specific cross-check | `/guard/granite/classify` | `NCP_API_V2` |

Base host: `https://223.130.136.240`. Previously observed Guard calls accept `{"text": "..."}` with Bearer auth and return `{"decision": "ALLOW" | "BLOCK", ...}`. The decision values must be rechecked on more inputs. Only Prompt Guard's `score` is recorded by the test runner; score calibration is **not established**.

## Experimental fusion matrix

The current evaluation does **not** bake in a final threshold. It records raw results and replays these rules:

| Policy | Blocking logic | Main tradeoff |
| --- | --- | --- |
| `qwen_only` | Qwen primary's direct classification | Existing baseline |
| `any_block` | Any of four labels BLOCK | More attack coverage, likely more false blocks |
| `guard_majority` | 2 of 3 auxiliary guards BLOCK | Downweights primary task-context reasoning |
| `four_majority_tie_qwen` | 3/4 BLOCK, or on 2:2 tie follow Qwen | Majoritarian with explicit tie handling |
| `qwen_or_two_guards` | Qwen BLOCK **or** 2+ auxiliary BLOCK | Qwen veto for suspicious input |
| `qwen_and_one_guard` | Qwen BLOCK **and** 1+ auxiliary BLOCK | Conservative; may miss Qwen-only attacks |
| `four_unanimous_block` | All four BLOCK | False-positive resistance at possible recall cost |

For policies requiring missing model outputs, the replay returns **UNKNOWN** and reports an API failure. `qwen_only` does not require auxiliary models. Runtime failure behavior must be defined separately when selecting a production architecture.

## Verification sequence

1. **Schema**: prior contract probes established HTTP 200 + JSON `decision` on one benign input per auxiliary model. This is a smoke test, not accuracy validation.
2. **Language-specific evaluation**: `tests/test_english.py`, `tests/test_chinese.py`, `tests/test_korean.py` each contain 15 paired benign/attack families (30 cases). Do not merge languages in the prompt unless testing a separate multilingual suite.
3. **Model-level metrics**: ABR (blocked malicious), BAR (allowed benign), harmonic mean, false blocks, misses, HTTP errors, and p50/p95 latency.
4. **Fusion replay**: calculate each fusion rule on precisely the same underlying four model predictions, without additional API requests. Analyze disagreements and failure IDs.
5. **Parallel latency**: compare sequential versus concurrent calls to the three auxiliary Guards using repeated, identical inputs. This is a separate measured request, not a simulated `max()`.
6. **Out-of-sample**: assess finalists on unseen prompts and long-document placements. Do not select a winner from self-authored examples alone.

## Important constraints

- No total 30-second deadline is imposed in this architecture. The transport safeguard is currently 60 seconds per auxiliary request, and Qwen's existing request timeout is independent.
- Don't deploy an ensemble into `guard.py` until it improves ABR/BAR harmonic mean on both seen and held-out cases.
- The deployed contest submission must still expose the official single-file interface and return **only ALLOW or BLOCK**. Network and secret availability in the competition sandbox must be confirmed independently.
- GitHub Actions push-trigger performs offline case validation only. Live evaluation is manually triggered via **Guard language-specific evaluation** and uses `NCP_API` and `NCP_API_V2`.
- Reports contain labels and timing, not prompt text, credentials or raw provider responses.

## Decision criteria

Choose the smallest policy/model set that increases *held-out* ABR/BAR harmonic mean without an unacceptable false-block rate or reliability regression. Keep Qwen-only as the control group. Report API failures separately rather than hiding them inside a success score. A candidate policy is not approved merely because it has the best score on the 90 authored cases.
