# LLM retry, phase-3b prompt caching, and step outcomes: design

Date: 2026-11-21
Issue: #103
Status: decisions 1-3 below are Eric's (2026-11-21). Everything else is the architect's
design and is open to review; section 12 lists the questions that change behavior.

## 1. Intent

A production run on profile `claude-mythos-5-2` (job `01a1fcb6...`, 2026-11-21, image
`68af326`) identified 28 threats, analyzed 3, produced no DFD, and still reported
"Analysis complete!". Three defects combine:

1. `tmi_tf/retry.py::retry_transient_llm_call` retries once after a fixed 3 s. A
   per-minute rate limit does not clear in 3 s.
2. Every phase-3b call resends about 76,000 input tokens of shared context with nothing
   cacheable, against a 50,000 input-tokens-per-minute limit.
3. A run that loses threats or the DFD is reported exactly like a clean run, and the
   status note does not say which step failed or why.

This spec fixes all three in one PR.

## 2. Human decisions (Eric, 2026-11-21)

These are recorded as human-made decisions and are not to be changed during
implementation without going back to Eric.

- **Decision 1, scope.** The retry fix and phase-3b prompt caching ship in one PR, as
  separate commits and tasks.
- **Decision 2, callback status.** When a run finishes but some 3b threats or the DFD
  failed, the addon callback reports `completed` with a gap summary message (for example
  "completed with gaps: 25 of 28 threats not analyzed (rate limit); DFD not generated").
  `failed` stays reserved for runs that produced nothing (the existing `all_failed`
  path).
- **Decision 3, status note.** Updates to the "TMI-TF Analysis Status" note show success
  or failure on the completion row of each step just performed. A failure includes an
  error hint, at minimum an HTTP status code (for example
  "failed: HTTP 429 rate_limit_error").

## 3. Evidence

Every claim here was checked against source, a local probe, or the vendor docs on
2026-11-21. Probes ran against local fake HTTP servers; no vendor API was called.

### 3.1 Code

- `tmi_tf/retry.py:29-62`: one retry, `time.sleep(3.0)`, no header use.
- `tmi_tf/tmi_client_wrapper.py:365-392`: the same single fixed-3 s retry for TMI API
  429/5xx.
- `tmi_tf/llm_analyzer.py:671-679`: the 3b user prompt is built per threat from
  `prompts/threat_analysis_user.txt`, which puts the threat fields before
  `{inventory_json}` and `{infrastructure_json}`.
- `tmi_tf/llm_analyzer.py:698-704`: an unparseable 3b answer is skipped with a log line
  only. `:815-819`: any other 3b exception is skipped with a log line only.
- `tmi_tf/dfd_llm_generator.py:125-129`: every DFD exception except a refusal is turned
  into `None`; `tmi_tf/analyzer.py:601` then logs "Failed to generate structured data".
- `tmi_tf/analyzer.py:703-714`: the final status is "Analysis complete" unless every
  analysis failed.
- `tmi_tf/worker.py:233`: a child's outcome is `success` or `failed` only. The callback
  message is built in `_finish_child` (`:469-489`) and `_watchdog` (`:539-557`) from
  note metadata, not from the run's result.
- `tmi_tf/invocation.py`: `OUTCOMES = ("success", "failed", "aborted")`; `read_state`
  drops any other value; anything other than `success` counts as failed;
  `open_invocation` deletes only `tf_child_` keys.
- `tmi_tf/worker.py:162-165`: `asyncio.wait_for(..., timeout=job_timeout)` stops waiting
  for the job but cannot stop the analysis thread. `JOB_TIMEOUT` defaults to 3600 s
  (`config.py:90`).
- Threats are written to TMI after phase 3b, the reports and the DFD
  (`analyzer.py:636-698`).

### 3.2 LiteLLM 1.103.10 (installed), probed locally

- A raised exception carries the provider's response headers on
  `e.litellm_response_headers` (an `httpx.Headers`). On every path probed (anthropic,
  openai chat, openai responses, xai) `retry-after` and
  `anthropic-ratelimit-input-tokens-reset` were present there and absent from
  `e.response.headers`. `RateLimitError.headers` is deliberately not populated from
  vendor headers (`litellm/exceptions.py:487-497`).
- A `RateLimitError` built by hand with `response=httpx.Response(429, headers=...)` does
  copy those headers to `e.response.headers`, so tests can exercise both sources.
- Gemini with `stream=True` raises `litellm.exceptions.MidStreamFallbackError`, a
  `ServiceUnavailableError` subclass with `status_code` 429. The headers are on
  `e.original_exception.litellm_response_headers`. So "rate limited" must be decided by
  status code, not by class.
- Retry multiplication: the openai chat path hit the server 3 times per call (OpenAI
  SDK default `max_retries=2`). Anthropic, openai responses, xai and gemini hit it once.
  With `num_retries=0` every probed path hit it once and none rejected the parameter
  (`litellm.drop_params` is False). The OCI path was not probed; its transformation
  drops `max_retries` silently (`litellm/llms/oci/chat/transformation.py:344-349`).
  Nothing in `tmi_tf/` sets `num_retries` or `max_retries` today.
- `str(e)` for an Anthropic 429 embeds the raw response body
  (`AnthropicException - b'{"type": "error", "error": {"type": "rate_limit_error", ...`).
- Anthropic request shape: a user message whose content is
  `[{"type": "text", "text": P, "cache_control": {"type": "ephemeral"}}, {"type": "text", "text": S}]`
  is sent on the wire unchanged.
- Cache accounting through a fake Anthropic SSE stream, `stream_chunk_builder` and
  `completion_cost`: `usage.prompt_tokens` includes cache-read and cache-creation tokens
  (75,400 for 400 uncached + 75,000 cached), `usage.cache_read_input_tokens` and
  `usage.cache_creation_input_tokens` survive the chunk builder, and the cost equals
  uncached x input price + cached x cache-read price. The cost map has cache prices for
  `claude-mythos-5-2` and `claude-fable-5-2` (input 8e-06, cache write 1e-05, cache read
  2e-07 per token).

### 3.3 Anthropic rate-limit docs

Source: https://platform.claude.com/docs/en/api/rate-limits (fetched 2026-11-21).

- "The API's default ITPM rate limits count only uncached input tokens."
  `input_tokens` and `cache_creation_input_tokens` count toward ITPM;
  `cache_read_input_tokens` "Do NOT count toward ITPM". The page lists no model
  exception.
- "ITPM rate limits are estimated at the beginning of each request, and the estimate is
  adjusted during the request."
- `retry-after`: "The number of seconds to wait until you can retry the request. Earlier
  retries might fail. Not every 429 carries it; the spend-cap 429 never does."
- `anthropic-ratelimit-{requests,tokens,input-tokens,output-tokens}-reset`: "The time
  when the ... rate limit is fully replenished, provided in RFC 3339 format."
  `-remaining` values are rounded to the nearest thousand.
- A spend-cap 429 has error type `rate_limit_error`, no `retry-after`, and
  `error.details.error_code` `enforced_spend_limit_reached`; "Retrying ... fails until
  access resumes."
- Token-bucket limiting, continuously replenished. Mythos 5.2, 5.1 and 5 share one
  combined limit. Mythos is not in the published tier tables.

### 3.4 Live limits for this key (from the prod job)

`claude-mythos-5-2`: input tokens 50,000/min, output tokens 10,000/min, requests 50/min,
tokens 60,000. Every response carries the `anthropic-ratelimit-*` headers.

### 3.5 Arithmetic

- 28 threats x 76,000 input tokens = 2,128,000 input tokens for phase 3b. At 50,000
  ITPM that is about 43 minutes for 3b alone, before phases 1 to 3a, the DFD and the
  writes. The job measured 566,601 tokens in 695 s, about 48,900 tokens/min: it was
  already pinned at the limit.
- So a correct retry alone turns this job from "25 threats dropped in 12 minutes" into
  "most threats analyzed, deadline reached near 50 minutes". Caching is what lets it
  finish: one 76,000-token cache write, then 27 calls whose uncached input is the
  threat text only.
- Input cost for 3b at the cost-map prices: uncached 28 x 76,000 x $8/M = $17.02;
  cached 76,000 x $10/M + 27 x 76,000 x $0.20/M = $1.17.
- Output is not helped by caching. At 10,000 output tokens/min, 28 answers will still
  be paced by `retry-after` waits. This is an estimate, not a measurement.

## 4. Goals and non-goals

Goals:

- No threat is dropped because a per-minute limit needed more than 3 s to clear.
- Waiting is bounded by the job deadline, leaves time to write what was found, and is
  visible in the status note while it happens.
- Phase 3b reuses its shared context through the provider's prompt cache.
- Every step's completion row says succeeded or failed, with a hint on failure.
- A run with gaps says so in the status note, the analysis report and the callback.

Non-goals:

- Proactive pacing of 3b calls against a token budget (issue #103 "Related").
- Running 3b calls in parallel.
- Bounding the duration of a phase 1, 2 or 3a call by the deadline (they keep
  `timeout=1200`). The DFD call is bounded; see section 6.3.
- Stopping the analysis thread when `asyncio.wait_for` times out.
- A 1-hour cache TTL or cache pre-warming.
- Caching in any phase other than 3b.
- Changing `error_message` for a failed analysis (it still carries `str(e)`).

## 5. Retry design (`tmi_tf/retry.py`)

### 5.1 Classification

`TRANSIENT_LLM_EXCEPTIONS` is unchanged. For a caught transient exception:

- `status = http_status(e)` (section 8.1). "Rate limited" means `status == 429`,
  whatever the class.
- A 429 whose `str(e)` contains `enforced_spend_limit_reached` is not retried: it is
  re-raised at once. `str(e)` is read for this test only; it is never put in a status
  row.
- Attempt limits (total calls, including the first):

  | Condition | Constant | Value |
  | --- | --- | --- |
  | status 429 | `RATE_LIMIT_MAX_ATTEMPTS` | 8 |
  | `litellm.Timeout` | `TIMEOUT_MAX_ATTEMPTS` | 2 |
  | any other transient error | `MAX_ATTEMPTS` | 5 |

  A timeout keeps today's single retry because each attempt can use the whole call
  timeout (up to 1200 s).

### 5.2 How long to wait

Headers come from `response_headers(e)`: a lowercase-keyed dict merged from, in priority
order, `e.litellm_response_headers`, `e.response.headers`, then the same two attributes
of `e.original_exception`.

1. **`retry-after`** (any transient status). Valid when it parses as a finite number
   of seconds `>= 0`. HTTP-date forms, text, negative, NaN and infinite values are
   rejected and the next source is tried.
2. **`anthropic-ratelimit-*-reset`** (status 429 only). For each dimension in
   `("input-tokens", "output-tokens", "requests", "tokens")`, parse the reset as a
   timezone-aware RFC 3339 timestamp and take `reset - now`. Naive timestamps, parse
   failures and results `<= 0` (clock skew, or already replenished) are rejected. The
   relevant dimension is one whose `-remaining` header parses to an integer `<= 0`; the
   wait is the latest reset among those. If no dimension is exhausted or `-remaining`
   is unparseable, the wait is the latest valid reset of all dimensions.
3. **Exponential backoff.** `backoff_delay(n) = min(5 * 2^(n-1), 60) * (1 + 0.2 * j)`
   for retry number `n` and jitter `j` in `[0, 1)`: 5, 10, 20, 40, 60, 60, 60 s before
   jitter.

A server-directed wait (sources 1 and 2) above `SERVER_WAIT_MAX` = 300 s is clamped to
300 s, then padded by `j` seconds (0 to 1 s) because "earlier retries might fail". It is
not clamped at 60 s: a 76,000-token request against a 50,000/min bucket may need more
than one window.

Jitter only ever adds. The worst-case cumulative backoff for a 429 with no usable
headers is therefore 5+10+20+40+60+60+60 = 255 s, and it passes 60 s after the fourth
retry (75 s). For other transient errors (5 attempts) it is 75 s.

### 5.3 Deadline

`RetryBudget(deadline, clock=time.monotonic)` holds one absolute monotonic deadline for
all LLM calls of a job. It is not a sum of sleeps.

- Before sleeping, if `budget.remaining() <= wait` the wait would end at or after the
  deadline: the retry sets `budget.exhausted = True` and re-raises the last error
  without sleeping. Because a wait is only started when it ends before the deadline, no
  attempt starts after the deadline, including after a long `litellm.Timeout`.
- `budget.expired()` is `exhausted or remaining() <= 0`. Callers use it as a circuit
  breaker (section 6.2).
- With `budget=None` (CLI, legacy callers) only the attempt limits apply.

The original exception type is always re-raised, so existing `except` clauses and
`error_hint` keep working.

### 5.4 Visibility and injection

- Before each sleep the retry logs a warning and calls `on_wait(message)` when given:
  - 429: `"{description}: rate limited (HTTP 429), waiting {N}s (attempt {k} of {limit})"`
  - other: `"{description}: {error_hint(e)}, retrying in {N}s (attempt {k} of {limit})"`

  `N` is the wait rounded up. For a 429 the log line also lists the
  `anthropic-ratelimit-*-remaining` values, to diagnose which bucket tripped.
- An `Exception` raised by `on_wait` is logged and ignored. A `BaseException`
  (`AnalysisAborted`) propagates, so a cancelled job stops at the next wait.
- `sleep`, `jitter` and `now` are keyword parameters defaulting to `None` and resolved
  at call time to `time.sleep`, `random.random` and `datetime.now(UTC)`. Resolving at
  call time keeps `monkeypatch.setattr("tmi_tf.retry.time.sleep", ...)` working
  (`tests/test_script_pipeline.py:227`).
- The `delay` parameter is removed; no caller passes it.

Known limit: a sleep is not interruptible, so an abort is noticed at the next status
row, at most `SERVER_WAIT_MAX` + 1 s later.

### 5.5 No multiplied retries

`BaseLLMProvider.complete` passes `num_retries=0` to `litellm.completion`, so the OpenAI
SDK's two internal retries do not multiply ours. `providers/api_key.py` and
`providers/oci.py` set no retry parameter and need no change.

## 6. Deadline plumbing and gap accounting

### 6.1 Where the deadline comes from

- `WorkerPool._run_job` computes `deadline = time.monotonic() + config.job_timeout` on
  entry and passes `deadline=` to `run_analysis`.
- `run_analysis(..., deadline: float | None = None)` derives two budgets when a
  deadline is given (`_retry_budgets`), with `total = max(deadline - now, 0)`:
  - analysis budget (phases 1 to 3b): `deadline - min(600, 0.2 * total)`
  - DFD budget: `deadline - min(120, 0.05 * total)`

  The first reserves time for the reports, the DFD call and the threat writes; the
  second reserves time for the threat writes. The fractions keep a small `JOB_TIMEOUT`
  from producing a deadline already in the past.
- The CLI passes no deadline.
- `LLMAnalyzer(llm_provider, jev_shadow=None, retry_budget=None)` stores the budget.
  `analyze_repository` stores its `status_callback` as the `on_wait` sink for the
  duration of the call. `_call_llm` passes both to `call_llm_checked`.
- `DFDLLMGenerator(llm_provider, retry_budget=None, on_wait=None)` does the same.
- `ThreatProcessor.extract_threats_from_analysis` (legacy, unused by the pipeline) gets
  the new attempt limits and no budget.

### 6.2 Phase 3b

`ThreatGaps` (frozen dataclass in `llm_analyzer.py`) counts what 3b did not deliver:

| Field | Meaning |
| --- | --- |
| `identified` | threats entering 3b (phase 3a plus script/metadata findings) |
| `failed` | the call raised, or the answer was empty/unparseable |
| `refused` | `content_filter` refusals (also still reported in `refusals`) |
| `skipped` | not attempted because the budget expired |
| `hints` | distinct failure hints, first-seen order |

Invariant: `identified == len(security_findings) + failed + refused + skipped`.

`summary()` returns `""` when nothing is missing, else
`"{failed+refused+skipped} of {identified} threats not analyzed ({causes})"`, where
causes are the hints, then `"refused"` if any, then `"deadline reached"` if any skipped.

Loop behavior:

- Before each threat, if the budget is expired, the remaining threats are counted as
  `skipped`, one status row is written, and the loop ends. Findings already made are
  kept and the analysis is still `success=True`.
- An exception counts as `failed` with `error_hint(e)`. An unparseable answer counts as
  `failed` with hint `unparseable response`. A refusal counts as `refused`, as today.
- `TerraformAnalysis` gains `threat_gaps: ThreatGaps`, `cache_read_tokens` and
  `cache_creation_tokens`.

### 6.3 DFD

`DFDLLMGenerator.last_error` is set whenever `generate_structured_components` returns
`None`: `error_hint(e)` for an exception, `empty response`, `unparseable response` or
`invalid structure` otherwise. `run_analysis` reports it.

The DFD call runs after 3b and before the threat writes, and today it may take up to
1200 s. A `RetryBudget` bounds waits, not the call itself. So if 3b used its whole
budget, a slow DFD call could pass `JOB_TIMEOUT`: the worker would report
`failed: Job timed out` while the thread went on to write threats and a
"completed with gaps" row. To prevent that (section 12, question 6):

- `_dfd_timeout(budget)` returns 1200 s with no budget, `None` when less than
  `DFD_MIN_SECONDS` = 60 s of the DFD budget remains, else
  `min(1200, budget.remaining())`.
- `None` skips the DFD: no call is made and the failure reason is `deadline reached`.
- Otherwise the value is the DFD call's `timeout`. A timed-out call is not retried,
  because no wait fits in what is left of the budget.

### 6.4 Run-level gaps

`AnalysisResult.gaps: list[str]` collects, in order:

- each analysis's `threat_gaps.summary()` (prefixed `"{repo_name}: "` when the run has
  more than one analysis),
- `"DFD not generated ({hint})"` (a refusal uses the hint `refused`),
- `"{k} of {n} threats not created in TMI ({hints})"`, or
  `"threats not created in TMI ({hint})"` when the step raised.

For the production job the list would have been `25 of 28 threats not analyzed (HTTP
429 rate_limit_error)` and `DFD not generated (HTTP 429 rate_limit_error)`. The final
status row joins the list with `"; "` (section 8.2); the callback text is built from
it in section 7.

`success` keeps its meaning: False only when every analysis failed.

The analysis report's job information gains one line, `**Analysis gaps**: ...`, built
from the per-repository summaries plus the DFD failure. A DFD failure rewrites the
analysis note the same way a DFD refusal does today. Threat-creation failures are not
added to the report (it is written before that step).

## 7. Callback summary (`invocation.py`, `worker.py`)

The final callback is sent by whichever child closes the invocation, or by the
watchdog, from note metadata. Gap text therefore has to be stored there.

- `OUTCOMES = ("success", "gaps", "failed", "aborted")`.
- `mark_child(tmi, threat_model_id, job_id, outcome, gaps="")`: `gaps` must be non-empty
  exactly when `outcome == "gaps"`, else `ValueError`. It first upserts the outcome key
  `tf_child_<key>` exactly as today. For `gaps` it then upserts `tf_gaps_<key>` = the
  text cut to `GAP_TEXT_MAX` = 300 characters, in a second call whose failure is logged
  and ignored. The order matters: the outcome decides `completed` versus `failed`, so
  it must not depend on TMI accepting free text. If the text is lost the summary says
  `gaps not recorded`. TMI metadata values allow 1 to 1024 characters with no pattern
  (`tmi-openapi.json`, `Metadata.value`); that is read from the schema, not from a live
  write (Assumption 6).
- `InvocationState.gaps: dict[str, str]`, read from `tf_gaps_` keys.
- `open_invocation` deletes `tf_gaps_` keys as well as `tf_child_` keys.
- `invocation_summary(state, siblings) -> tuple[str, str]` replaces the two inline
  copies in `_finish_child` and `_watchdog`:
  - `failed` = siblings whose outcome is neither `success` nor `gaps` (unchanged rule
    otherwise: unmarked and aborted children count as failed).
  - `base` = `"{ok} succeeded, {n} failed"` plus `" (ids)"` when any failed. A gapped
    child counts as succeeded.
  - no gapped children: `("failed" if failed else "completed", base)`. Identical to
    today, so existing callback strings do not change.
  - gapped, none failed: `("completed", "completed with gaps: {details} ({base})")`.
  - gapped and failed: `("failed", "{base}; gaps: {details}")`.
  - `details` = `" | ".join("{job_id}: {text}")`; a gapped child with no stored text
    shows `gaps not recorded`.
- `_run_job` marks a child `failed` when `result.success` is False, `gaps` (with the
  text `"; ".join(result.gaps)`) when `result.gaps` is non-empty, else `success`.

For the production job, a single-environment invocation, the callback would have been
`completed` with the message `completed with gaps: <job id>: 25 of 28 threats not
analyzed (HTTP 429 rate_limit_error); DFD not generated (HTTP 429 rate_limit_error)
(1 succeeded, 0 failed)`.

The callback message is cut at 1024 characters by `AddonCallback`; the head, which
carries "completed with gaps:", survives.

## 8. Status note step outcomes

### 8.1 Hints (`tmi_tf/error_hints.py`, new)

- `http_status(e)`: `e.status_code` (LiteLLM), else `e.status` (TMI `ApiException`);
  an int or digit string in 100..599, else `None`.
- `error_hint(e)`:
  - `LLMOutputError` -> `unparseable response`
  - a class named `APIConnectionError` in the MRO -> `connection_error` (LiteLLM's 500
    there is synthetic; no HTTP response was received)
  - known status -> `HTTP {status} {label}` with `label` from a fixed map
    (400 invalid_request_error, 401 authentication_error, 403 permission_error,
    404 not_found_error, 408 timeout, 413 request_too_large, 429 rate_limit_error,
    500 internal_server_error, 502 bad_gateway, 503 service_unavailable,
    504 gateway_timeout, 529 overloaded_error); an unmapped status uses the exception's
    class name as the label
  - otherwise the class name.

  A hint never contains text from the exception message: `str(e)` embeds the provider's
  response body (section 3.2), and the code base already has a "never log/return
  str(e)" rule for the prescan and script review.
- `step_row(step, error=None, detail="")`: `"{step}: succeeded"` or
  `"{step}: failed: {hint}"`, each followed by `" ({detail})"` when given. `error` may
  be an exception or a ready-made hint string.
- `LLMOutputError(ValueError)` replaces the two bare `ValueError`s raised when phase 1
  or phase 2 returns no usable JSON.

### 8.2 Rows

Start rows are unchanged unless listed. "Before" is today's completion row.

| Step | Before | After |
| --- | --- | --- |
| Phase 1 | `Phase 1 (Inventory) complete` | `Phase 1 (Inventory): succeeded` |
| Phase 2 | `Phase 2 (Infrastructure) complete` | `Phase 2 (Infrastructure): succeeded` |
| Phase 3a | `Phase 3a complete: N threats identified` | `Phase 3a (Threat Identification): succeeded (N threats identified)` |
| Script review | none | `Script review: succeeded (N findings added)` or `Script review: failed: {script_review_error}` |
| 3b, each threat | start row `Phase 3b: Analyzing threat i/N` | completion row `Phase 3b: threat i/N: succeeded`, `...: failed: {hint}` or `...: failed: refused (content_filter)`; the start row is dropped |
| 3b, deadline | none | `Phase 3b: threats i-N of N: failed: skipped, deadline reached` |
| 3b, phase | `Phase 3 (Security) complete` | `Phase 3b (Per-Threat Analysis): succeeded (A of N threats analyzed)` or `Phase 3b (Per-Threat Analysis): failed: {ThreatGaps.summary()}` |
| any phase raising | none | `{current step}: failed: {hint}` |
| Clone | `Clone complete: {repo}` | `Clone {repo}: succeeded`; `Clone {repo}: failed: no Terraform files found`; `Repository {repo}: failed: {hint}` when the repository block raises |
| Inventory report | none | `Inventory report: succeeded` |
| Analysis report | none | `Analysis report: succeeded` |
| DFD | none | `DFD diagram: succeeded (N cells)` or `DFD diagram: failed: {hint}` |
| Threat creation | none | `Threat creation: succeeded (N created)` or `Threat creation: failed: K of N threats not created ({hints})` |
| fatal error in `run_analysis` | none | `{current step}: failed: {hint}` |
| Final | `Analysis complete` | `Analysis complete`, or `Analysis completed with gaps: {gaps}` |

Unchanged: `Analysis started (...)`, `Model refusals (content_filter): ...`,
`Analysis failed: ...`, and the environment-selection rows.

Script-review errors are built with `error_hint(e)` instead of the bare class name, so
an HTTP failure there also shows its status. For a non-HTTP error the text is the same
as today.

`ThreatProcessor.create_threats_in_tmi` records `create_error_hints` for the threats it
could not create.

Retry wait rows (section 5.4) also land in the status note through the same callback,
and each row sends the `in_progress` heartbeat and checks for cancellation.

## 9. TMI API retry (`tmi_client_wrapper.py`)

Every status row goes through `_call_with_retry`, so this stays short.

- 429: up to `TMI_RATE_LIMIT_MAX_ATTEMPTS` = 4 calls. Wait = a valid `Retry-After`
  (from `ApiException.headers`) clamped to `TMI_RETRY_AFTER_MAX` = 30 s, else
  `DEFAULT_RETRY_DELAY` backoff 3, 6, 12 s with up to 20% added jitter. A 429 means the
  request was not processed, so repeating a create is safe.
- 500/502/503/504: one retry after `DEFAULT_RETRY_DELAY`, as today. More attempts would
  raise the chance of duplicating a non-idempotent create (note, threat, diagram) whose
  first attempt was committed before the error.
- 401: re-authenticate once per call, then continue; a second 401 is raised.
- `DEFAULT_RETRY_DELAY` stays in `retry.py` and is still used.

## 10. Phase-3b prompt caching

### 10.1 Prompt order

`prompts/threat_analysis_user.txt` is reordered so the shared context comes first, with
one marker line where the cache breakpoint goes:

```
## Infrastructure Context

### Inventory
{inventory_json}

### Infrastructure Analysis
{infrastructure_json}

<!-- cache-breakpoint -->
## Threat To Analyze

**Name:** {threat_name}

**Description:** {threat_description}

**Affected Components:** {affected_components}

---

Analyze the above security threat in the context of the infrastructure. Produce STRIDE classification, a CVSS 4.0 vector string, CWE identifiers, a mitigation recommendation, and a category. Return ONLY the JSON object.
```

Every line is the same as today; only the order of the two sections changes (a test
compares the two templates line for line). The marker line is removed when the template
is loaded and is never sent.

`split_cache_prefix(template)` splits the raw template, before any formatting, at the
single marker line. It raises `ValueError` unless there is exactly one marker, the
prefix holds both JSON placeholders and no threat placeholder, and the suffix holds the
three threat placeholders and no JSON placeholder. Splitting before formatting means
repository-controlled text in the JSON cannot forge a marker.

The prefix is formatted once per repository, before the loop, so it is byte-identical
for every 3b call. The CWE corrective turn appends its text to the suffix and sends the
same prefix.

### 10.2 Provider interface

`LLMProvider.complete(system_prompt, user_prompt, max_tokens=64000, timeout=1200.0, *, cache_prefix="")`.

- `cache_prefix` is keyword-only and is passed by callers only when non-empty, so
  existing positional calls and test doubles are unaffected.
- Provider `anthropic` with a non-empty prefix: the user message content is two text
  blocks, the first `cache_prefix` with `cache_control: {"type": "ephemeral"}`, the
  second `user_prompt`. The breakpoint also covers the system prompt, which precedes it
  and is identical across 3b calls.
- Every other provider: the user message content is the string
  `cache_prefix + user_prompt`. No `cache_control` is sent (`drop_params` is False, so
  an unknown field could be rejected). OpenAI caches by prefix automatically, so the
  reorder alone helps there.
- With an empty prefix the request is exactly today's.

The default 5-minute TTL is used. Sequential 3b calls refresh it; if a wait outlasts
it, the next call rewrites the cache at the write price and counts toward ITPM again.

### 10.3 Accounting

- `LLMResponse` gains `cache_read_tokens` and `cache_creation_tokens` (default 0), read
  from `usage.cache_read_input_tokens` (falling back to
  `usage.prompt_tokens_details.cached_tokens`) and `usage.cache_creation_input_tokens`.
  Only real non-negative ints are accepted, so mocked usage objects yield 0.
- `input_tokens` stays `usage.prompt_tokens`, which already includes cached tokens, so
  token totals and artifact metadata keep their meaning.
- `cost` stays `litellm.completion_cost(...)`, which prices cached tokens correctly
  (section 3.2).
- The provider logs cache-read and cache-write tokens per call. The analyzer sums them
  per repository into `TerraformAnalysis` and logs one line when 3b ends.

## 11. State and reruns

- **Second run.** Nothing persists between jobs except the status note and its
  metadata. `open_invocation` clears `tf_child_` and `tf_gaps_` keys, so a new
  invocation never shows an old run's gaps.
- **Overlapping runs.** Each job has its own `RetryBudget`, analyzer and provider
  object. Two jobs on one key share the provider's rate limit; each waits on its own
  `retry-after`. Two jobs on the same repository write the same cache entry twice at
  worst.
- **Leftovers from a failed run.** A `tf_gaps_` key left by a job that died before the
  invocation closed is read by the watchdog (the child counts as succeeded with gaps)
  and deleted at the next `open_invocation`. A pod running the previous image would
  drop the `gaps` outcome and treat the child as unreported; the deployment runs one
  replica, so this window is the rollout only.
- **Retries of creates.** See section 9.

## 12. Open questions and assumptions

**Resolved 2026-11-21.** Eric decided Questions 3 and 4: refusals count as gaps
(human decision), and threat-creation failures count as gaps (human decision).
Questions 1, 2, 5 and 6 take the defaults below; they follow from his decision
that each completed step shows success or failure with an error hint. The plan
implements every default unchanged.

Questions that change behavior. The plan implements the stated default; each is
isolated to the task named.

1. **Per-threat rows.** Default: one completion row per threat replaces the start row
   `Phase 3b: Analyzing threat i/N`, to avoid doubling status-note writes. Alternative:
   keep the start row and add the completion row. (Plan Task 6.)
2. **Reserves and CLI.** Default: reserve `min(600 s, 20%)` after 3b and
   `min(120 s, 5%)` after the DFD; the CLI has no deadline. Alternative values, or a
   deadline for the CLI. (Plan Task 4.)
3. **Refusals as gaps.** Default: a refused threat or a refused DFD counts in the gap
   summary and so turns the callback message into "completed with gaps". Today a
   refusal-only run reports plain `completed`. Alternative: refusals stay out of the
   callback. (Plan Tasks 5 and 7.)
4. **Threat-creation failures as gaps.** Default: they are a gap in the status note
   and the callback. Decision 2 names only 3b threats and the DFD. (Plan Task 7.)
5. **Partial 3b row wording.** Default: a 3b phase with any gap is labeled `failed:`
   followed by the counts, keeping the two-word vocabulary of Decision 3. Alternative:
   a third word such as `partial`. (Plan Task 6.)
6. **DFD near the deadline.** Default: the DFD call's timeout is capped to what is left
   of the DFD budget, and the DFD is skipped (gap `DFD not generated (deadline
   reached)`) when less than 60 s is left, so that threats are still written and the
   job does not end as `failed: Job timed out`. Alternative: leave the DFD call at
   1200 s and accept that outcome. (Plan Tasks 4 and 6.)
   **Amended 2026-11-21 (human decision, Eric, Option B):** the pre-flight scan found
   that a timeout computed once is reused by later attempts (after a 429 wait, the
   empty-response retry, a second timeout attempt) and can run past `JOB_TIMEOUT`.
   `_dfd_timeout(budget)` is therefore evaluated per attempt, inside the retried
   callable; an attempt for which it returns `None` is not made and the DFD fails with
   `deadline reached`. Residual case accepted: on a streamed call the value is an httpx
   per-read timeout, so a stream that keeps producing chunks is not wall-clock bounded.

   **Amended 2026-11-21 (human decision, Eric, final review Finding 1, Option A):** an
   empty, truncated (`finish_reason == "length"`) or unparseable phase-3a answer raises
   `LLMOutputError`, so phase 3a fails through the same path as phases 1 and 2
   (`Phase 3a (Threat Identification): failed: unparseable response`); a valid `[]` stays a
   success with 0 threats. Likewise a script-review answer that is truncated or not a JSON
   array records `script review failed: unparseable response` and writes a failed
   `Script review` row; a valid empty array stays a success. `parse_review` still returns
   `[]` for garbage; `is_review_array` supplies the signal.

Assumptions to confirm in the first production run after deploy:

- **Assumption 1.** Cache reads do not count toward this key's Mythos ITPM limit. The docs say so
  for "default" limits and list no exception, but Mythos is not in the tier tables and
  this key's 50,000 limit is non-standard. Check: the pod log shows cache-read tokens
  near 75,000 on 3b calls 2 to N, and no `rate limited` status rows from input tokens
  after the first 3b call.
- **Assumption 2.** A 76,000-token request can pass a 50,000/min bucket after a wait. The prod
  job shows requests of that size succeeding; the docs do not state the rule.
- **Assumption 3.** A real Anthropic 429 carries `retry-after`. If not, the reset headers or the
  backoff apply.
- **Assumption 4.** `num_retries=0` is harmless on the OCI path (read from source, not run).
- **Assumption 5.** Two adjacent text blocks read the same to the model as one
  concatenated string.
- **Assumption 6.** TMI stores a gap text (spaces, parentheses, semicolons, colons) as
  a note metadata value. Check: the first run with gaps shows the text in the callback
  message, not `gaps not recorded`.

## 13. Testing

All tests are written first and must fail before the change.

- Retry: a real `litellm.RateLimitError` built with `httpx.Response(429, headers=...)`
  and with `litellm_response_headers` set. Cases: `retry-after` honored; taken from
  `e.response.headers` when the first source lacks it; reset-header fallback
  (exhausted dimension, and no exhausted dimension); backoff fallback and its
  cumulative floor; malformed, negative, NaN, infinite and huge values; reset in the
  past; naive timestamp; spend cap not retried; budget exhaustion; attempt limits per
  class; non-transient errors not retried; `MidStreamFallbackError` treated as a 429;
  `on_wait` failures.
- 3b: a provider that 429s N times then succeeds drops no threat; a budget that runs
  out keeps earlier findings and records the rest as gaps.
- Caching: the message structure for `anthropic` versus other providers; the prefix is
  identical across every 3b call including the CWE corrective turn; no script body
  appears in any prompt part, including `cache_prefix`.
- Status rows, gaps, invocation summary, TMI retry: per the plan.
- `tests/test_retry.py` pins the single retry today; the plan lists each test's before
  and after.
