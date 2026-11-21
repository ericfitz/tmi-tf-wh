# LLM Retry, Phase-3b Prompt Caching and Step Outcomes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop dropping phase-3b threats and the DFD to per-minute rate limits, cache the shared phase-3b context, and make every step's outcome and every gap visible in the status note, the report and the addon callback (issue #103).

**Architecture:** `retry.py` becomes a multi-attempt retry that takes its wait from `retry-after`, then the `anthropic-ratelimit-*-reset` headers, then jittered exponential backoff, bounded by a shared `RetryBudget` deadline. The phase-3b loop counts what it could not analyze (`ThreatGaps`) and stops when the budget expires; gaps flow through `TerraformAnalysis` and `AnalysisResult` into status rows, the analysis report and a new `gaps` invocation outcome. The 3b prompt is reordered so the shared JSON is a cacheable prefix that the Anthropic provider marks with `cache_control`.

**Tech Stack:** Python 3.13, LiteLLM 1.103.10, httpx 0.28, pytest, ruff, pyright, uv.

**Spec:** `docs/superpowers/specs/2026-11-21-llm-retry-caching-design.md`. Read it before starting any task; section numbers below refer to it.

## Global Constraints

- Done gate, run before claiming any task done and shown in the report:
  `uv run ruff check tmi_tf/ tests/ scripts/ && uv run ruff format --check tmi_tf/ tests/ scripts/ && uv run pyright && uv run pytest tests/`
- TDD: write the failing test, run it and see it fail for the stated reason, then implement.
- No test may really sleep. Inject `sleep`/`jitter`/`now`/`clock`, or monkeypatch `tmi_tf.retry.time.sleep` and `tmi_tf.retry.random.random`.
- Reject unrecognized inputs by default (malformed headers, unknown outcomes, a template without exactly one marker) and test the rejection.
- A status row, gap text or callback message that this plan adds or changes never contains `str(e)`; use `error_hint(e)`. The existing `Analysis failed: ...` row and `TerraformAnalysis.error_message` are out of scope and keep their text (spec section 4).
- Decisions 1 to 3 in spec section 2 are Eric's and are frozen. The six defaults in spec section 12 are implemented as written; if one turns out not to fit, stop and report instead of choosing another.
- American spelling. Use `rg PATTERN <path>` with an explicit path. Use `uv run` for Python.
- `tmi_client` imports carry `# type: ignore`; `litellm` imports carry the existing `# pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]` comment.
- Never edit `evals/jev/`.
- One commit per task, staging only the files the task names.

## Review Focus

1. **A security test goes blind.** `tests/test_script_pipeline.py:79` collects `c.args[0] + c.args[1]` to prove script bodies never reach a prompt. After Task 10 the 3b shared context travels in `c.kwargs["cache_prefix"]`, so the test would pass without looking at it. Task 10 Step 1 extends the collector.
2. **Mocked analyses invent gaps.** `tests/test_analyzer.py` and `tests/test_markdown_generator.py` use `MagicMock` analyses; `analysis.threat_gaps.summary()` on a mock is a truthy mock. Task 7 Step 1 sets `threat_gaps = ThreatGaps()` on every such double and pins that a clean run ends with exactly `Analysis complete`.
3. **A small `JOB_TIMEOUT` must not skip phase 3b.** A fixed 600 s reserve would put the deadline in the past. Task 4 tests `_retry_budgets` with a 10 s job.
4. **Hostile or skewed headers.** Whatever the headers say (negative, NaN, a reset in the past, a year away), a sleep is never negative and never above 301 s. Task 2 has a sweep test.
5. **Status-note trouble during a wait.** An ordinary exception from `on_wait` must not abort the retry; `AnalysisAborted` (a `BaseException`) must. Task 2 tests both.

## File Structure

| File | Responsibility after this plan |
| --- | --- |
| `tmi_tf/error_hints.py` (new) | `http_status`, `error_hint`, `step_row`, `LLMOutputError` |
| `tmi_tf/retry.py` | header parsing, backoff, `RetryBudget`, `retry_transient_llm_call`, `tmi_retry_wait` |
| `tmi_tf/providers/__init__.py`, `providers/llm_base.py` | `num_retries=0`, `cache_prefix`, cache token fields |
| `tmi_tf/llm_analyzer.py` | budget and wait rows through every call, `ThreatGaps`, 3b breaker, step rows, cache prefix |
| `tmi_tf/dfd_llm_generator.py` | budget, `last_error` |
| `tmi_tf/threat_processor.py` | `create_error_hints` |
| `tmi_tf/analyzer.py` | deadline to budgets, step rows, `AnalysisResult.gaps` |
| `tmi_tf/markdown_generator.py` | `**Analysis gaps**` line |
| `tmi_tf/invocation.py`, `tmi_tf/worker.py` | `gaps` outcome, `invocation_summary`, deadline |
| `tmi_tf/tmi_client_wrapper.py` | 429 backoff in `_call_with_retry` |
| `prompts/threat_analysis_user.txt` | shared context first, one marker line |
| `tests/llm_errors.py` (new) | builders for real LiteLLM errors, `FakeClock` |

---

### Task 1: Error hints and step rows

**Files:**
- Create: `tmi_tf/error_hints.py`
- Test: `tests/test_error_hints.py` (new)

**Interfaces:**
- Produces:
  - `class LLMOutputError(ValueError)`
  - `STATUS_LABELS: dict[int, str]` with exactly the twelve entries of spec section 8.1
  - `http_status(error: BaseException) -> int | None`
  - `error_hint(error: BaseException) -> str`
  - `step_row(step: str, error: BaseException | str | None = None, detail: str = "") -> str`

- [ ] **Step 1: Write the failing tests**

```python
import litellm  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]
import pytest  # pyright: ignore[reportMissingImports] # ty:ignore[unresolved-import]

from tmi_tf.error_hints import LLMOutputError, error_hint, http_status, step_row


def _llm(cls, **kw):
    return cls(message="secret body text", llm_provider="anthropic", model="m", **kw)


class _Api(Exception):  # shape of tmi_client.rest.ApiException
    def __init__(self, status):
        self.status = status


@pytest.mark.parametrize(
    ("error", "hint"),
    [
        (_llm(litellm.RateLimitError), "HTTP 429 rate_limit_error"),
        (_llm(litellm.ServiceUnavailableError), "HTTP 503 service_unavailable"),
        (_llm(litellm.InternalServerError), "HTTP 500 internal_server_error"),
        (_llm(litellm.BadGatewayError), "HTTP 502 bad_gateway"),
        (_llm(litellm.Timeout), "HTTP 408 timeout"),
        (_llm(litellm.AuthenticationError), "HTTP 401 authentication_error"),
        (_llm(litellm.APIConnectionError), "connection_error"),
        (_Api(429), "HTTP 429 rate_limit_error"),
        (_Api(418), "HTTP 418 _Api"),
        (LLMOutputError("no JSON"), "unparseable response"),
        (RuntimeError("leaked secret text"), "RuntimeError"),
    ],
)
def test_error_hint(error, hint):
    assert error_hint(error) == hint
    assert "secret" not in error_hint(error)


@pytest.mark.parametrize(
    ("value", "expected"),
    [(429, 429), ("429", 429), (True, None), (99, None), (600, None), ("4x9", None), (None, None)],
)
def test_http_status_accepts_only_real_codes(value, expected):
    error = Exception()
    error.status_code = value  # type: ignore[attr-defined]
    assert http_status(error) == expected


def test_http_status_falls_back_to_status_attribute():
    assert http_status(_Api(503)) == 503


def test_step_row():
    assert step_row("Phase 2 (Infrastructure)") == "Phase 2 (Infrastructure): succeeded"
    assert step_row("DFD diagram", detail="12 cells") == "DFD diagram: succeeded (12 cells)"
    assert (
        step_row("Phase 3b: threat 2/28", error=_llm(litellm.RateLimitError))
        == "Phase 3b: threat 2/28: failed: HTTP 429 rate_limit_error"
    )
    assert step_row("X", error="refused (content_filter)") == "X: failed: refused (content_filter)"
    assert step_row("X", error="boom", detail="1 of 2") == "X: failed: boom (1 of 2)"
```

- [ ] **Step 2: Run and see it fail**

Run: `uv run pytest tests/test_error_hints.py -q`
Expected: collection error, `No module named 'tmi_tf.error_hints'`.

- [ ] **Step 3: Implement `tmi_tf/error_hints.py`**

Rules, in this order, for `error_hint`: `LLMOutputError` -> `unparseable response`; any class named `APIConnectionError` in `type(error).__mro__` -> `connection_error` (checked by name so this module does not import litellm); a status from `http_status` -> `f"HTTP {status} {STATUS_LABELS.get(status, type(error).__name__)}"`; else `type(error).__name__`. `http_status` reads `status_code` then `status`, accepts an `int` (not `bool`) or an all-digit `str`, and returns it only when `100 <= value <= 599`.

- [ ] **Step 4: Run and see it pass**

Run: `uv run pytest tests/test_error_hints.py -q`
Expected: all pass.

- [ ] **Step 5: Done gate, then commit**

```bash
git add tmi_tf/error_hints.py tests/test_error_hints.py
git commit -m "feat(errors): status-code error hints and step outcome rows (#103)"
```

---

### Task 2: Retry core

**Files:**
- Modify: `tmi_tf/retry.py` (whole file)
- Create: `tests/llm_errors.py`
- Test: `tests/test_retry.py` (rewrite as listed)

**Interfaces:**
- Consumes: `http_status`, `error_hint` from Task 1.
- Produces (all in `tmi_tf/retry.py`):
  - constants `DEFAULT_RETRY_DELAY = 3.0` (kept), `MAX_ATTEMPTS = 5`, `RATE_LIMIT_MAX_ATTEMPTS = 8`, `TIMEOUT_MAX_ATTEMPTS = 2`, `BACKOFF_BASE = 5.0`, `BACKOFF_CAP = 60.0`, `JITTER_FRACTION = 0.2`, `SERVER_WAIT_MAX = 300.0`, `SPEND_CAP_MARKER = "enforced_spend_limit_reached"`, `RATELIMIT_DIMENSIONS = ("input-tokens", "output-tokens", "requests", "tokens")`; `TRANSIENT_LLM_EXCEPTIONS` and `TRANSIENT_API_STATUSES` unchanged
  - `class RetryBudget` with `__init__(self, deadline: float, clock: Callable[[], float] = time.monotonic)`, attributes `deadline: float` and `exhausted: bool` (starts False), methods `remaining() -> float` and `expired() -> bool` (`exhausted or remaining() <= 0`)
  - `response_headers(error: BaseException) -> dict[str, str]` (lowercase keys; priority per spec section 5.2)
  - `parse_retry_after(headers: Mapping[str, str] | None) -> float | None` (case-insensitive key lookup)
  - `parse_ratelimit_reset(headers: Mapping[str, str], now: datetime) -> float | None`
  - `backoff_delay(retry_number: int, *, base: float = BACKOFF_BASE, cap: float = BACKOFF_CAP, jitter: float = 0.0) -> float`
  - `retry_transient_llm_call[T](call: Callable[[], T], *, description: str = "LLM call", budget: RetryBudget | None = None, on_wait: Callable[[str], None] | None = None, sleep: Callable[[float], None] | None = None, jitter: Callable[[], float] | None = None, now: Callable[[], datetime] | None = None) -> T`
- Produces (in `tests/llm_errors.py`): `rate_limit_error(headers=None, *, response_headers=None, message="429")`, `mid_stream_429(headers)`, `class FakeClock` (callable returning `.t`; `.sleep(seconds)` adds to `.t`).

**Before/after for the existing `tests/test_retry.py`:**

| Existing test | After |
| --- | --- |
| `test_success_on_first_try` | unchanged |
| `test_retries_on_service_unavailable`, `_rate_limit`, `_internal_server_error`, `_bad_gateway`, `_timeout`, `_api_connection_error` | kept; pass `sleep=lambda s: None` instead of patching `time.sleep` |
| `test_raises_after_retry_exhausted` (pins 2 calls) | replaced by `test_other_transient_gets_five_attempts` (5 calls, sleeps `[5, 10, 20, 40]`) |
| `test_delay_is_applied` (pins `delay=5.0`) | deleted; the `delay` parameter is removed. Replaced by `test_backoff_schedule_and_cumulative_floor` |
| `test_default_delay_value` | unchanged (`DEFAULT_RETRY_DELAY == 3.0`) |
| `test_no_retry_on_bad_request`, `_auth_error`, `_context_window_exceeded` | unchanged |
| `TestTransientConstants` | unchanged |

- [ ] **Step 1: Write `tests/llm_errors.py`**

```python
"""Builders for real LiteLLM errors, shared by retry and analyzer tests."""

import httpx
import litellm  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]
from litellm.exceptions import MidStreamFallbackError  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

_REQUEST = httpx.Request("POST", "https://api.anthropic.com/v1/messages")


def rate_limit_error(headers=None, *, response_headers=None, message="429"):
    """A real RateLimitError. `headers` go on litellm_response_headers (where
    LiteLLM puts them on a real raise); `response_headers` on e.response.headers."""
    response = httpx.Response(429, headers=response_headers, request=_REQUEST)
    error = litellm.RateLimitError(
        message=message,
        llm_provider="anthropic",
        model="anthropic/claude-mythos-5-2",
        response=response,
    )
    if headers is not None:
        error.litellm_response_headers = httpx.Headers(headers)  # type: ignore[attr-defined]
    return error


def mid_stream_429(headers):
    """What gemini raises under stream=True: a ServiceUnavailableError subclass
    with status_code 429 and the headers on original_exception."""
    return MidStreamFallbackError(
        message="mid", model="gemini/x", llm_provider="gemini",
        original_exception=rate_limit_error(headers),
    )


class FakeClock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.t += seconds
```

- [ ] **Step 2: Write the failing tests in `tests/test_retry.py`**

Apply the before/after table, then add the following. `tests/` is on `sys.path` (see `from dfd_cases import ...` in `tests/test_diagram_builder.py`), so import with `from llm_errors import FakeClock, mid_stream_429, rate_limit_error`.

```python
NOW = datetime(2026, 11, 21, 12, 0, 0, tzinfo=UTC)


def at(seconds: float) -> str:
    return (NOW + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def run(errors, *, budget=None, jitter=0.0, on_wait=None, clock=None):
    """Raise `errors` in order, then return "ok". -> (outcome, sleeps, calls)."""
    call = MagicMock(side_effect=[*errors, "ok"])
    sleeps: list[float] = []

    def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        if clock is not None:
            clock.sleep(seconds)

    try:
        outcome = retry_transient_llm_call(
            call, description="test", budget=budget, on_wait=on_wait,
            sleep=sleep, jitter=lambda: jitter, now=lambda: NOW,
        )
    except Exception as e:
        outcome = e
    return outcome, sleeps, call.call_count


class TestWaitSource:
    def test_retry_after_from_litellm_headers(self):
        assert run([rate_limit_error({"retry-after": "17"})]) == ("ok", [17.0], 2)

    def test_retry_after_from_response_headers(self):
        assert run([rate_limit_error(response_headers={"retry-after": "9"})])[1] == [9.0]

    def test_litellm_headers_win_over_response_headers(self):
        e = rate_limit_error({"retry-after": "17"}, response_headers={"retry-after": "9"})
        assert run([e])[1] == [17.0]

    def test_header_names_are_case_insensitive(self):
        assert run([rate_limit_error({"Retry-After": " 17 "})])[1] == [17.0]

    def test_server_wait_is_padded_by_jitter(self):
        assert run([rate_limit_error({"retry-after": "17"})], jitter=0.5)[1] == [17.5]

    def test_reset_of_exhausted_dimension(self):
        e = rate_limit_error({
            "anthropic-ratelimit-input-tokens-remaining": "0",
            "anthropic-ratelimit-input-tokens-reset": at(42),
            "anthropic-ratelimit-output-tokens-remaining": "9000",
            "anthropic-ratelimit-output-tokens-reset": at(55),
        })
        assert run([e])[1] == [42.0]

    def test_latest_reset_when_no_dimension_is_exhausted(self):
        e = rate_limit_error({
            "anthropic-ratelimit-input-tokens-remaining": "20000",
            "anthropic-ratelimit-input-tokens-reset": at(42),
            "anthropic-ratelimit-requests-reset": at(55),
        })
        assert run([e])[1] == [55.0]

    def test_retry_after_wins_over_reset(self):
        e = rate_limit_error({"retry-after": "7", "anthropic-ratelimit-tokens-reset": at(55)})
        assert run([e])[1] == [7.0]

    def test_reset_headers_ignored_for_non_429(self):
        e = litellm.ServiceUnavailableError(message="503", llm_provider="p", model="m")
        e.litellm_response_headers = httpx.Headers({"anthropic-ratelimit-tokens-reset": at(55)})
        assert run([e])[1] == [5.0]

    def test_mid_stream_429_uses_original_exception_headers(self):
        outcome, sleeps, _ = run([mid_stream_429({"retry-after": "7"})])
        assert (outcome, sleeps) == ("ok", [7.0])

    @pytest.mark.parametrize(
        "value", ["soon", "-5", "nan", "inf", "-inf", "", "Sat, 21 Nov 2026 12:00:30 GMT"]
    )
    def test_malformed_retry_after_falls_back_to_backoff(self, value):
        assert run([rate_limit_error({"retry-after": value})])[1] == [5.0]

    def test_huge_retry_after_is_clamped(self):
        assert run([rate_limit_error({"retry-after": "86400"})])[1] == [300.0]

    @pytest.mark.parametrize(
        "reset", [at(-30), "2026-11-21T12:00:30", "not-a-time", ""]
    )
    def test_unusable_reset_falls_back_to_backoff(self, reset):
        e = rate_limit_error({"anthropic-ratelimit-input-tokens-reset": reset})
        assert run([e])[1] == [5.0]

    def test_far_future_reset_is_clamped(self):
        e = rate_limit_error({"anthropic-ratelimit-input-tokens-reset": at(86400 * 365)})
        assert run([e])[1] == [300.0]

    def test_no_header_set_can_produce_an_unsafe_sleep(self):
        nasty = ["-1", "nan", "inf", "1e999", "0", "0.0", "abc", "86400", at(-5), at(10**9)]
        for ra in nasty:
            for reset in nasty:
                e = rate_limit_error({
                    "retry-after": ra,
                    "anthropic-ratelimit-tokens-reset": reset,
                    "anthropic-ratelimit-tokens-remaining": ra,
                })
                for s in run([e], jitter=0.999)[1]:
                    assert 0 <= s <= 301, (ra, reset, s)


class TestBackoffAndLimits:
    def test_backoff_schedule_and_cumulative_floor(self):
        outcome, sleeps, calls = run([rate_limit_error()] * 7)
        assert (outcome, calls) == ("ok", 8)
        assert sleeps == [5.0, 10.0, 20.0, 40.0, 60.0, 60.0, 60.0]
        assert sum(sleeps[:4]) > 60

    def test_jitter_only_adds(self):
        _, sleeps, _ = run([rate_limit_error()] * 7, jitter=0.999)
        for s, base in zip(sleeps, [5, 10, 20, 40, 60, 60, 60], strict=True):
            assert base <= s <= base * 1.2

    def test_rate_limit_gives_up_after_eight_attempts(self):
        outcome, sleeps, calls = run([rate_limit_error()] * 8)
        assert isinstance(outcome, litellm.RateLimitError)
        assert (calls, len(sleeps)) == (8, 7)

    def test_other_transient_gets_five_attempts(self):
        e = litellm.ServiceUnavailableError(message="503", llm_provider="p", model="m")
        outcome, sleeps, calls = run([e] * 5)
        assert isinstance(outcome, litellm.ServiceUnavailableError)
        assert (calls, sleeps) == (5, [5.0, 10.0, 20.0, 40.0])

    def test_timeout_gets_two_attempts(self):
        e = litellm.Timeout(message="t", model="m", llm_provider="p")
        outcome, _, calls = run([e] * 2)
        assert isinstance(outcome, litellm.Timeout) and calls == 2

    def test_spend_cap_429_is_not_retried(self):
        e = rate_limit_error(message='{"details": {"error_code": "enforced_spend_limit_reached"}}')
        outcome, sleeps, calls = run([e])
        assert outcome is e and (sleeps, calls) == ([], 1)


class TestBudget:
    def test_wait_that_fits_is_taken(self):
        clock = FakeClock()
        budget = RetryBudget(100.0, clock)
        outcome, sleeps, _ = run([rate_limit_error({"retry-after": "60"})], budget=budget, clock=clock)
        assert (outcome, sleeps, budget.exhausted) == ("ok", [60.0], False)

    def test_wait_that_would_pass_the_deadline_is_not_started(self):
        clock = FakeClock()
        budget = RetryBudget(50.0, clock)
        e = rate_limit_error({"retry-after": "60"})
        outcome, sleeps, calls = run([e], budget=budget, clock=clock)
        assert outcome is e and (sleeps, calls) == ([], 1)
        assert budget.exhausted and budget.expired()

    def test_wait_ending_exactly_at_the_deadline_is_not_started(self):
        clock = FakeClock()
        budget = RetryBudget(60.0, clock)
        assert run([rate_limit_error({"retry-after": "60"})], budget=budget, clock=clock)[1] == []

    def test_no_attempt_after_a_slow_call_passed_the_deadline(self):
        clock = FakeClock()
        budget = RetryBudget(100.0, clock)

        def slow_timeout():
            clock.sleep(1200)
            raise litellm.Timeout(message="t", model="m", llm_provider="p")

        with pytest.raises(litellm.Timeout):
            retry_transient_llm_call(slow_timeout, budget=budget, sleep=clock.sleep, jitter=lambda: 0.0)
        assert clock.t == 1200 and budget.exhausted

    def test_expired_by_time_alone(self):
        clock = FakeClock()
        budget = RetryBudget(10.0, clock)
        assert not budget.expired()
        clock.t = 10.0
        assert budget.expired() and not budget.exhausted


class TestOnWait:
    def test_rate_limit_message(self):
        seen: list[str] = []
        run([rate_limit_error({"retry-after": "17"})], jitter=0.5, on_wait=seen.append)
        assert seen == ["test: rate limited (HTTP 429), waiting 18s (attempt 1 of 8)"]

    def test_other_transient_message(self):
        seen: list[str] = []
        e = litellm.ServiceUnavailableError(message="503", llm_provider="p", model="m")
        run([e], on_wait=seen.append)
        assert seen == ["test: HTTP 503 service_unavailable, retrying in 5s (attempt 1 of 5)"]

    def test_ordinary_exception_from_on_wait_is_ignored(self):
        def broken(_message: str) -> None:
            raise RuntimeError("status note down")

        assert run([rate_limit_error({"retry-after": "1"})], on_wait=broken)[0] == "ok"

    def test_base_exception_from_on_wait_propagates_before_sleeping(self):
        class Aborted(BaseException):
            pass

        def abort(_message: str) -> None:
            raise Aborted

        sleeps: list[float] = []
        with pytest.raises(Aborted):
            retry_transient_llm_call(
                MagicMock(side_effect=[rate_limit_error(), "ok"]),
                on_wait=abort, sleep=sleeps.append, jitter=lambda: 0.0,
            )
        assert sleeps == []


def test_default_sleep_is_resolved_at_call_time(monkeypatch):
    """tests/test_script_pipeline.py patches tmi_tf.retry.time.sleep; keep that working."""
    sleeps: list[float] = []
    monkeypatch.setattr("tmi_tf.retry.time.sleep", sleeps.append)
    monkeypatch.setattr("tmi_tf.retry.random.random", lambda: 0.0)
    call = MagicMock(side_effect=[rate_limit_error({"retry-after": "3"}), "ok"])
    assert retry_transient_llm_call(call) == "ok"
    assert sleeps == [3.0]
```

Also add direct tests of the pure helpers: `backoff_delay(1) == 5.0`, `backoff_delay(4) == 40.0`, `backoff_delay(9) == 60.0`, `backoff_delay(1, base=3.0, cap=30.0, jitter=1.0) == pytest.approx(3.6)`; `parse_retry_after(None) is None`, `parse_retry_after({"Retry-After": "0"}) == 0.0`; `response_headers(Exception()) == {}`.

- [ ] **Step 3: Run and see it fail**

Run: `uv run pytest tests/test_retry.py -q`
Expected: import error for `RetryBudget` (and the others).

- [ ] **Step 4: Implement `tmi_tf/retry.py`**

Follow spec sections 5.1 to 5.4. The loop, which the signature and tests do not fully determine:

```python
attempt = 1
while True:
    try:
        return call()
    except TRANSIENT_LLM_EXCEPTIONS as e:
        status = http_status(e)
        if status == 429 and SPEND_CAP_MARKER in str(e):
            raise
        limit = (
            RATE_LIMIT_MAX_ATTEMPTS if status == 429
            else TIMEOUT_MAX_ATTEMPTS if isinstance(e, litellm.Timeout)
            else MAX_ATTEMPTS
        )
        if attempt >= limit:
            raise
        wait = _wait_for(e, status, attempt, jitter_fn(), now_fn())   # sections 5.2
        if budget is not None and budget.remaining() <= wait:
            budget.exhausted = True
            raise
        # log, on_wait (Exception swallowed, BaseException propagates), sleep
        attempt += 1
```

`_wait_for`: a valid `retry-after`, or (429 only) a valid reset, gives `min(value, SERVER_WAIT_MAX) + jitter`; otherwise `backoff_delay(attempt, jitter=jitter)`. Resolve `sleep or time.sleep`, `jitter or random.random`, `now or (lambda: datetime.now(UTC))` inside the function body, not in the signature. Parse timestamps with `datetime.fromisoformat` and reject a result whose `tzinfo` is None. Reject non-finite floats with `math.isfinite`. The warning log for a 429 lists each present `anthropic-ratelimit-{dimension}-remaining` value; it may include `str(e)` cut to 300 characters, as today.

- [ ] **Step 5: Run and see it pass**

Run: `uv run pytest tests/test_retry.py tests/test_script_pipeline.py -q`
Expected: all pass.

- [ ] **Step 6: Done gate, then commit**

```bash
git add tmi_tf/retry.py tests/test_retry.py tests/llm_errors.py
git commit -m "fix(retry): honor retry-after and reset headers, jittered backoff, job deadline (#103)"
```

---

### Task 3: One provider attempt per call

**Files:**
- Modify: `tmi_tf/providers/llm_base.py` (the `litellm.completion(...)` call)
- Test: `tests/test_llm_provider.py`

**Interfaces:**
- Produces: every `litellm.completion` call carries `num_retries=0`.

Before/after: `TestBaseLLMProvider.test_complete_passes_extra_kwargs` asserts the exact kwargs; its `assert_called_once_with(...)` gains `num_retries=0`.

- [ ] **Step 1: Update that assertion and add**

```python
    @patch("tmi_tf.providers.llm_base.litellm")
    @patch("tmi_tf.providers.llm_base.save_llm_response", return_value="/tmp/test")
    def test_complete_disables_provider_side_retries(self, mock_save, mock_litellm):
        """The OpenAI SDK retries twice on its own; retry.py is the only retry (#103)."""
        mock_litellm.completion.return_value = iter([])
        mock_litellm.stream_chunk_builder.return_value = _make_litellm_response("ok")
        mock_litellm.completion_cost.return_value = 0.0
        BaseLLMProvider(provider="openai", model="openai/gpt-x").complete("s", "u")
        assert mock_litellm.completion.call_args.kwargs["num_retries"] == 0
```

- [ ] **Step 2: Run and see both fail**

Run: `uv run pytest tests/test_llm_provider.py -q`
Expected: 2 failures (`num_retries`).

- [ ] **Step 3: Add `num_retries=0` to the `litellm.completion` call, with a one-line comment naming #103**

- [ ] **Step 4: Run and see it pass; done gate; commit**

```bash
git add tmi_tf/providers/llm_base.py tests/test_llm_provider.py
git commit -m "fix(providers): disable provider-side retries so they do not multiply (#103)"
```

---

### Task 4: Thread the budget and wait rows through every LLM call

**Files:**
- Modify: `tmi_tf/llm_analyzer.py` (`call_llm_checked`, `LLMAnalyzer.__init__`, `analyze_repository` entry/exit, `_call_llm`)
- Modify: `tmi_tf/dfd_llm_generator.py` (`__init__`, the `call_llm_checked` call)
- Modify: `tmi_tf/analyzer.py` (`run_analysis` signature, analyzer and DFD construction)
- Modify: `tmi_tf/worker.py` (`_run_job`)
- Test: `tests/test_llm_analyzer.py`, `tests/test_dfd_llm_generator.py`, `tests/test_analyzer.py`, `tests/test_worker.py`

**Interfaces:**
- Consumes: `RetryBudget`, `retry_transient_llm_call` (Task 2).
- Produces:
  - `call_llm_checked(llm_provider, system_prompt, user_prompt, description, max_tokens=64000, timeout=1200.0, *, budget: RetryBudget | None = None, on_wait: Callable[[str], None] | None = None) -> LLMResponse`
  - `LLMAnalyzer(llm_provider, jev_shadow=None, retry_budget: RetryBudget | None = None)`; attribute `retry_budget`
  - `DFDLLMGenerator(llm_provider, retry_budget: RetryBudget | None = None, on_wait: Callable[[str], None] | None = None)`
  - `DFDLLMGenerator.generate_structured_components(self, inventory, infrastructure, timeout: float = 1200.0)`
  - `analyzer.FINALIZE_RESERVE_SECONDS = 600.0`, `analyzer.THREAT_WRITE_RESERVE_SECONDS = 120.0`, `analyzer.DFD_MIN_SECONDS = 60.0`
  - `analyzer._retry_budgets(deadline: float | None, now: float) -> tuple[RetryBudget | None, RetryBudget | None]`
  - `analyzer._dfd_timeout(budget: RetryBudget | None) -> float | None` (`None` means skip the DFD)
  - in `run_analysis`, a local `dfd_skipped_for_deadline: bool` that Task 6 reads
  - `run_analysis(..., environment=None, deadline: float | None = None)`

- [ ] **Step 1: Write the failing tests**

In `tests/test_llm_analyzer.py`, new class `TestPhase3bRateLimit`. Reuse the file's `_make_provider`, `_make_llm_response`, `_make_tf_repo` and the inventory/infrastructure/threat-analysis dicts from `test_phase3a_and_3b_produce_merged_findings`; `THREE` is a phase-3a list of three threats named `T1`, `T2`, `T3`.

```python
    def test_rate_limited_calls_are_retried_and_no_threat_is_dropped(self, monkeypatch):
        sleeps: list[float] = []
        monkeypatch.setattr("tmi_tf.retry.time.sleep", sleeps.append)
        monkeypatch.setattr("tmi_tf.retry.random.random", lambda: 0.0)
        limited = rate_limit_error({"retry-after": "30"})
        ok = _make_llm_response(json.dumps(THREAT_ANALYSIS))
        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response(json.dumps(INVENTORY)),
            _make_llm_response(json.dumps(INFRASTRUCTURE)),
            _make_llm_response(json.dumps(THREE)),
            limited, limited, limited, ok,  # T1: three 429s, then an answer
            ok,                             # T2
            limited, ok,                    # T3: one 429
        ]
        rows: list[str] = []
        result = LLMAnalyzer(provider).analyze_repository(
            _make_tf_repo(), status_callback=rows.append
        )
        assert [f["name"] for f in result.security_findings] == ["T1", "T2", "T3"]
        assert sleeps == [30.0, 30.0, 30.0, 30.0]
        waits = [r for r in rows if "rate limited (HTTP 429), waiting 30s" in r]
        assert len(waits) == 4
        assert waits[0].endswith("(attempt 1 of 8)")
```

In `tests/test_dfd_llm_generator.py`:

```python
class TestDFDRetry:
    def test_rate_limit_is_retried_with_budget_and_wait_rows(self, monkeypatch):
        monkeypatch.setattr("tmi_tf.retry.random.random", lambda: 0.0)
        clock = FakeClock()
        monkeypatch.setattr("tmi_tf.retry.time.sleep", clock.sleep)
        provider = MagicMock(model="anthropic/m", provider="anthropic")
        provider.complete.side_effect = [rate_limit_error({"retry-after": "20"}), VALID_DFD_RESPONSE]
        rows: list[str] = []
        gen = DFDLLMGenerator(provider, retry_budget=RetryBudget(100.0, clock), on_wait=rows.append)
        assert gen.generate_structured_components({}, {}) is not None
        assert clock.t == 20.0 and len(rows) == 1
```

(`VALID_DFD_RESPONSE`: an `LLMResponse` whose text is the smallest JSON that `_validate_structure` accepts; build it from the existing tests in that file.)

In `tests/test_analyzer.py`:

```python
class TestRetryBudgets:
    def test_no_deadline_means_no_budgets(self):
        assert _retry_budgets(None, 0.0) == (None, None)

    def test_default_job_timeout(self):
        analysis, dfd = _retry_budgets(3600.0, 0.0)
        assert (analysis.deadline, dfd.deadline) == (3000.0, 3480.0)

    def test_small_job_timeout_keeps_a_positive_window(self):
        analysis, dfd = _retry_budgets(10.0, 0.0)
        assert (analysis.deadline, dfd.deadline) == (8.0, 9.5)

    def test_deadline_already_passed(self):
        analysis, dfd = _retry_budgets(5.0, 9.0)
        assert analysis.deadline == dfd.deadline == 5.0


class TestDfdTimeout:
    def test_no_budget_keeps_the_full_timeout(self):
        assert _dfd_timeout(None) == 1200.0

    @pytest.mark.parametrize(
        ("remaining", "expected"),
        [(5000.0, 1200.0), (400.0, 400.0), (60.0, 60.0), (59.9, None), (0.0, None), (-30.0, None)],
    )
    def test_timeout_is_capped_and_a_short_window_skips(self, remaining, expected):
        clock = FakeClock()
        assert _dfd_timeout(RetryBudget(remaining, clock)) == expected

    def test_exhausted_budget_skips(self):
        budget = RetryBudget(5000.0, FakeClock())
        budget.exhausted = True
        assert _dfd_timeout(budget) is None
```

Two `run_analysis` tests modeled on `TestDFDRefusal`: with `deadline=time.monotonic() + 3600` the patched generator's `generate_structured_components` is called with a `timeout` keyword between 60 and 1200; with `deadline=time.monotonic() + 1` (so the DFD budget has under 60 s) it is not called at all and `tmi.create_or_update_diagram` is not called.

Add one `run_analysis` test modeled on `TestRunAnalysisProfile.test_provider_built_from_profile_and_named_in_status`: with `deadline=time.monotonic() + 3600`, the patched `LLMAnalyzer` is constructed with a `retry_budget` that is a `RetryBudget`; with no `deadline`, `retry_budget` is `None`.

In `tests/test_worker.py`, modeled on `test_child_passes_profile_to_run_analysis`: `run_analysis` receives a float `deadline` with `0 < deadline - time.monotonic() <= pool.config.job_timeout`.

- [ ] **Step 2: Run and see them fail**

Run: `uv run pytest tests/test_llm_analyzer.py::TestPhase3bRateLimit tests/test_dfd_llm_generator.py::TestDFDRetry tests/test_analyzer.py::TestRetryBudgets -q`
Expected: `test_rate_limited_calls...` fails with 0 wait rows (the retry itself already works after Task 2); the others fail on unknown names or keyword arguments.

- [ ] **Step 3: Implement**

- `call_llm_checked`: pass `budget=budget, on_wait=on_wait` to `retry_transient_llm_call`.
- `LLMAnalyzer.__init__`: store `self.retry_budget = retry_budget` and `self._on_wait: Callable[[str], None] | None = None`.
- `analyze_repository`: set `self._on_wait = status_callback` as its first statement and reset it to `None` in a `finally` that wraps the existing `try/except`.
- `_call_llm`: pass `budget=self.retry_budget, on_wait=self._on_wait`.
- `DFDLLMGenerator`: store both and pass them to `call_llm_checked`; `generate_structured_components` takes `timeout` and passes it instead of the literal `1200.0`.
- `_dfd_timeout`: `1200.0` when `budget is None`; `None` when `budget.expired()` or `budget.remaining() < DFD_MIN_SECONDS`; else `min(1200.0, budget.remaining())`.
- `run_analysis`, DFD block: `dfd_timeout = _dfd_timeout(dfd_budget)`; `dfd_skipped_for_deadline = dfd_timeout is None`. When skipped, log a warning and make no DFD call and no diagram; otherwise pass `timeout=dfd_timeout`.
- `_retry_budgets`: `total = max(deadline - now, 0.0)`; analysis deadline `deadline - min(FINALIZE_RESERVE_SECONDS, 0.2 * total)`; DFD deadline `deadline - min(THREAT_WRITE_RESERVE_SECONDS, 0.05 * total)`.
- `run_analysis`: call `_retry_budgets(deadline, time.monotonic())` first thing inside the `try`; build `LLMAnalyzer(llm_provider, jev_shadow=..., retry_budget=analysis_budget)` and `DFDLLMGenerator(llm_provider, retry_budget=dfd_budget, on_wait=lambda m: tmi_client.update_status_note(threat_model_id, m))`.
- `WorkerPool._run_job`: `deadline = time.monotonic() + self.config.job_timeout` as the first statement; pass `deadline=deadline` to `run_analysis`.
- `tmi_tf/cli.py` is not changed: the CLI has no deadline (spec section 12, question 2).

- [ ] **Step 4: Run the four test files and see them pass; done gate; commit**

```bash
git add tmi_tf/llm_analyzer.py tmi_tf/dfd_llm_generator.py tmi_tf/analyzer.py tmi_tf/worker.py tests/test_llm_analyzer.py tests/test_dfd_llm_generator.py tests/test_analyzer.py tests/test_worker.py
git commit -m "fix(retry): job-deadline budget and wait rows for every LLM call (#103)"
```

---

### Task 5: Phase-3b gap accounting, deadline breaker, DFD failure reason

**Files:**
- Modify: `tmi_tf/llm_analyzer.py` (`ThreatGaps`, `TerraformAnalysis`, the 3b loop, `_review_scripts` error text)
- Modify: `tmi_tf/dfd_llm_generator.py` (`last_error`)
- Test: `tests/test_llm_analyzer.py`, `tests/test_dfd_llm_generator.py`, `tests/test_script_pipeline.py`

**Interfaces:**
- Consumes: `error_hint` (Task 1), `RetryBudget.expired()` (Task 2), `LLMAnalyzer.retry_budget` (Task 4).
- Produces:

```python
@dataclass(frozen=True)
class ThreatGaps:
    identified: int = 0
    failed: int = 0
    refused: int = 0
    skipped: int = 0
    hints: tuple[str, ...] = ()

    @property
    def not_analyzed(self) -> int: ...   # failed + refused + skipped
    def summary(self) -> str: ...        # "" when not_analyzed == 0
```

  - `TerraformAnalysis(..., refusals="", threat_gaps: ThreatGaps | None = None)`; attribute `threat_gaps` is never None (defaults to `ThreatGaps()`).
  - `DFDLLMGenerator.last_error: str` (`""` after a success).

- [ ] **Step 1: Write the failing tests**

`tests/test_llm_analyzer.py`, in `TestPhase3bRateLimit` (same fixtures as Task 4):

```python
    def test_budget_exhaustion_keeps_findings_and_records_the_rest_as_gaps(self, monkeypatch):
        clock = FakeClock()
        monkeypatch.setattr("tmi_tf.retry.time.sleep", clock.sleep)
        monkeypatch.setattr("tmi_tf.retry.random.random", lambda: 0.0)
        limited = rate_limit_error({"retry-after": "40"})
        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response(json.dumps(INVENTORY)),
            _make_llm_response(json.dumps(INFRASTRUCTURE)),
            _make_llm_response(json.dumps(THREE)),
            _make_llm_response(json.dumps(THREAT_ANALYSIS)),  # T1
            limited, limited, limited,                        # T2: waits 40, 40, then no room
        ]
        analyzer = LLMAnalyzer(provider, retry_budget=RetryBudget(100.0, clock))
        result = analyzer.analyze_repository(_make_tf_repo())
        assert result.success is True
        assert [f["name"] for f in result.security_findings] == ["T1"]
        assert result.threat_gaps == ThreatGaps(
            identified=3, failed=1, refused=0, skipped=1,
            hints=("HTTP 429 rate_limit_error",),
        )
        assert provider.complete.call_count == 7  # T3 was never sent
        assert clock.t == 80.0

    def test_unparseable_answer_is_a_counted_gap(self):
        # T1 answers "not json", T2 answers normally
        ...
        assert result.threat_gaps == ThreatGaps(
            identified=2, failed=1, hints=("unparseable response",)
        )

    def test_refusal_is_counted_separately_from_errors(self):
        # T1 content_filter, T2 raises RuntimeError("x"), T3 answers normally
        ...
        assert result.threat_gaps == ThreatGaps(
            identified=3, failed=1, refused=1, hints=("RuntimeError",)
        )
        assert result.refusals == "phase 3b: 1 threat(s)"

    def test_clean_run_has_no_gaps(self):
        ...
        assert result.threat_gaps == ThreatGaps(identified=1)
        assert result.threat_gaps.summary() == ""


class TestThreatGapsSummary:
    def test_summary_lists_causes_in_order(self):
        gaps = ThreatGaps(identified=28, failed=22, refused=1, skipped=2,
                          hints=("HTTP 429 rate_limit_error", "unparseable response"))
        assert gaps.not_analyzed == 25
        assert gaps.summary() == (
            "25 of 28 threats not analyzed "
            "(HTTP 429 rate_limit_error, unparseable response, refused, deadline reached)"
        )

    def test_failed_analysis_defaults_to_empty_gaps(self):
        assert TerraformAnalysis("r", "u", success=False).threat_gaps == ThreatGaps()
```

Write the three `...` bodies in full, following `test_phase3b_refusal_is_counted_and_run_continues` and `test_phase3b_failure_skips_threat` in the same file for how to script a refusal and a raising call. In `tests/test_script_pipeline.py`, next to the existing test that asserts `"RuntimeError" in result.script_review_error`, add one where the review call raises `litellm.AuthenticationError` and assert `"script review failed: HTTP 401 authentication_error" in result.script_review_error`. Add to every 3b test in this class: `assert gaps.identified == len(result.security_findings) + gaps.not_analyzed`.

`tests/test_dfd_llm_generator.py`:

```python
class TestDFDLastError:
    @pytest.mark.parametrize(
        ("side_effect", "hint"),
        [
            ([litellm.AuthenticationError(message="x", llm_provider="a", model="m")],
             "HTTP 401 authentication_error"),
            ([_resp("not json")], "unparseable response"),
            ([_resp('{"components": "nope"}')], "invalid structure"),
        ],
    )
    def test_none_result_carries_a_reason(self, side_effect, hint):
        provider = MagicMock(model="anthropic/m", provider="anthropic")
        provider.complete.side_effect = side_effect
        gen = DFDLLMGenerator(provider)
        assert gen.generate_structured_components({}, {}) is None
        assert gen.last_error == hint

    def test_success_clears_last_error(self):
        ...  # VALID_DFD_RESPONSE -> not None, last_error == ""
```

(An empty `stop` response is retried once by `call_llm_checked`; two empty responses give `last_error == "empty response"`. Add that case.)

- [ ] **Step 2: Run and see them fail**

Run: `uv run pytest tests/test_llm_analyzer.py tests/test_dfd_llm_generator.py -q`
Expected: failures on `ThreatGaps`, `threat_gaps`, `last_error`.

- [ ] **Step 3: Implement**

3b loop, replacing `refused_threats` and the three silent `continue` paths:

- counters `failed = refused = skipped = 0` and `hints: list[str] = []` (append only when not already present).
- At the top of each iteration: `if self.retry_budget is not None and self.retry_budget.expired(): skipped = len(raw_threats) - i + 1; break`.
- `if not analysis_result:` -> `failed += 1`, hint `unparseable response`, `continue`.
- `except LLMRefusalError` -> `refused += 1` (token accounting unchanged).
- `except Exception as e` -> `failed += 1`, hint `error_hint(e)`; keep the existing `logger.error`.
- After the loop build `ThreatGaps(identified=len(raw_threats), failed=failed, refused=refused, skipped=skipped, hints=tuple(hints))` and pass it to the successful `TerraformAnalysis`. The `refusals` string is built from `refused` exactly as it is from `refused_threats` today.
- `_review_scripts`: `errors.append(f"script review failed: {error_hint(e)}")` and the same in its log line. For a non-HTTP error this is the same text as today.

`DFDLLMGenerator`: set `self.last_error = ""` at the start of `generate_structured_components`; set it at each `return None` (`empty response`, `unparseable response`, `invalid structure`, `error_hint(e)` in the `except Exception`).

- [ ] **Step 4: Run and see them pass; done gate; commit**

```bash
git add tmi_tf/llm_analyzer.py tmi_tf/dfd_llm_generator.py tests/test_llm_analyzer.py tests/test_dfd_llm_generator.py tests/test_script_pipeline.py
git commit -m "fix(analysis): count phase-3b errors and deadline skips, keep DFD failure reason (#103)"
```

---

### Task 6: Step outcome rows in the status note

**Files:**
- Modify: `tmi_tf/llm_analyzer.py` (every `status_callback(...)` call in `analyze_repository`, the two `raise ValueError`)
- Modify: `tmi_tf/analyzer.py` (rows in `run_analysis`)
- Modify: `tmi_tf/threat_processor.py` (`create_threats_in_tmi`)
- Test: `tests/test_llm_analyzer.py`, `tests/test_analyzer.py`, `tests/test_threat_processor.py`

**Interfaces:**
- Consumes: `step_row`, `error_hint`, `LLMOutputError` (Task 1); `ThreatGaps`, `DFDLLMGenerator.last_error` (Task 5).
- Produces:
  - the rows of spec section 8.2, exactly
  - `ThreatProcessor.create_error_hints: list[str]` (distinct, first-seen order; reset at the start of each `create_threats_in_tmi` call)
  - in `run_analysis`, locals later tasks read: `dfd_error: str` (`""` when the DFD was created or skipped) and `threats_not_created: str` (`""` or the gap text of spec section 6.4)

- [ ] **Step 1: Write the failing tests**

`tests/test_llm_analyzer.py`, new class `TestStatusRows`:

```python
    def test_happy_path_rows(self):
        ...  # one phase-3a threat, no scripts
        assert rows == [
            "Phase 1 (Inventory) started",
            "Phase 1 (Inventory): succeeded",
            "Phase 2 (Infrastructure) started",
            "Phase 2 (Infrastructure): succeeded",
            "Phase 3a (Threat Identification) started",
            "Phase 3a (Threat Identification): succeeded (1 threats identified)",
            "Script review started",
            "Script review: succeeded (0 findings added)",
            "Phase 3b (Per-Threat Analysis) started",
            "Phase 3b: threat 1/1: succeeded",
            "Phase 3b (Per-Threat Analysis): succeeded (1 of 1 threats analyzed)",
        ]

    def test_phase_failure_row_names_the_phase_and_the_http_status(self):
        ...  # phase 2 raises litellm.AuthenticationError
        assert rows[-1] == "Phase 2 (Infrastructure): failed: HTTP 401 authentication_error"
        assert result.success is False

    def test_unusable_phase_1_output_row(self):
        ...  # phase 1 answers "not json" twice
        assert rows[-1] == "Phase 1 (Inventory): failed: unparseable response"

    def test_per_threat_and_deadline_rows(self):
        ...  # the Task 5 budget-exhaustion scenario, with status_callback=rows.append
        assert "Phase 3b: threat 1/3: succeeded" in rows
        assert "Phase 3b: threat 2/3: failed: HTTP 429 rate_limit_error" in rows
        assert "Phase 3b: threats 3-3 of 3: failed: skipped, deadline reached" in rows
        assert rows[-1] == (
            "Phase 3b (Per-Threat Analysis): failed: 2 of 3 threats not analyzed "
            "(HTTP 429 rate_limit_error, deadline reached)"
        )

    def test_refused_and_unparseable_threat_rows(self):
        ...
        assert "Phase 3b: threat 1/2: failed: refused (content_filter)" in rows
        assert "Phase 3b: threat 2/2: failed: unparseable response" in rows
        assert "Model refusals (content_filter): phase 3b: 1 threat(s)" in rows

    def test_no_row_contains_exception_text(self):
        ...  # phase 2 raises AuthenticationError(message="sk-secret-body")
        assert not any("sk-secret-body" in r for r in rows)
```

`tests/test_analyzer.py`, new class `TestStepRows`, modeled on `TestDFDRefusal.test_dfd_refusal_reported_in_status_and_analysis_note` (same patches; give each mocked analysis `threat_gaps = ThreatGaps()`):

```python
    def test_dfd_failure_row_carries_the_generator_reason(self, tmp_path):
        ...  # generate_structured_components returns None, last_error = "HTTP 429 rate_limit_error"
        assert "DFD diagram: failed: HTTP 429 rate_limit_error" in notes

    def test_dfd_refusal_keeps_its_row_and_gets_an_outcome_row(self, tmp_path):
        ...
        assert "Model refusals (content_filter): DFD generation" in notes
        assert "DFD diagram: failed: refused (content_filter)" in notes

    def test_dfd_skipped_at_the_deadline_row(self, tmp_path):
        ...  # deadline=time.monotonic() + 1
        assert "DFD diagram: failed: deadline reached" in notes
        dfd_cls.return_value.generate_structured_components.assert_not_called()

    def test_dfd_success_row(self, tmp_path):
        ...  # DFDBuilder patched to return 12 cells
        assert "DFD diagram: succeeded (12 cells)" in notes

    def test_report_and_clone_rows(self, tmp_path):
        ...
        for row in ("Clone r: succeeded", "Inventory report: succeeded", "Analysis report: succeeded"):
            assert row in notes

    def test_fatal_error_row_names_the_step(self, tmp_path):
        ...  # generate_inventory_report raises an exception with .status_code = 503
        assert "Inventory report: failed: HTTP 503 service_unavailable" in notes
        assert result.success is False

    def test_threat_creation_rows(self, tmp_path):
        ...  # ThreatProcessor patched: 3 threats extracted, 2 created,
        #      create_error_hints == ["HTTP 500 internal_server_error"]
        assert (
            "Threat creation: failed: 1 of 3 threats not created "
            "(HTTP 500 internal_server_error)" in notes
        )
```

Use the repository name the existing fixtures produce in place of `r` if it differs.

`tests/test_threat_processor.py`:

```python
def test_create_threats_records_hints_for_failures():
    ...  # tmi_client.create_threat raises an exception with .status = 500 for the 2nd of 3 threats
    assert len(created) == 2
    assert processor.create_error_hints == ["HTTP 500 internal_server_error"]
```

- [ ] **Step 2: Run and see them fail**

Run: `uv run pytest tests/test_llm_analyzer.py::TestStatusRows tests/test_analyzer.py::TestStepRows tests/test_threat_processor.py -q`
Expected: assertion failures on the row text; `AttributeError` for `create_error_hints`.

- [ ] **Step 3: Implement in `llm_analyzer.py`**

- Keep a local `step = "Prescan"` and set it to `"Phase 1 (Inventory)"`, `"Phase 2 (Infrastructure)"`, `"Phase 3a (Threat Identification)"`, `"Script review"`, `"Phase 3b (Per-Threat Analysis)"` as each begins. In the outer `except Exception as e`, call `status_callback(step_row(step, error=e))` when a callback is set, before returning the failed `TerraformAnalysis`.
- Replace the two `raise ValueError(...)` (phase 1 and phase 2 unusable output) with `raise LLMOutputError(...)`, same messages.
- Completion rows per spec section 8.2. Script review: `step_row("Script review", error=script_review_error or None, detail="" if script_review_error else f"{len(extra_threats)} findings added")`.
- 3b: delete the per-threat start row `Phase 3b: Analyzing threat i/N`. Emit one completion row per threat on each of the four paths (success, unparseable, refused, exception) with step `f"Phase 3b: threat {i}/{n}"`. On the deadline break emit `step_row(f"Phase 3b: threats {i}-{n} of {n}", error="skipped, deadline reached")`.
- Replace `Phase 3 (Security) complete` with `step_row("Phase 3b (Per-Threat Analysis)", detail=f"{len(security_findings)} of {n} threats analyzed")` when `gaps.summary()` is empty, else `step_row("Phase 3b (Per-Threat Analysis)", error=gaps.summary())`. The `Model refusals (content_filter): ...` row stays, just before it.

- [ ] **Step 4: Implement in `analyzer.py` and `threat_processor.py`**

- `create_threats_in_tmi`: `self.create_error_hints = []` at the start; in the per-threat `except`, append `error_hint(e)` if not already present.
- `run_analysis`, per spec section 8.2:
  - `Clone {repo_name}: succeeded` replaces `Clone complete: {repo_name}`; the `else` branch (no Terraform files) writes `step_row(f"Clone {repo_name}", error="no Terraform files found")`; the per-repository `except Exception as e` writes `step_row(f"Repository {repo.name}", error=e)`.
  - `Inventory report: succeeded` after the inventory note is written; `Analysis report: succeeded` after the analysis note is written.
  - DFD: `dfd_error = ""` before the block. `dfd_skipped_for_deadline` (Task 4) -> `dfd_error = "deadline reached"`. `structured_data` is None -> `dfd_error = dfd_generator.last_error or "unknown error"`. `except LLMRefusalError` -> `dfd_error = "refused (content_filter)"` (existing refusal row and note rewrite stay). `except Exception as e` -> `dfd_error = error_hint(e)`. Then one row: `step_row("DFD diagram", detail=f"{len(cells)} cells")` or `step_row("DFD diagram", error=dfd_error)`.
  - Threat creation: `threats_not_created = ""`. After `create_threats_in_tmi`: `missing = len(all_threats) - len(created_threats)`; when `missing`, `threats_not_created = f"{missing} of {len(all_threats)} threats not created ({', '.join(threat_processor.create_error_hints) or 'unknown error'})"` and the row is `step_row("Threat creation", error=threats_not_created)`; otherwise `step_row("Threat creation", detail=f"{len(created_threats)} created")` (`0 created` when nothing was extracted). `except Exception as e` -> `threats_not_created = f"threats not created ({error_hint(e)})"`, row `step_row("Threat creation", error=e)`.
  - A local `step` (`"Initialization"`, `"Inventory report"`, `"Analysis report"`) and, in the outermost `except Exception as e`, a best-effort `tmi_client.update_status_note(threat_model_id, step_row(step, error=e))` inside its own `try/except Exception`.

- [ ] **Step 5: Run the three test files plus `tests/test_script_pipeline.py`; fix any other test that pinned a replaced row; done gate; commit**

Run: `uv run pytest tests/ -q`
Expected: all pass.

```bash
git add tmi_tf/llm_analyzer.py tmi_tf/analyzer.py tmi_tf/threat_processor.py tests/test_llm_analyzer.py tests/test_analyzer.py tests/test_threat_processor.py
git commit -m "feat(status): success or failure with an error hint on every step row (#103)"
```

---

### Task 7: Run-level gaps in the result, the final row and the report

**Files:**
- Modify: `tmi_tf/analyzer.py` (`AnalysisResult`, end of `run_analysis`, the DFD refusal rewrite)
- Modify: `tmi_tf/markdown_generator.py` (`_generate_analysis_job_info`, `generate_analysis_report`)
- Test: `tests/test_analyzer.py`, `tests/test_markdown_generator.py`

**Interfaces:**
- Consumes: `TerraformAnalysis.threat_gaps` (Task 5); `dfd_error`, `threats_not_created` (Task 6).
- Produces:
  - `AnalysisResult.gaps: list[str] = field(default_factory=list)`
  - `MarkdownGenerator.generate_analysis_report(..., dfd_refused: bool = False, dfd_error: str = "")` and the same on `_generate_analysis_job_info`
  - final status row `Analysis completed with gaps: {'; '.join(gaps)}`

- [ ] **Step 1: Fix the test doubles (Review Focus 2), then write the failing tests**

Run `rg -n "MagicMock\(success=" tests/` and give every mocked analysis `threat_gaps = ThreatGaps()` (import from `tmi_tf.llm_analyzer`).

`tests/test_analyzer.py`, new class `TestRunGaps` (patches as in `TestStepRows`):

```python
    def test_clean_run_reports_no_gaps(self, tmp_path):
        ...
        assert result.gaps == []
        assert tmi.update_status_note.call_args.args[1] == "Analysis complete"

    def test_threat_and_dfd_gaps_reach_the_result_and_the_final_row(self, tmp_path):
        ...  # analysis.threat_gaps = ThreatGaps(28, failed=25, hints=("HTTP 429 rate_limit_error",))
        #      DFD returns None with last_error "HTTP 429 rate_limit_error"
        assert result.success is True
        assert result.gaps == [
            "25 of 28 threats not analyzed (HTTP 429 rate_limit_error)",
            "DFD not generated (HTTP 429 rate_limit_error)",
        ]
        assert tmi.update_status_note.call_args.args[1] == (
            "Analysis completed with gaps: 25 of 28 threats not analyzed "
            "(HTTP 429 rate_limit_error); DFD not generated (HTTP 429 rate_limit_error)"
        )

    def test_dfd_refusal_is_a_gap(self, tmp_path):
        ...
        assert result.gaps == ["DFD not generated (refused)"]

    def test_dfd_skipped_at_the_deadline_is_a_gap(self, tmp_path):
        ...  # deadline=time.monotonic() + 1
        assert result.gaps == ["DFD not generated (deadline reached)"]

    def test_threat_creation_shortfall_is_a_gap(self, tmp_path):
        ...
        assert result.gaps == [
            "1 of 3 threats not created in TMI (HTTP 500 internal_server_error)"
        ]

    def test_repo_name_prefix_only_with_several_analyses(self, tmp_path):
        ...  # two analyses, the second with gaps
        assert result.gaps == ["r2: 1 of 2 threats not analyzed (RuntimeError)"]

    def test_dfd_failure_rewrites_the_analysis_note(self, tmp_path):
        ...  # as the refusal test: generate_analysis_report called again with dfd_error set
        assert md_cls.return_value.generate_analysis_report.call_args.kwargs["dfd_error"] == (
            "HTTP 429 rate_limit_error"
        )

    def test_all_failed_path_is_unchanged(self, tmp_path):
        ...  # as test_job_fails_when_every_analysis_failed
        assert result.success is False and result.gaps == []
```

`tests/test_markdown_generator.py` (use real `TerraformAnalysis` objects):

```python
    def test_job_info_lists_analysis_gaps(self):
        a = TerraformAnalysis("repo", "u", threat_gaps=ThreatGaps(
            28, failed=25, hints=("HTTP 429 rate_limit_error",)))
        info = gen._generate_analysis_job_info("tm", [a], dfd_error="HTTP 429 rate_limit_error")
        assert (
            "**Analysis gaps**: repo: 25 of 28 threats not analyzed (HTTP 429 rate_limit_error); "
            "DFD not generated (HTTP 429 rate_limit_error)" in info
        )

    def test_job_info_has_no_gaps_line_for_a_clean_run(self):
        assert "Analysis gaps" not in gen._generate_analysis_job_info(
            "tm", [TerraformAnalysis("repo", "u")]
        )
```

- [ ] **Step 2: Run and see them fail**

Run: `uv run pytest tests/test_analyzer.py::TestRunGaps tests/test_markdown_generator.py -q`
Expected: failures on `gaps`, `dfd_error`, the final row.

- [ ] **Step 3: Implement**

- `run_analysis`, just before the final status row: build `gaps` in the order of spec section 6.4: each successful analysis's `threat_gaps.summary()` (prefixed `f"{a.repo_name}: "` only when `len(analyses) > 1`); `f"DFD not generated ({'refused' if dfd_error == 'refused (content_filter)' else dfd_error})"` when `dfd_error`; `threats_not_created` with `not created` replaced by `not created in TMI`. Simplest: have Task 6's `threats_not_created` text built by one local helper that takes the phrase, so the row and the gap share it.
- Final row: `Analysis failed: ...` unchanged when `all_failed`; else `Analysis completed with gaps: ...` when `gaps`; else `Analysis complete`. Pass `gaps=gaps` in the final `AnalysisResult` (and leave it empty on the `all_failed` and early-return paths).
- DFD failure rewrite: extract the existing refusal rewrite (regenerate the analysis report, `create_or_update_note`) into a local function taking `dfd_refused` and `dfd_error`. Call it with `dfd_refused=True` for a refusal (as today) and with `dfd_error=<hint>` for any other DFD failure.
- `_generate_analysis_job_info`: after the refusals line, `items = [f"{a.repo_name}: {a.threat_gaps.summary()}" for a in successful if a.threat_gaps.summary()]`, plus `f"DFD not generated ({dfd_error})"` when `dfd_error` and not `dfd_refused`; when `items`, append `f"**Analysis gaps**: {'; '.join(items)}"`. Pass gap text through the module's existing cell/markdown escaping helper if the refusals line does.

- [ ] **Step 4: Run and see them pass; done gate; commit**

```bash
git add tmi_tf/analyzer.py tmi_tf/markdown_generator.py tests/test_analyzer.py tests/test_markdown_generator.py
git commit -m "feat(analysis): report run-level gaps in the result, final status row and report (#103)"
```

---

### Task 8: `gaps` invocation outcome and the callback summary

**Files:**
- Modify: `tmi_tf/invocation.py`
- Modify: `tmi_tf/worker.py` (`_run_job`, `_finish_child`, `_watchdog`)
- Test: `tests/test_invocation.py`, `tests/test_worker.py`

**Interfaces:**
- Consumes: `AnalysisResult.gaps` (Task 7).
- Produces (in `invocation.py`):
  - `OUTCOMES = ("success", "gaps", "failed", "aborted")`, `GAPS_PREFIX = "tf_gaps_"`, `GAP_TEXT_MAX = 300`
  - `InvocationState.gaps: dict[str, str] = field(default_factory=dict)`
  - `mark_child(tmi, threat_model_id, job_id, outcome, gaps: str = "") -> InvocationState`
  - `gaps_of(state: InvocationState, job_id: str) -> str | None`
  - `invocation_summary(state: InvocationState, siblings: list[str]) -> tuple[str, str]` (callback status, message)
  - `WorkerPool._finish_child(self, job, outcome, gaps: str = "")`

- [ ] **Step 1: Write the failing tests**

`tests/test_invocation.py` (use the file's existing fake TMI; `st` builds an `InvocationState` with the given `children` and `gaps`, keyed as `child_key(job)[len(CHILD_PREFIX):]`):

```python
def test_mark_child_gaps_stores_outcome_first_then_text():
    state = inv.mark_child(tmi, "tm1", "p1:aws", "gaps", "DFD not generated (HTTP 429 rate_limit_error)")
    assert inv.outcome_of(state, "p1:aws") == "gaps"
    assert inv.gaps_of(state, "p1:aws") == "DFD not generated (HTTP 429 rate_limit_error)"
    # two upsert_note_metadata calls, in this order (however the fake records them)
    assert [set(u) for u in tmi.upserts] == [{"tf_child_p1_aws"}, {"tf_gaps_p1_aws"}]


def test_outcome_survives_a_rejected_gap_text():
    """TMI refusing the free text must not turn `completed with gaps` into `failed`."""
    ...  # the fake raises on any upsert whose keys start with tf_gaps_
    state = inv.mark_child(tmi, "tm1", "p1:aws", "gaps", "some text")
    assert inv.outcome_of(state, "p1:aws") == "gaps"
    assert inv.gaps_of(state, "p1:aws") is None
    assert inv.invocation_summary(state, ["p1:aws"]) == (
        "completed",
        "completed with gaps: p1:aws: gaps not recorded (1 succeeded, 0 failed)",
    )


def test_gap_text_is_cut_to_the_limit():
    state = inv.mark_child(tmi, "tm1", "p1:aws", "gaps", "x" * 2000)
    assert len(inv.gaps_of(state, "p1:aws")) == inv.GAP_TEXT_MAX


@pytest.mark.parametrize(
    ("outcome", "gaps"), [("gaps", ""), ("success", "text"), ("failed", "text")]
)
def test_gap_text_must_match_outcome(outcome, gaps):
    with pytest.raises(ValueError):
        inv.mark_child(tmi, "tm1", "p1:aws", outcome, gaps)


def test_unknown_outcome_is_rejected():
    with pytest.raises(AssertionError):
        inv.mark_child(tmi, "tm1", "p1:aws", "partial")


def test_open_invocation_clears_old_gap_keys():
    ...  # seed tf_gaps_p1_aws and tf_child_p1_aws, open a new invocation
    assert not any(k.startswith(("tf_gaps_", "tf_child_")) for k in tmi.metadata)


@pytest.mark.parametrize(
    ("children", "gaps", "expected"),
    [
        ({"p1:a": "success", "p1:b": "success"}, {}, ("completed", "2 succeeded, 0 failed")),
        ({"p1:a": "success", "p1:b": "failed"}, {}, ("failed", "1 succeeded, 1 failed (p1:b)")),
        ({"p1:a": "success"}, {}, ("failed", "1 succeeded, 1 failed (p1:b)")),  # p1:b unmarked
        ({"p1:a": "aborted", "p1:b": "success"}, {}, ("failed", "1 succeeded, 1 failed (p1:a)")),
        (
            {"p1:a": "gaps", "p1:b": "success"},
            {"p1:a": "25 of 28 threats not analyzed (HTTP 429 rate_limit_error)"},
            ("completed",
             "completed with gaps: p1:a: 25 of 28 threats not analyzed "
             "(HTTP 429 rate_limit_error) (2 succeeded, 0 failed)"),
        ),
        (
            {"p1:a": "gaps", "p1:b": "gaps"}, {"p1:a": "A", "p1:b": "B"},
            ("completed", "completed with gaps: p1:a: A | p1:b: B (2 succeeded, 0 failed)"),
        ),
        (
            {"p1:a": "gaps", "p1:b": "failed"}, {"p1:a": "A"},
            ("failed", "1 succeeded, 1 failed (p1:b); gaps: p1:a: A"),
        ),
        (
            {"p1:a": "gaps", "p1:b": "success"}, {},
            ("completed", "completed with gaps: p1:a: gaps not recorded (2 succeeded, 0 failed)"),
        ),
    ],
)
def test_invocation_summary(children, gaps, expected):
    assert inv.invocation_summary(st(children, gaps), ["p1:a", "p1:b"]) == expected
```

`tests/test_worker.py` (model on the existing `_finish_child` tests around lines 305-360):

```python
    def test_child_with_gaps_is_marked_gaps_and_callback_says_completed_with_gaps(self):
        ...  # run_analysis returns AnalysisResult(success=True,
        #        gaps=["25 of 28 threats not analyzed (HTTP 429 rate_limit_error)",
        #              "DFD not generated (HTTP 429 rate_limit_error)"])
        mark.assert_called_once_with(
            ANY, "tm1", "p1:aws", "gaps",
            "25 of 28 threats not analyzed (HTTP 429 rate_limit_error); "
            "DFD not generated (HTTP 429 rate_limit_error)",
        )
        cb.send_status.assert_called_once_with(
            "completed",
            "completed with gaps: p1:aws: 25 of 28 threats not analyzed "
            "(HTTP 429 rate_limit_error); DFD not generated (HTTP 429 rate_limit_error) "
            "(1 succeeded, 0 failed)",
        )

    def test_clean_child_still_calls_mark_child_with_four_arguments(self):
        ...
        mark.assert_called_once_with(ANY, "tm1", "p1:aws", "success")

    def test_watchdog_reports_gaps_from_stored_state(self):
        ...  # state: p1:aws = gaps (text "A"), p1:gcp = success, deadline passed
        cb_cls.return_value.send_status.assert_called_once_with(
            "completed", "completed with gaps: p1:aws: A (2 succeeded, 0 failed)"
        )
```

- [ ] **Step 2: Run and see them fail**

Run: `uv run pytest tests/test_invocation.py tests/test_worker.py -q`
Expected: new tests fail; every existing test still passes.

- [ ] **Step 3: Implement**

- `mark_child`: keep `assert outcome in OUTCOMES`; `if (outcome == "gaps") != bool(gaps): raise ValueError(...)`. Upsert the outcome key exactly as today. For `gaps`, then upsert `GAPS_PREFIX + child_key(job_id)[len(CHILD_PREFIX):]` (text cut to `GAP_TEXT_MAX`) in a second call wrapped in `try/except Exception` that logs a warning and carries on. Then `read_state`, as today.
- `read_state`: fill `gaps` from keys starting with `GAPS_PREFIX`; `children` filter is unchanged apart from the wider `OUTCOMES`.
- `open_invocation`: delete keys starting with `CHILD_PREFIX` or `GAPS_PREFIX`.
- `invocation_summary`: spec section 7.
- `_finish_child` and `_watchdog`: replace the inline `failed`/`summary`/status code with `status, summary = invocation_summary(state, siblings)`; the `close_invocation` line keeps its `Invocation complete: ` / `Invocation timed out: ` prefix.
- `_finish_child` passes `gaps` to `mark_child` as a fifth positional argument only when `outcome == "gaps"`. Existing tests patch `mark_child` with `lambda *a` and assert four-argument calls; a keyword or an always-present fifth argument breaks them.
- `_run_job`: `outcome = "failed" if not result.success else "gaps" if result.gaps else "success"`; `await self._finish_child(job, outcome, "; ".join(result.gaps) if outcome == "gaps" else "")`.

- [ ] **Step 4: Run and see them pass; done gate; commit**

```bash
git add tmi_tf/invocation.py tmi_tf/worker.py tests/test_invocation.py tests/test_worker.py
git commit -m "feat(worker): report completed-with-gaps in the addon callback (#103)"
```

---

### Task 9: TMI API retry backoff

**Files:**
- Modify: `tmi_tf/retry.py` (add `tmi_retry_wait` and two constants)
- Modify: `tmi_tf/tmi_client_wrapper.py` (`_call_with_retry`, imports)
- Test: `tests/test_tmi_retry.py` (new), `tests/test_retry.py`

**Interfaces:**
- Consumes: `parse_retry_after`, `backoff_delay`, `DEFAULT_RETRY_DELAY` (Task 2).
- Produces: `TMI_RATE_LIMIT_MAX_ATTEMPTS = 4`, `TMI_RETRY_AFTER_MAX = 30.0`, `tmi_retry_wait(headers: Mapping[str, str] | None, retry_number: int, jitter: float = 0.0) -> float`.

- [ ] **Step 1: Write the failing tests**

`tests/test_retry.py`:

```python
class TestTmiRetryWait:
    def test_backoff_from_the_default_delay(self):
        assert [tmi_retry_wait(None, n) for n in (1, 2, 3)] == [3.0, 6.0, 12.0]
        assert tmi_retry_wait(None, 1, jitter=1.0) == pytest.approx(3.6)

    def test_retry_after_is_honored_and_clamped(self):
        assert tmi_retry_wait({"Retry-After": "7"}, 1) == 7.0
        assert tmi_retry_wait({"Retry-After": "600"}, 1) == 30.0

    @pytest.mark.parametrize("value", ["soon", "-1", "nan"])
    def test_bad_retry_after_falls_back(self, value):
        assert tmi_retry_wait({"Retry-After": value}, 2) == 6.0
```

`tests/test_tmi_retry.py`: build the client with `TMIClient.__new__(TMIClient)` (as `tests/test_tmi_client_wrapper.py` does) and set `client._reauthenticate = MagicMock()`. Import `ApiException` with `from tmi_client.rest import ApiException  # type: ignore[import-not-found]` after importing `tmi_tf.tmi_client_wrapper`. A fixture patches `tmi_tf.tmi_client_wrapper.time.sleep` to record waits and `tmi_tf.tmi_client_wrapper.random.random` to return 0.0. `api(status, headers=None)` builds `ApiException(status=status, reason="r")` and sets `.headers`.

```python
def test_429_is_retried_with_backoff_until_it_succeeds(client, sleeps):
    call = MagicMock(side_effect=[api(429), api(429), api(429), "ok"])
    assert client._call_with_retry(call) == "ok"
    assert sleeps == [3.0, 6.0, 12.0]


def test_429_gives_up_after_four_attempts(client, sleeps):
    call = MagicMock(side_effect=[api(429)] * 4)
    with pytest.raises(ApiException):
        client._call_with_retry(call)
    assert call.call_count == 4 and len(sleeps) == 3


def test_retry_after_header_is_honored(client, sleeps):
    call = MagicMock(side_effect=[api(429, {"Retry-After": "7"}), "ok"])
    client._call_with_retry(call)
    assert sleeps == [7.0]


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_5xx_is_retried_exactly_once(client, sleeps, status):
    call = MagicMock(side_effect=[api(status), api(status)])
    with pytest.raises(ApiException):
        client._call_with_retry(call)
    assert call.call_count == 2 and sleeps == [3.0]


def test_401_reauthenticates_once_without_sleeping(client, sleeps):
    call = MagicMock(side_effect=[api(401), "ok"])
    assert client._call_with_retry(call) == "ok"
    client._reauthenticate.assert_called_once()
    assert sleeps == []


def test_second_401_is_raised(client, sleeps):
    call = MagicMock(side_effect=[api(401), api(401)])
    with pytest.raises(ApiException):
        client._call_with_retry(call)
    assert call.call_count == 2


def test_429_after_reauthentication_still_backs_off(client, sleeps):
    call = MagicMock(side_effect=[api(401), api(429), "ok"])
    assert client._call_with_retry(call) == "ok"
    assert sleeps == [3.0]


@pytest.mark.parametrize("status", [400, 403, 404, 409, 422])
def test_other_statuses_are_not_retried(client, sleeps, status):
    call = MagicMock(side_effect=[api(status)])
    with pytest.raises(ApiException):
        client._call_with_retry(call)
    assert call.call_count == 1 and sleeps == []
```

- [ ] **Step 2: Run and see them fail**

Run: `uv run pytest tests/test_tmi_retry.py tests/test_retry.py::TestTmiRetryWait -q`
Expected: import error for `tmi_retry_wait`; the 429 tests fail at the second call.

- [ ] **Step 3: Implement**

`tmi_retry_wait`: a valid `parse_retry_after(headers)` gives `min(value, TMI_RETRY_AFTER_MAX)`; else `backoff_delay(retry_number, base=DEFAULT_RETRY_DELAY, cap=TMI_RETRY_AFTER_MAX, jitter=jitter)`.

`_call_with_retry`:

```python
attempt, reauthenticated = 1, False
while True:
    try:
        return api_call()
    except ApiException as e:
        if e.status == 401 and not reauthenticated:
            self._reauthenticate()
            reauthenticated = True
            continue
        if e.status == 429 and attempt < TMI_RATE_LIMIT_MAX_ATTEMPTS:
            wait = tmi_retry_wait(getattr(e, "headers", None), attempt, random.random())
        elif e.status in TRANSIENT_API_STATUSES and e.status != 429 and attempt < 2:
            wait = DEFAULT_RETRY_DELAY
        else:
            raise
        # existing warning log, with the wait
        time.sleep(wait)
        attempt += 1
```

Update the docstring: 429 up to four calls with backoff or `Retry-After`; 5xx one retry (more could duplicate a create that was committed before the error); 401 one re-authentication.

- [ ] **Step 4: Run and see them pass; done gate; commit**

```bash
git add tmi_tf/retry.py tmi_tf/tmi_client_wrapper.py tests/test_tmi_retry.py tests/test_retry.py
git commit -m "fix(tmi): back off on TMI API 429 and honor Retry-After (#103)"
```

---

### Task 10: Phase-3b prompt reorder and Anthropic prompt caching

**Files:**
- Modify: `prompts/threat_analysis_user.txt`
- Modify: `tmi_tf/providers/__init__.py` (`LLMResponse`, `LLMProvider.complete`)
- Modify: `tmi_tf/providers/llm_base.py` (`complete`)
- Modify: `tmi_tf/llm_analyzer.py` (`split_cache_prefix`, `_load_phase_prompts`, `call_llm_checked`, `_call_llm`, `_call_llm_json`, the 3b loop, `TerraformAnalysis`)
- Test: `tests/test_llm_provider.py`, `tests/test_llm_analyzer.py`, `tests/test_script_pipeline.py`

**Interfaces:**
- Produces:
  - `LLMResponse(..., finish_reason, cache_read_tokens: int = 0, cache_creation_tokens: int = 0)`
  - `LLMProvider.complete(self, system_prompt, user_prompt, max_tokens=64000, timeout=1200.0, *, cache_prefix: str = "") -> LLMResponse` (Protocol and `BaseLLMProvider`)
  - `llm_analyzer.CACHE_BREAKPOINT_MARKER = "<!-- cache-breakpoint -->"`
  - `llm_analyzer.split_cache_prefix(template: str) -> tuple[str, str]`
  - `LLMAnalyzer.threat_analysis_prefix_template`, `.threat_analysis_suffix_template` (replace `.threat_analysis_user_template`)
  - `call_llm_checked(..., *, cache_prefix: str = "", budget=None, on_wait=None)`; `_call_llm(..., cache_prefix: str = "")`; `_call_llm_json(..., attempts=1, cache_prefix: str = "")`
  - `TerraformAnalysis(..., cache_read_tokens: int = 0, cache_creation_tokens: int = 0)`

- [ ] **Step 1: Keep the security test looking at the whole prompt (Review Focus 1)**

In `tests/test_script_pipeline.py:79` change the collector to
`prompts = [c.args[0] + c.kwargs.get("cache_prefix", "") + c.args[1] for c in provider.complete.call_args_list]`
and apply the same to any other place in `tests/` that joins `args[0]` and `args[1]` (`rg -n "args\[0\] \+ c.args\[1\]" tests/`). Run that file; it must still pass before any other change.

- [ ] **Step 2: Write the failing tests**

`tests/test_llm_provider.py`:

```python
class TestCachePrefix:
    def _complete(self, mock_litellm, provider_name, **kw):
        mock_litellm.completion.return_value = iter([])
        mock_litellm.stream_chunk_builder.return_value = _make_litellm_response("ok")
        mock_litellm.completion_cost.return_value = 0.0
        BaseLLMProvider(provider=provider_name, model=f"{provider_name}/m").complete(
            "sys", "SUFFIX", **kw
        )
        return mock_litellm.completion.call_args.kwargs["messages"]

    @patch("tmi_tf.providers.llm_base.litellm")
    @patch("tmi_tf.providers.llm_base.save_llm_response", return_value="/tmp/test")
    def test_anthropic_prefix_is_a_cached_block(self, _save, mock_litellm):
        assert self._complete(mock_litellm, "anthropic", cache_prefix="PREFIX") == [
            {"role": "system", "content": "sys"},
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "PREFIX", "cache_control": {"type": "ephemeral"}},
                    {"type": "text", "text": "SUFFIX"},
                ],
            },
        ]

    @pytest.mark.parametrize("name", ["openai", "xai", "gemini", "oci"])
    @patch("tmi_tf.providers.llm_base.litellm")
    @patch("tmi_tf.providers.llm_base.save_llm_response", return_value="/tmp/test")
    def test_other_providers_get_one_plain_string(self, _save, mock_litellm, name):
        messages = self._complete(mock_litellm, name, cache_prefix="PREFIX")
        assert messages[1] == {"role": "user", "content": "PREFIXSUFFIX"}
        assert "cache_control" not in json.dumps(messages)

    @patch("tmi_tf.providers.llm_base.litellm")
    @patch("tmi_tf.providers.llm_base.save_llm_response", return_value="/tmp/test")
    def test_without_a_prefix_the_request_is_unchanged(self, _save, mock_litellm):
        assert self._complete(mock_litellm, "anthropic")[1] == {"role": "user", "content": "SUFFIX"}


class TestCacheTokens:
    # each test: stream_chunk_builder returns a response whose .usage is the SimpleNamespace given
    def test_anthropic_cache_fields(self): ...
        # usage(prompt_tokens=75400, completion_tokens=500, cache_read_input_tokens=75000,
        #       cache_creation_input_tokens=0, prompt_tokens_details=None)
        # -> input_tokens == 75400, cache_read_tokens == 75000, cache_creation_tokens == 0
    def test_cache_creation_field(self): ...       # cache_creation_input_tokens=75000 -> 75000
    def test_openai_cached_tokens_fallback(self): ...
        # no cache_read_input_tokens attribute; prompt_tokens_details.cached_tokens=1024 -> 1024
    def test_mock_or_bad_usage_values_yield_zero(self): ...
        # usage is a MagicMock, or the fields are None / -1 / True -> both 0
```

`tests/test_llm_analyzer.py`:

```python
OLD_3B_TEMPLATE_LINES = sorted(
    line for line in """## Threat To Analyze
**Name:** {threat_name}
**Description:** {threat_description}
**Affected Components:** {affected_components}
## Infrastructure Context
### Inventory
{inventory_json}
### Infrastructure Analysis
{infrastructure_json}
---
Analyze the above security threat in the context of the infrastructure. Produce STRIDE classification, a CVSS 4.0 vector string, CWE identifiers, a mitigation recommendation, and a category. Return ONLY the JSON object.""".splitlines()
)


class TestCachePrefix:
    def test_template_is_reordered_not_reworded(self):
        text = (prompts_dir() / "threat_analysis_user.txt").read_text(encoding="utf-8")
        lines = [l for l in text.splitlines() if l.strip() and l != CACHE_BREAKPOINT_MARKER]
        assert sorted(lines) == OLD_3B_TEMPLATE_LINES

    def test_shipped_template_splits_into_shared_prefix_and_threat_suffix(self):
        a = LLMAnalyzer(_make_provider())
        assert "{inventory_json}" in a.threat_analysis_prefix_template
        assert "{infrastructure_json}" in a.threat_analysis_prefix_template
        assert a.threat_analysis_suffix_template.startswith("## Threat To Analyze")
        assert CACHE_BREAKPOINT_MARKER not in (
            a.threat_analysis_prefix_template + a.threat_analysis_suffix_template
        )

    @pytest.mark.parametrize(
        "template",
        [
            "{inventory_json}{infrastructure_json}{threat_name}{threat_description}{affected_components}",
            "A\n<!-- cache-breakpoint -->\nB\n<!-- cache-breakpoint -->\nC",
            "{inventory_json}\n<!-- cache-breakpoint -->\n{infrastructure_json}{threat_name}{threat_description}{affected_components}",
            "{inventory_json}{infrastructure_json}{threat_name}\n<!-- cache-breakpoint -->\n{threat_description}{affected_components}",
            "",
        ],
    )
    def test_split_rejects_a_bad_template(self, template):
        with pytest.raises(ValueError):
            split_cache_prefix(template)

    def test_every_3b_call_shares_one_prefix_including_the_cwe_corrective_turn(self):
        ...  # two threats; the first answer maps to a disallowed CWE (see TestCweRedirect)
        calls = provider.complete.call_args_list
        early, third_b = calls[:3], calls[3:]
        assert all("cache_prefix" not in c.kwargs for c in early)
        prefixes = {c.kwargs["cache_prefix"] for c in third_b}
        assert len(third_b) == 3 and len(prefixes) == 1
        prefix = prefixes.pop()
        assert json.dumps(result.inventory, indent=2) in prefix
        assert json.dumps(result.infrastructure, indent=2) in prefix
        for c in third_b:
            assert json.dumps(result.infrastructure, indent=2) not in c.args[1]
            assert c.args[1].startswith("## Threat To Analyze")
        assert "not allowed" in third_b[1].args[1]

    def test_repository_text_cannot_forge_a_breakpoint(self):
        ...  # the phase-2 answer has "architecture_summary": "<!-- cache-breakpoint -->"
        assert CACHE_BREAKPOINT_MARKER in provider.complete.call_args_list[3].kwargs["cache_prefix"]
        assert result.success

    def test_cache_tokens_are_summed_on_the_analysis(self):
        ...  # 3b responses carry cache_creation_tokens=75000 then cache_read_tokens=75000
        assert (result.cache_creation_tokens, result.cache_read_tokens) == (75000, 75000)

    def test_empty_response_retry_sums_cache_tokens(self):
        ...  # call_llm_checked: empty "stop" response with cache_read_tokens=10, then a
        #      normal one with cache_read_tokens=20 -> response.cache_read_tokens == 30
```

- [ ] **Step 3: Run and see them fail**

Run: `uv run pytest tests/test_llm_provider.py tests/test_llm_analyzer.py -q`
Expected: failures on `cache_prefix`, `split_cache_prefix`, the template order.

- [ ] **Step 4: Reorder `prompts/threat_analysis_user.txt`**

Exactly the text of spec section 10.1: the `## Infrastructure Context` section first, a blank line, the marker line, then `## Threat To Analyze` through the final instruction. No line is added or reworded.

- [ ] **Step 5: Implement the provider side**

- `LLMResponse`: two new fields with default 0, after `finish_reason`.
- `BaseLLMProvider.complete`: keyword-only `cache_prefix: str = ""`. When `cache_prefix and self._provider == "anthropic"`, the user content is the two-block list of spec section 10.2; otherwise it is `cache_prefix + user_prompt`. The prompt-size log counts the prefix.
- Cache tokens: a module helper `_usage_int(obj: object, name: str) -> int` returning the attribute only when it is an `int`, not a `bool`, and `>= 0`, else 0. `cache_read = _usage_int(usage, "cache_read_input_tokens") or _usage_int(getattr(usage, "prompt_tokens_details", None), "cached_tokens")`; `cache_creation = _usage_int(usage, "cache_creation_input_tokens")`. `tokens_in` stays `usage.prompt_tokens`; `cost` stays `litellm.completion_cost`.
- The per-call log line becomes `"%s (%s): %d input (%d cache read, %d cache write), %d output tokens, finish_reason=%s, $%.4f"`. Return both counts on both `LLMResponse(...)` constructions.
- Update the `LLMProvider` Protocol signature and docstring.

- [ ] **Step 6: Implement the analyzer side**

- `split_cache_prefix`: split on the line equal to `CACHE_BREAKPOINT_MARKER` (with `splitlines(keepends=True)`); require exactly one such line; prefix = lines before, suffix = lines after; validate placeholders per spec section 10.1; raise `ValueError` naming what is wrong.
- `_load_phase_prompts`: set the two templates from `split_cache_prefix(self._load_prompt("threat_analysis_user.txt"))`. Run `rg -n "threat_analysis_user_template" tmi_tf/ tests/ scripts/` and update every use.
- `call_llm_checked`: `cache_prefix` keyword; pass `cache_prefix=cache_prefix` to `llm_provider.complete` only when it is non-empty (build the keyword dict conditionally), so every existing positional call and exact-argument assertion is untouched. In the empty-response retry, add both cache counts to the `replace(...)` sum.
- `_call_llm` and `_call_llm_json`: accept and forward `cache_prefix`. `_call_llm` also adds each response's cache counts to `self._cache_read_tokens` / `self._cache_creation_tokens`, which `analyze_repository` zeroes at entry.
- 3b: format the prefix once before the loop: `threat_prefix = self.threat_analysis_prefix_template.format(inventory_json=inventory_json_str, infrastructure_json=infrastructure_json_str)`. Per threat, format the suffix with the three threat fields and call `_call_llm_json(..., user_prompt=suffix, cache_prefix=threat_prefix)`. The CWE corrective turn is `suffix + "\n\n# Your previous answer\n\n" + ...` with the same `cache_prefix`.
- After the loop: `logger.info("Phase 3b cache: %d read, %d written input tokens", ...)`; pass both totals to `TerraformAnalysis`.

- [ ] **Step 7: Run and see them pass**

Run: `uv run pytest tests/ -q`
Expected: all pass, including `tests/test_script_pipeline.py` and `tests/test_prompt_hardening.py`. A test that looked for the inventory JSON in a 3b call's `args[1]` now looks in `kwargs["cache_prefix"]`.

- [ ] **Step 8: Done gate, then commit**

```bash
git add prompts/threat_analysis_user.txt tmi_tf/providers/__init__.py tmi_tf/providers/llm_base.py tmi_tf/llm_analyzer.py tests/test_llm_provider.py tests/test_llm_analyzer.py tests/test_script_pipeline.py
git commit -m "feat(llm): cache the shared phase-3b context on Anthropic, reorder the 3b prompt (#103)"
```

---

### Task 11: Documentation

**Files:**
- Modify: `.claude/CLAUDE.md` (Modules list)
- Modify: `README.md` (the "Rate Limits" section near line 350)

- [ ] **Step 1: Update `.claude/CLAUDE.md`**

Replace the `retry.py` bullet and add one for the new module; adjust the two bullets whose behavior changed. Keep the file's existing bullet style and leave everything else as it is.

```
- **`retry.py`** — LLM retry: waits for `retry-after`, else the `anthropic-ratelimit-*-reset` headers, else jittered exponential backoff; attempt limits per error class; `RetryBudget` stops waits at the job deadline. Also the TMI API 429 wait (`tmi_retry_wait`)
- **`error_hints.py`** — `error_hint` (HTTP status + fixed label, never exception text) and `step_row` for status-note outcome rows
```

- `llm_analyzer.py` bullet: add "phase 3b sends the shared inventory/infrastructure JSON as a cache prefix (`cache_prefix`, split at the `<!-- cache-breakpoint -->` line of `threat_analysis_user.txt`) and counts unanalyzed threats in `ThreatGaps`".
- LLM providers paragraph: add "Provider `anthropic` marks a `cache_prefix` with `cache_control`; other providers get it concatenated. `num_retries=0`: `retry.py` is the only retry."

- [ ] **Step 2: Update `README.md`**

Under "LLM API" in the Rate Limits section, replace "Tool will retry with exponential backoff" with:

```
- On a rate limit the tool waits for the provider's `retry-after` (or backs off
  exponentially) and retries; the status note shows each wait
- In the webhook service, waits stop before `JOB_TIMEOUT`; threats that could not be
  analyzed are reported as gaps ("completed with gaps: ...") instead of being dropped
- With Anthropic profiles, phase 3b reuses its shared context through prompt caching
```

- [ ] **Step 3: Check every claim against the code**

Run: `rg -n "retry-after|RetryBudget|cache_prefix|num_retries|completed with gaps" tmi_tf/` and confirm each sentence added in Steps 1 and 2 matches what the code does. Check for British spellings in the lines touched.

- [ ] **Step 4: Done gate, then commit**

```bash
git add .claude/CLAUDE.md README.md
git commit -m "docs: retry, 3b prompt caching and gap reporting (#103)"
```

---

## After the last task

The PR description lists the six open questions of spec section 12 with the default implemented for each, and the production checks for Assumptions 1, 2, 3 and 6 (cache-read tokens near 75,000 on 3b calls 2 to N in the pod log; no `rate limited` rows from input tokens after the first 3b call; the header that supplied each wait; the gap text, not `gaps not recorded`, in the callback message of the first run with gaps). Deploying and the production run are Eric's call.
