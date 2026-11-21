# pyright: reportPrivateImportUsage=false
"""Tests for transient error retry logic."""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import httpx
import litellm  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]
import pytest  # pyright: ignore[reportMissingImports] # ty:ignore[unresolved-import]
from llm_errors import FakeClock, mid_stream_429, rate_limit_error

from tmi_tf.retry import (
    DEFAULT_RETRY_DELAY,
    TRANSIENT_API_STATUSES,
    TRANSIENT_LLM_EXCEPTIONS,
    RetryBudget,
    backoff_delay,
    parse_retry_after,
    response_headers,
    retry_transient_llm_call,
    tmi_retry_wait,
)


class TestRetryTransientLlmCall:
    """Tests for retry_transient_llm_call."""

    def test_success_on_first_try(self):
        call = MagicMock(return_value="result")
        result = retry_transient_llm_call(call, description="test")
        assert result == "result"
        assert call.call_count == 1

    def test_retries_on_service_unavailable(self):
        exc = litellm.ServiceUnavailableError(
            message="503", llm_provider="gemini", model="gemini/gemini-3.1-pro-preview"
        )
        call = MagicMock(side_effect=[exc, "result"])
        result = retry_transient_llm_call(
            call, description="test", sleep=lambda s: None, jitter=lambda: 0.0
        )
        assert result == "result"
        assert call.call_count == 2

    def test_retries_on_rate_limit(self):
        exc = litellm.RateLimitError(
            message="429", llm_provider="anthropic", model="anthropic/claude-opus-4-6"
        )
        call = MagicMock(side_effect=[exc, "result"])
        result = retry_transient_llm_call(
            call, description="test", sleep=lambda s: None, jitter=lambda: 0.0
        )
        assert result == "result"
        assert call.call_count == 2

    def test_retries_on_internal_server_error(self):
        exc = litellm.InternalServerError(
            message="500", llm_provider="openai", model="openai/gpt-4"
        )
        call = MagicMock(side_effect=[exc, "result"])
        result = retry_transient_llm_call(
            call, description="test", sleep=lambda s: None, jitter=lambda: 0.0
        )
        assert result == "result"
        assert call.call_count == 2

    def test_retries_on_bad_gateway(self):
        exc = litellm.BadGatewayError(
            message="502", llm_provider="openai", model="openai/gpt-4"
        )
        call = MagicMock(side_effect=[exc, "result"])
        result = retry_transient_llm_call(
            call, description="test", sleep=lambda s: None, jitter=lambda: 0.0
        )
        assert result == "result"
        assert call.call_count == 2

    def test_retries_on_timeout(self):
        exc = litellm.Timeout(
            message="timeout", model="openai/gpt-4", llm_provider="openai"
        )
        call = MagicMock(side_effect=[exc, "result"])
        result = retry_transient_llm_call(
            call, description="test", sleep=lambda s: None, jitter=lambda: 0.0
        )
        assert result == "result"
        assert call.call_count == 2

    def test_retries_on_api_connection_error(self):
        exc = litellm.APIConnectionError(
            message="connection failed", llm_provider="openai", model="openai/gpt-4"
        )
        call = MagicMock(side_effect=[exc, "result"])
        result = retry_transient_llm_call(
            call, description="test", sleep=lambda s: None, jitter=lambda: 0.0
        )
        assert result == "result"
        assert call.call_count == 2

    def test_no_retry_on_bad_request(self):
        exc = litellm.BadRequestError(
            message="bad request", model="test", llm_provider="anthropic"
        )
        call = MagicMock(side_effect=exc)
        with pytest.raises(litellm.BadRequestError):
            retry_transient_llm_call(call, description="test")
        assert call.call_count == 1

    def test_no_retry_on_auth_error(self):
        exc = litellm.AuthenticationError(
            message="invalid key", llm_provider="anthropic", model="test"
        )
        call = MagicMock(side_effect=exc)
        with pytest.raises(litellm.AuthenticationError):
            retry_transient_llm_call(call, description="test")
        assert call.call_count == 1

    def test_no_retry_on_context_window_exceeded(self):
        exc = litellm.ContextWindowExceededError(
            message="too long", model="test", llm_provider="anthropic"
        )
        call = MagicMock(side_effect=exc)
        with pytest.raises(litellm.ContextWindowExceededError):
            retry_transient_llm_call(call, description="test")
        assert call.call_count == 1

    def test_default_delay_value(self):
        assert DEFAULT_RETRY_DELAY == 3.0


class TestTransientConstants:
    """Test the transient error classification constants."""

    def test_all_transient_llm_types_covered(self):
        expected = {
            litellm.ServiceUnavailableError,
            litellm.RateLimitError,
            litellm.InternalServerError,
            litellm.BadGatewayError,
            litellm.Timeout,
            litellm.APIConnectionError,
        }
        assert set(TRANSIENT_LLM_EXCEPTIONS) == expected

    def test_transient_api_statuses(self):
        assert TRANSIENT_API_STATUSES == frozenset({429, 500, 502, 503, 504})


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
            call,
            description="test",
            budget=budget,
            on_wait=on_wait,
            sleep=sleep,
            jitter=lambda: jitter,
            now=lambda: NOW,
        )
    except Exception as e:
        outcome = e
    return outcome, sleeps, call.call_count


class TestWaitSource:
    def test_retry_after_from_litellm_headers(self):
        assert run([rate_limit_error({"retry-after": "17"})]) == ("ok", [17.0], 2)

    def test_retry_after_from_response_headers(self):
        assert run([rate_limit_error(response_headers={"retry-after": "9"})])[1] == [
            9.0
        ]

    def test_litellm_headers_win_over_response_headers(self):
        e = rate_limit_error(
            {"retry-after": "17"}, response_headers={"retry-after": "9"}
        )
        assert run([e])[1] == [17.0]

    def test_header_names_are_case_insensitive(self):
        assert run([rate_limit_error({"Retry-After": " 17 "})])[1] == [17.0]

    def test_server_wait_is_padded_by_jitter(self):
        assert run([rate_limit_error({"retry-after": "17"})], jitter=0.5)[1] == [17.5]

    def test_reset_of_exhausted_dimension(self):
        e = rate_limit_error(
            {
                "anthropic-ratelimit-input-tokens-remaining": "0",
                "anthropic-ratelimit-input-tokens-reset": at(42),
                "anthropic-ratelimit-output-tokens-remaining": "9000",
                "anthropic-ratelimit-output-tokens-reset": at(55),
            }
        )
        assert run([e])[1] == [42.0]

    def test_latest_reset_when_no_dimension_is_exhausted(self):
        e = rate_limit_error(
            {
                "anthropic-ratelimit-input-tokens-remaining": "20000",
                "anthropic-ratelimit-input-tokens-reset": at(42),
                "anthropic-ratelimit-requests-reset": at(55),
            }
        )
        assert run([e])[1] == [55.0]

    def test_retry_after_wins_over_reset(self):
        e = rate_limit_error(
            {"retry-after": "7", "anthropic-ratelimit-tokens-reset": at(55)}
        )
        assert run([e])[1] == [7.0]

    def test_reset_headers_ignored_for_non_429(self):
        e = litellm.ServiceUnavailableError(message="503", llm_provider="p", model="m")
        e.litellm_response_headers = httpx.Headers(  # type: ignore[attr-defined]  # pyright: ignore[reportAttributeAccessIssue]
            {"anthropic-ratelimit-tokens-reset": at(55)}
        )
        assert run([e])[1] == [5.0]

    def test_mid_stream_429_uses_original_exception_headers(self):
        outcome, sleeps, _ = run([mid_stream_429({"retry-after": "7"})])
        assert (outcome, sleeps) == ("ok", [7.0])

    @pytest.mark.parametrize(
        "value",
        ["soon", "-5", "nan", "inf", "-inf", "", "Sat, 21 Nov 2026 12:00:30 GMT"],
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
        e = rate_limit_error(
            {"anthropic-ratelimit-input-tokens-reset": at(86400 * 365)}
        )
        assert run([e])[1] == [300.0]

    def test_no_header_set_can_produce_an_unsafe_sleep(self):
        nasty = [
            "-1",
            "nan",
            "inf",
            "1e999",
            "0",
            "0.0",
            "abc",
            "86400",
            at(-5),
            at(10**9),
        ]
        for ra in nasty:
            for reset in nasty:
                e = rate_limit_error(
                    {
                        "retry-after": ra,
                        "anthropic-ratelimit-tokens-reset": reset,
                        "anthropic-ratelimit-tokens-remaining": ra,
                    }
                )
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
        e = rate_limit_error(
            message='{"details": {"error_code": "enforced_spend_limit_reached"}}'
        )
        outcome, sleeps, calls = run([e])
        assert outcome is e and (sleeps, calls) == ([], 1)


class TestBudget:
    def test_wait_that_fits_is_taken(self):
        clock = FakeClock()
        budget = RetryBudget(100.0, clock)
        outcome, sleeps, _ = run(
            [rate_limit_error({"retry-after": "60"})], budget=budget, clock=clock
        )
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
        assert (
            run([rate_limit_error({"retry-after": "60"})], budget=budget, clock=clock)[
                1
            ]
            == []
        )

    def test_no_attempt_after_a_slow_call_passed_the_deadline(self):
        clock = FakeClock()
        budget = RetryBudget(100.0, clock)

        def slow_timeout():
            clock.sleep(1200)
            raise litellm.Timeout(message="t", model="m", llm_provider="p")

        with pytest.raises(litellm.Timeout):
            retry_transient_llm_call(
                slow_timeout, budget=budget, sleep=clock.sleep, jitter=lambda: 0.0
            )
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
        assert seen == [
            "test: HTTP 503 service_unavailable, retrying in 5s (attempt 1 of 5)"
        ]

    def test_message_never_contains_error_text(self):
        seen: list[str] = []
        e = litellm.ServiceUnavailableError(
            message="SECRET-BODY", llm_provider="p", model="m"
        )
        run([e], on_wait=seen.append)
        assert all("SECRET-BODY" not in m for m in seen)

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
                on_wait=abort,
                sleep=sleeps.append,
                jitter=lambda: 0.0,
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


class TestPureHelpers:
    def test_backoff_delay(self):
        assert backoff_delay(1) == 5.0
        assert backoff_delay(4) == 40.0
        assert backoff_delay(9) == 60.0
        assert backoff_delay(1, base=3.0, cap=30.0, jitter=1.0) == pytest.approx(3.6)

    def test_parse_retry_after(self):
        assert parse_retry_after(None) is None
        assert parse_retry_after({"Retry-After": "0"}) == 0.0
        assert parse_retry_after({"retry-after": "x"}) is None

    def test_response_headers_of_plain_exception(self):
        assert response_headers(Exception()) == {}


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
