"""Transient error retry utilities for LLM and API calls."""

import logging
import math
import random
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime

import litellm  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

from tmi_tf.error_hints import error_hint, http_status

logger = logging.getLogger(__name__)


# LiteLLM exception types that indicate transient errors worth retrying
TRANSIENT_LLM_EXCEPTIONS: tuple[type[BaseException], ...] = (
    litellm.ServiceUnavailableError,  # pyright: ignore[reportPrivateImportUsage]
    litellm.RateLimitError,  # pyright: ignore[reportPrivateImportUsage]
    litellm.InternalServerError,  # pyright: ignore[reportPrivateImportUsage]
    litellm.BadGatewayError,  # pyright: ignore[reportPrivateImportUsage]
    litellm.Timeout,  # pyright: ignore[reportPrivateImportUsage]
    litellm.APIConnectionError,  # pyright: ignore[reportPrivateImportUsage]
)

# TMI API HTTP status codes that indicate transient errors
TRANSIENT_API_STATUSES: frozenset[int] = frozenset({429, 500, 502, 503, 504})

# Delay between retries in seconds
DEFAULT_RETRY_DELAY: float = 3.0


MAX_ATTEMPTS: int = 5
RATE_LIMIT_MAX_ATTEMPTS: int = 8
TIMEOUT_MAX_ATTEMPTS: int = 2
BACKOFF_BASE: float = 5.0
BACKOFF_CAP: float = 60.0
JITTER_FRACTION: float = 0.2
SERVER_WAIT_MAX: float = 300.0
SPEND_CAP_MARKER = "enforced_spend_limit_reached"
RATELIMIT_DIMENSIONS: tuple[str, ...] = (
    "input-tokens",
    "output-tokens",
    "requests",
    "tokens",
)


class DeadlineReached(Exception):
    """The job deadline passed before an LLM attempt could start. Not transient:
    it is never retried."""


class RetryBudget:
    """One absolute monotonic deadline shared by all LLM calls of a job."""

    def __init__(
        self, deadline: float, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.deadline = deadline
        self.exhausted = False
        self._clock = clock

    def remaining(self) -> float:
        return self.deadline - self._clock()

    def expired(self) -> bool:
        return self.exhausted or self.remaining() <= 0


def _header_mapping(source: object) -> dict[str, str]:
    if not isinstance(source, Mapping) and not hasattr(source, "items"):
        return {}
    try:
        return {str(k).lower(): str(v) for k, v in source.items()}  # type: ignore[attr-defined]
    except Exception:
        return {}


def response_headers(error: BaseException) -> dict[str, str]:
    """Lowercase-keyed headers merged from the error and its original_exception.

    Priority (highest first): error.litellm_response_headers, error.response.headers,
    original_exception.litellm_response_headers, original_exception.response.headers.
    """
    merged: dict[str, str] = {}
    holders = [error, getattr(error, "original_exception", None)]
    sources: list[object] = []
    for holder in holders:
        if holder is None:
            continue
        sources.append(getattr(holder, "litellm_response_headers", None))
        sources.append(getattr(getattr(holder, "response", None), "headers", None))
    for source in reversed(sources):
        merged.update(_header_mapping(source))
    return merged


def _finite_float(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        number = float(value.strip())
    except ValueError:
        return None
    return number if math.isfinite(number) else None


def parse_retry_after(headers: Mapping[str, str] | None) -> float | None:
    """Seconds from a numeric `retry-after` header; None if absent or unusable."""
    if not headers:
        return None
    value = next((v for k, v in headers.items() if k.lower() == "retry-after"), None)
    number = _finite_float(value)
    if number is None or number < 0:
        return None
    return number


def _seconds_until(value: str, now: datetime) -> float | None:
    try:
        reset = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    if reset.tzinfo is None:
        return None
    seconds = (reset - now).total_seconds()
    if not math.isfinite(seconds) or seconds <= 0:
        return None
    return seconds


def parse_ratelimit_reset(headers: Mapping[str, str], now: datetime) -> float | None:
    """Seconds until the relevant anthropic-ratelimit-*-reset; None if unusable."""
    lowered = {k.lower(): v for k, v in headers.items()}
    exhausted: list[float] = []
    every: list[float] = []
    for dim in RATELIMIT_DIMENSIONS:
        reset = lowered.get(f"anthropic-ratelimit-{dim}-reset")
        if reset is None:
            continue
        seconds = _seconds_until(reset, now)
        if seconds is None:
            continue
        every.append(seconds)
        try:
            remaining = int(lowered.get(f"anthropic-ratelimit-{dim}-remaining", ""))
        except ValueError:
            continue
        if remaining <= 0:
            exhausted.append(seconds)
    if exhausted:
        return max(exhausted)
    return max(every) if every else None


def backoff_delay(
    retry_number: int,
    *,
    base: float = BACKOFF_BASE,
    cap: float = BACKOFF_CAP,
    jitter: float = 0.0,
) -> float:
    """min(base * 2^(n-1), cap) * (1 + JITTER_FRACTION * jitter)."""
    exponent = max(retry_number - 1, 0)
    return min(base * 2.0**exponent, cap) * (1 + JITTER_FRACTION * jitter)


TMI_RATE_LIMIT_MAX_ATTEMPTS: int = 4
TMI_RETRY_AFTER_MAX: float = 30.0


def tmi_retry_wait(
    headers: Mapping[str, str] | None, retry_number: int, jitter: float = 0.0
) -> float:
    """Wait before retrying a TMI API 429: a valid Retry-After (clamped), else backoff."""
    server = parse_retry_after(headers)
    if server is not None:
        return min(server, TMI_RETRY_AFTER_MAX)
    return backoff_delay(
        retry_number, base=DEFAULT_RETRY_DELAY, cap=TMI_RETRY_AFTER_MAX, jitter=jitter
    )


def _wait_for(
    error: BaseException,
    status: int | None,
    attempt: int,
    jitter: float,
    now: datetime,
) -> float:
    headers = response_headers(error)
    server = parse_retry_after(headers)
    if server is None and status == 429:
        server = parse_ratelimit_reset(headers, now)
    if server is not None:
        return min(server, SERVER_WAIT_MAX) + jitter
    return backoff_delay(attempt, jitter=jitter)


def retry_transient_llm_call[T](
    call: Callable[[], T],
    *,
    description: str = "LLM call",
    budget: RetryBudget | None = None,
    on_wait: Callable[[str], None] | None = None,
    sleep: Callable[[float], None] | None = None,
    jitter: Callable[[], float] | None = None,
    now: Callable[[], datetime] | None = None,
) -> T:
    """Execute an LLM call, retrying transient errors with server-directed waits.

    Waits honor retry-after / ratelimit-reset headers, else jittered exponential
    backoff. With a budget, a wait that would end at or after the deadline is not
    started and the last error is re-raised (budget.exhausted is set).

    Raises:
        The original exception when attempts or the budget run out, or when the
        error is not transient (or is a spend-cap 429).
    """
    sleep_fn = sleep or time.sleep
    jitter_fn = jitter or random.random
    now_fn = now or (lambda: datetime.now(UTC))
    attempt = 1
    while True:
        try:
            return call()
        except TRANSIENT_LLM_EXCEPTIONS as e:
            status = http_status(e)
            if status == 429 and SPEND_CAP_MARKER in str(e):
                raise
            limit = (
                RATE_LIMIT_MAX_ATTEMPTS
                if status == 429
                else TIMEOUT_MAX_ATTEMPTS
                if isinstance(e, litellm.Timeout)  # pyright: ignore[reportPrivateImportUsage]
                else MAX_ATTEMPTS
            )
            if attempt >= limit:
                raise
            wait = _wait_for(e, status, attempt, jitter_fn(), now_fn())
            if budget is not None and budget.remaining() <= wait:
                budget.exhausted = True
                raise
            seconds = math.ceil(wait)
            if status == 429:
                message = (
                    f"{description}: rate limited (HTTP 429), waiting {seconds}s "
                    f"(attempt {attempt} of {limit})"
                )
                headers = response_headers(e)
                remaining = ", ".join(
                    f"{d}={headers[k]}"
                    for d in RATELIMIT_DIMENSIONS
                    if (k := f"anthropic-ratelimit-{d}-remaining") in headers
                )
                logger.warning(
                    "%s failed (%s): %s; remaining: %s; waiting %.1fs",
                    description,
                    type(e).__name__,
                    str(e)[:300],
                    remaining or "n/a",
                    wait,
                )
            else:
                message = (
                    f"{description}: {error_hint(e)}, retrying in {seconds}s "
                    f"(attempt {attempt} of {limit})"
                )
                logger.warning(
                    "%s failed (%s): %s; retrying in %.1fs",
                    description,
                    type(e).__name__,
                    str(e)[:300],
                    wait,
                )
            if on_wait is not None:
                try:
                    on_wait(message)
                except Exception:
                    logger.warning("on_wait callback failed; ignoring", exc_info=True)
            sleep_fn(wait)
            logger.info("Retrying %s...", description)
            attempt += 1
