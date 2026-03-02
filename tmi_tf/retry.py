"""Transient error retry utilities for LLM and API calls."""

import logging
import time
from typing import Callable, TypeVar

import litellm  # pyright: ignore[reportMissingImports]

logger = logging.getLogger(__name__)

T = TypeVar("T")

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


def retry_transient_llm_call(
    call: Callable[[], T],
    *,
    description: str = "LLM call",
    delay: float = DEFAULT_RETRY_DELAY,
) -> T:
    """Execute an LLM call, retrying once on transient errors.

    Args:
        call: Zero-argument callable that makes the LLM API call.
        description: Human-readable description for log messages.
        delay: Seconds to wait before retrying.

    Returns:
        The return value of the callable.

    Raises:
        The original exception if the retry also fails, or if the
        error is not transient.
    """
    try:
        return call()
    except TRANSIENT_LLM_EXCEPTIONS as e:
        error_type = type(e).__name__
        logger.warning(
            "%s failed with transient error (%s): %s. Retrying in %.0f seconds...",
            description,
            error_type,
            e,
            delay,
        )
        time.sleep(delay)
        logger.info("Retrying %s...", description)
        return call()
