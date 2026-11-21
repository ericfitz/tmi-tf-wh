# pyright: reportPrivateImportUsage=false
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
        error.litellm_response_headers = httpx.Headers(headers)  # type: ignore[attr-defined]  # pyright: ignore[reportAttributeAccessIssue]
    return error


def mid_stream_429(headers):
    """What gemini raises under stream=True: a ServiceUnavailableError subclass
    with status_code 429 and the headers on original_exception."""
    return MidStreamFallbackError(
        message="mid",
        model="gemini/x",
        llm_provider="gemini",
        original_exception=rate_limit_error(headers),
    )


class FakeClock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.t += seconds
