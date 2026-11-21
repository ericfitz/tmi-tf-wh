# pyright: reportPrivateImportUsage=false
import litellm  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]
import pytest  # pyright: ignore[reportMissingImports] # ty:ignore[unresolved-import]

from tmi_tf.error_hints import (
    STATUS_LABELS,
    LLMOutputError,
    error_hint,
    http_status,
    step_row,
)


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


def test_timeout_is_not_connection_error():
    """litellm.Timeout has APIConnectionError in its MRO but must report as 408."""
    error = _llm(litellm.Timeout)
    assert "APIConnectionError" in {c.__name__ for c in type(error).__mro__}
    assert error_hint(error) != "connection_error"


def test_status_labels_has_the_twelve_entries():
    assert sorted(STATUS_LABELS) == [
        400,
        401,
        403,
        404,
        408,
        413,
        429,
        500,
        502,
        503,
        504,
        529,
    ]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (429, 429),
        ("429", 429),
        (True, None),
        (99, None),
        (600, None),
        ("4x9", None),
        (None, None),
    ],
)
def test_http_status_accepts_only_real_codes(value, expected):
    error = Exception()
    error.status_code = value  # type: ignore[attr-defined]
    assert http_status(error) == expected


def test_http_status_falls_back_to_status_attribute():
    assert http_status(_Api(503)) == 503


def test_step_row():
    assert step_row("Phase 2 (Infrastructure)") == "Phase 2 (Infrastructure): succeeded"
    assert (
        step_row("DFD diagram", detail="12 cells")
        == "DFD diagram: succeeded (12 cells)"
    )
    assert (
        step_row("Phase 3b: threat 2/28", error=_llm(litellm.RateLimitError))
        == "Phase 3b: threat 2/28: failed: HTTP 429 rate_limit_error"
    )
    assert (
        step_row("X", error="refused (content_filter)")
        == "X: failed: refused (content_filter)"
    )
    assert step_row("X", error="boom", detail="1 of 2") == "X: failed: boom (1 of 2)"
