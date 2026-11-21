"""Status-code error hints and step outcome rows.

A hint never contains text from the exception message: ``str(e)`` can embed a
provider's response body.
"""


class LLMOutputError(ValueError):
    """The LLM returned no usable JSON."""


STATUS_LABELS: dict[int, str] = {
    400: "invalid_request_error",
    401: "authentication_error",
    403: "permission_error",
    404: "not_found_error",
    408: "timeout",
    413: "request_too_large",
    429: "rate_limit_error",
    500: "internal_server_error",
    502: "bad_gateway",
    503: "service_unavailable",
    504: "gateway_timeout",
    529: "overloaded_error",
}


def _coerce_status(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and value.isascii() and value.isdigit():
        number = int(value)
    else:
        return None
    return number if 100 <= number <= 599 else None


def http_status(error: BaseException) -> int | None:
    """Return the HTTP status from ``status_code`` then ``status``, if valid."""
    for attr in ("status_code", "status"):
        status = _coerce_status(getattr(error, attr, None))
        if status is not None:
            return status
    return None


def error_hint(error: BaseException) -> str:
    """Short, message-free description of an error."""
    if isinstance(error, LLMOutputError):
        return "unparseable response"
    names = {cls.__name__ for cls in type(error).__mro__}
    # litellm.Timeout subclasses APIConnectionError; a timeout carries a status.
    if "APIConnectionError" in names and "APITimeoutError" not in names:
        return "connection_error"
    status = http_status(error)
    if status is not None:
        return f"HTTP {status} {STATUS_LABELS.get(status, type(error).__name__)}"
    return type(error).__name__


def step_row(
    step: str, error: BaseException | str | None = None, detail: str = ""
) -> str:
    """Format a step outcome row for the status note."""
    if error is None:
        row = f"{step}: succeeded"
    else:
        hint = error if isinstance(error, str) else error_hint(error)
        row = f"{step}: failed: {hint}"
    return f"{row} ({detail})" if detail else row


DFD_REFUSED = "refused (content_filter)"


def dfd_gap_text(dfd_error: str) -> str:
    """Run-level gap text for a DFD that was not generated.

    ``dfd_error`` is the step's failure reason; a content-filter refusal reads
    ``refused``. Shared by the run result and the analysis report.
    """
    reason = "refused" if dfd_error == DFD_REFUSED else dfd_error
    return f"DFD not generated ({reason})"
