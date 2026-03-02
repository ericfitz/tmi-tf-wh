# pyright: reportPrivateImportUsage=false
"""Tests for transient error retry logic."""

from unittest.mock import MagicMock, patch

import pytest  # pyright: ignore[reportMissingImports] # ty:ignore[unresolved-import]

import litellm  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

from tmi_tf.retry import (
    DEFAULT_RETRY_DELAY,
    TRANSIENT_API_STATUSES,
    TRANSIENT_LLM_EXCEPTIONS,
    retry_transient_llm_call,
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
            message="503", llm_provider="gemini", model="gemini/gemini-2.0-flash"
        )
        call = MagicMock(side_effect=[exc, "result"])
        with patch("tmi_tf.retry.time.sleep"):
            result = retry_transient_llm_call(call, description="test")
        assert result == "result"
        assert call.call_count == 2

    def test_retries_on_rate_limit(self):
        exc = litellm.RateLimitError(
            message="429", llm_provider="anthropic", model="anthropic/claude-opus-4-5"
        )
        call = MagicMock(side_effect=[exc, "result"])
        with patch("tmi_tf.retry.time.sleep"):
            result = retry_transient_llm_call(call, description="test")
        assert result == "result"
        assert call.call_count == 2

    def test_retries_on_internal_server_error(self):
        exc = litellm.InternalServerError(
            message="500", llm_provider="openai", model="openai/gpt-4"
        )
        call = MagicMock(side_effect=[exc, "result"])
        with patch("tmi_tf.retry.time.sleep"):
            result = retry_transient_llm_call(call, description="test")
        assert result == "result"
        assert call.call_count == 2

    def test_retries_on_bad_gateway(self):
        exc = litellm.BadGatewayError(
            message="502", llm_provider="openai", model="openai/gpt-4"
        )
        call = MagicMock(side_effect=[exc, "result"])
        with patch("tmi_tf.retry.time.sleep"):
            result = retry_transient_llm_call(call, description="test")
        assert result == "result"
        assert call.call_count == 2

    def test_retries_on_timeout(self):
        exc = litellm.Timeout(
            message="timeout", model="openai/gpt-4", llm_provider="openai"
        )
        call = MagicMock(side_effect=[exc, "result"])
        with patch("tmi_tf.retry.time.sleep"):
            result = retry_transient_llm_call(call, description="test")
        assert result == "result"
        assert call.call_count == 2

    def test_retries_on_api_connection_error(self):
        exc = litellm.APIConnectionError(
            message="connection failed", llm_provider="openai", model="openai/gpt-4"
        )
        call = MagicMock(side_effect=[exc, "result"])
        with patch("tmi_tf.retry.time.sleep"):
            result = retry_transient_llm_call(call, description="test")
        assert result == "result"
        assert call.call_count == 2

    def test_raises_after_retry_exhausted(self):
        exc = litellm.ServiceUnavailableError(
            message="503", llm_provider="gemini", model="gemini/gemini-2.0-flash"
        )
        call = MagicMock(side_effect=[exc, exc])
        with patch("tmi_tf.retry.time.sleep"):
            with pytest.raises(litellm.ServiceUnavailableError):
                retry_transient_llm_call(call, description="test")
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

    def test_delay_is_applied(self):
        exc = litellm.InternalServerError(
            message="500", llm_provider="openai", model="gpt-4"
        )
        call = MagicMock(side_effect=[exc, "ok"])
        with patch("tmi_tf.retry.time.sleep") as mock_sleep:
            retry_transient_llm_call(call, description="test", delay=5.0)
        mock_sleep.assert_called_once_with(5.0)

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
