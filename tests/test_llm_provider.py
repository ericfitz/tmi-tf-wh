"""Tests for LLM provider implementations."""

from unittest.mock import MagicMock, patch

from tmi_tf.providers import LLMResponse
from tmi_tf.providers.llm_base import BaseLLMProvider


def _make_litellm_response(
    content: str,
    tokens_in: int = 100,
    tokens_out: int = 50,
    finish_reason: str = "stop",
):
    """Create a mock LiteLLM ModelResponse."""
    message = MagicMock()
    message.content = content
    choice = MagicMock()
    choice.message = message
    choice.finish_reason = finish_reason
    usage = MagicMock()
    usage.prompt_tokens = tokens_in
    usage.completion_tokens = tokens_out
    response = MagicMock()
    response.choices = [choice]
    response.usage = usage
    return response


class TestBaseLLMProvider:
    @patch("tmi_tf.providers.llm_base.litellm")
    @patch("tmi_tf.providers.llm_base.save_llm_response", return_value="/tmp/test")
    def test_complete_returns_llm_response(self, mock_save, mock_litellm):
        mock_litellm.completion.return_value = _make_litellm_response("hello world")
        mock_litellm.completion_cost.return_value = 0.01

        provider = BaseLLMProvider(provider="anthropic", model="anthropic/test-model")
        result = provider.complete("system", "user")

        assert isinstance(result, LLMResponse)
        assert result.text == "hello world"
        assert result.input_tokens == 100
        assert result.output_tokens == 50
        assert result.cost == 0.01
        assert result.finish_reason == "stop"

    @patch("tmi_tf.providers.llm_base.litellm")
    @patch("tmi_tf.providers.llm_base.save_llm_response", return_value="/tmp/test")
    def test_complete_passes_extra_kwargs(self, mock_save, mock_litellm):
        mock_litellm.completion.return_value = _make_litellm_response("ok")
        mock_litellm.completion_cost.return_value = 0.0

        provider = BaseLLMProvider(provider="oci", model="oci/test-model")
        provider._extra_kwargs = {"oci_region": "us-ashburn-1"}
        provider.complete("sys", "usr", max_tokens=4000, timeout=60.0)

        mock_litellm.completion.assert_called_once_with(
            model="oci/test-model",
            messages=[
                {"role": "system", "content": "sys"},
                {"role": "user", "content": "usr"},
            ],
            max_tokens=4000,
            timeout=60.0,
            oci_region="us-ashburn-1",
        )

    @patch("tmi_tf.providers.llm_base.litellm")
    @patch("tmi_tf.providers.llm_base.save_llm_response", return_value="/tmp/test")
    def test_complete_returns_none_text_on_empty_content(self, mock_save, mock_litellm):
        mock_litellm.completion.return_value = _make_litellm_response("")
        mock_litellm.completion_cost.return_value = 0.0

        provider = BaseLLMProvider(provider="anthropic", model="anthropic/test")
        result = provider.complete("sys", "usr")

        assert result.text is None

    @patch("tmi_tf.providers.llm_base.litellm")
    @patch("tmi_tf.providers.llm_base.save_llm_response", return_value="/tmp/test")
    def test_complete_handles_cost_error(self, mock_save, mock_litellm):
        mock_litellm.completion.return_value = _make_litellm_response("ok")
        mock_litellm.completion_cost.side_effect = Exception("no cost data")

        provider = BaseLLMProvider(provider="anthropic", model="anthropic/test")
        result = provider.complete("sys", "usr")

        assert result.cost == 0.0
        assert result.text == "ok"

    def test_model_property(self):
        provider = BaseLLMProvider(provider="anthropic", model="anthropic/claude-opus-4-6")
        assert provider.model == "anthropic/claude-opus-4-6"

    @patch("tmi_tf.providers.llm_base.litellm")
    @patch("tmi_tf.providers.llm_base.save_llm_response", return_value="/tmp/test")
    def test_complete_warns_on_truncation(self, mock_save, mock_litellm):
        mock_litellm.completion.return_value = _make_litellm_response(
            "truncated", finish_reason="length"
        )
        mock_litellm.completion_cost.return_value = 0.0

        provider = BaseLLMProvider(provider="anthropic", model="anthropic/test")
        result = provider.complete("sys", "usr")

        assert result.finish_reason == "length"
        assert result.text == "truncated"
