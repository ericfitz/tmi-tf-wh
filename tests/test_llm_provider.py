"""Tests for LLM provider implementations."""

import os
from unittest.mock import MagicMock, patch

import pytest

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
        provider = BaseLLMProvider(
            provider="anthropic", model="anthropic/claude-opus-4-6"
        )
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


from tmi_tf.providers.api_key import ApiKeyLLMProvider, DEFAULT_MODELS  # noqa: E402


class TestApiKeyLLMProvider:
    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test-key"}, clear=False)
    def test_anthropic_provider_reads_env(self):
        provider = ApiKeyLLMProvider(provider="anthropic", model=None)
        assert provider.model == DEFAULT_MODELS["anthropic"]
        assert os.environ["ANTHROPIC_API_KEY"] == "sk-test-key"

    @patch.dict(os.environ, {"OPENAI_API_KEY": "sk-openai-key"}, clear=False)
    def test_openai_provider_reads_env(self):
        provider = ApiKeyLLMProvider(provider="openai", model="gpt-4o")
        assert provider.model == "openai/gpt-4o"

    @patch.dict(os.environ, {"XAI_API_KEY": "xai-key"}, clear=False)
    def test_xai_provider_reads_env(self):
        provider = ApiKeyLLMProvider(provider="xai", model=None)
        assert provider.model == DEFAULT_MODELS["xai"]

    @patch.dict(os.environ, {"GEMINI_API_KEY": "gem-key"}, clear=False)
    def test_gemini_provider_reads_env(self):
        provider = ApiKeyLLMProvider(provider="gemini", model=None)
        assert provider.model == DEFAULT_MODELS["gemini"]

    @patch.dict(os.environ, {}, clear=False)
    def test_raises_on_missing_api_key(self):
        os.environ.pop("ANTHROPIC_API_KEY", None)
        with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
            ApiKeyLLMProvider(provider="anthropic", model=None)

    @patch.dict(
        os.environ,
        {"ANTHROPIC_API_KEY": "placeholder_anthropic_api_key"},
        clear=False,
    )
    def test_raises_on_placeholder_api_key(self):
        with pytest.raises(ValueError, match="placeholder"):
            ApiKeyLLMProvider(provider="anthropic", model=None)

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-real-key"}, clear=False)
    def test_model_with_prefix_kept_as_is(self):
        provider = ApiKeyLLMProvider(provider="anthropic", model="anthropic/claude-opus-4-6")
        assert provider.model == "anthropic/claude-opus-4-6"

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-real-key"}, clear=False)
    def test_model_without_prefix_gets_prefix(self):
        provider = ApiKeyLLMProvider(provider="anthropic", model="claude-opus-4-6")
        assert provider.model == "anthropic/claude-opus-4-6"

    def test_raises_on_unknown_provider(self):
        with pytest.raises(ValueError, match="Unknown API key provider"):
            ApiKeyLLMProvider(provider="unknown", model=None)
