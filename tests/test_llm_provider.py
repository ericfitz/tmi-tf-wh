"""Tests for LLM provider implementations."""

import os
from unittest.mock import MagicMock, patch

import pytest  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

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
        mock_litellm.completion.return_value = iter([])
        mock_litellm.stream_chunk_builder.return_value = _make_litellm_response(
            "hello world"
        )
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
        mock_litellm.completion.return_value = iter([])
        mock_litellm.stream_chunk_builder.return_value = _make_litellm_response("ok")
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
            stream=True,
            stream_options={"include_usage": True},
            oci_region="us-ashburn-1",
        )

    @patch("tmi_tf.providers.llm_base.litellm")
    @patch("tmi_tf.providers.llm_base.save_llm_response", return_value="/tmp/test")
    def test_complete_returns_none_text_on_empty_content(self, mock_save, mock_litellm):
        mock_litellm.completion.return_value = iter([])
        mock_litellm.stream_chunk_builder.return_value = _make_litellm_response("")
        mock_litellm.completion_cost.return_value = 0.0

        provider = BaseLLMProvider(provider="anthropic", model="anthropic/test")
        result = provider.complete("sys", "usr")

        assert result.text is None

    @patch("tmi_tf.providers.llm_base.litellm")
    @patch("tmi_tf.providers.llm_base.save_llm_response", return_value="/tmp/test")
    def test_complete_handles_cost_error(self, mock_save, mock_litellm):
        mock_litellm.completion.return_value = iter([])
        mock_litellm.stream_chunk_builder.return_value = _make_litellm_response("ok")
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
        mock_litellm.completion.return_value = iter([])
        mock_litellm.stream_chunk_builder.return_value = _make_litellm_response(
            "truncated", finish_reason="length"
        )
        mock_litellm.completion_cost.return_value = 0.0

        provider = BaseLLMProvider(provider="anthropic", model="anthropic/test")
        result = provider.complete("sys", "usr")

        assert result.finish_reason == "length"
        assert result.text == "truncated"


from tmi_tf.llm_profiles import LLMProfile, ProfileError
from tmi_tf.providers import get_llm_provider
from tmi_tf.providers.api_key import ApiKeyLLMProvider

CYBER = LLMProfile(
    "gpt56cyber", "openai", "gpt-5.6-cyber", "api_key", "T_CYBER_KEY", "responses"
)
PROXIED = LLMProfile(
    "px",
    "anthropic",
    "claude-opus-4-8",
    "api_key",
    "T_PX_KEY",
    base_url="https://proxy/v1",
)


class TestApiKeyLLMProvider:
    @patch.dict(os.environ, {"T_CYBER_KEY": "sk-c"})
    def test_model_and_key_from_profile(self):
        before = dict(os.environ)
        p = ApiKeyLLMProvider(CYBER)
        assert p.model == "openai/responses/gpt-5.6-cyber"
        assert p.provider == "openai"
        assert p.profile == "gpt56cyber"
        assert p._extra_kwargs == {"api_key": "sk-c"}
        assert dict(os.environ) == before

    @patch.dict(os.environ, {"T_PX_KEY": "sk-p"})
    def test_base_url_becomes_api_base(self):
        assert ApiKeyLLMProvider(PROXIED)._extra_kwargs == {
            "api_key": "sk-p",
            "api_base": "https://proxy/v1",
        }

    def test_missing_key_raises(self):
        os.environ.pop("T_CYBER_KEY", None)
        with pytest.raises(ProfileError, match="T_CYBER_KEY"):
            ApiKeyLLMProvider(CYBER)

    @patch.dict(os.environ, {"T_PX_KEY": "sk-p"})
    def test_complete_passes_key_to_litellm(self):
        with patch("tmi_tf.providers.llm_base.litellm") as ll:
            ll.completion.return_value = iter([])
            ll.stream_chunk_builder.return_value = _make_litellm_response("ok")
            ApiKeyLLMProvider(PROXIED).complete("s", "u")
            kw = ll.completion.call_args.kwargs
        assert kw["api_key"] == "sk-p"
        assert kw["api_base"] == "https://proxy/v1"
        assert kw["model"] == "anthropic/claude-opus-4-8"


class TestGetLLMProvider:
    @patch.dict(os.environ, {"T_CYBER_KEY": "sk-c"})
    def test_api_key_profile(self):
        assert isinstance(get_llm_provider(CYBER), ApiKeyLLMProvider)

    @patch.dict(os.environ, {"OCI_COMPARTMENT_ID": "ocid1.compartment.oc1..test"})
    def test_oci_profile(self):
        with (
            patch("pathlib.Path.exists", return_value=False),
            patch(
                "oci.auth.signers.get_resource_principals_signer",
                return_value=MagicMock(region="r"),
            ),
        ):
            p = get_llm_provider(LLMProfile("g", "oci", "xai.grok-4", "oci"))
        assert p.model == "oci/xai.grok-4"
        assert p.profile == "g"
