"""Tests for LLM provider implementations."""

import json
import os
from types import SimpleNamespace
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
            num_retries=0,
        )

    @patch("tmi_tf.providers.llm_base.litellm")
    @patch("tmi_tf.providers.llm_base.save_llm_response", return_value="/tmp/test")
    def test_complete_disables_provider_side_retries(self, mock_save, mock_litellm):
        """The OpenAI SDK retries twice on its own; retry.py is the only retry (#103)."""
        mock_litellm.completion.return_value = iter([])
        mock_litellm.stream_chunk_builder.return_value = _make_litellm_response("ok")
        mock_litellm.completion_cost.return_value = 0.0
        BaseLLMProvider(provider="openai", model="openai/gpt-x").complete("s", "u")
        assert mock_litellm.completion.call_args.kwargs["num_retries"] == 0

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


class _FakeStream:
    """A LiteLLM sync stream: iterable wrapper whose HTTP response hides inside."""

    def __init__(self, chunks, fail: bool = False):
        self._chunks = chunks
        self._fail = fail
        self.completion_stream = MagicMock()  # the provider iterator
        self.completion_stream.close = None  # iterators have no close()

    def __iter__(self):
        yield from self._chunks
        if self._fail:
            raise RuntimeError("stream broke")


class TestStreamClosed:
    """complete() must release the HTTP response itself (#90): left to cyclic GC,
    httpcore's close can run under its own pool lock and deadlock the thread."""

    @patch("tmi_tf.providers.llm_base.litellm")
    @patch("tmi_tf.providers.llm_base.save_llm_response", return_value="/tmp/test")
    def test_closes_stream_after_success(self, mock_save, mock_litellm):
        stream = _FakeStream(["c"])
        mock_litellm.completion.return_value = stream
        mock_litellm.stream_chunk_builder.return_value = _make_litellm_response("ok")
        mock_litellm.completion_cost.return_value = 0.0

        BaseLLMProvider(provider="anthropic", model="m").complete("s", "u")

        # Anthropic: the iterator's streaming_response is the line generator.
        stream.completion_stream.streaming_response.close.assert_called_once()
        # OpenAI responses API: its streaming_response.response is the httpx.Response.
        stream.completion_stream.streaming_response.response.close.assert_called_once()

    @patch("tmi_tf.providers.llm_base.litellm")
    def test_closes_stream_when_iteration_fails(self, mock_litellm):
        stream = _FakeStream(["c"], fail=True)
        mock_litellm.completion.return_value = stream

        with pytest.raises(RuntimeError, match="stream broke"):
            BaseLLMProvider(provider="anthropic", model="m").complete("s", "u")

        stream.completion_stream.streaming_response.close.assert_called_once()

    @patch("tmi_tf.providers.llm_base.litellm")
    @patch("tmi_tf.providers.llm_base.save_llm_response", return_value="/tmp/test")
    def test_close_errors_do_not_mask_result(self, mock_save, mock_litellm):
        stream = _FakeStream(["c"])
        stream.completion_stream.streaming_response.close.side_effect = OSError("x")
        mock_litellm.completion.return_value = stream
        mock_litellm.stream_chunk_builder.return_value = _make_litellm_response("ok")
        mock_litellm.completion_cost.return_value = 0.0

        result = BaseLLMProvider(provider="anthropic", model="m").complete("s", "u")

        assert result.text == "ok"


class TestCachePrefix:
    def _complete(self, mock_litellm, provider_name, **kw):
        mock_litellm.completion.return_value = iter([])
        mock_litellm.stream_chunk_builder.return_value = _make_litellm_response("ok")
        mock_litellm.completion_cost.return_value = 0.0
        BaseLLMProvider(provider=provider_name, model=f"{provider_name}/m").complete(
            "sys", "SUFFIX", **kw
        )
        return mock_litellm.completion.call_args.kwargs["messages"]

    @patch("tmi_tf.providers.llm_base.litellm")
    @patch("tmi_tf.providers.llm_base.save_llm_response", return_value="/tmp/test")
    def test_anthropic_prefix_is_a_cached_block(self, _save, mock_litellm):
        assert self._complete(mock_litellm, "anthropic", cache_prefix="PREFIX") == [
            {"role": "system", "content": "sys"},
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": "PREFIX",
                        "cache_control": {"type": "ephemeral"},
                    },
                    {"type": "text", "text": "SUFFIX"},
                ],
            },
        ]

    @pytest.mark.parametrize("name", ["openai", "xai", "gemini", "oci"])
    @patch("tmi_tf.providers.llm_base.litellm")
    @patch("tmi_tf.providers.llm_base.save_llm_response", return_value="/tmp/test")
    def test_other_providers_get_one_plain_string(self, _save, mock_litellm, name):
        messages = self._complete(mock_litellm, name, cache_prefix="PREFIX")
        assert messages[1] == {"role": "user", "content": "PREFIXSUFFIX"}
        assert "cache_control" not in json.dumps(messages)

    @patch("tmi_tf.providers.llm_base.litellm")
    @patch("tmi_tf.providers.llm_base.save_llm_response", return_value="/tmp/test")
    def test_without_a_prefix_the_request_is_unchanged(self, _save, mock_litellm):
        assert self._complete(mock_litellm, "anthropic")[1] == {
            "role": "user",
            "content": "SUFFIX",
        }


class TestCacheTokens:
    def _complete_with_usage(self, usage):
        with (
            patch("tmi_tf.providers.llm_base.litellm") as mock_litellm,
            patch("tmi_tf.providers.llm_base.save_llm_response", return_value="/tmp/t"),
        ):
            mock_litellm.completion.return_value = iter([])
            response = _make_litellm_response("ok")
            response.usage = usage
            mock_litellm.stream_chunk_builder.return_value = response
            mock_litellm.completion_cost.return_value = 0.0
            return BaseLLMProvider(provider="anthropic", model="anthropic/m").complete(
                "s", "u"
            )

    def test_anthropic_cache_fields(self):
        result = self._complete_with_usage(
            SimpleNamespace(
                prompt_tokens=75400,
                completion_tokens=500,
                cache_read_input_tokens=75000,
                cache_creation_input_tokens=0,
                prompt_tokens_details=None,
            )
        )
        assert result.input_tokens == 75400
        assert result.cache_read_tokens == 75000
        assert result.cache_creation_tokens == 0

    def test_cache_creation_field(self):
        result = self._complete_with_usage(
            SimpleNamespace(
                prompt_tokens=75400,
                completion_tokens=500,
                cache_read_input_tokens=0,
                cache_creation_input_tokens=75000,
                prompt_tokens_details=None,
            )
        )
        assert result.cache_creation_tokens == 75000
        assert result.cache_read_tokens == 0

    def test_openai_cached_tokens_fallback(self):
        result = self._complete_with_usage(
            SimpleNamespace(
                prompt_tokens=2000,
                completion_tokens=10,
                prompt_tokens_details=SimpleNamespace(cached_tokens=1024),
            )
        )
        assert result.cache_read_tokens == 1024
        assert result.cache_creation_tokens == 0

    def test_mock_usage_yields_zero(self):
        usage = MagicMock()
        usage.prompt_tokens = 10
        usage.completion_tokens = 5
        result = self._complete_with_usage(usage)
        assert (result.cache_read_tokens, result.cache_creation_tokens) == (0, 0)

    @pytest.mark.parametrize("bad", [None, -1, True, 1.5, "7"])
    def test_bad_usage_values_yield_zero(self, bad):
        result = self._complete_with_usage(
            SimpleNamespace(
                prompt_tokens=10,
                completion_tokens=5,
                cache_read_input_tokens=bad,
                cache_creation_input_tokens=bad,
                prompt_tokens_details=SimpleNamespace(cached_tokens=bad),
            )
        )
        assert (result.cache_read_tokens, result.cache_creation_tokens) == (0, 0)
