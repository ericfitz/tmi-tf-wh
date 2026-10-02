"""Tests for tmi_tf.dfd_llm_generator refusal and empty-response handling (#89)."""

import json
from unittest.mock import MagicMock

import pytest

from tmi_tf.dfd_llm_generator import DFDLLMGenerator
from tmi_tf.llm_analyzer import LLMRefusalError
from tmi_tf.providers import LLMResponse

VALID = json.dumps(
    {
        "components": [{"id": "c1", "name": "web", "type": "compute"}],
        "flows": [],
    }
)


def _response(text, finish_reason="stop", tokens_in=100, tokens_out=50, cost=0.01):
    return LLMResponse(
        text=text,
        input_tokens=tokens_in,
        output_tokens=tokens_out,
        cost=cost,
        finish_reason=finish_reason,
    )


def _generator(*responses) -> tuple[DFDLLMGenerator, MagicMock]:
    provider = MagicMock()
    provider.model = "anthropic/test-model"
    provider.provider = "anthropic"
    provider.complete.side_effect = list(responses)
    return DFDLLMGenerator(provider), provider


class TestDFDRefusal:
    def test_empty_content_filter_raises_refusal(self):
        gen, provider = _generator(_response(None, "content_filter"))
        with pytest.raises(LLMRefusalError):
            gen.generate_structured_components({}, {})
        assert provider.complete.call_count == 1

    def test_partial_content_filter_is_a_refusal_not_a_diagram(self):
        gen, _ = _generator(_response(VALID, "content_filter"))
        with pytest.raises(LLMRefusalError):
            gen.generate_structured_components({}, {})

    def test_refusal_records_tokens_and_cost(self):
        gen, _ = _generator(
            _response(None, "content_filter", tokens_in=700, tokens_out=3, cost=0.5)
        )
        with pytest.raises(LLMRefusalError):
            gen.generate_structured_components({}, {})
        assert (gen.input_tokens, gen.output_tokens, gen.total_cost) == (700, 3, 0.5)


class TestDFDEmptyResponse:
    def test_empty_stop_response_is_retried_once(self):
        gen, provider = _generator(
            _response(None, tokens_in=10, tokens_out=0, cost=0.1),
            _response(VALID, tokens_in=20, tokens_out=5, cost=0.2),
        )
        data = gen.generate_structured_components({}, {})
        assert provider.complete.call_count == 2
        assert data is not None and data["components"][0]["name"] == "web"
        assert (gen.input_tokens, gen.output_tokens) == (30, 5)
        assert gen.total_cost == pytest.approx(0.3)
