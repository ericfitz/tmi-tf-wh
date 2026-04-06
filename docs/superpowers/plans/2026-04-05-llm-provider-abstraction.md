# LLM Provider Abstraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Abstract LLM provider configuration behind an `LLMProvider` protocol, eliminating duplicated model/key/kwargs logic from three consumer classes and moving provider-specific concerns out of `config.py`.

**Architecture:** Define an `LLMProvider` protocol with a `complete()` method wrapping `litellm.completion()`. Two concrete implementations — `ApiKeyLLMProvider` (anthropic/openai/xai/gemini) and `OciLLMProvider` — share a `BaseLLMProvider` base class. A factory function creates the right provider from config. A shared `json_extract` module replaces duplicated JSON extraction logic.

**Tech Stack:** Python 3.12, LiteLLM, pytest, pyright, ruff

---

## File Structure

### New files
| File | Responsibility |
|------|---------------|
| `tmi_tf/providers/llm_base.py` | `BaseLLMProvider` — shared `complete()` logic wrapping `litellm.completion()` |
| `tmi_tf/providers/api_key.py` | `ApiKeyLLMProvider` — handles anthropic, openai, xai, gemini |
| `tmi_tf/json_extract.py` | `extract_json_object()`, `extract_json_array()` — shared JSON extraction |
| `tests/test_llm_provider.py` | Tests for both providers and factory |
| `tests/test_json_extract.py` | Tests for JSON extraction utility |

### Modified files
| File | Changes |
|------|---------|
| `tmi_tf/providers/__init__.py` | Add `LLMResponse` dataclass, `LLMProvider` protocol, `get_llm_provider()` factory |
| `tmi_tf/providers/oci.py` | Add `OciLLMProvider` class |
| `tmi_tf/config.py` | Remove LLM-specific logic (validation, kwargs, model helpers, API key fields) |
| `tmi_tf/llm_analyzer.py` | Take `LLMProvider` instead of config, remove duplicated logic, use `json_extract` |
| `tmi_tf/threat_processor.py` | Take `LLMProvider` instead of config, remove duplicated logic |
| `tmi_tf/dfd_llm_generator.py` | Take `LLMProvider` instead of config, remove duplicated logic |
| `tmi_tf/analyzer.py` | Create provider via factory, pass to consumers |
| `tests/test_config.py` | Remove tests for deleted config methods |
| `tests/test_llm_analyzer.py` | Mock `LLMProvider` instead of litellm + config |

---

### Task 1: JSON Extraction Utility

**Files:**
- Create: `tmi_tf/json_extract.py`
- Create: `tests/test_json_extract.py`

- [ ] **Step 1: Write failing tests for `extract_json_object`**

```python
# tests/test_json_extract.py
"""Tests for JSON extraction utility."""

import pytest

from tmi_tf.json_extract import extract_json_object, extract_json_array


class TestExtractJsonObject:
    def test_parses_plain_json(self):
        text = '{"key": "value", "count": 42}'
        result = extract_json_object(text)
        assert result == {"key": "value", "count": 42}

    def test_extracts_from_code_block(self):
        text = 'Here is the result:\n```json\n{"key": "value"}\n```\nDone.'
        result = extract_json_object(text)
        assert result == {"key": "value"}

    def test_extracts_from_code_block_without_json_tag(self):
        text = 'Result:\n```\n{"key": "value"}\n```'
        result = extract_json_object(text)
        assert result == {"key": "value"}

    def test_extracts_embedded_json_object(self):
        text = 'The analysis found: {"components": [1, 2]} in the data.'
        result = extract_json_object(text)
        assert result == {"components": [1, 2]}

    def test_returns_none_for_no_json(self):
        result = extract_json_object("no json here")
        assert result is None

    def test_returns_none_for_json_array(self):
        result = extract_json_object('[{"key": "value"}]')
        assert result is None

    def test_returns_none_for_invalid_json(self):
        result = extract_json_object('{"key": broken}')
        assert result is None


class TestExtractJsonArray:
    def test_parses_plain_json_array(self):
        text = '[{"name": "threat1"}, {"name": "threat2"}]'
        result = extract_json_array(text)
        assert result == [{"name": "threat1"}, {"name": "threat2"}]

    def test_extracts_from_code_block(self):
        text = 'Threats:\n```json\n[{"name": "t1"}]\n```'
        result = extract_json_array(text)
        assert result == [{"name": "t1"}]

    def test_extracts_embedded_json_array(self):
        text = 'Found these: [{"id": 1}] in the response.'
        result = extract_json_array(text)
        assert result == [{"id": 1}]

    def test_returns_none_for_no_json(self):
        result = extract_json_array("no json here")
        assert result is None

    def test_returns_none_for_json_object(self):
        result = extract_json_array('{"key": "value"}')
        assert result is None

    def test_returns_empty_list(self):
        result = extract_json_array("[]")
        assert result == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_json_extract.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'tmi_tf.json_extract'`

- [ ] **Step 3: Implement `json_extract.py`**

```python
# tmi_tf/json_extract.py
"""Shared JSON extraction utilities for LLM response parsing."""

import json
import re
from typing import Any


def extract_json_object(text: str) -> dict[str, Any] | None:
    """Extract a JSON object from LLM response text.

    Tries three strategies in order:
    1. Direct json.loads()
    2. Extract from markdown code blocks
    3. Regex match for {...} in text
    """
    # Try parsing directly
    try:
        result = json.loads(text)
        if isinstance(result, dict):
            return result
    except json.JSONDecodeError:
        pass

    # Try extracting from code block
    code_block_pattern = r"```(?:json)?\s*\n(.*?)\n```"
    matches = re.findall(code_block_pattern, text, re.DOTALL)
    for match in matches:
        try:
            result = json.loads(match)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            continue

    # Try finding JSON object in text
    json_pattern = r"\{[\s\S]*\}"
    matches = re.findall(json_pattern, text)
    for match in matches:
        try:
            result = json.loads(match)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            continue

    return None


def extract_json_array(text: str) -> list[dict[str, Any]] | None:
    """Extract a JSON array from LLM response text.

    Tries three strategies in order:
    1. Direct json.loads()
    2. Extract from markdown code blocks
    3. Regex match for [...] in text
    """
    # Try parsing directly
    try:
        result = json.loads(text)
        if isinstance(result, list):
            return result
    except json.JSONDecodeError:
        pass

    # Try extracting from code block
    code_block_pattern = r"```(?:json)?\s*\n(.*?)\n```"
    matches = re.findall(code_block_pattern, text, re.DOTALL)
    for match in matches:
        try:
            result = json.loads(match)
            if isinstance(result, list):
                return result
        except json.JSONDecodeError:
            continue

    # Try finding JSON array in text
    json_match = re.search(r"\[[\s\S]*\]", text)
    if json_match:
        try:
            result = json.loads(json_match.group(0))
            if isinstance(result, list):
                return result
        except json.JSONDecodeError:
            pass

    return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_json_extract.py -v`
Expected: All 13 tests PASS

- [ ] **Step 5: Lint**

Run: `uv run ruff check tmi_tf/json_extract.py tests/test_json_extract.py`
Expected: No errors

- [ ] **Step 6: Commit**

```bash
git add tmi_tf/json_extract.py tests/test_json_extract.py
git commit -m "feat(#9): add shared JSON extraction utility"
```

---

### Task 2: LLMResponse Dataclass and LLMProvider Protocol

**Files:**
- Modify: `tmi_tf/providers/__init__.py`
- Modify: `tests/test_providers.py`

- [ ] **Step 1: Write failing test for protocol and dataclass**

Add to the end of `tests/test_providers.py`:

```python
from tmi_tf.providers import LLMResponse, LLMProvider


class TestLLMResponse:
    def test_dataclass_fields(self):
        resp = LLMResponse(
            text="hello",
            input_tokens=100,
            output_tokens=50,
            cost=0.01,
            finish_reason="stop",
        )
        assert resp.text == "hello"
        assert resp.input_tokens == 100
        assert resp.output_tokens == 50
        assert resp.cost == 0.01
        assert resp.finish_reason == "stop"

    def test_none_text(self):
        resp = LLMResponse(
            text=None,
            input_tokens=0,
            output_tokens=0,
            cost=0.0,
            finish_reason="stop",
        )
        assert resp.text is None


class TestLLMProviderProtocol:
    def test_protocol_has_model_and_complete(self):
        assert hasattr(LLMProvider, "model")
        assert hasattr(LLMProvider, "complete")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_providers.py::TestLLMResponse -v`
Expected: FAIL — `ImportError: cannot import name 'LLMResponse' from 'tmi_tf.providers'`

- [ ] **Step 3: Add `LLMResponse` and `LLMProvider` to `providers/__init__.py`**

Add after the existing `QueueProvider` protocol (after line 39):

```python
@dataclass
class LLMResponse:
    """Response from an LLM completion call."""

    text: str | None
    input_tokens: int
    output_tokens: int
    cost: float
    finish_reason: str


class LLMProvider(Protocol):
    """Protocol for LLM provider implementations."""

    @property
    def model(self) -> str:
        """Fully-qualified model name with LiteLLM prefix."""
        ...

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 16000,
        timeout: float = 300.0,
    ) -> LLMResponse:
        """Make a single LLM completion call."""
        ...
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_providers.py::TestLLMResponse tests/test_providers.py::TestLLMProviderProtocol -v`
Expected: All 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add tmi_tf/providers/__init__.py tests/test_providers.py
git commit -m "feat(#9): add LLMResponse dataclass and LLMProvider protocol"
```

---

### Task 3: BaseLLMProvider

**Files:**
- Create: `tmi_tf/providers/llm_base.py`
- Create: `tests/test_llm_provider.py`

- [ ] **Step 1: Write failing tests for `BaseLLMProvider.complete()`**

```python
# tests/test_llm_provider.py
"""Tests for LLM provider implementations."""

import json
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_llm_provider.py::TestBaseLLMProvider -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'tmi_tf.providers.llm_base'`

- [ ] **Step 3: Implement `BaseLLMProvider`**

```python
# tmi_tf/providers/llm_base.py
"""Base LLM provider with shared completion logic."""

import logging

import litellm  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

from tmi_tf.config import save_llm_response
from tmi_tf.providers import LLMResponse

logger = logging.getLogger(__name__)

# Suppress LiteLLM's verbose logging
litellm.suppress_debug_info = True  # type: ignore[assignment]
litellm.drop_params = False  # type: ignore[assignment]


class BaseLLMProvider:
    """Base class for LLM providers. Handles the litellm.completion() call."""

    def __init__(self, provider: str, model: str) -> None:
        self._provider = provider
        self._model = model
        self._extra_kwargs: dict = {}

    @property
    def model(self) -> str:
        return self._model

    @property
    def provider(self) -> str:
        return self._provider

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 16000,
        timeout: float = 300.0,
    ) -> LLMResponse:
        """Make a single LLM completion call via LiteLLM."""
        prompt_chars = len(system_prompt) + len(user_prompt)
        estimated_tokens = prompt_chars // 4
        logger.info(
            "Calling %s (%s), prompt ~%d chars (~%d tokens est.)",
            self._provider,
            self._model,
            prompt_chars,
            estimated_tokens,
        )

        response = litellm.completion(
            model=self._model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=max_tokens,
            timeout=timeout,
            **self._extra_kwargs,
        )

        # Extract token usage
        usage = getattr(response, "usage", None)
        tokens_in = usage.prompt_tokens if usage else 0
        tokens_out = usage.completion_tokens if usage else 0

        # Extract finish reason
        choices = response.choices  # type: ignore[union-attr]
        finish_reason = (
            getattr(choices[0], "finish_reason", "unknown")
            if choices
            else "no_choices"
        )

        # Calculate cost
        try:
            cost = litellm.completion_cost(completion_response=response)
        except Exception:
            cost = 0.0

        logger.info(
            "%s (%s): %d input, %d output tokens, finish_reason=%s, $%.4f",
            self._provider,
            self._model,
            tokens_in,
            tokens_out,
            finish_reason,
            cost,
        )

        if finish_reason == "length":
            logger.warning(
                "Response truncated (finish_reason=length). "
                "max_tokens=%d may be insufficient.",
                max_tokens,
            )

        # Extract content
        content = response.choices[0].message.content  # type: ignore[union-attr]
        if not content:
            logger.warning(
                "Empty response from LLM. finish_reason=%s, tokens_out=%d, model=%s",
                finish_reason,
                tokens_out,
                self._model,
            )
            return LLMResponse(
                text=None,
                input_tokens=tokens_in,
                output_tokens=tokens_out,
                cost=cost,
                finish_reason=finish_reason,
            )

        # Save response for debugging
        response_file = save_llm_response(content, self._provider)
        logger.info("Response saved to %s", response_file)

        return LLMResponse(
            text=content.strip(),
            input_tokens=tokens_in,
            output_tokens=tokens_out,
            cost=cost,
            finish_reason=finish_reason,
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_llm_provider.py::TestBaseLLMProvider -v`
Expected: All 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add tmi_tf/providers/llm_base.py tests/test_llm_provider.py
git commit -m "feat(#9): add BaseLLMProvider with shared completion logic"
```

---

### Task 4: ApiKeyLLMProvider

**Files:**
- Create: `tmi_tf/providers/api_key.py`
- Modify: `tests/test_llm_provider.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/test_llm_provider.py`:

```python
import os
from unittest.mock import patch

from tmi_tf.providers.api_key import ApiKeyLLMProvider, API_KEY_PROVIDERS, DEFAULT_MODELS


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
        # Ensure the key is not set
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_llm_provider.py::TestApiKeyLLMProvider -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'tmi_tf.providers.api_key'`

- [ ] **Step 3: Implement `ApiKeyLLMProvider`**

```python
# tmi_tf/providers/api_key.py
"""API-key-based LLM provider for anthropic, openai, xai, gemini."""

import logging
import os

from tmi_tf.providers.llm_base import BaseLLMProvider

logger = logging.getLogger(__name__)

# Env var name and model prefix per provider
API_KEY_PROVIDERS: dict[str, tuple[str, str]] = {
    "anthropic": ("ANTHROPIC_API_KEY", "anthropic/"),
    "openai": ("OPENAI_API_KEY", "openai/"),
    "xai": ("XAI_API_KEY", "xai/"),
    "gemini": ("GEMINI_API_KEY", "gemini/"),
}

DEFAULT_MODELS: dict[str, str] = {
    "anthropic": "anthropic/claude-opus-4-6",
    "openai": "openai/gpt-5.4",
    "xai": "xai/grok-4-1-fast-reasoning",
    "gemini": "gemini/gemini-3.1-pro-preview",
}


class ApiKeyLLMProvider(BaseLLMProvider):
    """LLM provider for API-key-based services (Anthropic, OpenAI, xAI, Gemini)."""

    def __init__(self, provider: str, model: str | None) -> None:
        if provider not in API_KEY_PROVIDERS:
            raise ValueError(
                f"Unknown API key provider: {provider!r}. "
                f"Must be one of: {', '.join(API_KEY_PROVIDERS)}"
            )

        env_var, prefix = API_KEY_PROVIDERS[provider]

        # Read and validate API key
        api_key = os.environ.get(env_var)
        if not api_key or "placeholder" in (api_key or ""):
            raise ValueError(
                f"{env_var} not configured or is a placeholder. "
                f"Set it in your .env file or environment."
            )

        # Ensure the env var is set for LiteLLM
        os.environ[env_var] = api_key

        # Normalize model name
        if model:
            resolved_model = model if "/" in model else f"{prefix}{model}"
        else:
            resolved_model = DEFAULT_MODELS[provider]

        super().__init__(provider=provider, model=resolved_model)
        logger.info("Initialized %s LLM provider: model=%s", provider, resolved_model)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_llm_provider.py::TestApiKeyLLMProvider -v`
Expected: All 9 tests PASS

- [ ] **Step 5: Commit**

```bash
git add tmi_tf/providers/api_key.py tests/test_llm_provider.py
git commit -m "feat(#9): add ApiKeyLLMProvider for anthropic/openai/xai/gemini"
```

---

### Task 5: OciLLMProvider

**Files:**
- Modify: `tmi_tf/providers/oci.py`
- Modify: `tests/test_llm_provider.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/test_llm_provider.py`:

```python
from tmi_tf.providers.oci import OciLLMProvider


class TestOciLLMProvider:
    @patch.dict(
        os.environ,
        {"OCI_COMPARTMENT_ID": "ocid1.compartment.oc1..test"},
        clear=False,
    )
    def test_reads_compartment_from_env(self):
        mock_oci_config = {
            "region": "us-ashburn-1",
            "user": "ocid1.user.oc1..test",
            "fingerprint": "aa:bb:cc",
            "tenancy": "ocid1.tenancy.oc1..test",
            "key_file": "/path/to/key.pem",
        }
        with patch("pathlib.Path.exists", return_value=True):
            with patch("oci.config.from_file", return_value=mock_oci_config):
                provider = OciLLMProvider(model=None)
                assert provider._extra_kwargs["oci_compartment_id"] == "ocid1.compartment.oc1..test"
                assert provider._extra_kwargs["oci_region"] == "us-ashburn-1"

    @patch.dict(os.environ, {}, clear=False)
    def test_raises_when_no_compartment_id(self):
        os.environ.pop("OCI_COMPARTMENT_ID", None)
        with pytest.raises(ValueError, match="OCI_COMPARTMENT_ID"):
            OciLLMProvider(model=None)

    @patch.dict(
        os.environ,
        {"OCI_COMPARTMENT_ID": "ocid1.compartment.oc1..test"},
        clear=False,
    )
    def test_uses_instance_principal_when_no_config_file(self):
        mock_signer = MagicMock()
        mock_signer.region = "us-phoenix-1"
        with patch("pathlib.Path.exists", return_value=False):
            with patch(
                "oci.auth.signers.get_resource_principals_signer",
                return_value=mock_signer,
            ):
                provider = OciLLMProvider(model=None)
                assert provider._extra_kwargs["oci_signer"] is mock_signer
                assert provider._extra_kwargs["oci_region"] == "us-phoenix-1"

    @patch.dict(
        os.environ,
        {
            "OCI_COMPARTMENT_ID": "ocid1.compartment.oc1..test",
            "OCI_CONFIG_PROFILE": "CUSTOM",
        },
        clear=False,
    )
    def test_uses_custom_config_profile(self):
        mock_oci_config = {
            "region": "eu-frankfurt-1",
            "user": "ocid1.user.oc1..test",
            "fingerprint": "dd:ee:ff",
            "tenancy": "ocid1.tenancy.oc1..test",
            "key_file": "/path/to/key.pem",
        }
        with patch("pathlib.Path.exists", return_value=True):
            with patch("oci.config.from_file", return_value=mock_oci_config) as mock_from_file:
                provider = OciLLMProvider(model=None)
                mock_from_file.assert_called_once()
                # Second arg should be the profile name
                call_args = mock_from_file.call_args
                assert call_args[0][1] == "CUSTOM"

    @patch.dict(
        os.environ,
        {"OCI_COMPARTMENT_ID": "ocid1.compartment.oc1..test"},
        clear=False,
    )
    def test_default_model(self):
        mock_oci_config = {
            "region": "us-ashburn-1",
            "user": "u",
            "fingerprint": "f",
            "tenancy": "t",
            "key_file": "k",
        }
        with patch("pathlib.Path.exists", return_value=True):
            with patch("oci.config.from_file", return_value=mock_oci_config):
                provider = OciLLMProvider(model=None)
                assert provider.model.startswith("oci/")

    @patch.dict(
        os.environ,
        {"OCI_COMPARTMENT_ID": "ocid1.compartment.oc1..test"},
        clear=False,
    )
    def test_custom_model_gets_prefix(self):
        mock_oci_config = {
            "region": "us-ashburn-1",
            "user": "u",
            "fingerprint": "f",
            "tenancy": "t",
            "key_file": "k",
        }
        with patch("pathlib.Path.exists", return_value=True):
            with patch("oci.config.from_file", return_value=mock_oci_config):
                provider = OciLLMProvider(model="xai.grok-4")
                assert provider.model == "oci/xai.grok-4"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_llm_provider.py::TestOciLLMProvider -v`
Expected: FAIL — `ImportError: cannot import name 'OciLLMProvider' from 'tmi_tf.providers.oci'`

- [ ] **Step 3: Implement `OciLLMProvider`**

Add to the end of `tmi_tf/providers/oci.py`:

```python
from tmi_tf.providers.llm_base import BaseLLMProvider

OCI_DEFAULT_MODEL = "oci/xai.grok-4"


class OciLLMProvider(BaseLLMProvider):
    """LLM provider for OCI Generative AI service."""

    def __init__(self, model: str | None) -> None:
        compartment_id = os.environ.get("OCI_COMPARTMENT_ID")
        if not compartment_id:
            raise ValueError(
                "OCI_COMPARTMENT_ID required when LLM_PROVIDER=oci. "
                "Set it in your .env file or environment."
            )

        config_profile = os.environ.get("OCI_CONFIG_PROFILE", "DEFAULT")

        # Resolve model
        if model:
            resolved_model = model if "/" in model else f"oci/{model}"
        else:
            resolved_model = OCI_DEFAULT_MODEL

        super().__init__(provider="oci", model=resolved_model)

        # Build completion kwargs
        oci_config_path = Path.home() / ".oci" / "config"
        if oci_config_path.exists():
            from oci.config import from_file as oci_from_file  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

            oci_config = oci_from_file(str(oci_config_path), config_profile)
            self._extra_kwargs = {
                "oci_region": oci_config.get("region", "us-ashburn-1"),
                "oci_user": oci_config["user"],
                "oci_fingerprint": oci_config["fingerprint"],
                "oci_tenancy": oci_config["tenancy"],
                "oci_key_file": oci_config["key_file"],
                "oci_compartment_id": compartment_id,
            }
        else:
            # Instance principal / resource principal
            try:
                from oci.auth.signers import get_resource_principals_signer  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

                signer = get_resource_principals_signer()
                region = getattr(signer, "region", None) or "us-ashburn-1"
                self._extra_kwargs = {
                    "oci_region": region,
                    "oci_compartment_id": compartment_id,
                    "oci_signer": signer,
                }
            except Exception as e:
                logger.error("No OCI credentials available for LLM calls: %s", e)
                self._extra_kwargs = {"oci_compartment_id": compartment_id}

        logger.info(
            "Initialized OCI LLM provider: model=%s, compartment=%s",
            resolved_model,
            compartment_id,
        )
```

Also add this import at the top of `oci.py` (with the existing imports):

```python
from pathlib import Path
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_llm_provider.py::TestOciLLMProvider -v`
Expected: All 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add tmi_tf/providers/oci.py tests/test_llm_provider.py
git commit -m "feat(#9): add OciLLMProvider to providers/oci.py"
```

---

### Task 6: Factory Function

**Files:**
- Modify: `tmi_tf/providers/__init__.py`
- Modify: `tests/test_llm_provider.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/test_llm_provider.py`:

```python
from types import SimpleNamespace

from tmi_tf.providers import get_llm_provider


class TestGetLLMProvider:
    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test"}, clear=False)
    def test_returns_api_key_provider_for_anthropic(self):
        config = SimpleNamespace(llm_provider="anthropic", llm_model=None)
        provider = get_llm_provider(config)
        assert provider.model.startswith("anthropic/")

    @patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=False)
    def test_returns_api_key_provider_for_openai(self):
        config = SimpleNamespace(llm_provider="openai", llm_model="gpt-4o")
        provider = get_llm_provider(config)
        assert provider.model == "openai/gpt-4o"

    @patch.dict(
        os.environ,
        {"OCI_COMPARTMENT_ID": "ocid1.compartment.oc1..test"},
        clear=False,
    )
    def test_returns_oci_provider(self):
        mock_oci_config = {
            "region": "us-ashburn-1",
            "user": "u",
            "fingerprint": "f",
            "tenancy": "t",
            "key_file": "k",
        }
        with patch("pathlib.Path.exists", return_value=True):
            with patch("oci.config.from_file", return_value=mock_oci_config):
                config = SimpleNamespace(llm_provider="oci", llm_model=None)
                provider = get_llm_provider(config)
                assert provider.model.startswith("oci/")

    def test_raises_for_unknown_provider(self):
        config = SimpleNamespace(llm_provider="unknown", llm_model=None)
        with pytest.raises(ValueError, match="Unknown LLM provider"):
            get_llm_provider(config)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_llm_provider.py::TestGetLLMProvider -v`
Expected: FAIL — `ImportError: cannot import name 'get_llm_provider' from 'tmi_tf.providers'`

- [ ] **Step 3: Add `get_llm_provider()` to `providers/__init__.py`**

Add after the existing `get_queue_provider()` function:

```python
def get_llm_provider(config: "Config") -> LLMProvider:
    """Create an LLMProvider based on configuration."""
    if config.llm_provider == "oci":
        from tmi_tf.providers.oci import OciLLMProvider

        return OciLLMProvider(model=config.llm_model)
    elif config.llm_provider in ("anthropic", "openai", "xai", "gemini"):
        from tmi_tf.providers.api_key import ApiKeyLLMProvider

        return ApiKeyLLMProvider(
            provider=config.llm_provider, model=config.llm_model
        )
    else:
        raise ValueError(
            f"Unknown LLM provider: {config.llm_provider!r}. "
            f"Must be 'anthropic', 'openai', 'xai', 'gemini', or 'oci'."
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_llm_provider.py::TestGetLLMProvider -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Run full provider test suite**

Run: `uv run pytest tests/test_llm_provider.py tests/test_providers.py -v`
Expected: All tests PASS

- [ ] **Step 6: Commit**

```bash
git add tmi_tf/providers/__init__.py tests/test_llm_provider.py
git commit -m "feat(#9): add get_llm_provider() factory function"
```

---

### Task 7: Migrate LLMAnalyzer to Use LLMProvider

**Files:**
- Modify: `tmi_tf/llm_analyzer.py`
- Modify: `tests/test_llm_analyzer.py`

- [ ] **Step 1: Update tests to use LLMProvider mock**

Rewrite `tests/test_llm_analyzer.py`. Replace the `_make_config` helper and mock setup with an `LLMProvider` mock:

```python
"""Tests for Phase 3a/3b flow in tmi_tf.llm_analyzer."""

import json
from unittest.mock import MagicMock, patch

from tmi_tf.llm_analyzer import LLMAnalyzer
from tmi_tf.providers import LLMResponse


def _make_provider(model: str = "anthropic/test-model") -> MagicMock:
    """Create a mock LLMProvider."""
    provider = MagicMock()
    provider.model = model
    provider.provider = "anthropic"
    return provider


def _make_llm_response(
    content: str, tokens_in: int = 100, tokens_out: int = 50
) -> LLMResponse:
    """Create an LLMResponse for test use."""
    return LLMResponse(
        text=content,
        input_tokens=tokens_in,
        output_tokens=tokens_out,
        cost=0.01,
        finish_reason="stop",
    )


def _make_tf_repo(name="test-repo", url="https://github.com/test/repo"):
    """Create a minimal mock TerraformRepository."""
    repo = MagicMock()
    repo.name = name
    repo.url = url
    repo.get_terraform_content.return_value = {
        "main.tf": 'resource "aws_s3_bucket" "b" {}'
    }
    return repo


class TestPhase3Decomposition:
    """Tests for the Phase 3a + 3b decomposition in analyze_repository."""

    def test_phase3a_and_3b_produce_merged_findings(self):
        """Phase 3a identifies threats, Phase 3b enriches each one."""
        inventory = {"components": [{"id": "aws_s3_bucket.b"}], "services": []}
        infrastructure = {"relationships": [], "data_flows": [], "trust_boundaries": []}
        raw_threats = [
            {
                "name": "Public S3 Bucket",
                "description": "S3 bucket is publicly accessible",
                "affected_components": ["aws_s3_bucket.b"],
            }
        ]
        threat_analysis = {
            "threat_type": "Information Disclosure",
            "severity": "High",
            "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            "cwe_id": ["CWE-284"],
            "mitigation": "Enable S3 Block Public Access",
            "category": "Public Exposure",
        }

        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response(json.dumps(inventory)),
            _make_llm_response(json.dumps(infrastructure)),
            _make_llm_response(json.dumps(raw_threats)),
            _make_llm_response(json.dumps(threat_analysis)),
        ]

        analyzer = LLMAnalyzer(provider)
        result = analyzer.analyze_repository(_make_tf_repo())

        assert result.success is True
        assert len(result.security_findings) == 1

        finding = result.security_findings[0]
        assert finding["name"] == "Public S3 Bucket"
        assert finding["threat_type"] == "Information Disclosure"
        assert finding["cwe_id"] == ["CWE-284"]
        assert finding["mitigation"] == "Enable S3 Block Public Access"
        assert finding["score"] is not None
        assert len(finding["cvss"]) == 1
        assert finding["cvss"][0]["vector"].startswith("CVSS:4.0/")

    def test_phase3a_empty_produces_no_findings(self):
        """When Phase 3a finds no threats, result has empty security_findings."""
        inventory = {"components": [], "services": []}
        infrastructure = {"relationships": [], "data_flows": []}

        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response(json.dumps(inventory)),
            _make_llm_response(json.dumps(infrastructure)),
            _make_llm_response(json.dumps([])),
        ]

        analyzer = LLMAnalyzer(provider)
        result = analyzer.analyze_repository(_make_tf_repo())

        assert result.success is True
        assert result.security_findings == []

    def test_phase3b_failure_skips_threat(self):
        """When Phase 3b fails for one threat, it's skipped but others succeed."""
        inventory = {"components": [], "services": []}
        infrastructure = {"relationships": [], "data_flows": []}
        raw_threats = [
            {"name": "Threat A", "description": "desc A", "affected_components": []},
            {"name": "Threat B", "description": "desc B", "affected_components": []},
        ]
        threat_b_analysis = {
            "threat_type": "Tampering",
            "severity": "Medium",
            "cvss_vector": "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
            "cwe_id": ["CWE-345"],
            "mitigation": "Add integrity checks",
            "category": "Best Practices",
        }

        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response(json.dumps(inventory)),
            _make_llm_response(json.dumps(infrastructure)),
            _make_llm_response(json.dumps(raw_threats)),
            _make_llm_response("not valid json"),
            _make_llm_response(json.dumps(threat_b_analysis)),
        ]

        analyzer = LLMAnalyzer(provider)
        result = analyzer.analyze_repository(_make_tf_repo())

        assert result.success is True
        assert len(result.security_findings) == 1
        assert result.security_findings[0]["name"] == "Threat B"

    def test_invalid_cvss_vector_keeps_threat_without_score(self):
        """Invalid CVSS vector: threat kept with score=None, severity from LLM."""
        inventory = {"components": [], "services": []}
        infrastructure = {"relationships": [], "data_flows": []}
        raw_threats = [
            {"name": "Threat X", "description": "desc", "affected_components": []},
        ]
        threat_analysis = {
            "threat_type": "Spoofing",
            "severity": "High",
            "cvss_vector": "CVSS:4.0/AV:INVALID",
            "cwe_id": ["CWE-287"],
            "mitigation": "Fix auth",
            "category": "Authentication/Authorization",
        }

        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response(json.dumps(inventory)),
            _make_llm_response(json.dumps(infrastructure)),
            _make_llm_response(json.dumps(raw_threats)),
            _make_llm_response(json.dumps(threat_analysis)),
        ]

        analyzer = LLMAnalyzer(provider)
        result = analyzer.analyze_repository(_make_tf_repo())

        assert result.success is True
        assert len(result.security_findings) == 1

        finding = result.security_findings[0]
        assert finding["score"] is None
        assert finding["cvss"] == []
        assert finding["severity"] == "High"

    def test_all_phase3b_calls_fail_produces_empty_findings(self):
        """When all Phase 3b calls fail, result succeeds with empty findings."""
        inventory = {"components": [], "services": []}
        infrastructure = {"relationships": [], "data_flows": []}
        raw_threats = [
            {"name": "Threat A", "description": "desc A", "affected_components": []},
            {"name": "Threat B", "description": "desc B", "affected_components": []},
        ]

        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response(json.dumps(inventory)),
            _make_llm_response(json.dumps(infrastructure)),
            _make_llm_response(json.dumps(raw_threats)),
            _make_llm_response("not valid json"),
            _make_llm_response("also not json"),
        ]

        analyzer = LLMAnalyzer(provider)
        result = analyzer.analyze_repository(_make_tf_repo())

        assert result.success is True
        assert result.security_findings == []
```

- [ ] **Step 2: Run updated tests to verify they fail (LLMAnalyzer still takes config)**

Run: `uv run pytest tests/test_llm_analyzer.py -v`
Expected: FAIL — `LLMAnalyzer.__init__()` still expects config, not provider

- [ ] **Step 3: Refactor `LLMAnalyzer` to take `LLMProvider`**

Replace the `__init__`, remove `DEFAULT_MODELS`, `MODEL_PREFIXES`, `_normalize_model_name`, `_configure_api_keys`, `_extract_json_object`, `_extract_json_array`, and update `_call_llm` to use the provider. The key changes:

In `tmi_tf/llm_analyzer.py`:

1. Remove these imports: none needed to remove (litellm stays for `litellm.suppress_debug_info`)
2. Add import: `from tmi_tf.json_extract import extract_json_object, extract_json_array`
3. Add import: `from tmi_tf.providers import LLMProvider, LLMResponse`
4. Remove: `DEFAULT_MODELS` dict (lines 124-131), `MODEL_PREFIXES` dict (lines 133-140)
5. Replace `__init__` (lines 142-170) with:

```python
    def __init__(self, llm_provider: LLMProvider):
        """Initialize LLM analyzer.

        Args:
            llm_provider: Configured LLM provider for completion calls
        """
        self.llm_provider = llm_provider
        self.model = llm_provider.model
        self.provider = llm_provider.provider

        # Load all phase prompts
        self.prompts_dir = Path(__file__).parent.parent / "prompts"
        self._load_phase_prompts()

        logger.info(
            "LLM analyzer initialized: provider=%s, model=%s",
            self.provider,
            self.model,
        )
```

6. Remove `_normalize_model_name` (lines 189-207)
7. Remove `_configure_api_keys` (lines 209-227)
8. Replace `_call_llm_json` (lines 517-552) to use `extract_json_object`:

```python
    def _call_llm_json(
        self,
        system_prompt: str,
        user_prompt: str,
        phase_name: str,
        max_tokens: int = 16000,
        timeout: float = 300.0,
    ) -> tuple[Optional[Dict[str, Any]], int, int, float]:
        """Call LLM and parse JSON object response."""
        response = self._call_llm(
            system_prompt, user_prompt, phase_name, max_tokens, timeout
        )

        if not response.text:
            return None, response.input_tokens, response.output_tokens, response.cost

        parsed = extract_json_object(response.text)
        if not parsed:
            preview = response.text[:500]
            logger.error(
                "Phase %s: Failed to parse JSON object from response. "
                "Response length: %d chars. Preview: %s",
                phase_name,
                len(response.text),
                preview,
            )
        return parsed, response.input_tokens, response.output_tokens, response.cost
```

9. Replace `_call_llm_json_array` (lines 554-588) similarly with `extract_json_array`:

```python
    def _call_llm_json_array(
        self,
        system_prompt: str,
        user_prompt: str,
        phase_name: str,
        max_tokens: int = 16000,
        timeout: float = 300.0,
    ) -> tuple[List[Dict[str, Any]], int, int, float]:
        """Call LLM and parse JSON array response."""
        response = self._call_llm(
            system_prompt, user_prompt, phase_name, max_tokens, timeout
        )

        if not response.text:
            return [], response.input_tokens, response.output_tokens, response.cost

        parsed = extract_json_array(response.text)
        if parsed is None:
            logger.error(
                "Phase %s: Failed to parse JSON array from response", phase_name
            )
            return [], response.input_tokens, response.output_tokens, response.cost
        return parsed, response.input_tokens, response.output_tokens, response.cost
```

10. Replace `_call_llm` (lines 590-674) to use provider:

```python
    def _call_llm(
        self,
        system_prompt: str,
        user_prompt: str,
        phase_name: str,
        max_tokens: int = 16000,
        timeout: float = 300.0,
    ) -> LLMResponse:
        """Make a single LLM API call via the provider."""
        logger.info("Phase %s: Calling LLM provider", phase_name)

        response = retry_transient_llm_call(
            lambda: self.llm_provider.complete(
                system_prompt, user_prompt, max_tokens, timeout
            ),
            description=f"Phase {phase_name}",
        )

        logger.info(
            "Phase %s: %d input, %d output tokens, "
            "finish_reason=%s, $%.4f",
            phase_name,
            response.input_tokens,
            response.output_tokens,
            response.finish_reason,
            response.cost,
        )

        return response
```

11. Remove `_extract_json_object` (lines 676-718) and `_extract_json_array` (lines 720-759)

12. Remove unused imports: `re` (no longer needed after removing JSON extraction)

13. Remove `from tmi_tf.config import save_llm_response` (moved into BaseLLMProvider)

14. Keep `ClaudeAnalyzer = LLMAnalyzer` alias at the bottom

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_llm_analyzer.py -v`
Expected: All 5 tests PASS

- [ ] **Step 5: Lint**

Run: `uv run ruff check tmi_tf/llm_analyzer.py tests/test_llm_analyzer.py`
Expected: No errors

- [ ] **Step 6: Commit**

```bash
git add tmi_tf/llm_analyzer.py tests/test_llm_analyzer.py
git commit -m "refactor(#9): migrate LLMAnalyzer to use LLMProvider"
```

---

### Task 8: Migrate ThreatProcessor to Use LLMProvider

**Files:**
- Modify: `tmi_tf/threat_processor.py`

- [ ] **Step 1: Refactor `ThreatProcessor` to take `LLMProvider`**

In `tmi_tf/threat_processor.py`:

1. Remove `import os`
2. Remove `import re`  
3. Remove `import litellm` and `from litellm import ModelResponse`
4. Remove litellm suppression lines (`litellm.suppress_debug_info`, `litellm.drop_params`)
5. Add imports: `from tmi_tf.json_extract import extract_json_array` and `from tmi_tf.providers import LLMProvider`
6. Remove `MODEL_PREFIXES` dict (lines 78-85)
7. Replace `__init__` (lines 87-107) with:

```python
    def __init__(self, llm_provider: LLMProvider):
        """Initialize threat processor.

        Args:
            llm_provider: Configured LLM provider for completion calls
        """
        self.llm_provider = llm_provider
        self._load_prompts()

        # Token and cost tracking for threat extraction
        self.input_tokens = 0
        self.output_tokens = 0
        self.total_cost = 0.0
```

8. Remove `_normalize_model_name` (lines 109-127)
9. Remove `_configure_api_keys` (lines 163-179)
10. Update `extract_threats_from_analysis` (lines 181-279) to use `self.llm_provider.complete()` and `extract_json_array()`:

```python
    def extract_threats_from_analysis(
        self, analysis_content: str, repo_name: str
    ) -> List[SecurityThreat]:
        """Extract structured threats from analysis markdown content using LLM."""
        logger.info(f"Extracting threats from analysis for {repo_name}")

        system_prompt = self.system_prompt
        user_prompt = self.user_prompt_template.format(
            repo_name=repo_name,
            analysis_content=analysis_content,
        )

        try:
            response = retry_transient_llm_call(
                lambda: self.llm_provider.complete(
                    system_prompt, user_prompt, max_tokens=16000, timeout=180.0
                ),
                description=f"Threat extraction for {repo_name}",
            )

            # Accumulate token usage
            self.input_tokens += response.input_tokens
            self.output_tokens += response.output_tokens
            self.total_cost += response.cost
            logger.info(
                "Threat extraction for %s: %d input tokens, %d output tokens",
                repo_name,
                response.input_tokens,
                response.output_tokens,
            )

            if not response.text:
                logger.warning("Empty response from LLM for %s", repo_name)
                return []

            threats_data = extract_json_array(response.text)
            if not threats_data:
                logger.warning("No JSON array found in LLM response for %s", repo_name)
                return []

            threats = []
            for threat_data in threats_data:
                threat = SecurityThreat(
                    name=threat_data.get("name", "Unnamed Threat"),
                    description=threat_data.get("description", ""),
                    threat_type=threat_data.get("threat_type", "Unclassified"),
                    severity=threat_data.get("severity", "Medium"),
                    score=threat_data.get("score"),
                    cvss=threat_data.get("cvss"),
                    cwe_id=threat_data.get("cwe_id"),
                    mitigation=threat_data.get("mitigation"),
                    affected_components=threat_data.get("affected_components"),
                    status="Open",
                )
                threats.append(threat)

            logger.info("Extracted %d threats from %s", len(threats), repo_name)
            return threats

        except Exception as e:
            logger.error("Failed to extract threats from analysis: %s", e)
            return []
```

11. Remove `from tmi_tf.config import Config, save_llm_response`. Replace with `from tmi_tf.config import save_llm_response` only if still needed — since `save_llm_response` is now called from `BaseLLMProvider`, it's not needed here. Keep the `Config` import only if `Config` is still referenced elsewhere in the file — check `threats_from_findings` and `create_threats_in_tmi`. Neither references `Config`, so remove the entire config import line. But `_load_prompts` and `_get_default_*` don't use Config either. Remove `from tmi_tf.config import Config, save_llm_response` entirely.

- [ ] **Step 2: Run existing tests**

Run: `uv run pytest tests/ -v`
Expected: Pass (there are no existing tests specifically for ThreatProcessor LLM calls — the class is only tested indirectly)

- [ ] **Step 3: Lint**

Run: `uv run ruff check tmi_tf/threat_processor.py`
Expected: No errors

- [ ] **Step 4: Commit**

```bash
git add tmi_tf/threat_processor.py
git commit -m "refactor(#9): migrate ThreatProcessor to use LLMProvider"
```

---

### Task 9: Migrate DFDLLMGenerator to Use LLMProvider

**Files:**
- Modify: `tmi_tf/dfd_llm_generator.py`

- [ ] **Step 1: Refactor `DFDLLMGenerator` to take `LLMProvider`**

In `tmi_tf/dfd_llm_generator.py`:

1. Remove `import os`
2. Remove `import litellm` and `from litellm import ModelResponse`
3. Remove litellm suppression lines
4. Add imports: `from tmi_tf.json_extract import extract_json_object` and `from tmi_tf.providers import LLMProvider`
5. Remove `MODEL_PREFIXES` dict (lines 31-38)
6. Replace `__init__` (lines 40-75) with:

```python
    def __init__(self, llm_provider: LLMProvider):
        """Initialize the DFD LLM generator.

        Args:
            llm_provider: Configured LLM provider for completion calls
        """
        self.llm_provider = llm_provider
        self.provider = llm_provider.provider
        self.model = llm_provider.model

        # Token and cost tracking
        self.input_tokens = 0
        self.output_tokens = 0
        self.total_cost = 0.0

        self._load_prompt_template()
```

7. Remove `_normalize_model_name` (lines 77-95)
8. Remove `_configure_api_keys_from_config` (lines 97-110)
9. Update `generate_structured_components` (lines 128-226) — replace the `litellm.completion` call block (lines 152-185) with:

```python
            response = retry_transient_llm_call(
                lambda: self.llm_provider.complete(
                    self.system_prompt, user_prompt, max_tokens=16000, timeout=180.0
                ),
                description="DFD generation",
            )

            self.input_tokens = response.input_tokens
            self.output_tokens = response.output_tokens
            self.total_cost = response.cost
            logger.info(
                "DFD generation: %d input tokens, %d output tokens, $%.4f",
                self.input_tokens,
                self.output_tokens,
                self.total_cost,
            )

            if not response.text:
                logger.error("Empty content in LLM response")
                return None

            response_text = response.text
```

10. Replace `_extract_json` call (line 202) with `extract_json_object`:

```python
            structured_data = extract_json_object(response_text)
```

11. Remove the `_extract_json` method (lines 228-267) entirely
12. Remove `from tmi_tf.config import save_llm_response` (no longer needed — BaseLLMProvider saves)
13. Remove unused `import re` only if `_strip_markup_string` still uses it — check: yes it does (line 277). Keep `import re`.
14. Remove unused `import json` only if not used elsewhere — check: yes, `json.dumps` is used in `generate_structured_components`. Keep it.

- [ ] **Step 2: Run all tests**

Run: `uv run pytest tests/ -v`
Expected: All tests pass

- [ ] **Step 3: Lint**

Run: `uv run ruff check tmi_tf/dfd_llm_generator.py`
Expected: No errors

- [ ] **Step 4: Commit**

```bash
git add tmi_tf/dfd_llm_generator.py
git commit -m "refactor(#9): migrate DFDLLMGenerator to use LLMProvider"
```

---

### Task 10: Update Orchestrator (analyzer.py)

**Files:**
- Modify: `tmi_tf/analyzer.py`

- [ ] **Step 1: Update `analyzer.py` to create LLM provider and pass to consumers**

In `tmi_tf/analyzer.py`:

1. Add import: `from tmi_tf.providers import get_llm_provider`
2. Remove import of `DFDLLMGenerator` (it's only created in one place, but we still need it — keep the import)
3. In `run_analysis()`, after line 130 (`repo_analyzer = RepositoryAnalyzer(config)`), add provider creation:

Replace line 131:
```python
        llm_analyzer = LLMAnalyzer(config)
```
With:
```python
        llm_provider = get_llm_provider(config)
        llm_analyzer = LLMAnalyzer(llm_provider)
```

4. Replace line 402:
```python
                dfd_generator = DFDLLMGenerator(config=config)
```
With:
```python
                dfd_generator = DFDLLMGenerator(llm_provider)
```

5. Replace line 494:
```python
                threat_processor = ThreatProcessor(config)
```
With:
```python
                threat_processor = ThreatProcessor(llm_provider)
```

6. Update metadata lines that reference `llm_analyzer.provider` and `llm_analyzer.model` (lines 368-369, 527-528). These still work because `LLMAnalyzer` exposes `self.provider` and `self.model` from the provider. No change needed.

7. Update metadata lines that reference `dfd_generator.provider` and `dfd_generator.model` (lines 462-463). These still work because `DFDLLMGenerator` exposes `self.provider` and `self.model`. No change needed.

- [ ] **Step 2: Run all tests**

Run: `uv run pytest tests/ -v`
Expected: All tests pass

- [ ] **Step 3: Lint**

Run: `uv run ruff check tmi_tf/analyzer.py`
Expected: No errors

- [ ] **Step 4: Commit**

```bash
git add tmi_tf/analyzer.py
git commit -m "refactor(#9): create LLM provider in analyzer.py and pass to consumers"
```

---

### Task 11: Clean Up Config

**Files:**
- Modify: `tmi_tf/config.py`
- Modify: `tests/test_config.py`

- [ ] **Step 1: Remove LLM-specific logic from `config.py`**

1. Remove `DEFAULT_MODELS` class variable (lines 20-27)
2. Remove `PROVIDER_PREFIXES` class variable (lines 29-36)
3. Remove the `LLM_API_KEY` mapping block (lines 56-67) — this moves to the provider. Actually wait: the `LLM_API_KEY` → provider-specific env var mapping is still useful because it runs *before* provider construction (e.g., secrets provider loads `LLM_API_KEY` from vault, then config maps it to `ANTHROPIC_API_KEY` before `ApiKeyLLMProvider` reads it). **Keep this mapping block.**
4. Remove per-provider API key fields (lines 69-79): `anthropic_api_key`, `openai_api_key`, `xai_api_key`, `gemini_api_key`
5. Remove `oci_config_profile` field (line 82)
6. Remove `self._validate_llm_credentials()` call (line 86)
7. Remove `effective_model` field (lines 96-98) — this was used for artifact naming. Check `analyzer.py` — it's not used there; the model comes from `llm_analyzer.model`. Check `cli.py` — grep for `effective_model`:

    ```
    # If effective_model is used elsewhere, keep it or replace with llm_model
    ```
    
    Actually `effective_model` is used at line 96 for `config.effective_model` and referenced in `analyzer.py` at line 317 for building artifact names (`model_label = config.effective_model`). Since we're removing `DEFAULT_MODELS` from config, we need to either:
    - Keep `effective_model` simple: `self.effective_model = self.llm_model or "default"`
    - Or move artifact naming to use `llm_provider.model` in analyzer.py
    
    The simpler fix: in `analyzer.py`, replace `config.effective_model` with `llm_provider.model` (already available as `llm_analyzer.model`). Then remove `effective_model` from config.

8. Remove `get_llm_model()` method (lines 145-159)
9. Remove `_validate_llm_credentials()` method (lines 161-193)
10. Remove `_oci_credentials_available()` static method (lines 195-228)
11. Remove `get_oci_completion_kwargs()` method (lines 230-269)

- [ ] **Step 2: Update `analyzer.py` to use `llm_analyzer.model` instead of `config.effective_model`**

Replace line 317:
```python
        model_label = config.effective_model
```
With:
```python
        model_label = llm_analyzer.model
```

- [ ] **Step 2b: Update `cli.py` to remove references to deleted config fields**

In `tmi_tf/cli.py`, replace line 268:
```python
        print(f"LLM Model: {config.effective_model}")
```
With:
```python
        print(f"LLM Provider: {config.llm_provider}")
        print(f"LLM Model: {config.llm_model or '(default)'}")
```

Replace lines 273-275:
```python
        print(
            f"Anthropic API Key: {'Configured' if config.anthropic_api_key else 'Not configured'}"
        )
```
With:
```python
        print(f"LLM Provider: {config.llm_provider}")
```

(The provider-specific API key check is no longer relevant — the provider validates its own credentials at construction time.)

- [ ] **Step 3: Update `tests/test_config.py`**

Remove these test classes entirely:
- `TestOCIValidation` (lines 149-222) — credential validation moved to `OciLLMProvider`
- `TestOCICompletionKwargs` (lines 263-328) — kwargs moved to `OciLLMProvider`

The `TestLLMAPIKeyMapping` tests stay because the mapping logic stays in config.

- [ ] **Step 4: Run all tests**

Run: `uv run pytest tests/ -v`
Expected: All tests pass

- [ ] **Step 5: Lint and type check**

Run: `uv run ruff check tmi_tf/config.py tmi_tf/analyzer.py tests/test_config.py && uv run pyright`
Expected: No errors (pyright may have existing warnings — ensure no new ones)

- [ ] **Step 6: Commit**

```bash
git add tmi_tf/config.py tmi_tf/analyzer.py tmi_tf/cli.py tests/test_config.py
git commit -m "refactor(#9): remove LLM-specific logic from Config"
```

---

### Task 12: Final Verification

**Files:** None (verification only)

- [ ] **Step 1: Run full test suite**

Run: `uv run pytest tests/ -v`
Expected: All tests pass

- [ ] **Step 2: Lint entire codebase**

Run: `uv run ruff check tmi_tf/ tests/`
Expected: No errors

- [ ] **Step 3: Format check**

Run: `uv run ruff format --check tmi_tf/ tests/`
Expected: No formatting issues

- [ ] **Step 4: Type check**

Run: `uv run pyright`
Expected: No new errors

- [ ] **Step 5: Verify no remaining references to removed methods**

Run these grep checks:
```bash
grep -r "get_oci_completion_kwargs\|_validate_llm_credentials\|_oci_credentials_available\|get_llm_model" tmi_tf/ tests/ --include="*.py"
grep -r "MODEL_PREFIXES\|_normalize_model_name\|_configure_api_keys" tmi_tf/llm_analyzer.py tmi_tf/threat_processor.py tmi_tf/dfd_llm_generator.py
```
Expected: No matches (all references removed)

- [ ] **Step 6: Final commit if any cleanup was needed**

```bash
git add -A
git commit -m "chore(#9): final cleanup for LLM provider abstraction"
```
