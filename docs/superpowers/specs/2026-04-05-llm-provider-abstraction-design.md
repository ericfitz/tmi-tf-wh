# LLM Provider Abstraction Design

**Issue:** [ericfitz/tmi-tf-wh#9](https://github.com/ericfitz/tmi-tf-wh/issues/9)
**Date:** 2026-04-05
**Scope:** Abstract LLM provider configuration behind a provider interface. Extract JSON response parsing to a shared utility.

## Problem

`config.py` contains OCI-specific LLM logic (`get_oci_completion_kwargs()`, `_oci_credentials_available()`) and provider-specific credential validation (`_validate_llm_credentials()`). Additionally, `MODEL_PREFIXES`, `_normalize_model_name()`, and `_configure_api_keys()` are duplicated across three files: `llm_analyzer.py`, `threat_processor.py`, and `dfd_llm_generator.py`. JSON extraction logic (`_extract_json_object`, `_extract_json_array`) is also duplicated across callers.

## Design Decisions

1. **Full provider, not thin wrapper** — The `LLMProvider` protocol wraps `litellm.completion()` entirely, centralizing credential setup, model prefixing, API key configuration, and the completion call. Callers get back a clean `LLMResponse` dataclass.

2. **Generic `ApiKeyLLMProvider` + `OciLLMProvider`** — The four API-key-based providers (anthropic, openai, xai, gemini) are structurally identical. A single parameterized `ApiKeyLLMProvider` handles all of them. OCI gets its own class for signer/compartment logic.

3. **Providers read their own env vars** — `Config` only stores `llm_provider` and `llm_model`. Each provider reads its own credentials from the environment at construction time. This follows the pattern established by `OciSecretProvider` and `OciQueueProvider`.

4. **JSON extraction as shared utility** — Extracted to `tmi_tf/json_extract.py`, not part of the provider protocol (consumer logic, not provider logic).

5. **Retry stays with callers** — `complete()` does not include retry logic. Callers wrap with `retry_transient_llm_call()` as they do today, since retry policy is caller-specific.

## Protocol & Types (`providers/__init__.py`)

```python
@dataclass
class LLMResponse:
    text: str | None
    input_tokens: int
    output_tokens: int
    cost: float
    finish_reason: str

class LLMProvider(Protocol):
    @property
    def model(self) -> str:
        """Fully-qualified model name (with LiteLLM prefix)."""
        ...

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 16000,
        timeout: float = 300.0,
    ) -> LLMResponse:
        """Make a single LLM completion call. Returns LLMResponse."""
        ...
```

## Base Class (`providers/llm_base.py`)

Both concrete providers share the same `complete()` core logic. A `BaseLLMProvider` implements it with a hook for extra kwargs:

```python
class BaseLLMProvider:
    def __init__(self, provider: str, model: str):
        self._provider = provider
        self._model = model
        self._extra_kwargs: dict = {}

    @property
    def model(self) -> str:
        return self._model

    def complete(self, system_prompt, user_prompt, max_tokens=16000, timeout=300.0) -> LLMResponse:
        # Calls litellm.completion() with self._extra_kwargs
        # Extracts usage (input_tokens, output_tokens), finish_reason, cost
        # Logs prompt size, token counts, cost
        # Saves response to file via save_llm_response() for debugging
        # Returns LLMResponse
        ...
```

The `complete()` method consolidates the logic currently in `LLMAnalyzer._call_llm()`: token/cost extraction, finish_reason diagnostics, truncation warnings, debug file saving.

## Providers

### `ApiKeyLLMProvider` (`providers/api_key.py`)

Handles: anthropic, openai, xai, gemini.

```python
# Env var name and model prefix per provider
API_KEY_PROVIDERS = {
    "anthropic": ("ANTHROPIC_API_KEY", "anthropic/"),
    "openai": ("OPENAI_API_KEY", "openai/"),
    "xai": ("XAI_API_KEY", "xai/"),
    "gemini": ("GEMINI_API_KEY", "gemini/"),
}

DEFAULT_MODELS = {
    "anthropic": "anthropic/claude-opus-4-6",
    "openai": "openai/gpt-4",
    "xai": "xai/grok-3-latest",
    "gemini": "gemini/gemini-2.5-pro",
}
```

Constructor:
1. Reads the API key from the corresponding env var (e.g., `ANTHROPIC_API_KEY`)
2. Validates it is present and not a placeholder value
3. Sets the provider-specific env var so LiteLLM can find it (always sets, since the secrets provider may have loaded the key under a generic name like `LLM_API_KEY`)
4. Normalizes the model name with the provider prefix (or uses default if model is empty/None)

### `OciLLMProvider` (`providers/oci.py`)

Constructor:
1. Reads `OCI_COMPARTMENT_ID` from env, validates present
2. Reads `OCI_CONFIG_PROFILE` from env (defaults to `"DEFAULT"`)
3. Checks OCI credentials are available (moves `_oci_credentials_available()` logic here, but uses `get_oci_signer()` from the same module where possible)
4. Builds completion kwargs at construction time:
   - Config-file auth: extracts region, user, fingerprint, tenancy, key_file
   - Instance principal: gets signer + region
   - Stores as `self._extra_kwargs`
5. Normalizes model name with `"oci/"` prefix

Default model: `"oci/meta.llama-3.1-405b-instruct"` (or current default from config).

## Factory (`providers/__init__.py`)

```python
def get_llm_provider(config: "Config") -> LLMProvider:
    if config.llm_provider == "oci":
        from tmi_tf.providers.oci import OciLLMProvider
        return OciLLMProvider(model=config.llm_model)
    elif config.llm_provider in ("anthropic", "openai", "xai", "gemini"):
        from tmi_tf.providers.api_key import ApiKeyLLMProvider
        return ApiKeyLLMProvider(provider=config.llm_provider, model=config.llm_model)
    else:
        raise ValueError(
            f"Unknown LLM provider: {config.llm_provider!r}. "
            f"Must be 'anthropic', 'openai', 'xai', 'gemini', or 'oci'."
        )
```

## JSON Extraction Utility (`tmi_tf/json_extract.py`)

Two public functions:

```python
def extract_json_object(text: str) -> dict[str, Any] | None: ...
def extract_json_array(text: str) -> list[dict[str, Any]] | None: ...
```

Three-stage extraction strategy (same as current `LLMAnalyzer`):
1. Try direct `json.loads()`
2. Try extracting from markdown code blocks (`` ```json ... ``` ``)
3. Try regex match for `{...}` or `[...]` in text

## Config Changes (`config.py`)

**Remove:**
- `_validate_llm_credentials()`
- `_oci_credentials_available()`
- `get_oci_completion_kwargs()`
- `get_llm_model()`
- `PROVIDER_PREFIXES` dict
- `DEFAULT_MODELS` dict
- Per-provider API key fields: `anthropic_api_key`, `openai_api_key`, `xai_api_key`, `gemini_api_key`
- `oci_config_profile`

**Keep:**
- `llm_provider: str` — from `LLM_PROVIDER` env var, defaults to `"anthropic"`
- `llm_model: str | None` — from `LLM_MODEL` env var (optional)

The `__init__` no longer calls credential validation — that happens when the factory constructs the provider.

## Consumer Changes

### `LLMAnalyzer` (`llm_analyzer.py`)

**Remove:** `MODEL_PREFIXES`, `DEFAULT_MODELS`, `_normalize_model_name()`, `_configure_api_keys()`, `self.oci_kwargs`, `_extract_json_object()`, `_extract_json_array()`.

**Change:** Constructor takes `LLMProvider` instead of `Config`. `_call_llm()` becomes `self.provider.complete(...)` wrapped in `retry_transient_llm_call()`. JSON extraction calls switch to `extract_json_object()` / `extract_json_array()` from the shared utility.

### `ThreatProcessor` (`threat_processor.py`)

**Remove:** `MODEL_PREFIXES`, `_normalize_model_name()`, `_configure_api_keys()`, `self.oci_kwargs`.

**Change:** Constructor takes `LLMProvider` instead of `Config`. LLM calls use `self.provider.complete(...)`.

### `DFDLLMGenerator` (`dfd_llm_generator.py`)

**Remove:** `MODEL_PREFIXES`, `_normalize_model_name()`, `_configure_api_keys_from_config()`, `self.oci_kwargs`. Remove deprecated `api_key`/`model` constructor path.

**Change:** Constructor takes `LLMProvider` instead of `Config`. LLM calls use `self.provider.complete(...)`.

### Orchestrators (`cli.py`, `analyzer.py`, `server.py`, `worker.py`)

Create the provider once via `get_llm_provider(config)` and pass it to `LLMAnalyzer`, `ThreatProcessor`, and `DFDLLMGenerator`. Single point of LLM setup.

## File Summary

### New files

```
tmi_tf/providers/llm_base.py   — BaseLLMProvider with shared complete() logic
tmi_tf/providers/api_key.py    — ApiKeyLLMProvider
tmi_tf/json_extract.py         — extract_json_object(), extract_json_array()
tests/test_llm_provider.py     — ApiKeyLLMProvider, OciLLMProvider, factory tests
tests/test_json_extract.py     — JSON extraction utility tests
```

### Modified files

```
tmi_tf/providers/__init__.py   — Add LLMResponse, LLMProvider protocol, get_llm_provider()
tmi_tf/providers/oci.py        — Add OciLLMProvider
tmi_tf/config.py               — Remove LLM-specific logic (validation, kwargs, model helpers, API keys)
tmi_tf/llm_analyzer.py         — Take LLMProvider, remove duplicated logic, use json_extract
tmi_tf/threat_processor.py     — Take LLMProvider, remove duplicated logic
tmi_tf/dfd_llm_generator.py    — Take LLMProvider, remove duplicated logic
tmi_tf/cli.py                  — Create provider via factory, pass to consumers
tmi_tf/analyzer.py             — Create provider via factory, pass to consumers
tmi_tf/server.py               — Create provider via factory, pass to consumers
tmi_tf/worker.py               — Create provider via factory, pass to consumers
tests/test_config.py           — Remove LLM validation/kwargs/model tests
tests/test_llm_analyzer.py     — Mock LLMProvider instead of litellm + config
tests/test_threat_processor.py — Mock LLMProvider instead of litellm + config
tests/test_dfd_llm_generator.py — Mock LLMProvider instead of litellm + config
```
