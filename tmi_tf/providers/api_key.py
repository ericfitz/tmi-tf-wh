"""API-key-based LLM provider for anthropic, openai, xai, gemini."""

import logging
import os

from tmi_tf.providers.llm_base import BaseLLMProvider

logger = logging.getLogger(__name__)

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

        api_key = os.environ.get(env_var)
        if not api_key or "placeholder" in (api_key or ""):
            raise ValueError(
                f"{env_var} not configured or is a placeholder. "
                f"Set it in your .env file or environment."
            )

        os.environ[env_var] = api_key

        if model:
            resolved_model = model if "/" in model else f"{prefix}{model}"
        else:
            resolved_model = DEFAULT_MODELS[provider]

        super().__init__(provider=provider, model=resolved_model)
        logger.info("Initialized %s LLM provider: model=%s", provider, resolved_model)
