"""Configuration management for tmi-tf."""

import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv


class Config:
    """Application configuration loaded from environment variables."""

    # Default models for each provider (LiteLLM format)
    DEFAULT_MODELS = {
        "anthropic": "anthropic/claude-opus-4-5-20251101",
        "openai": "openai/gpt-5.2",
        "xai": "xai/grok-4-1-fast-reasoning",
        "gemini": "gemini/gemini-3-pro-preview",
    }

    # Provider prefixes for LiteLLM
    PROVIDER_PREFIXES = {
        "anthropic": "anthropic/",
        "openai": "openai/",
        "xai": "xai/",
        "gemini": "gemini/",
    }

    def __init__(self):
        """Initialize configuration from .env file."""
        # Load .env file from project root
        project_root = Path(__file__).parent.parent
        env_file = project_root / ".env"
        # Override existing environment variables with .env file values
        load_dotenv(env_file, override=True)

        # TMI Server Configuration
        self.tmi_server_url: str = os.getenv("TMI_SERVER_URL", "https://api.tmi.dev")
        self.tmi_oauth_idp: str = os.getenv("TMI_OAUTH_IDP", "google")

        # LLM Provider Configuration
        self.llm_provider: str = os.getenv("LLM_PROVIDER", "anthropic")
        self.llm_model: Optional[str] = os.getenv("LLM_MODEL")

        # Anthropic (Claude) API Configuration
        self.anthropic_api_key: Optional[str] = os.getenv("ANTHROPIC_API_KEY") or None

        # OpenAI API Configuration
        self.openai_api_key: Optional[str] = os.getenv("OPENAI_API_KEY") or None

        # x.ai (Grok) API Configuration
        self.xai_api_key: Optional[str] = os.getenv("XAI_API_KEY") or None

        # Google (Gemini) API Configuration
        self.gemini_api_key: Optional[str] = os.getenv("GEMINI_API_KEY") or None

        # Validate credentials for selected provider
        self._validate_llm_credentials()

        # GitHub API Configuration
        self.github_token: Optional[str] = os.getenv("GITHUB_TOKEN") or None

        # Application Settings
        self.max_repos: int = int(os.getenv("MAX_REPOS", "3"))
        self.clone_timeout: int = int(os.getenv("CLONE_TIMEOUT", "300"))

        # Note and diagram names include model identifier
        effective_model = self.llm_model or self.DEFAULT_MODELS.get(
            self.llm_provider, "unknown"
        )
        base_note_name = os.getenv("ANALYSIS_NOTE_NAME", "Terraform Analysis Report")
        base_diagram_name = os.getenv(
            "DIAGRAM_NAME", "Infrastructure Data Flow Diagram"
        )
        self.analysis_note_name: str = f"{base_note_name} ({effective_model})"
        self.diagram_name: str = f"{base_diagram_name} ({effective_model})"

        # Token cache directory
        self.cache_dir = Path.home() / ".tmi-tf"
        self.cache_dir.mkdir(exist_ok=True)
        self.token_cache_file = self.cache_dir / "token.json"

    def get_llm_model(self) -> str:
        """Get the LLM model with proper provider prefix for LiteLLM.

        If LLM_MODEL is set without a prefix, prepends the provider prefix.
        If LLM_MODEL already has a prefix (contains '/'), uses it as-is.
        If LLM_MODEL is not set, returns the default model for the provider.
        """
        if self.llm_model:
            # If model already has a provider prefix, use as-is
            if "/" in self.llm_model:
                return self.llm_model
            # Otherwise prepend the provider prefix
            prefix = self.PROVIDER_PREFIXES.get(self.llm_provider, "")
            return f"{prefix}{self.llm_model}"
        return self.DEFAULT_MODELS.get(self.llm_provider, "gpt-4")

    def _validate_llm_credentials(self):
        """Validate that required credentials exist for the selected LLM provider."""
        if self.llm_provider == "anthropic":
            if (
                not self.anthropic_api_key
                or self.anthropic_api_key == "placeholder_anthropic_api_key"
            ):
                raise ValueError(
                    "ANTHROPIC_API_KEY not configured. "
                    "Please set it in .env file with your actual API key."
                )
        elif self.llm_provider == "openai":
            if not self.openai_api_key:
                raise ValueError("OPENAI_API_KEY required when LLM_PROVIDER=openai")
        elif self.llm_provider == "xai":
            if not self.xai_api_key:
                raise ValueError("XAI_API_KEY required when LLM_PROVIDER=xai")
        elif self.llm_provider == "gemini":
            if not self.gemini_api_key:
                raise ValueError("GEMINI_API_KEY required when LLM_PROVIDER=gemini")
        else:
            raise ValueError(
                f"Invalid LLM_PROVIDER: {self.llm_provider}. "
                f"Must be 'anthropic', 'openai', 'xai', or 'gemini'"
            )

    def __repr__(self) -> str:
        """Return string representation of config (without secrets)."""
        return (
            f"Config(llm_provider={self.llm_provider}, "
            f"llm_model={self.llm_model or 'default'}, "
            f"tmi_server_url={self.tmi_server_url}, "
            f"max_repos={self.max_repos}, "
            f"github_token={'***' if self.github_token else 'None'})"
        )


def get_effective_temperature(model: str, desired: float) -> float:
    """Return the effective temperature for the given model.

    Some models require default temperature (1.0):
    - Gemini 3+ models: custom temperature causes loops and degraded reasoning
    - OpenAI GPT-5/o-series reasoning models: temperature parameter not supported
    """
    model_lower = model.lower()
    if "gemini-3" in model_lower or "gemini-2.5" in model_lower:
        return 1.0
    if (
        "gpt-5" in model_lower
        or "/o1" in model_lower
        or "/o3" in model_lower
        or "/o4" in model_lower
    ):
        return 1.0
    return desired


# Global config instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get or create global config instance."""
    global _config
    if _config is None:
        _config = Config()
    return _config
