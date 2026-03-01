"""Configuration management for tmi-tf."""

import itertools
import logging
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

logger = logging.getLogger(__name__)


class Config:
    """Application configuration loaded from environment variables."""

    # Default models for each provider (LiteLLM format)
    DEFAULT_MODELS = {
        "anthropic": "anthropic/claude-opus-4-5-20251101",
        "openai": "openai/gpt-5.2",
        "xai": "xai/grok-4-1-fast-non-reasoning",
        "gemini": "gemini/gemini-2.0-flash",
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

        # Note and diagram names include model identifier and timestamp
        effective_model = self.llm_model or self.DEFAULT_MODELS.get(
            self.llm_provider, "unknown"
        )
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        base_note_name = os.getenv("ANALYSIS_NOTE_NAME", "Terraform Analysis Report")
        base_diagram_name = os.getenv(
            "DIAGRAM_NAME", "Infrastructure Data Flow Diagram"
        )
        self.analysis_note_name: str = (
            f"{base_note_name} ({effective_model}, {timestamp})"
        )
        self.diagram_name: str = f"{base_diagram_name} ({effective_model}, {timestamp})"

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


# Global config instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get or create global config instance."""
    global _config
    if _config is None:
        _config = Config()
    return _config


# LLM response file management
_response_dir: Optional[Path] = None
_response_counter = itertools.count(1)


def get_response_dir() -> Path:
    """Get or create session-level temp directory for LLM response files."""
    global _response_dir
    if _response_dir is None:
        _response_dir = Path(tempfile.mkdtemp(prefix="tmi-tf-responses-"))
        logger.info(f"LLM response files directory: {_response_dir}")
    return _response_dir


def save_llm_response(content: str, label: str) -> Path:
    """Save LLM response content to a file in the response directory.

    Args:
        content: The raw LLM response text
        label: Descriptive label for the file (e.g. "inventory", "dfd")

    Returns:
        Path to the saved response file
    """
    response_dir = get_response_dir()
    safe_label = re.sub(r"[^\w\-.]", "_", label)
    n = next(_response_counter)
    filepath = response_dir / f"{n:02d}_{safe_label}.txt"
    filepath.write_text(content, encoding="utf-8")
    return filepath
