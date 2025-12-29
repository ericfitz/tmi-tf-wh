"""Configuration management for tmi-tf."""

import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv


class Config:
    """Application configuration loaded from environment variables."""

    # Default models for each provider
    DEFAULT_MODELS = {
        "anthropic": "claude-sonnet-4-5",
        "xai": "grok-beta",
        "gemini": "gemini-2.0-flash-exp",
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

        # x.ai (Grok) API Configuration
        self.xai_api_key: Optional[str] = os.getenv("XAI_API_KEY") or None

        # Google Cloud (Gemini) Configuration
        self.gcp_service_account_key: Optional[str] = (
            os.getenv("GCP_SERVICE_ACCOUNT_KEY") or None
        )
        self.gcp_project_id: Optional[str] = os.getenv("GCP_PROJECT_ID") or None
        self.gcp_location: str = os.getenv("GCP_LOCATION", "us-central1")

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
        elif self.llm_provider == "xai":
            if not self.xai_api_key:
                raise ValueError("XAI_API_KEY required when LLM_PROVIDER=xai")
        elif self.llm_provider == "gemini":
            if not self.gcp_service_account_key:
                raise ValueError(
                    "GCP_SERVICE_ACCOUNT_KEY required when LLM_PROVIDER=gemini"
                )
            if not self.gcp_project_id:
                raise ValueError("GCP_PROJECT_ID required when LLM_PROVIDER=gemini")
        else:
            raise ValueError(
                f"Invalid LLM_PROVIDER: {self.llm_provider}. "
                f"Must be 'anthropic', 'xai', or 'gemini'"
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
