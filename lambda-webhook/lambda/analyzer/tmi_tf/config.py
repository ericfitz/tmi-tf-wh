"""Configuration management for tmi-tf."""

import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv


class Config:
    """Application configuration loaded from environment variables."""

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

        # Claude API Configuration
        self.anthropic_api_key: str = os.getenv("ANTHROPIC_API_KEY", "")
        if (
            not self.anthropic_api_key
            or self.anthropic_api_key == "placeholder_anthropic_api_key"
        ):
            raise ValueError(
                "ANTHROPIC_API_KEY not configured. "
                "Please set it in .env file with your actual API key."
            )

        # GitHub API Configuration
        self.github_token: Optional[str] = os.getenv("GITHUB_TOKEN") or None

        # Application Settings
        self.max_repos: int = int(os.getenv("MAX_REPOS", "3"))
        self.clone_timeout: int = int(os.getenv("CLONE_TIMEOUT", "300"))
        self.analysis_note_name: str = os.getenv(
            "ANALYSIS_NOTE_NAME", "Terraform Analysis Report"
        )
        self.diagram_name: str = os.getenv(
            "DIAGRAM_NAME", "Infrastructure Data Flow Diagram"
        )

        # Token cache directory
        self.cache_dir = Path.home() / ".tmi-tf"
        self.cache_dir.mkdir(exist_ok=True)
        self.token_cache_file = self.cache_dir / "token.json"

    def __repr__(self) -> str:
        """Return string representation of config (without secrets)."""
        return (
            f"Config(tmi_server_url={self.tmi_server_url}, "
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
