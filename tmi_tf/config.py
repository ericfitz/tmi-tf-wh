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
        self.tmi_client_id: Optional[str] = os.getenv("TMI_CLIENT_ID") or None
        self.tmi_client_secret: Optional[str] = os.getenv("TMI_CLIENT_SECRET") or None

        # LLM Provider Configuration
        self.llm_provider: str = os.getenv("LLM_PROVIDER", "anthropic")
        self.llm_model: Optional[str] = os.getenv("LLM_MODEL")

        # Map generic LLM_API_KEY to provider-specific env var
        llm_api_key = os.getenv("LLM_API_KEY")
        if llm_api_key:
            key_map = {
                "anthropic": "ANTHROPIC_API_KEY",
                "openai": "OPENAI_API_KEY",
                "xai": "XAI_API_KEY",
                "gemini": "GEMINI_API_KEY",
            }
            target = key_map.get(self.llm_provider)
            if target:
                os.environ[target] = llm_api_key

        # OCI Generative AI Configuration
        self.oci_compartment_id: Optional[str] = os.getenv("OCI_COMPARTMENT_ID") or None

        # GitHub API Configuration
        self.github_token: Optional[str] = os.getenv("GITHUB_TOKEN") or None

        # Application Settings
        self.max_repos: int = int(os.getenv("MAX_REPOS", "3"))
        self.clone_timeout: int = int(os.getenv("CLONE_TIMEOUT", "300"))

        self.timestamp: str = datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )

        # Token cache directory
        self.cache_dir = Path.home() / ".tmi-tf"
        self.cache_dir.mkdir(exist_ok=True)
        self.token_cache_file = self.cache_dir / "token.json"

        # Server configuration
        self.max_concurrent_jobs: int = int(os.getenv("MAX_CONCURRENT_JOBS", "3"))
        self.job_timeout: int = int(os.getenv("JOB_TIMEOUT", "3600"))
        self.max_message_age_hours: int = int(os.getenv("MAX_MESSAGE_AGE_HOURS", "24"))
        self.server_port: int = int(os.getenv("SERVER_PORT", "8080"))
        self.webhook_secret: Optional[str] = os.getenv("WEBHOOK_SECRET") or None
        self.webhook_subscription_id: Optional[str] = (
            os.getenv("WEBHOOK_SUBSCRIPTION_ID") or None
        )
        self.queue_ocid: Optional[str] = os.getenv("QUEUE_OCID") or None
        self.vault_ocid: Optional[str] = os.getenv("VAULT_OCID") or None

        # Secret provider selection (inferred from VAULT_OCID if not explicit)
        explicit_provider = os.getenv("SECRET_PROVIDER")
        if explicit_provider:
            self.secret_provider: str = explicit_provider
        elif self.vault_ocid:
            self.secret_provider = "oci"
        else:
            self.secret_provider = "none"

        # Queue provider selection (inferred from QUEUE_OCID if not explicit)
        explicit_queue_provider = os.getenv("QUEUE_PROVIDER")
        if explicit_queue_provider:
            self.queue_provider: str = explicit_queue_provider
        elif self.queue_ocid:
            self.queue_provider = "oci"
        else:
            self.queue_provider = "none"

        self.tmi_client_path: Optional[str] = os.getenv("TMI_CLIENT_PATH") or None

        # OCI service endpoints (required for in-cluster OKE access)
        self.queue_endpoint: Optional[str] = os.getenv("QUEUE_ENDPOINT") or None
        self.vault_endpoint: Optional[str] = os.getenv("VAULT_ENDPOINT") or None
        self.secrets_endpoint: Optional[str] = os.getenv("SECRETS_ENDPOINT") or None

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
