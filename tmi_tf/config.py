"""Configuration management for tmi-tf."""

import itertools
import logging
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import (
    load_dotenv,  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]
)

logger = logging.getLogger(__name__)


# Default .env location: the project root, one level above this package.
DEFAULT_ENV_FILE: Path | None = Path(__file__).parent.parent / ".env"

# Distinguishes "caller passed nothing" from "caller passed None", so that
# Config(env_file=None) can explicitly opt out of .env loading.
_UNSET = object()


def prompts_dir() -> Path:
    """Directory holding the LLM prompt templates; override with PROMPTS_DIR (containers)."""
    return Path(
        os.environ.get("PROMPTS_DIR") or Path(__file__).parent.parent / "prompts"
    )


class Config:
    """Application configuration loaded from environment variables."""

    def __init__(self, env_file: Any = _UNSET):
        """Initialize configuration from environment variables.

        Args:
            env_file: Path to a .env file to load, or None to skip loading one
                and read the ambient environment only. Defaults to the project
                root .env. Tests pass None (see tests/conftest.py) so that a
                developer's local .env cannot leak into assertions -- values
                there are loaded with override=True and would otherwise beat
                anything the test set up via patch.dict.
        """
        if env_file is _UNSET:
            # Read at call time rather than binding as a default argument, so
            # the module global stays monkeypatchable.
            env_file = DEFAULT_ENV_FILE
        if env_file is not None:
            # Override existing environment variables with .env file values
            load_dotenv(env_file, override=True)

        # TMI Server Configuration
        self.tmi_server_url: str = os.getenv("TMI_SERVER_URL", "https://api.tmi.dev")
        self.tmi_oauth_idp: str = os.getenv("TMI_OAUTH_IDP", "google")
        self.tmi_client_id: str | None = os.getenv("TMI_CLIENT_ID") or None
        self.tmi_client_secret: str | None = os.getenv("TMI_CLIENT_SECRET") or None

        # LLM Provider Configuration
        self.llm_provider: str = os.getenv("LLM_PROVIDER", "anthropic")
        self.llm_model: str | None = os.getenv("LLM_MODEL")

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
        self.oci_compartment_id: str | None = os.getenv("OCI_COMPARTMENT_ID") or None

        # GitHub API Configuration
        self.github_token: str | None = os.getenv("GITHUB_TOKEN") or None

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
        self.webhook_secret: str | None = os.getenv("WEBHOOK_SECRET") or None
        self.webhook_subscription_id: str | None = (
            os.getenv("WEBHOOK_SUBSCRIPTION_ID") or None
        )
        self.queue_ocid: str | None = os.getenv("QUEUE_OCID") or None
        self.vault_ocid: str | None = os.getenv("VAULT_OCID") or None
        self.queue_url: str | None = os.getenv("QUEUE_URL") or None
        self.aws_region: str | None = os.getenv("AWS_REGION") or None

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
        elif self.queue_url:
            self.queue_provider = "aws"
        else:
            self.queue_provider = "none"

        self.tmi_client_path: str | None = os.getenv("TMI_CLIENT_PATH") or None

        # OCI service endpoints (required for in-cluster OKE access)
        self.queue_endpoint: str | None = os.getenv("QUEUE_ENDPOINT") or None
        self.vault_endpoint: str | None = os.getenv("VAULT_ENDPOINT") or None
        self.secrets_endpoint: str | None = os.getenv("SECRETS_ENDPOINT") or None

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
_config: Config | None = None


def get_config() -> Config:
    """Get or create global config instance."""
    global _config
    if _config is None:
        _config = Config()
    return _config


# LLM response file management
_response_dir: Path | None = None
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
