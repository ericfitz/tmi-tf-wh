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
        "anthropic": "anthropic/claude-opus-4-6",
        "openai": "openai/gpt-5.4",
        "xai": "xai/grok-4-1-fast-reasoning",
        "gemini": "gemini/gemini-3.1-pro-preview",
        "oci": "oci/xai.grok-4",
    }

    # Provider prefixes for LiteLLM
    PROVIDER_PREFIXES = {
        "anthropic": "anthropic/",
        "openai": "openai/",
        "xai": "xai/",
        "gemini": "gemini/",
        "oci": "oci/",
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

        # Anthropic (Claude) API Configuration
        self.anthropic_api_key: Optional[str] = os.getenv("ANTHROPIC_API_KEY") or None

        # OpenAI API Configuration
        self.openai_api_key: Optional[str] = os.getenv("OPENAI_API_KEY") or None

        # x.ai (Grok) API Configuration
        self.xai_api_key: Optional[str] = os.getenv("XAI_API_KEY") or None

        # Google (Gemini) API Configuration
        self.gemini_api_key: Optional[str] = os.getenv("GEMINI_API_KEY") or None

        # OCI Generative AI Configuration
        self.oci_config_profile: str = os.getenv("OCI_CONFIG_PROFILE", "DEFAULT")
        self.oci_compartment_id: Optional[str] = os.getenv("OCI_COMPARTMENT_ID") or None

        # Validate credentials for selected provider
        self._validate_llm_credentials()

        # GitHub API Configuration
        self.github_token: Optional[str] = os.getenv("GITHUB_TOKEN") or None

        # Application Settings
        self.max_repos: int = int(os.getenv("MAX_REPOS", "3"))
        self.clone_timeout: int = int(os.getenv("CLONE_TIMEOUT", "300"))

        # Model identifier and timestamp for artifact naming (constructed in cli.py)
        self.effective_model: str = self.llm_model or self.DEFAULT_MODELS.get(
            self.llm_provider, "unknown"
        )
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

        self.tmi_client_path: Optional[str] = os.getenv("TMI_CLIENT_PATH") or None

        # OCI service endpoints (required for in-cluster OKE access)
        self.queue_endpoint: Optional[str] = os.getenv("QUEUE_ENDPOINT") or None
        self.vault_endpoint: Optional[str] = os.getenv("VAULT_ENDPOINT") or None
        self.secrets_endpoint: Optional[str] = os.getenv("SECRETS_ENDPOINT") or None

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
        elif self.llm_provider == "oci":
            if not self.oci_compartment_id:
                raise ValueError("OCI_COMPARTMENT_ID required when LLM_PROVIDER=oci")
            if not self._oci_credentials_available():
                logger.warning(
                    "OCI credentials not found via ~/.oci/config, instance principal, or IMDS. "
                    "LiteLLM will fail unless OCI credentials are available."
                )
        else:
            raise ValueError(
                f"Invalid LLM_PROVIDER: {self.llm_provider}. "
                f"Must be 'anthropic', 'openai', 'xai', 'gemini', or 'oci'"
            )

    @staticmethod
    def _oci_credentials_available() -> bool:
        """Check if OCI credentials are available.

        Checks in order: ~/.oci/config file, instance principal signer
        (works with OKE workload identity), IMDS metadata service.
        Returns True if any credential source is available.
        """
        import urllib.request

        # Check for OCI config file
        oci_config_path = Path.home() / ".oci" / "config"
        if oci_config_path.exists():
            return True

        # Check instance principal (OKE workload identity)
        try:
            from oci.auth.signers import InstancePrincipalsSecurityTokenSigner  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

            InstancePrincipalsSecurityTokenSigner()
            return True
        except Exception:
            pass

        # Check IMDS (OCI instance metadata service)
        try:
            req = urllib.request.Request(
                "http://169.254.169.254/opc/v2/instance/",
                headers={"Authorization": "Bearer Oracle"},
            )
            with urllib.request.urlopen(req, timeout=2):
                return True
        except Exception:
            return False

    def get_oci_completion_kwargs(self) -> dict:
        """Return kwargs to pass to litellm.completion() for OCI provider.

        For non-OCI providers, returns an empty dict so callers can always
        unpack this into their completion() calls.

        Tries instance principal (OKE workload identity) first, then
        falls back to ~/.oci/config — matching providers.oci.get_oci_signer().
        """
        if self.llm_provider != "oci":
            return {}

        oci_config_path = Path.home() / ".oci" / "config"
        if oci_config_path.exists():
            from oci.config import from_file as oci_from_file  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

            oci_config = oci_from_file(str(oci_config_path), self.oci_config_profile)
            return {
                "oci_region": oci_config.get("region", "us-ashburn-1"),
                "oci_user": oci_config["user"],
                "oci_fingerprint": oci_config["fingerprint"],
                "oci_tenancy": oci_config["tenancy"],
                "oci_key_file": oci_config["key_file"],
                "oci_compartment_id": self.oci_compartment_id,
            }

        # Instance principal (OKE workload identity)
        try:
            from oci.auth.signers import InstancePrincipalsSecurityTokenSigner  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

            signer = InstancePrincipalsSecurityTokenSigner()
            region = getattr(signer, "region", None) or "us-ashburn-1"
            return {
                "oci_region": region,
                "oci_compartment_id": self.oci_compartment_id,
                "oci_signer": signer,
            }
        except Exception as e:
            logger.error("No OCI credentials available for LLM calls: %s", e)
            return {}

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
