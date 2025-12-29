"""
Configuration adapter for Lambda environment.

This module creates Config objects compatible with the original tmi_tf.Config
but loads values from AWS Secrets Manager instead of .env files.
"""

import os
import json
import logging
import boto3
from pathlib import Path
from typing import Optional, Dict

logger = logging.getLogger(__name__)


class LambdaConfig:
    """Configuration for Lambda environment (mirrors tmi_tf.Config structure)."""

    # Default models for each provider
    DEFAULT_MODELS = {
        "anthropic": "claude-sonnet-4-5",
        "xai": "grok-beta",
        "gemini": "gemini-2.0-flash-exp",
    }

    def __init__(self, secrets: Dict[str, str]):
        """
        Initialize configuration from secrets dictionary.

        Args:
            secrets: Dictionary from AWS Secrets Manager containing configuration values
        """
        # TMI Server Configuration
        self.tmi_server_url: str = os.getenv("TMI_SERVER_URL", "https://api.tmi.dev")
        self.tmi_oauth_idp: str = "google"  # Not used for client credentials

        # LLM Provider Configuration
        self.llm_provider: str = os.getenv('LLM_PROVIDER', 'anthropic')  # anthropic, xai, or gemini
        self.llm_model: Optional[str] = os.getenv('LLM_MODEL')  # Optional model override

        # Anthropic (Claude) API Configuration
        self.anthropic_api_key: Optional[str] = secrets.get('anthropic_api_key')

        # x.ai (Grok) API Configuration
        self.xai_api_key: Optional[str] = secrets.get('xai_api_key')

        # Google Cloud (Gemini) Configuration
        self.gcp_service_account_key: Optional[str] = secrets.get('gcp_service_account_key')
        self.gcp_project_id: Optional[str] = secrets.get('gcp_project_id')
        self.gcp_location: str = secrets.get('gcp_location', 'us-central1')

        # Validate that required credentials exist for selected provider
        self._validate_llm_credentials()

        # GitHub API Configuration (optional)
        self.github_token: Optional[str] = secrets.get('github_token')

        # Application Settings (use Lambda environment variables with defaults)
        self.max_repos: int = int(os.getenv('MAX_REPOS', '1'))  # Lambda: analyze one repo at a time
        self.clone_timeout: int = int(os.getenv('CLONE_TIMEOUT', '300'))

        # Note and diagram names include model identifier
        effective_model = self.llm_model or self.DEFAULT_MODELS.get(
            self.llm_provider, "unknown"
        )
        base_note_name = os.getenv('ANALYSIS_NOTE_NAME', 'Terraform Analysis Report')
        base_diagram_name = os.getenv('DIAGRAM_NAME', 'Infrastructure Data Flow Diagram')
        self.analysis_note_name: str = f"{base_note_name} ({effective_model})"
        self.diagram_name: str = f"{base_diagram_name} ({effective_model})"

        # Lambda doesn't use token cache (uses OAuth client credentials instead)
        self.cache_dir = Path('/tmp/.tmi-tf')  # Lambda /tmp directory
        self.cache_dir.mkdir(exist_ok=True)
        self.token_cache_file = self.cache_dir / 'token.json'

    @classmethod
    def from_secrets_manager(cls, secrets_arn: Optional[str] = None) -> 'LambdaConfig':
        """
        Create configuration by loading secrets from AWS Secrets Manager.

        Args:
            secrets_arn: ARN of the Secrets Manager secret (defaults to SECRETS_ARN env var)

        Returns:
            LambdaConfig instance with loaded configuration

        Raises:
            ValueError: If SECRETS_ARN not provided and not in environment
        """
        arn = secrets_arn or os.environ.get('SECRETS_ARN')
        if not arn:
            raise ValueError("SECRETS_ARN environment variable not set")

        try:
            logger.info(f"Loading configuration from Secrets Manager: {arn}")
            secretsmanager = boto3.client('secretsmanager')
            response = secretsmanager.get_secret_value(SecretId=arn)
            secrets = json.loads(response['SecretString'])
            logger.info("Configuration loaded successfully")

            return cls(secrets)

        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise

    def _validate_llm_credentials(self):
        """Validate that required credentials exist for the selected LLM provider."""
        if self.llm_provider == 'anthropic':
            if not self.anthropic_api_key:
                raise ValueError("anthropic_api_key required when LLM_PROVIDER=anthropic")
        elif self.llm_provider == 'xai':
            if not self.xai_api_key:
                raise ValueError("xai_api_key required when LLM_PROVIDER=xai")
        elif self.llm_provider == 'gemini':
            if not self.gcp_service_account_key:
                raise ValueError("gcp_service_account_key required when LLM_PROVIDER=gemini")
            if not self.gcp_project_id:
                raise ValueError("gcp_project_id required when LLM_PROVIDER=gemini")
        else:
            raise ValueError(
                f"Invalid LLM_PROVIDER: {self.llm_provider}. "
                f"Must be 'anthropic', 'xai', or 'gemini'"
            )

    def __repr__(self) -> str:
        """Return string representation of config (without secrets)."""
        return (
            f"LambdaConfig(llm_provider={self.llm_provider}, "
            f"llm_model={self.llm_model or 'default'}, "
            f"tmi_server_url={self.tmi_server_url}, "
            f"max_repos={self.max_repos})"
        )
