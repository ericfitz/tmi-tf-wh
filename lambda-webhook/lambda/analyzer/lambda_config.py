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

    def __init__(self, secrets: Dict[str, str]):
        """
        Initialize configuration from secrets dictionary.

        Args:
            secrets: Dictionary from AWS Secrets Manager containing configuration values
        """
        # TMI Server Configuration
        self.tmi_server_url: str = os.getenv("TMI_SERVER_URL", "https://api.tmi.dev")
        self.tmi_oauth_idp: str = "google"  # Not used for client credentials

        # Claude API Configuration
        self.anthropic_api_key: str = secrets.get('anthropic_api_key', '')
        if not self.anthropic_api_key:
            raise ValueError("anthropic_api_key not found in Secrets Manager")

        # GitHub API Configuration (optional)
        self.github_token: Optional[str] = secrets.get('github_token')

        # Application Settings (use Lambda environment variables with defaults)
        self.max_repos: int = int(os.getenv('MAX_REPOS', '1'))  # Lambda: analyze one repo at a time
        self.clone_timeout: int = int(os.getenv('CLONE_TIMEOUT', '300'))
        self.analysis_note_name: str = os.getenv(
            'ANALYSIS_NOTE_NAME', 'Terraform Analysis Report'
        )
        self.diagram_name: str = os.getenv(
            'DIAGRAM_NAME', 'Infrastructure Data Flow Diagram'
        )

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

    def __repr__(self) -> str:
        """Return string representation of config (without secrets)."""
        return (
            f"LambdaConfig(tmi_server_url={self.tmi_server_url}, "
            f"max_repos={self.max_repos}, "
            f"github_token={'***' if self.github_token else 'None'})"
        )
