"""
OAuth 2.0 Client Credentials authenticator for AWS Lambda.

This module provides authentication for Lambda functions using OAuth 2.0
client credentials grant (machine-to-machine authentication).
"""

import os
import json
import logging
import boto3
import requests
from datetime import datetime, timedelta
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class LambdaOAuthClient:
    """OAuth 2.0 client credentials authenticator for Lambda environment."""

    # Class-level caches for Lambda container reuse
    _token_cache: Optional[str] = None
    _token_expires_at: Optional[datetime] = None
    _secrets: Optional[Dict[str, str]] = None

    def __init__(self, tmi_server_url: str, secrets_arn: Optional[str] = None):
        """
        Initialize Lambda OAuth client.

        Args:
            tmi_server_url: TMI server base URL (e.g., https://api.tmi.dev)
            secrets_arn: ARN of AWS Secrets Manager secret (defaults to SECRETS_ARN env var)
        """
        self.tmi_server_url = tmi_server_url
        self.secrets_arn = secrets_arn or os.environ.get('SECRETS_ARN')

        if not self.secrets_arn:
            raise ValueError("SECRETS_ARN environment variable not set")

        self.secretsmanager = boto3.client('secretsmanager')

    def get_token(self) -> str:
        """
        Get valid OAuth access token (uses cached token if still valid).

        Returns:
            JWT access token for TMI API authentication

        Raises:
            requests.HTTPError: If token exchange fails
        """
        # Check if cached token is still valid
        if self._token_cache and self._token_expires_at:
            if datetime.now() < self._token_expires_at:
                logger.info("Using cached OAuth token")
                return self._token_cache

        # Fetch new token
        logger.info("Fetching new OAuth token via client credentials")
        secrets = self._get_secrets()

        try:
            response = requests.post(
                f"{self.tmi_server_url}/oauth2/token",
                json={'grant_type': 'client_credentials'},
                auth=(secrets['client_id'], secrets['client_secret']),
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            response.raise_for_status()

            data = response.json()

            # Cache token with 60-second buffer before expiration
            LambdaOAuthClient._token_cache = data['access_token']
            expires_in = data.get('expires_in', 3600)
            LambdaOAuthClient._token_expires_at = datetime.now() + timedelta(seconds=expires_in - 60)

            logger.info(f"OAuth token obtained (expires in {expires_in}s)")
            return self._token_cache

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to obtain OAuth token: {e}")
            raise

    def _get_secrets(self) -> Dict[str, str]:
        """
        Load secrets from AWS Secrets Manager.

        Secrets are cached at class level for Lambda container reuse.

        Returns:
            Dictionary containing client_id, client_secret, and other credentials
        """
        if LambdaOAuthClient._secrets is None:
            try:
                logger.info(f"Loading secrets from {self.secrets_arn}")
                response = self.secretsmanager.get_secret_value(SecretId=self.secrets_arn)
                LambdaOAuthClient._secrets = json.loads(response['SecretString'])
                logger.info("Secrets loaded successfully")
            except Exception as e:
                logger.error(f"Failed to load secrets from Secrets Manager: {e}")
                raise

        return LambdaOAuthClient._secrets
