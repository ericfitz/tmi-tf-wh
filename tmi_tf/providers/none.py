"""No-op secret provider for environments with platform-injected secrets."""

import logging

logger = logging.getLogger(__name__)


class NoneSecretProvider:
    """No-op provider: assumes secrets are already in the environment."""

    def load_secrets(self, secret_map: dict[str, str]) -> None:
        """Log that secrets are expected from the environment and return."""
        logger.info(
            "Secret provider is 'none'; expecting %d secrets from environment",
            len(secret_map),
        )
