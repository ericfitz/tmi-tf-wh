"""Provider abstraction layer for secret loading."""

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from tmi_tf.config import Config

VAULT_SECRET_MAP = {
    "webhook-secret": "WEBHOOK_SECRET",
    "tmi-client-id": "TMI_CLIENT_ID",
    "tmi-client-secret": "TMI_CLIENT_SECRET",
    "llm-api-key": "LLM_API_KEY",
    "github-token": "GITHUB_TOKEN",
}


class SecretProvider(Protocol):
    def load_secrets(self, secret_map: dict[str, str]) -> None:
        """Fetch secrets named in secret_map and set corresponding env vars.

        secret_map: {"secret-name": "ENV_VAR_NAME", ...}
        Errors for individual secrets are logged, not raised.
        """
        ...


def get_secret_provider(config: "Config") -> SecretProvider:
    """Create a SecretProvider based on configuration."""
    if config.secret_provider == "oci":
        from tmi_tf.providers.oci import OciSecretProvider  # pyright: ignore[reportMissingImports]

        return OciSecretProvider(
            vault_ocid=config.vault_ocid or "",
            compartment_ocid=config.oci_compartment_id or "",
            vault_endpoint=config.vault_endpoint,
            secrets_endpoint=config.secrets_endpoint,
        )
    elif config.secret_provider == "none":
        from tmi_tf.providers.none import NoneSecretProvider  # pyright: ignore[reportMissingImports]

        return NoneSecretProvider()
    else:
        raise ValueError(
            f"Unknown secret provider: {config.secret_provider!r}. "
            f"Must be 'oci' or 'none'."
        )
