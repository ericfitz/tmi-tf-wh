"""Provider abstraction layer for secrets and queue operations."""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from tmi_tf.config import Config


@dataclass
class QueueMessage:
    body: dict[str, Any]
    receipt: str


class SecretProvider(Protocol):
    def load_secrets(self, secret_map: dict[str, str]) -> None:
        """Fetch secrets named in secret_map and set corresponding env vars.

        secret_map: {"secret-name": "ENV_VAR_NAME", ...}
        Errors for individual secrets are logged, not raised.
        """
        ...


class QueueProvider(Protocol):
    def publish(self, message: dict[str, Any]) -> None:
        """Serialize message and publish it to the queue."""
        ...

    def consume(
        self, max_messages: int = 1, visibility_timeout: int = 900
    ) -> list["QueueMessage"]:
        """Get messages from the queue and return parsed QueueMessage objects."""
        ...

    def delete(self, receipt: str) -> None:
        """Delete a message from the queue by its receipt."""
        ...


@dataclass
class LLMResponse:
    """Response from an LLM completion call."""

    text: str | None
    input_tokens: int
    output_tokens: int
    cost: float
    finish_reason: str


class LLMProvider(Protocol):
    """Protocol for LLM provider implementations."""

    @property
    def model(self) -> str:
        """Fully-qualified model name with LiteLLM prefix."""
        ...

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 16000,
        timeout: float = 300.0,
    ) -> LLMResponse:
        """Make a single LLM completion call."""
        ...


VAULT_SECRET_MAP = {
    "webhook-secret": "WEBHOOK_SECRET",
    "tmi-client-id": "TMI_CLIENT_ID",
    "tmi-client-secret": "TMI_CLIENT_SECRET",
    "llm-api-key": "LLM_API_KEY",
    "github-token": "GITHUB_TOKEN",
}


def get_secret_provider(config: "Config") -> SecretProvider:
    """Create a SecretProvider based on configuration."""
    if config.secret_provider == "oci":
        from tmi_tf.providers.oci import OciSecretProvider

        return OciSecretProvider(
            vault_ocid=config.vault_ocid or "",
            compartment_ocid=config.oci_compartment_id or "",
            vault_endpoint=config.vault_endpoint,
            secrets_endpoint=config.secrets_endpoint,
        )
    elif config.secret_provider == "none":
        from tmi_tf.providers.none import NoneSecretProvider

        return NoneSecretProvider()
    else:
        raise ValueError(
            f"Unknown secret provider: {config.secret_provider!r}. "
            f"Must be 'oci' or 'none'."
        )


def get_queue_provider(config: "Config") -> QueueProvider:
    """Create a QueueProvider based on configuration."""
    if config.queue_provider == "oci":
        from tmi_tf.providers.oci import OciQueueProvider

        return OciQueueProvider(
            queue_ocid=config.queue_ocid or "",
            queue_endpoint=config.queue_endpoint,
        )
    else:
        raise ValueError(
            f"Unknown queue provider: {config.queue_provider!r}. Must be 'oci'."
        )
