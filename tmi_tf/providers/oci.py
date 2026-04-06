"""OCI provider: signer helper and secret loading."""

import base64
import json
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from tmi_tf.providers import QueueMessage

logger = logging.getLogger(__name__)


def get_oci_signer():  # type: ignore[return]
    """Return an OCI signer, preferring resource principal over config file.

    Tries get_resource_principals_signer() first (handles both instance
    principals and OKE workload identity), then falls back to ~/.oci/config.
    """
    try:
        from oci.auth.signers import get_resource_principals_signer  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

        signer = get_resource_principals_signer()
        logger.debug("Using OCI resource principal signer")
        return signer
    except Exception as e:
        logger.debug(
            "Resource principal signer unavailable (%s), falling back to ~/.oci/config",
            e,
        )

    from oci.config import from_file  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]
    from oci.signer import Signer  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

    config = from_file()
    signer = Signer(
        tenancy=config["tenancy"],
        user=config["user"],
        fingerprint=config["fingerprint"],
        private_key_file_location=config["key_file"],
        pass_phrase=config.get("pass_phrase"),
    )
    logger.debug("Using OCI config file signer")
    return signer


def _get_vaults_client(vault_endpoint: Optional[str] = None):  # type: ignore[return]
    """Create and return an OCI VaultsClient using the shared signer."""
    from oci.vault import VaultsClient  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

    signer = get_oci_signer()
    kwargs: dict = {"config": {}, "signer": signer}
    if vault_endpoint:
        kwargs["service_endpoint"] = vault_endpoint
    return VaultsClient(**kwargs)


def _get_secrets_client(secrets_endpoint: Optional[str] = None):  # type: ignore[return]
    """Create and return an OCI SecretsClient using the shared signer."""
    from oci.secrets import SecretsClient  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

    signer = get_oci_signer()
    kwargs: dict = {"config": {}, "signer": signer}
    if secrets_endpoint:
        kwargs["service_endpoint"] = secrets_endpoint
    return SecretsClient(**kwargs)


class OciSecretProvider:
    """Load secrets from OCI Vault and set them as environment variables."""

    def __init__(
        self,
        vault_ocid: str,
        compartment_ocid: str,
        vault_endpoint: Optional[str] = None,
        secrets_endpoint: Optional[str] = None,
    ) -> None:
        self._vault_ocid = vault_ocid
        self._compartment_ocid = compartment_ocid
        self._vault_endpoint = vault_endpoint
        self._secrets_endpoint = secrets_endpoint

    def load_secrets(self, secret_map: dict[str, str]) -> None:
        """Fetch secrets from OCI Vault and set corresponding env vars.

        Lists secrets in the vault, fetches each that appears in secret_map,
        base64-decodes the content, and sets the environment variable.
        Errors for individual secrets are logged but not raised.
        """
        vaults_client = _get_vaults_client(self._vault_endpoint)
        secrets_client = _get_secrets_client(self._secrets_endpoint)

        try:
            list_response = vaults_client.list_secrets(
                compartment_id=self._compartment_ocid,
                vault_id=self._vault_ocid,
            )
            vault_secrets = list_response.data  # pyright: ignore[reportOptionalMemberAccess]
        except Exception as e:
            logger.error(
                "Failed to list secrets from vault %s: %s", self._vault_ocid, e
            )
            return

        for secret in vault_secrets:
            secret_name: str = secret.secret_name
            env_var = secret_map.get(secret_name)
            if env_var is None:
                continue

            try:
                bundle_response = secrets_client.get_secret_bundle(secret.id)
                content_b64: str = (
                    bundle_response.data.data.secret_bundle_content.content  # pyright: ignore[reportOptionalMemberAccess]
                )
                value = base64.b64decode(content_b64).decode("utf-8")
                os.environ[env_var] = value
                logger.info("Loaded secret %s -> %s", secret_name, env_var)
            except Exception as e:
                logger.error("Failed to load secret %s: %s", secret_name, e)


class OciQueueProvider:
    """OCI Queue SDK wrapper for publish/consume/delete operations."""

    def __init__(self, queue_ocid: str, queue_endpoint: Optional[str] = None) -> None:
        self._queue_ocid = queue_ocid
        self._queue_endpoint = queue_endpoint
        self._client = None

    def _get_client(self):  # type: ignore[return]
        """Lazy-initialize and return the OCI QueueClient."""
        if self._client is None:
            from oci.queue import QueueClient as OCIQueueClient  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

            signer = get_oci_signer()
            kwargs: dict = {"config": {}, "signer": signer}
            if self._queue_endpoint:
                kwargs["service_endpoint"] = self._queue_endpoint
            self._client = OCIQueueClient(**kwargs)
        return self._client

    def publish(self, message: dict[str, Any]) -> None:
        """Serialize message to JSON and publish it to the queue."""
        from oci.queue.models import PutMessagesDetails, PutMessagesDetailsEntry  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

        client = self._get_client()
        body = json.dumps(message)
        entry = PutMessagesDetailsEntry(content=body)
        details = PutMessagesDetails(messages=[entry])
        client.put_messages(queue_id=self._queue_ocid, put_messages_details=details)
        job_id = message.get("job_id", "<unknown>")
        logger.info(
            "Published message for job_id=%s to queue %s", job_id, self._queue_ocid
        )

    def consume(
        self, max_messages: int = 1, visibility_timeout: int = 900
    ) -> list["QueueMessage"]:
        """Get messages from the queue and return parsed QueueMessage objects.

        If JSON parsing fails for a message, it is deleted from the queue and skipped.
        """
        from tmi_tf.providers import QueueMessage

        client = self._get_client()
        response = client.get_messages(
            queue_id=self._queue_ocid,
            visibility_in_seconds=visibility_timeout,
            limit=max_messages,
        )
        raw_messages = response.data.messages or []
        result: list[QueueMessage] = []
        for msg in raw_messages:
            try:
                body = json.loads(msg.content)
            except (json.JSONDecodeError, TypeError) as e:
                logger.warning(
                    "Failed to parse message body (receipt=%s): %s — deleting",
                    msg.receipt,
                    e,
                )
                try:
                    self.delete(msg.receipt)
                except Exception as del_err:
                    logger.error(
                        "Failed to delete unparseable message (receipt=%s): %s",
                        msg.receipt,
                        del_err,
                    )
                continue
            result.append(QueueMessage(body=body, receipt=msg.receipt))
        return result

    def delete(self, receipt: str) -> None:
        """Delete a message from the queue by its receipt."""
        client = self._get_client()
        client.delete_message(queue_id=self._queue_ocid, message_receipt=receipt)
        logger.debug(
            "Deleted message with receipt=%s from queue %s", receipt, self._queue_ocid
        )


from tmi_tf.providers.llm_base import BaseLLMProvider  # noqa: E402

OCI_DEFAULT_MODEL = "oci/xai.grok-4"


class OciLLMProvider(BaseLLMProvider):
    """LLM provider for OCI Generative AI service."""

    def __init__(self, model: str | None) -> None:
        compartment_id = os.environ.get("OCI_COMPARTMENT_ID")
        if not compartment_id:
            raise ValueError(
                "OCI_COMPARTMENT_ID required when LLM_PROVIDER=oci. "
                "Set it in your .env file or environment."
            )

        config_profile = os.environ.get("OCI_CONFIG_PROFILE", "DEFAULT")

        if model:
            resolved_model = model if "/" in model else f"oci/{model}"
        else:
            resolved_model = OCI_DEFAULT_MODEL

        super().__init__(provider="oci", model=resolved_model)

        # Build completion kwargs
        oci_config_path = Path.home() / ".oci" / "config"
        if oci_config_path.exists():
            from oci.config import from_file as oci_from_file  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

            oci_config = oci_from_file(str(oci_config_path), config_profile)
            self._extra_kwargs = {
                "oci_region": oci_config.get("region", "us-ashburn-1"),
                "oci_user": oci_config["user"],
                "oci_fingerprint": oci_config["fingerprint"],
                "oci_tenancy": oci_config["tenancy"],
                "oci_key_file": oci_config["key_file"],
                "oci_compartment_id": compartment_id,
            }
        else:
            try:
                from oci.auth.signers import get_resource_principals_signer  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

                signer = get_resource_principals_signer()
                region = getattr(signer, "region", None) or "us-ashburn-1"
                self._extra_kwargs = {
                    "oci_region": region,
                    "oci_compartment_id": compartment_id,
                    "oci_signer": signer,
                }
            except Exception as e:
                logger.error("No OCI credentials available for LLM calls: %s", e)
                self._extra_kwargs = {"oci_compartment_id": compartment_id}

        logger.info(
            "Initialized OCI LLM provider: model=%s, compartment=%s",
            resolved_model,
            compartment_id,
        )
