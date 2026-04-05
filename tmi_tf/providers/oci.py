"""OCI provider: signer helper and secret loading."""

import base64
import logging
import os
from typing import Optional

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
