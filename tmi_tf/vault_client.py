"""OCI Vault client for loading secrets into environment variables."""

import base64
import logging
import os

logger = logging.getLogger(__name__)

VAULT_SECRET_MAP = {
    "webhook-secret": "WEBHOOK_SECRET",
    "tmi-client-id": "TMI_CLIENT_ID",
    "tmi-client-secret": "TMI_CLIENT_SECRET",
    "llm-api-key": "LLM_API_KEY",
    "github-token": "GITHUB_TOKEN",
}


def _get_oci_signer():  # type: ignore[return]
    """Return an OCI signer, preferring instance principal over config file."""
    try:
        from oci.auth.signers import InstancePrincipalsSecurityTokenSigner  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

        signer = InstancePrincipalsSecurityTokenSigner()
        logger.debug("Using OCI instance principal signer")
        return signer
    except Exception as e:
        logger.debug(
            "Instance principal signer unavailable (%s), falling back to ~/.oci/config",
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


def _get_secrets_client():  # type: ignore[return]
    """Create and return an OCI SecretsClient using the appropriate signer."""
    from oci.secrets import SecretsClient  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

    signer = _get_oci_signer()
    return SecretsClient(config={}, signer=signer)


def _get_vaults_client():  # type: ignore[return]
    """Create and return an OCI VaultsClient using the appropriate signer."""
    from oci.vault import VaultsClient  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

    signer = _get_oci_signer()
    return VaultsClient(config={}, signer=signer)


def load_secrets_from_vault(vault_ocid: str, compartment_ocid: str) -> None:
    """Load secrets from OCI Vault and set them as environment variables.

    Lists secrets in the given vault, fetches each secret that appears in
    VAULT_SECRET_MAP, base64-decodes the content, and sets the corresponding
    environment variable. Errors for individual secrets are logged but not raised.
    """
    vaults_client = _get_vaults_client()
    secrets_client = _get_secrets_client()

    try:
        list_response = vaults_client.list_secrets(
            compartment_id=compartment_ocid,
            vault_id=vault_ocid,
        )
        vault_secrets = list_response.data  # pyright: ignore[reportOptionalMemberAccess]
    except Exception as e:
        logger.error("Failed to list secrets from vault %s: %s", vault_ocid, e)
        return

    for secret in vault_secrets:
        secret_name: str = secret.secret_name
        env_var = VAULT_SECRET_MAP.get(secret_name)
        if env_var is None:
            continue

        try:
            bundle_response = secrets_client.get_secret_bundle(secret.id)
            content_b64: str = bundle_response.data.data.secret_bundle_content.content  # pyright: ignore[reportOptionalMemberAccess]
            value = base64.b64decode(content_b64).decode("utf-8")
            os.environ[env_var] = value
            logger.info("Loaded secret %s -> %s", secret_name, env_var)
        except Exception as e:
            logger.error("Failed to load secret %s: %s", secret_name, e)
