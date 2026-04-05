"""Tests for secret provider protocol and factory."""

from unittest.mock import MagicMock

import pytest

from tmi_tf.providers import VAULT_SECRET_MAP, SecretProvider, get_secret_provider  # noqa: F401


class TestVaultSecretMap:
    def test_vault_secret_map_complete(self):
        expected = {
            "webhook-secret",
            "tmi-client-id",
            "tmi-client-secret",
            "llm-api-key",
            "github-token",
        }
        assert set(VAULT_SECRET_MAP.keys()) == expected

    def test_vault_secret_map_env_var_mapping(self):
        assert VAULT_SECRET_MAP["webhook-secret"] == "WEBHOOK_SECRET"
        assert VAULT_SECRET_MAP["tmi-client-id"] == "TMI_CLIENT_ID"
        assert VAULT_SECRET_MAP["tmi-client-secret"] == "TMI_CLIENT_SECRET"
        assert VAULT_SECRET_MAP["llm-api-key"] == "LLM_API_KEY"
        assert VAULT_SECRET_MAP["github-token"] == "GITHUB_TOKEN"


class TestGetSecretProvider:
    def test_factory_returns_oci_provider(self):
        config = MagicMock()
        config.secret_provider = "oci"
        config.vault_ocid = "ocid1.vault.oc1..test"
        config.oci_compartment_id = "ocid1.compartment.oc1..test"
        config.vault_endpoint = None
        config.secrets_endpoint = None
        provider = get_secret_provider(config)
        from tmi_tf.providers.oci import OciSecretProvider  # pyright: ignore[reportMissingImports]

        assert isinstance(provider, OciSecretProvider)

    def test_factory_returns_none_provider(self):
        config = MagicMock()
        config.secret_provider = "none"
        provider = get_secret_provider(config)
        from tmi_tf.providers.none import NoneSecretProvider  # pyright: ignore[reportMissingImports]

        assert isinstance(provider, NoneSecretProvider)

    def test_factory_raises_for_unknown_provider(self):
        config = MagicMock()
        config.secret_provider = "aws"
        with pytest.raises(ValueError, match="Unknown secret provider"):
            get_secret_provider(config)
