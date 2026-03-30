# pyright: reportPrivateImportUsage=false
"""Tests for OCI Vault client secret loading."""

import os
from unittest.mock import MagicMock, patch

from tmi_tf.vault_client import VAULT_SECRET_MAP, load_secrets_from_vault


class TestLoadSecrets:
    @patch("tmi_tf.vault_client._get_secrets_client")
    @patch("tmi_tf.vault_client._get_vaults_client")
    def test_loads_secrets_into_env(self, mock_vaults_client, mock_secrets_client):
        mock_secret = MagicMock()
        mock_secret.secret_name = "webhook-secret"
        mock_vaults_client.return_value.list_secrets.return_value.data = [mock_secret]
        mock_bundle = MagicMock()
        mock_bundle.data.secret_bundle_content.content = (
            "dGVzdC12YWx1ZQ=="  # base64 "test-value"
        )
        mock_secrets_client.return_value.get_secret_bundle.return_value.data = (
            mock_bundle
        )
        load_secrets_from_vault("ocid1.vault.oc1..test", "ocid1.compartment.oc1..test")
        assert os.environ.get("WEBHOOK_SECRET") == "test-value"

    def test_vault_secret_map_complete(self):
        expected = {
            "webhook-secret",
            "tmi-client-id",
            "tmi-client-secret",
            "llm-api-key",
            "github-token",
        }
        assert set(VAULT_SECRET_MAP.keys()) == expected

    @patch("tmi_tf.vault_client._get_secrets_client")
    @patch("tmi_tf.vault_client._get_vaults_client")
    def test_loads_multiple_secrets(self, mock_vaults_client, mock_secrets_client):
        import base64

        mock_secret1 = MagicMock()
        mock_secret1.secret_name = "tmi-client-id"
        mock_secret2 = MagicMock()
        mock_secret2.secret_name = "tmi-client-secret"
        mock_vaults_client.return_value.list_secrets.return_value.data = [
            mock_secret1,
            mock_secret2,
        ]

        response1 = MagicMock()
        response1.data.data.secret_bundle_content.content = base64.b64encode(
            b"client-id-value"
        ).decode()
        response2 = MagicMock()
        response2.data.data.secret_bundle_content.content = base64.b64encode(
            b"client-secret-value"
        ).decode()

        mock_secrets_client.return_value.get_secret_bundle.side_effect = [
            response1,
            response2,
        ]
        load_secrets_from_vault("ocid1.vault.oc1..test", "ocid1.compartment.oc1..test")
        assert os.environ.get("TMI_CLIENT_ID") == "client-id-value"
        assert os.environ.get("TMI_CLIENT_SECRET") == "client-secret-value"

    @patch("tmi_tf.vault_client._get_secrets_client")
    @patch("tmi_tf.vault_client._get_vaults_client")
    def test_skips_unknown_secrets(self, mock_vaults_client, mock_secrets_client):
        mock_secret = MagicMock()
        mock_secret.secret_name = "unknown-secret"
        mock_vaults_client.return_value.list_secrets.return_value.data = [mock_secret]
        load_secrets_from_vault("ocid1.vault.oc1..test", "ocid1.compartment.oc1..test")
        # get_secret_bundle should not have been called for an unknown secret
        mock_secrets_client.return_value.get_secret_bundle.assert_not_called()

    @patch("tmi_tf.vault_client._get_secrets_client")
    @patch("tmi_tf.vault_client._get_vaults_client")
    def test_handles_individual_secret_errors_gracefully(
        self, mock_vaults_client, mock_secrets_client
    ):
        mock_secret = MagicMock()
        mock_secret.secret_name = "llm-api-key"
        mock_vaults_client.return_value.list_secrets.return_value.data = [mock_secret]
        mock_secrets_client.return_value.get_secret_bundle.side_effect = Exception(
            "OCI error"
        )
        # Should not raise
        load_secrets_from_vault("ocid1.vault.oc1..test", "ocid1.compartment.oc1..test")

    def test_vault_secret_map_env_var_mapping(self):
        assert VAULT_SECRET_MAP["webhook-secret"] == "WEBHOOK_SECRET"
        assert VAULT_SECRET_MAP["tmi-client-id"] == "TMI_CLIENT_ID"
        assert VAULT_SECRET_MAP["tmi-client-secret"] == "TMI_CLIENT_SECRET"
        assert VAULT_SECRET_MAP["llm-api-key"] == "LLM_API_KEY"
        assert VAULT_SECRET_MAP["github-token"] == "GITHUB_TOKEN"


class TestServiceEndpoints:
    @patch("tmi_tf.vault_client._get_oci_signer")
    def test_vaults_client_uses_service_endpoint(self, mock_signer):
        mock_signer.return_value = MagicMock()
        with patch.dict(
            os.environ,
            {"VAULT_ENDPOINT": "https://vaults.us-ashburn-1.oci.oraclecloud.com"},
        ):
            with patch("oci.vault.VaultsClient", create=True) as mock_cls:
                from tmi_tf.vault_client import _get_vaults_client

                _get_vaults_client()
                mock_cls.assert_called_once_with(
                    config={},
                    signer=mock_signer.return_value,
                    service_endpoint="https://vaults.us-ashburn-1.oci.oraclecloud.com",
                )

    @patch("tmi_tf.vault_client._get_oci_signer")
    def test_vaults_client_no_endpoint_when_unset(self, mock_signer):
        mock_signer.return_value = MagicMock()
        with patch.dict(os.environ, {}, clear=False):
            # Ensure VAULT_ENDPOINT is not set
            os.environ.pop("VAULT_ENDPOINT", None)
            with patch("oci.vault.VaultsClient", create=True) as mock_cls:
                from tmi_tf.vault_client import _get_vaults_client

                _get_vaults_client()
                mock_cls.assert_called_once_with(
                    config={},
                    signer=mock_signer.return_value,
                )

    @patch("tmi_tf.vault_client._get_oci_signer")
    def test_secrets_client_uses_service_endpoint(self, mock_signer):
        mock_signer.return_value = MagicMock()
        with patch.dict(
            os.environ,
            {
                "SECRETS_ENDPOINT": "https://secrets.vaults.us-ashburn-1.oci.oraclecloud.com"
            },
        ):
            with patch("oci.secrets.SecretsClient", create=True) as mock_cls:
                from tmi_tf.vault_client import _get_secrets_client

                _get_secrets_client()
                mock_cls.assert_called_once_with(
                    config={},
                    signer=mock_signer.return_value,
                    service_endpoint="https://secrets.vaults.us-ashburn-1.oci.oraclecloud.com",
                )

    @patch("tmi_tf.vault_client._get_oci_signer")
    def test_secrets_client_no_endpoint_when_unset(self, mock_signer):
        mock_signer.return_value = MagicMock()
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SECRETS_ENDPOINT", None)
            with patch("oci.secrets.SecretsClient", create=True) as mock_cls:
                from tmi_tf.vault_client import _get_secrets_client

                _get_secrets_client()
                mock_cls.assert_called_once_with(
                    config={},
                    signer=mock_signer.return_value,
                )
