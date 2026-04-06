"""Tests for secret provider protocol and factory."""

import json
import os
from dataclasses import fields
from unittest.mock import MagicMock, patch

import pytest  # type: ignore # ty:ignore[unresolved-import]

from tmi_tf.providers import (  # noqa: F401
    VAULT_SECRET_MAP,
    QueueMessage,
    QueueProvider,
    SecretProvider,
    get_queue_provider,
    get_secret_provider,
)


class TestQueueMessage:
    def test_is_dataclass_with_body_and_receipt(self):
        msg = QueueMessage(body={"job_id": "j1"}, receipt="r1")
        assert msg.body == {"job_id": "j1"}
        assert msg.receipt == "r1"

    def test_fields(self):
        names = {f.name for f in fields(QueueMessage)}
        assert names == {"body", "receipt"}


class TestQueueProviderProtocol:
    def test_protocol_has_required_methods(self):
        assert hasattr(QueueProvider, "publish")
        assert hasattr(QueueProvider, "consume")
        assert hasattr(QueueProvider, "delete")


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
        from tmi_tf.providers.oci import OciSecretProvider

        assert isinstance(provider, OciSecretProvider)

    def test_factory_returns_none_provider(self):
        config = MagicMock()
        config.secret_provider = "none"
        provider = get_secret_provider(config)
        from tmi_tf.providers.none import NoneSecretProvider

        assert isinstance(provider, NoneSecretProvider)

    def test_factory_raises_for_unknown_provider(self):
        config = MagicMock()
        config.secret_provider = "aws"
        with pytest.raises(ValueError, match="Unknown secret provider"):
            get_secret_provider(config)


class TestGetOciSigner:
    @patch("oci.auth.signers.get_resource_principals_signer", create=True)
    def test_prefers_resource_principal(self, mock_rp):
        from tmi_tf.providers.oci import get_oci_signer

        mock_signer = MagicMock()
        mock_rp.return_value = mock_signer
        result = get_oci_signer()
        assert result is mock_signer

    @patch(
        "oci.auth.signers.get_resource_principals_signer",
        create=True,
        side_effect=Exception("no RP"),
    )
    @patch("oci.config.from_file", create=True)
    @patch("oci.signer.Signer", create=True)
    def test_falls_back_to_config_file(self, mock_signer_cls, mock_from_file, mock_rp):
        from tmi_tf.providers.oci import get_oci_signer

        mock_from_file.return_value = {
            "tenancy": "ocid1.tenancy.oc1..test",
            "user": "ocid1.user.oc1..test",
            "fingerprint": "aa:bb:cc",
            "key_file": "/path/to/key.pem",
        }
        mock_signer_obj = MagicMock()
        mock_signer_cls.return_value = mock_signer_obj
        result = get_oci_signer()
        assert result is mock_signer_obj
        mock_signer_cls.assert_called_once_with(
            tenancy="ocid1.tenancy.oc1..test",
            user="ocid1.user.oc1..test",
            fingerprint="aa:bb:cc",
            private_key_file_location="/path/to/key.pem",
            pass_phrase=None,
        )


class TestOciSecretProvider:
    @patch("tmi_tf.providers.oci._get_secrets_client")
    @patch("tmi_tf.providers.oci._get_vaults_client")
    def test_loads_secrets_into_env(self, mock_vaults_client, mock_secrets_client):
        from tmi_tf.providers.oci import OciSecretProvider

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

        provider = OciSecretProvider(
            vault_ocid="ocid1.vault.oc1..test",
            compartment_ocid="ocid1.compartment.oc1..test",
        )
        provider.load_secrets({"webhook-secret": "WEBHOOK_SECRET"})
        assert os.environ.get("WEBHOOK_SECRET") == "test-value"

    @patch("tmi_tf.providers.oci._get_secrets_client")
    @patch("tmi_tf.providers.oci._get_vaults_client")
    def test_loads_multiple_secrets(self, mock_vaults_client, mock_secrets_client):
        import base64

        from tmi_tf.providers.oci import OciSecretProvider

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

        provider = OciSecretProvider(
            vault_ocid="ocid1.vault.oc1..test",
            compartment_ocid="ocid1.compartment.oc1..test",
        )
        provider.load_secrets(
            {"tmi-client-id": "TMI_CLIENT_ID", "tmi-client-secret": "TMI_CLIENT_SECRET"}
        )
        assert os.environ.get("TMI_CLIENT_ID") == "client-id-value"
        assert os.environ.get("TMI_CLIENT_SECRET") == "client-secret-value"

    @patch("tmi_tf.providers.oci._get_secrets_client")
    @patch("tmi_tf.providers.oci._get_vaults_client")
    def test_skips_unknown_secrets(self, mock_vaults_client, mock_secrets_client):
        from tmi_tf.providers.oci import OciSecretProvider

        mock_secret = MagicMock()
        mock_secret.secret_name = "unknown-secret"
        mock_vaults_client.return_value.list_secrets.return_value.data = [mock_secret]

        provider = OciSecretProvider(
            vault_ocid="ocid1.vault.oc1..test",
            compartment_ocid="ocid1.compartment.oc1..test",
        )
        provider.load_secrets({"webhook-secret": "WEBHOOK_SECRET"})
        mock_secrets_client.return_value.get_secret_bundle.assert_not_called()

    @patch("tmi_tf.providers.oci._get_secrets_client")
    @patch("tmi_tf.providers.oci._get_vaults_client")
    def test_handles_individual_secret_errors_gracefully(
        self, mock_vaults_client, mock_secrets_client
    ):
        from tmi_tf.providers.oci import OciSecretProvider

        mock_secret = MagicMock()
        mock_secret.secret_name = "llm-api-key"
        mock_vaults_client.return_value.list_secrets.return_value.data = [mock_secret]
        mock_secrets_client.return_value.get_secret_bundle.side_effect = Exception(
            "OCI error"
        )

        provider = OciSecretProvider(
            vault_ocid="ocid1.vault.oc1..test",
            compartment_ocid="ocid1.compartment.oc1..test",
        )
        # Should not raise
        provider.load_secrets({"llm-api-key": "LLM_API_KEY"})

    @patch("tmi_tf.providers.oci.get_oci_signer")
    def test_vaults_client_uses_service_endpoint(self, mock_signer):
        mock_signer.return_value = MagicMock()
        with patch("oci.vault.VaultsClient", create=True) as mock_cls:
            from tmi_tf.providers.oci import _get_vaults_client

            _get_vaults_client(
                vault_endpoint="https://vaults.us-ashburn-1.oci.oraclecloud.com"
            )
            mock_cls.assert_called_once_with(
                config={},
                signer=mock_signer.return_value,
                service_endpoint="https://vaults.us-ashburn-1.oci.oraclecloud.com",
            )

    @patch("tmi_tf.providers.oci.get_oci_signer")
    def test_vaults_client_no_endpoint_when_none(self, mock_signer):
        mock_signer.return_value = MagicMock()
        with patch("oci.vault.VaultsClient", create=True) as mock_cls:
            from tmi_tf.providers.oci import _get_vaults_client

            _get_vaults_client(vault_endpoint=None)
            mock_cls.assert_called_once_with(
                config={},
                signer=mock_signer.return_value,
            )

    @patch("tmi_tf.providers.oci.get_oci_signer")
    def test_secrets_client_uses_service_endpoint(self, mock_signer):
        mock_signer.return_value = MagicMock()
        with patch("oci.secrets.SecretsClient", create=True) as mock_cls:
            from tmi_tf.providers.oci import _get_secrets_client

            _get_secrets_client(
                secrets_endpoint="https://secrets.vaults.us-ashburn-1.oci.oraclecloud.com"
            )
            mock_cls.assert_called_once_with(
                config={},
                signer=mock_signer.return_value,
                service_endpoint="https://secrets.vaults.us-ashburn-1.oci.oraclecloud.com",
            )

    @patch("tmi_tf.providers.oci.get_oci_signer")
    def test_secrets_client_no_endpoint_when_none(self, mock_signer):
        mock_signer.return_value = MagicMock()
        with patch("oci.secrets.SecretsClient", create=True) as mock_cls:
            from tmi_tf.providers.oci import _get_secrets_client

            _get_secrets_client(secrets_endpoint=None)
            mock_cls.assert_called_once_with(
                config={},
                signer=mock_signer.return_value,
            )


class TestNoneSecretProvider:
    def test_load_secrets_is_noop(self):
        from tmi_tf.providers.none import NoneSecretProvider

        provider = NoneSecretProvider()
        # Should not raise
        provider.load_secrets({"webhook-secret": "WEBHOOK_SECRET"})

    def test_conforms_to_protocol(self):
        from tmi_tf.providers.none import NoneSecretProvider

        provider = NoneSecretProvider()
        assert hasattr(provider, "load_secrets")
        assert callable(provider.load_secrets)


class TestOciQueueProvider:
    @patch("tmi_tf.providers.oci.OciQueueProvider._get_client")
    def test_publish(self, mock_get: MagicMock) -> None:
        from tmi_tf.providers.oci import OciQueueProvider

        mock_client = MagicMock()
        mock_get.return_value = mock_client
        provider = OciQueueProvider(
            queue_ocid="ocid1.queue.oc1..test", queue_endpoint=None
        )
        provider.publish({"job_id": "j1", "threat_model_id": "tm-1"})
        mock_client.put_messages.assert_called_once()

    @patch("tmi_tf.providers.oci.OciQueueProvider._get_client")
    def test_consume_returns_messages(self, mock_get: MagicMock) -> None:
        from tmi_tf.providers.oci import OciQueueProvider

        mock_client = MagicMock()
        mock_msg = MagicMock()
        mock_msg.content = json.dumps({"job_id": "j1"})
        mock_msg.receipt = "receipt-1"
        mock_client.get_messages.return_value.data.messages = [mock_msg]
        mock_get.return_value = mock_client
        provider = OciQueueProvider(
            queue_ocid="ocid1.queue.oc1..test", queue_endpoint=None
        )
        messages = provider.consume(max_messages=1)
        assert len(messages) == 1
        assert messages[0].body == {"job_id": "j1"}
        assert messages[0].receipt == "receipt-1"

    @patch("tmi_tf.providers.oci.OciQueueProvider._get_client")
    def test_delete(self, mock_get: MagicMock) -> None:
        from tmi_tf.providers.oci import OciQueueProvider

        mock_client = MagicMock()
        mock_get.return_value = mock_client
        provider = OciQueueProvider(
            queue_ocid="ocid1.queue.oc1..test", queue_endpoint=None
        )
        provider.delete("receipt-1")
        mock_client.delete_message.assert_called_once()

    @patch("tmi_tf.providers.oci.OciQueueProvider._get_client")
    def test_consume_skips_unparseable_messages(self, mock_get: MagicMock) -> None:
        from tmi_tf.providers.oci import OciQueueProvider

        mock_client = MagicMock()
        bad_msg = MagicMock()
        bad_msg.content = "not-json"
        bad_msg.receipt = "bad-receipt"
        good_msg = MagicMock()
        good_msg.content = json.dumps({"job_id": "j2"})
        good_msg.receipt = "good-receipt"
        mock_client.get_messages.return_value.data.messages = [bad_msg, good_msg]
        mock_get.return_value = mock_client
        provider = OciQueueProvider(
            queue_ocid="ocid1.queue.oc1..test", queue_endpoint=None
        )
        messages = provider.consume()
        assert len(messages) == 1
        assert messages[0].body == {"job_id": "j2"}
        # Bad message should have been deleted
        mock_client.delete_message.assert_called_once()

    @patch("tmi_tf.providers.oci.get_oci_signer")
    @patch("oci.queue.QueueClient", create=True)
    def test_get_client_uses_service_endpoint(
        self, mock_oci_cls: MagicMock, mock_signer: MagicMock
    ) -> None:
        from tmi_tf.providers.oci import OciQueueProvider

        mock_signer.return_value = MagicMock()
        provider = OciQueueProvider(
            queue_ocid="ocid1.queue.oc1..test",
            queue_endpoint="https://cell-1.queue.oc1.us-ashburn-1.oci.oraclecloud.com",
        )
        provider._get_client()
        mock_oci_cls.assert_called_once_with(
            config={},
            signer=mock_signer.return_value,
            service_endpoint="https://cell-1.queue.oc1.us-ashburn-1.oci.oraclecloud.com",
        )

    @patch("tmi_tf.providers.oci.get_oci_signer")
    @patch("oci.queue.QueueClient", create=True)
    def test_get_client_no_endpoint_when_none(
        self, mock_oci_cls: MagicMock, mock_signer: MagicMock
    ) -> None:
        from tmi_tf.providers.oci import OciQueueProvider

        mock_signer.return_value = MagicMock()
        provider = OciQueueProvider(
            queue_ocid="ocid1.queue.oc1..test", queue_endpoint=None
        )
        provider._get_client()
        mock_oci_cls.assert_called_once_with(
            config={},
            signer=mock_signer.return_value,
        )


class TestSecretProviderConfig:
    @patch("tmi_tf.config.load_dotenv")
    def test_defaults_to_oci_when_vault_ocid_set(self, mock_dotenv):
        with patch.dict(
            os.environ,
            {
                "VAULT_OCID": "ocid1.vault.oc1..test",
                "ANTHROPIC_API_KEY": "test-key",
            },
            clear=True,
        ):
            from tmi_tf.config import Config

            config = Config()
            assert config.secret_provider == "oci"

    @patch("tmi_tf.config.load_dotenv")
    def test_defaults_to_none_when_no_vault_ocid(self, mock_dotenv):
        with patch.dict(
            os.environ,
            {"ANTHROPIC_API_KEY": "test-key"},
            clear=True,
        ):
            from tmi_tf.config import Config

            config = Config()
            assert config.secret_provider == "none"

    @patch("tmi_tf.config.load_dotenv")
    def test_explicit_secret_provider_overrides_inference(self, mock_dotenv):
        with patch.dict(
            os.environ,
            {
                "SECRET_PROVIDER": "none",
                "VAULT_OCID": "ocid1.vault.oc1..test",
                "ANTHROPIC_API_KEY": "test-key",
            },
            clear=True,
        ):
            from tmi_tf.config import Config

            config = Config()
            assert config.secret_provider == "none"


class TestGetQueueProvider:
    def test_factory_returns_oci_provider(self):
        config = MagicMock()
        config.queue_provider = "oci"
        config.queue_ocid = "ocid1.queue.oc1..test"
        config.queue_endpoint = None
        provider = get_queue_provider(config)
        from tmi_tf.providers.oci import OciQueueProvider

        assert isinstance(provider, OciQueueProvider)

    def test_factory_raises_for_unknown_provider(self):
        config = MagicMock()
        config.queue_provider = "aws"
        with pytest.raises(ValueError, match="Unknown queue provider"):
            get_queue_provider(config)


class TestQueueProviderConfig:
    @patch("tmi_tf.config.load_dotenv")
    def test_defaults_to_oci_when_queue_ocid_set(self, mock_dotenv):
        with patch.dict(
            os.environ,
            {
                "QUEUE_OCID": "ocid1.queue.oc1..test",
                "ANTHROPIC_API_KEY": "test-key",
            },
            clear=True,
        ):
            from tmi_tf.config import Config

            config = Config()
            assert config.queue_provider == "oci"

    @patch("tmi_tf.config.load_dotenv")
    def test_defaults_to_none_when_no_queue_ocid(self, mock_dotenv):
        with patch.dict(
            os.environ,
            {"ANTHROPIC_API_KEY": "test-key"},
            clear=True,
        ):
            from tmi_tf.config import Config

            config = Config()
            assert config.queue_provider == "none"

    @patch("tmi_tf.config.load_dotenv")
    def test_explicit_queue_provider_overrides_inference(self, mock_dotenv):
        with patch.dict(
            os.environ,
            {
                "QUEUE_PROVIDER": "oci",
                "ANTHROPIC_API_KEY": "test-key",
            },
            clear=True,
        ):
            from tmi_tf.config import Config

            config = Config()
            assert config.queue_provider == "oci"
