# pyright: reportPrivateImportUsage=false
"""Tests for Config class changes: LLM_API_KEY mapping, server config vars, OCI IMDS."""

import os
from unittest.mock import MagicMock, patch

import pytest  # pyright: ignore[reportMissingImports] # ty:ignore[unresolved-import]

import tmi_tf.config as config_module
from tmi_tf.config import Config


def reset_config():
    """Reset the global config singleton between tests."""
    config_module._config = None


@pytest.fixture(autouse=True)
def clear_config_singleton():
    """Reset singleton before and after each test, and prevent .env from overriding test env vars."""
    reset_config()
    with patch("tmi_tf.config.load_dotenv"):
        yield
    reset_config()


class TestLLMAPIKeyMapping:
    @patch.dict(
        os.environ,
        {"LLM_PROVIDER": "anthropic", "LLM_API_KEY": "test-key-123"},
        clear=False,
    )
    def test_maps_llm_api_key_to_anthropic(self):
        Config()
        assert os.environ.get("ANTHROPIC_API_KEY") == "test-key-123"

    @patch.dict(
        os.environ,
        {"LLM_PROVIDER": "openai", "LLM_API_KEY": "test-key-456"},
        clear=False,
    )
    def test_maps_llm_api_key_to_openai(self):
        Config()
        assert os.environ.get("OPENAI_API_KEY") == "test-key-456"

    @patch.dict(
        os.environ,
        {"LLM_PROVIDER": "xai", "LLM_API_KEY": "test-key-xai"},
        clear=False,
    )
    def test_maps_llm_api_key_to_xai(self):
        Config()
        assert os.environ.get("XAI_API_KEY") == "test-key-xai"

    @patch.dict(
        os.environ,
        {"LLM_PROVIDER": "gemini", "LLM_API_KEY": "test-key-gemini"},
        clear=False,
    )
    def test_maps_llm_api_key_to_gemini(self):
        Config()
        assert os.environ.get("GEMINI_API_KEY") == "test-key-gemini"

    @patch.dict(
        os.environ,
        {
            "LLM_PROVIDER": "oci",
            "OCI_COMPARTMENT_ID": "ocid1.compartment.oc1..test",
            "LLM_API_KEY": "irrelevant-key",
        },
        clear=False,
    )
    @patch("tmi_tf.config.Config._oci_credentials_available", return_value=True)
    def test_oci_provider_no_key_map(self, mock_creds):
        # OCI is not in the key_map, so LLM_API_KEY should not set any OCI env var
        config = Config()
        assert config.llm_provider == "oci"
        # No OCI_API_KEY env var expected
        assert os.environ.get("OCI_API_KEY") is None


class TestServerConfigVars:
    @patch.dict(
        os.environ,
        {
            "LLM_PROVIDER": "anthropic",
            "ANTHROPIC_API_KEY": "test",
            "MAX_CONCURRENT_JOBS": "5",
            "JOB_TIMEOUT": "1800",
            "MAX_MESSAGE_AGE_HOURS": "12",
            "SERVER_PORT": "9090",
            "WEBHOOK_SECRET": "my-secret",
            "WEBHOOK_SUBSCRIPTION_ID": "sub-123",
        },
        clear=False,
    )
    def test_server_config_loaded(self):
        config = Config()
        assert config.max_concurrent_jobs == 5
        assert config.job_timeout == 1800
        assert config.max_message_age_hours == 12
        assert config.server_port == 9090
        assert config.webhook_secret == "my-secret"
        assert config.webhook_subscription_id == "sub-123"

    @patch.dict(
        os.environ,
        {"LLM_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "test"},
        clear=False,
    )
    def test_server_config_defaults(self):
        config = Config()
        assert config.max_concurrent_jobs == 3
        assert config.job_timeout == 3600
        assert config.max_message_age_hours == 24
        assert config.server_port == 8080

    @patch.dict(
        os.environ,
        {
            "LLM_PROVIDER": "anthropic",
            "ANTHROPIC_API_KEY": "test",
            "QUEUE_OCID": "ocid1.queue.oc1..test",
            "VAULT_OCID": "ocid1.vault.oc1..test",
            "TMI_CLIENT_PATH": "/some/path",
        },
        clear=False,
    )
    def test_optional_server_config(self):
        config = Config()
        assert config.queue_ocid == "ocid1.queue.oc1..test"
        assert config.vault_ocid == "ocid1.vault.oc1..test"
        assert config.tmi_client_path == "/some/path"

    @patch.dict(
        os.environ,
        {"LLM_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "test"},
        clear=False,
    )
    def test_optional_server_config_none_defaults(self):
        config = Config()
        assert config.webhook_secret is None
        assert config.webhook_subscription_id is None
        assert config.queue_ocid is None
        assert config.vault_ocid is None
        assert config.tmi_client_path is None


class TestOCIValidation:
    @patch.dict(
        os.environ,
        {"LLM_PROVIDER": "oci", "OCI_COMPARTMENT_ID": "ocid1.compartment.oc1..test"},
        clear=False,
    )
    @patch("tmi_tf.config.Config._oci_credentials_available", return_value=True)
    def test_oci_accepts_imds(self, mock_creds):
        config = Config()
        assert config.llm_provider == "oci"

    @patch.dict(
        os.environ,
        {"LLM_PROVIDER": "oci", "OCI_COMPARTMENT_ID": "ocid1.compartment.oc1..test"},
        clear=False,
    )
    @patch("tmi_tf.config.Config._oci_credentials_available", return_value=False)
    def test_oci_warns_when_no_credentials(self, mock_creds):
        # Should not raise; just warns
        config = Config()
        assert config.llm_provider == "oci"

    @patch.dict(
        os.environ,
        {"LLM_PROVIDER": "oci"},
        clear=False,
    )
    @patch("tmi_tf.config.Config._oci_credentials_available", return_value=True)
    def test_oci_requires_compartment_id(self, mock_creds):
        with pytest.raises(ValueError, match="OCI_COMPARTMENT_ID"):
            Config()

    def test_oci_credentials_available_checks_file(self):
        """_oci_credentials_available returns True when ~/.oci/config exists."""
        with patch("pathlib.Path.exists", return_value=True):
            result = Config._oci_credentials_available()
            assert result is True

    def test_oci_credentials_available_checks_imds(self):
        """_oci_credentials_available returns True when IMDS responds."""
        with patch("pathlib.Path.exists", return_value=False):
            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_urlopen.return_value.__enter__ = lambda s: s
                mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)
                result = Config._oci_credentials_available()
                assert result is True

    def test_oci_credentials_available_returns_false_when_neither(self):
        """_oci_credentials_available returns False when file, instance principal, and IMDS all fail."""
        with patch("pathlib.Path.exists", return_value=False):
            with patch(
                "oci.auth.signers.InstancePrincipalsSecurityTokenSigner",
                side_effect=Exception("not on OCI"),
            ):
                with patch(
                    "urllib.request.urlopen",
                    side_effect=Exception("connection refused"),
                ):
                    result = Config._oci_credentials_available()
                    assert result is False

    def test_oci_credentials_available_checks_instance_principal(self):
        """_oci_credentials_available returns True when instance principal signer works."""
        with patch("pathlib.Path.exists", return_value=False):
            with patch(
                "urllib.request.urlopen", side_effect=Exception("connection refused")
            ):
                mock_signer = MagicMock()
                with patch(
                    "oci.auth.signers.InstancePrincipalsSecurityTokenSigner",
                    return_value=mock_signer,
                ):
                    result = Config._oci_credentials_available()
                    assert result is True


class TestServiceEndpointConfig:
    @patch.dict(
        os.environ,
        {
            "LLM_PROVIDER": "anthropic",
            "ANTHROPIC_API_KEY": "test",
            "QUEUE_ENDPOINT": "https://cell-1.queue.oc1.us-ashburn-1.oci.oraclecloud.com",
            "VAULT_ENDPOINT": "https://vaults.us-ashburn-1.oci.oraclecloud.com",
            "SECRETS_ENDPOINT": "https://secrets.vaults.us-ashburn-1.oci.oraclecloud.com",
        },
        clear=False,
    )
    def test_service_endpoints_loaded(self):
        config = Config()
        assert (
            config.queue_endpoint
            == "https://cell-1.queue.oc1.us-ashburn-1.oci.oraclecloud.com"
        )
        assert (
            config.vault_endpoint == "https://vaults.us-ashburn-1.oci.oraclecloud.com"
        )
        assert (
            config.secrets_endpoint
            == "https://secrets.vaults.us-ashburn-1.oci.oraclecloud.com"
        )

    @patch.dict(
        os.environ,
        {"LLM_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "test"},
        clear=False,
    )
    def test_service_endpoints_default_none(self):
        config = Config()
        assert config.queue_endpoint is None
        assert config.vault_endpoint is None
        assert config.secrets_endpoint is None


class TestOCICompletionKwargs:
    @patch.dict(
        os.environ,
        {
            "LLM_PROVIDER": "oci",
            "OCI_COMPARTMENT_ID": "ocid1.compartment.oc1..test",
        },
        clear=False,
    )
    @patch("tmi_tf.config.Config._oci_credentials_available", return_value=True)
    def test_returns_empty_for_non_oci_provider(self, mock_creds):
        config = Config()
        config.llm_provider = "anthropic"
        result = config.get_oci_completion_kwargs()
        assert result == {}

    @patch.dict(
        os.environ,
        {
            "LLM_PROVIDER": "oci",
            "OCI_COMPARTMENT_ID": "ocid1.compartment.oc1..test",
        },
        clear=False,
    )
    @patch("tmi_tf.config.Config._oci_credentials_available", return_value=True)
    def test_uses_instance_principal_when_no_config_file(self, mock_creds):
        config = Config()
        mock_signer = MagicMock()
        mock_signer.region = "us-phoenix-1"
        with patch("pathlib.Path.exists", return_value=False):
            with patch(
                "oci.auth.signers.InstancePrincipalsSecurityTokenSigner",
                return_value=mock_signer,
            ):
                result = config.get_oci_completion_kwargs()
                assert result["oci_region"] == "us-phoenix-1"
                assert result["oci_compartment_id"] == "ocid1.compartment.oc1..test"
                assert result["oci_signer"] is mock_signer

    @patch.dict(
        os.environ,
        {
            "LLM_PROVIDER": "oci",
            "OCI_COMPARTMENT_ID": "ocid1.compartment.oc1..test",
        },
        clear=False,
    )
    @patch("tmi_tf.config.Config._oci_credentials_available", return_value=True)
    def test_falls_back_to_config_file(self, mock_creds):
        config = Config()
        mock_oci_config = {
            "region": "us-ashburn-1",
            "user": "ocid1.user.oc1..test",
            "fingerprint": "aa:bb:cc",
            "tenancy": "ocid1.tenancy.oc1..test",
            "key_file": "/path/to/key.pem",
        }
        with patch("pathlib.Path.exists", return_value=True):
            with patch("oci.config.from_file", return_value=mock_oci_config):
                result = config.get_oci_completion_kwargs()
                assert result["oci_region"] == "us-ashburn-1"
                assert result["oci_user"] == "ocid1.user.oc1..test"
                assert result["oci_fingerprint"] == "aa:bb:cc"
                assert result["oci_tenancy"] == "ocid1.tenancy.oc1..test"
                assert result["oci_key_file"] == "/path/to/key.pem"
                assert result["oci_compartment_id"] == "ocid1.compartment.oc1..test"
