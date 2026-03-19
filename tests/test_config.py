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
    """Reset singleton before and after each test."""
    reset_config()
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
        """_oci_credentials_available returns False when neither file nor IMDS available."""
        with patch("pathlib.Path.exists", return_value=False):
            with patch(
                "urllib.request.urlopen", side_effect=Exception("connection refused")
            ):
                result = Config._oci_credentials_available()
                assert result is False
