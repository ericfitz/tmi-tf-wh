# pyright: reportPrivateImportUsage=false
"""Tests for Config class changes: LLM_API_KEY mapping, server config vars, OCI IMDS."""

import os
from unittest.mock import patch

import pytest  # pyright: ignore[reportMissingImports] # ty:ignore[unresolved-import]

import tmi_tf.config as config_module
from tmi_tf.config import Config


def reset_config():
    """Reset the global config singleton between tests."""
    config_module._config = None


@pytest.fixture(autouse=True)
def clear_config_singleton():
    """Reset the singleton before and after each test.

    This used to also patch out ``tmi_tf.config.load_dotenv`` to keep a local
    .env from overriding test env vars. That is now handled suite-wide in
    tests/conftest.py by disabling the default .env path, which is both more
    thorough (it covers modules that construct Config() outside this file, the
    actual source of the #36 leak) and less blunt -- patching the function out
    here also prevented tests from loading an .env file on purpose.
    """
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
    def test_oci_provider_no_key_map(self):
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


class TestDotenvIsolation:
    """Config must not read a developer's .env when a caller opts out.

    Regression cover for #36. The original failure was order-dependent: other
    test modules construct Config() and load_dotenv(override=True) mutates
    os.environ for the rest of the process, so tests/test_config.py passed in
    isolation and failed in a full run. tests/conftest.py now disables .env
    loading suite-wide; these tests pin the mechanism it relies on.
    """

    def test_env_file_none_skips_dotenv_entirely(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("TMI_SERVER_URL=https://from-dotenv.example\n")

        with patch.dict(
            os.environ,
            {"LLM_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "test"},
            clear=False,
        ):
            os.environ.pop("TMI_SERVER_URL", None)
            config = Config(env_file=None)

        assert config.tmi_server_url == "https://api.tmi.dev"

    def test_explicit_env_file_is_loaded(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("TMI_SERVER_URL=https://from-dotenv.example\n")

        with patch.dict(
            os.environ,
            {"LLM_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "test"},
            clear=False,
        ):
            config = Config(env_file=env_file)

        assert config.tmi_server_url == "https://from-dotenv.example"

    def test_conftest_disables_the_default_env_file(self):
        """The autouse fixture in conftest.py is what keeps the suite honest."""
        assert config_module.DEFAULT_ENV_FILE is None
