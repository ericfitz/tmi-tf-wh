# pyright: reportPrivateImportUsage=false
"""Tests for Config: LLM profiles, server config vars, OCI IMDS."""

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


class TestLLMProfiles:
    @patch.dict(os.environ, {"LLM_PROFILE": "opus48"}, clear=False)
    def test_default_profile_from_env(self):
        config = Config()
        assert config.llm_profile == "opus48"
        assert "gpt56cyber" in config.llm_profiles

    def test_no_default_profile(self):
        os.environ.pop("LLM_PROFILE", None)
        assert Config().llm_profile is None

    def test_legacy_llm_vars_gone(self):
        config = Config()
        assert not hasattr(config, "llm_provider")
        assert not hasattr(config, "llm_model")

    @patch.dict(
        os.environ,
        {"LLM_API_KEY": "legacy-key", "LLM_PROVIDER": "anthropic"},
        clear=False,
    )
    def test_llm_api_key_not_copied(self):
        os.environ.pop("ANTHROPIC_API_KEY", None)
        Config()
        assert os.environ.get("ANTHROPIC_API_KEY") is None

    def test_bad_profiles_file_fails(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("foo: 1")
        with (
            patch.dict(os.environ, {"LLM_PROFILES_FILE": str(bad)}),
            pytest.raises(ValueError, match="bad.yaml"),
        ):
            Config()


class TestServerConfigVars:
    @patch.dict(
        os.environ,
        {
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
        {"ANTHROPIC_API_KEY": "test"},
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
        {"ANTHROPIC_API_KEY": "test"},
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
        {"ANTHROPIC_API_KEY": "test"},
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
            {"ANTHROPIC_API_KEY": "test"},
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
            {"ANTHROPIC_API_KEY": "test"},
            clear=False,
        ):
            config = Config(env_file=env_file)

        assert config.tmi_server_url == "https://from-dotenv.example"

    def test_conftest_disables_the_default_env_file(self):
        """The autouse fixture in conftest.py is what keeps the suite honest."""
        assert config_module.DEFAULT_ENV_FILE is None


class TestLatestCommitDepth:
    def test_default(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("LATEST_COMMIT_DEPTH", None)
            assert Config().latest_commit_depth == 200

    def test_override(self):
        with patch.dict(os.environ, {"LATEST_COMMIT_DEPTH": "50"}):
            assert Config().latest_commit_depth == 50
