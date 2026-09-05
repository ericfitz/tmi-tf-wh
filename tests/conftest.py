"""Shared pytest configuration.

Isolates the suite from developer machine state. Without this, `Config()` loads
the repo-root `.env` with `override=True`, which beats anything a test set up
via `patch.dict(os.environ, ...)` -- so assertions passed or failed depending on
whether the developer running them happened to have a `.env`.
"""

import os

import pytest  # type: ignore

from tmi_tf import config as config_module

# Variables a local .env commonly sets that would otherwise leak into
# assertions through the ambient environment rather than through the .env file.
_LEAKY_ENV_VARS = (
    "WEBHOOK_SECRET",
    "WEBHOOK_SUBSCRIPTION_ID",
    "QUEUE_OCID",
    "VAULT_OCID",
    "QUEUE_URL",
    "AWS_REGION",
    "TMI_CLIENT_PATH",
    "QUEUE_ENDPOINT",
    "VAULT_ENDPOINT",
    "SECRETS_ENDPOINT",
)


@pytest.fixture(autouse=True)
def _isolate_from_local_dotenv(monkeypatch):
    """Stop Config() from reading the developer's .env, for every test.

    Patches the module global rather than passing an argument so that the
    hundreds of existing bare `Config()` calls are covered without edits.
    Individual tests can still opt back in with `Config(env_file=<path>)`.
    """
    monkeypatch.setattr(config_module, "DEFAULT_ENV_FILE", None)


@pytest.fixture(autouse=True)
def _clear_leaky_env_vars(monkeypatch):
    """Clear config vars that may be exported in the developer's shell.

    Disabling .env loading is not sufficient on its own: the same values are
    often exported directly, and tests that assert a None default would still
    see them. Tests that want these set do so explicitly via patch.dict, which
    applies after this fixture.
    """
    for name in _LEAKY_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    assert not any(name in os.environ for name in _LEAKY_ENV_VARS)
