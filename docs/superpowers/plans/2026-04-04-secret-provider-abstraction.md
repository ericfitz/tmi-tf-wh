# Secret Provider Abstraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decouple secret loading from OCI Vault behind a `SecretProvider` protocol so different backends can be swapped via config, and extract the OCI signer as a shared utility.

**Architecture:** New `tmi_tf/providers/` package with a `SecretProvider` protocol, `OciSecretProvider` (extracted from `vault_client.py`), `NoneSecretProvider` (no-op), and a factory function. The OCI signer helper becomes a public function in `providers/oci.py`. Server and queue client are updated to use the new locations.

**Tech Stack:** Python 3.10+, `typing.Protocol`, OCI Python SDK, pytest

**Spec:** `docs/superpowers/specs/2026-04-04-secret-provider-abstraction-design.md`

---

## File Structure

```
tmi_tf/providers/
    __init__.py    — SecretProvider protocol, VAULT_SECRET_MAP, get_secret_provider() factory
    oci.py         — get_oci_signer(), OciSecretProvider
    none.py        — NoneSecretProvider
```

**Delete:** `tmi_tf/vault_client.py`
**Delete:** `tests/test_vault_client.py`
**Create:** `tests/test_providers.py`
**Modify:** `tmi_tf/config.py` (add `secret_provider` field)
**Modify:** `tmi_tf/server.py` (use factory instead of vault_client)
**Modify:** `tmi_tf/queue_client.py` (import signer from new location)
**Modify:** `tests/test_queue_client.py` (update mock paths)

---

### Task 1: Create `providers/__init__.py` with protocol and factory

**Files:**
- Create: `tmi_tf/providers/__init__.py`
- Test: `tests/test_providers.py`

- [ ] **Step 1: Write failing tests for protocol, secret map, and factory**

Create `tests/test_providers.py`:

```python
"""Tests for secret provider protocol and factory."""

import os
from unittest.mock import MagicMock, patch

import pytest

from tmi_tf.providers import VAULT_SECRET_MAP, SecretProvider, get_secret_provider


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_providers.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'tmi_tf.providers'`

- [ ] **Step 3: Create `tmi_tf/providers/__init__.py`**

```python
"""Provider abstraction layer for secret loading."""

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from tmi_tf.config import Config

VAULT_SECRET_MAP = {
    "webhook-secret": "WEBHOOK_SECRET",
    "tmi-client-id": "TMI_CLIENT_ID",
    "tmi-client-secret": "TMI_CLIENT_SECRET",
    "llm-api-key": "LLM_API_KEY",
    "github-token": "GITHUB_TOKEN",
}


class SecretProvider(Protocol):
    def load_secrets(self, secret_map: dict[str, str]) -> None:
        """Fetch secrets named in secret_map and set corresponding env vars.

        secret_map: {"secret-name": "ENV_VAR_NAME", ...}
        Errors for individual secrets are logged, not raised.
        """
        ...


def get_secret_provider(config: "Config") -> SecretProvider:
    """Create a SecretProvider based on configuration."""
    if config.secret_provider == "oci":
        from tmi_tf.providers.oci import OciSecretProvider

        return OciSecretProvider(
            vault_ocid=config.vault_ocid or "",
            compartment_ocid=config.oci_compartment_id or "",
            vault_endpoint=config.vault_endpoint,
            secrets_endpoint=config.secrets_endpoint,
        )
    elif config.secret_provider == "none":
        from tmi_tf.providers.none import NoneSecretProvider

        return NoneSecretProvider()
    else:
        raise ValueError(
            f"Unknown secret provider: {config.secret_provider!r}. "
            f"Must be 'oci' or 'none'."
        )
```

- [ ] **Step 4: Run tests to verify they still fail (providers.oci not yet created)**

Run: `uv run pytest tests/test_providers.py::TestGetSecretProvider::test_factory_returns_oci_provider -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'tmi_tf.providers.oci'`

But the secret map tests should pass:

Run: `uv run pytest tests/test_providers.py::TestVaultSecretMap -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tmi_tf/providers/__init__.py tests/test_providers.py
git commit -m "feat(providers): add SecretProvider protocol, secret map, and factory"
```

---

### Task 2: Create `providers/oci.py` with signer and OciSecretProvider

**Files:**
- Create: `tmi_tf/providers/oci.py`
- Test: `tests/test_providers.py` (append)

- [ ] **Step 1: Write failing tests for `get_oci_signer`**

Append to `tests/test_providers.py`:

```python
class TestGetOciSigner:
    @patch("oci.auth.signers.get_resource_principals_signer", create=True)
    def test_prefers_resource_principal(self, mock_rp):
        from tmi_tf.providers.oci import get_oci_signer

        mock_signer = MagicMock()
        mock_rp.return_value = mock_signer
        result = get_oci_signer()
        assert result is mock_signer

    @patch("oci.auth.signers.get_resource_principals_signer", create=True, side_effect=Exception("no RP"))
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_providers.py::TestGetOciSigner -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'tmi_tf.providers.oci'`

- [ ] **Step 3: Write failing tests for `OciSecretProvider`**

Append to `tests/test_providers.py`:

```python
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
        mock_secrets_client.return_value.get_secret_bundle.return_value.data = mock_bundle

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
```

- [ ] **Step 4: Create `tmi_tf/providers/oci.py`**

```python
"""OCI provider: signer helper and secret loading."""

import base64
import logging
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


import os


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
                content_b64: str = bundle_response.data.data.secret_bundle_content.content  # pyright: ignore[reportOptionalMemberAccess]
                value = base64.b64decode(content_b64).decode("utf-8")
                os.environ[env_var] = value
                logger.info("Loaded secret %s -> %s", secret_name, env_var)
            except Exception as e:
                logger.error("Failed to load secret %s: %s", secret_name, e)
```

- [ ] **Step 5: Run tests to verify signer and OCI provider tests pass**

Run: `uv run pytest tests/test_providers.py::TestGetOciSigner tests/test_providers.py::TestOciSecretProvider -v`
Expected: PASS

- [ ] **Step 6: Run all provider tests to verify factory now works too**

Run: `uv run pytest tests/test_providers.py -v`
Expected: PASS (factory test for OCI provider can now import OciSecretProvider)

- [ ] **Step 7: Commit**

```bash
git add tmi_tf/providers/oci.py tests/test_providers.py
git commit -m "feat(providers): add OCI signer helper and OciSecretProvider"
```

---

### Task 3: Create `providers/none.py` with NoneSecretProvider

**Files:**
- Create: `tmi_tf/providers/none.py`
- Test: `tests/test_providers.py` (append)

- [ ] **Step 1: Write failing test for NoneSecretProvider**

Append to `tests/test_providers.py`:

```python
class TestNoneSecretProvider:
    def test_load_secrets_is_noop(self):
        from tmi_tf.providers.none import NoneSecretProvider

        provider = NoneSecretProvider()
        # Should not raise, should not set any env vars
        env_before = dict(os.environ)
        provider.load_secrets({"webhook-secret": "WEBHOOK_SECRET"})
        # No new env vars added (env may have WEBHOOK_SECRET from prior tests,
        # so just verify no exception)

    def test_conforms_to_protocol(self):
        from tmi_tf.providers.none import NoneSecretProvider

        provider = NoneSecretProvider()
        assert hasattr(provider, "load_secrets")
        assert callable(provider.load_secrets)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_providers.py::TestNoneSecretProvider -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'tmi_tf.providers.none'`

- [ ] **Step 3: Create `tmi_tf/providers/none.py`**

```python
"""No-op secret provider for environments with platform-injected secrets."""

import logging

logger = logging.getLogger(__name__)


class NoneSecretProvider:
    """No-op provider: assumes secrets are already in the environment."""

    def load_secrets(self, secret_map: dict[str, str]) -> None:
        """Log that secrets are expected from the environment and return."""
        logger.info(
            "Secret provider is 'none'; expecting %d secrets from environment",
            len(secret_map),
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_providers.py::TestNoneSecretProvider -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tmi_tf/providers/none.py tests/test_providers.py
git commit -m "feat(providers): add NoneSecretProvider"
```

---

### Task 4: Add `secret_provider` to Config

**Files:**
- Modify: `tmi_tf/config.py`
- Test: `tests/test_config.py` (if exists, otherwise `tests/test_providers.py`)

- [ ] **Step 1: Check if test_config.py exists and read it**

Run: `ls tests/test_config.py`

- [ ] **Step 2: Write failing test for secret_provider config field**

Add to the appropriate test file (append to `tests/test_providers.py` if no config tests exist, or to `tests/test_config.py`):

```python
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/test_providers.py::TestSecretProviderConfig -v` (or appropriate test file)
Expected: FAIL — `AttributeError: 'Config' object has no attribute 'secret_provider'`

- [ ] **Step 4: Add `secret_provider` field to `Config.__init__`**

In `tmi_tf/config.py`, add after the `self.vault_ocid` line (around line 118):

```python
        # Secret provider selection (inferred from VAULT_OCID if not explicit)
        explicit_provider = os.getenv("SECRET_PROVIDER")
        if explicit_provider:
            self.secret_provider: str = explicit_provider
        elif self.vault_ocid:
            self.secret_provider = "oci"
        else:
            self.secret_provider = "none"
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_providers.py::TestSecretProviderConfig -v`
Expected: PASS

- [ ] **Step 6: Run all existing config tests to check for regressions**

Run: `uv run pytest tests/test_config.py -v` (if it exists)
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add tmi_tf/config.py tests/test_providers.py
git commit -m "feat(config): add secret_provider field with backward-compatible inference"
```

---

### Task 5: Update server.py to use the provider factory

**Files:**
- Modify: `tmi_tf/server.py`

- [ ] **Step 1: Update the lifespan function in `tmi_tf/server.py`**

Replace lines 48-60 (the vault secret loading block):

```python
    # Load secrets from vault if configured
    if config.vault_ocid:
        from tmi_tf.vault_client import load_secrets_from_vault

        compartment_ocid = config.oci_compartment_id or ""
        logger.info("Loading secrets from vault %s", config.vault_ocid)
        load_secrets_from_vault(config.vault_ocid, compartment_ocid)

        # Reset config singleton so it re-reads env vars with vault secrets
        import tmi_tf.config

        tmi_tf.config._config = None
        config = get_config()
```

With:

```python
    # Load secrets via configured provider
    from tmi_tf.providers import VAULT_SECRET_MAP, get_secret_provider

    provider = get_secret_provider(config)
    provider.load_secrets(VAULT_SECRET_MAP)

    if config.secret_provider != "none":
        # Reset config singleton so it re-reads env vars with provider secrets
        import tmi_tf.config

        tmi_tf.config._config = None
        config = get_config()
```

- [ ] **Step 2: Run existing server tests (if any) and full test suite**

Run: `uv run pytest tests/ -v`
Expected: PASS (except possibly test_vault_client.py which we'll remove in Task 7)

- [ ] **Step 3: Commit**

```bash
git add tmi_tf/server.py
git commit -m "refactor(server): use secret provider factory instead of vault_client"
```

---

### Task 6: Update queue_client.py to import signer from new location

**Files:**
- Modify: `tmi_tf/queue_client.py`
- Modify: `tests/test_queue_client.py`

- [ ] **Step 1: Update the import in `tmi_tf/queue_client.py`**

In `tmi_tf/queue_client.py` line 30, replace:

```python
            from tmi_tf.vault_client import _get_oci_signer
```

With:

```python
            from tmi_tf.providers.oci import get_oci_signer
```

And on line 32, replace:

```python
            signer = _get_oci_signer()
```

With:

```python
            signer = get_oci_signer()
```

- [ ] **Step 2: Update mock paths in `tests/test_queue_client.py`**

Replace both occurrences of `"tmi_tf.vault_client._get_oci_signer"` with `"tmi_tf.providers.oci.get_oci_signer"`:

Line 41:
```python
    @patch("tmi_tf.providers.oci.get_oci_signer")
```

Line 62:
```python
    @patch("tmi_tf.providers.oci.get_oci_signer")
```

- [ ] **Step 3: Run queue client tests**

Run: `uv run pytest tests/test_queue_client.py -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add tmi_tf/queue_client.py tests/test_queue_client.py
git commit -m "refactor(queue_client): import signer from providers.oci"
```

---

### Task 7: Delete old vault_client.py and test_vault_client.py

**Files:**
- Delete: `tmi_tf/vault_client.py`
- Delete: `tests/test_vault_client.py`

- [ ] **Step 1: Verify no remaining imports of vault_client**

Run: `grep -r "vault_client" tmi_tf/ tests/ --include="*.py"`
Expected: Only the comment in `config.py` line 218 (`matching vault_client._get_oci_signer()`).

- [ ] **Step 2: Update the comment in `tmi_tf/config.py`**

In `tmi_tf/config.py` around line 218, replace:

```python
        falls back to ~/.oci/config — matching vault_client._get_oci_signer().
```

With:

```python
        falls back to ~/.oci/config — matching providers.oci.get_oci_signer().
```

- [ ] **Step 3: Delete the old files**

```bash
git rm tmi_tf/vault_client.py tests/test_vault_client.py
```

- [ ] **Step 4: Run full test suite**

Run: `uv run pytest tests/ -v`
Expected: PASS — all tests pass with no references to deleted files

- [ ] **Step 5: Run linter and type checker**

Run: `uv run ruff check tmi_tf/ tests/`
Run: `uv run ruff format --check tmi_tf/ tests/`
Run: `uv run pyright`

Fix any issues.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor: remove vault_client.py, replaced by providers package"
```

---

### Task 8: Create follow-up GitHub issues

- [ ] **Step 1: Create queue provider abstraction issue**

```bash
gh issue create --repo ericfitz/tmi-tf-wh \
  --title "Refactor queue client behind a provider-agnostic interface" \
  --body "## Summary

\`queue_client.py\` is tightly coupled to OCI Queue SDK. Extract behind a \`QueueProvider\` protocol in \`tmi_tf/providers/\` so different queue backends can be swapped via configuration.

The OCI signer is already available in \`providers/oci.py\` (from #3).

## Suggested approach

1. Define a \`QueueProvider\` protocol with \`publish()\`, \`consume()\`, \`delete()\` methods
2. Extract current \`QueueClient\` as \`OciQueueProvider\` in \`providers/oci.py\`
3. Add provider selection via \`QUEUE_PROVIDER\` config
4. Update \`server.py\` to use the factory

## Context

Part of the provider abstraction initiative started in #3."
```

- [ ] **Step 2: Create model provider abstraction issue**

```bash
gh issue create --repo ericfitz/tmi-tf-wh \
  --title "Abstract LLM provider configuration behind a provider interface" \
  --body "## Summary

\`config.py\` contains OCI-specific logic in \`get_oci_completion_kwargs()\` and \`_validate_llm_credentials()\`. Move provider-specific credential validation and completion kwargs into provider modules.

## Suggested approach

1. Evaluate whether LiteLLM already serves as sufficient abstraction
2. If not, define a \`ModelProvider\` protocol for credential validation and completion kwargs
3. Move OCI-specific logic to \`providers/oci.py\`
4. Move provider-specific API key validation into respective provider modules
5. Simplify \`Config\` to be provider-agnostic

## Context

Part of the provider abstraction initiative started in #3."
```

- [ ] **Step 3: Commit (no code change — just noting the issues were created)**

No commit needed for this step.
