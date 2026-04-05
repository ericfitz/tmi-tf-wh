# Secret Provider Abstraction Design

**Issue:** [ericfitz/tmi-tf-wh#3](https://github.com/ericfitz/tmi-tf-wh/issues/3)
**Date:** 2026-04-04
**Scope:** Secrets + OCI signer extraction only. Queue and model provider abstraction are follow-up issues.

## Goal

Decouple secret loading from OCI Vault so different backends can be swapped via configuration. Extract the OCI signer helper as a shared utility within the OCI provider module.

No new cloud providers are implemented — only the protocol, OCI provider (extracted from existing code), and a no-op `none` provider.

## Protocol

```python
class SecretProvider(Protocol):
    def load_secrets(self, secret_map: dict[str, str]) -> None:
        """Fetch secrets named in secret_map and set corresponding env vars.

        secret_map: {"secret-name": "ENV_VAR_NAME", ...}
        Errors for individual secrets are logged, not raised.
        """
        ...
```

The `secret_map` is passed in by the caller (application concern), not owned by the provider.

## Providers

### OciSecretProvider

Extracted from current `vault_client.py`. Constructor takes `vault_ocid`, `compartment_ocid`, and optional `vault_endpoint` and `secrets_endpoint` strings (for in-cluster OKE access where regional endpoints aren't routable). Uses the OCI signer helper internally. `load_secrets()` lists vault secrets, fetches + base64-decodes matches, sets env vars.

### NoneSecretProvider

No-op implementation. `load_secrets()` logs that secrets are expected from the environment and returns. Used when secrets are injected by the platform (e.g., ECS task definition `secrets` block, EKS CSI driver).

## OCI Signer Helper

A public function in `providers/oci.py` that consolidates signer logic currently duplicated across `vault_client.py`, `queue_client.py`, and `config.py`:

```python
def get_oci_signer():
    """Return an OCI signer, preferring resource principal over config file."""
    try:
        from oci.auth.signers import get_resource_principals_signer
        signer = get_resource_principals_signer()
        return signer
    except Exception:
        from oci.config import from_file
        from oci.signer import Signer
        config = from_file()
        return Signer(
            tenancy=config["tenancy"],
            user=config["user"],
            fingerprint=config["fingerprint"],
            private_key_file_location=config["key_file"],
            pass_phrase=config.get("pass_phrase"),
        )
```

Uses `get_resource_principals_signer()` instead of `InstancePrincipalsSecurityTokenSigner` — handles both instance principals and OKE workload identity automatically.

## File Structure

### New files

```
tmi_tf/providers/
    __init__.py    — VAULT_SECRET_MAP, get_secret_provider() factory
    oci.py         — get_oci_signer(), OciSecretProvider
    none.py        — NoneSecretProvider
```

### Deleted files

- `tmi_tf/vault_client.py` — fully replaced by `providers/oci.py`

### Modified files

- `tmi_tf/config.py` — adds `secret_provider: str` from `SECRET_PROVIDER` env var
- `tmi_tf/server.py` — replaces `vault_client.load_secrets_from_vault()` with factory call
- `tmi_tf/queue_client.py` — imports `get_oci_signer` from `tmi_tf.providers.oci`

### Tests

- `tests/test_vault_client.py` — renamed/rewritten as `tests/test_providers.py` covering `OciSecretProvider`, `NoneSecretProvider`, factory logic, and `get_oci_signer`
- `tests/test_queue_client.py` — update mock paths from `tmi_tf.vault_client._get_oci_signer` to `tmi_tf.providers.oci.get_oci_signer`

## Factory

`get_secret_provider(config) -> SecretProvider` in `providers/__init__.py`:

- `"oci"` → `OciSecretProvider(vault_ocid, compartment_ocid, endpoints)`
- `"none"` → `NoneSecretProvider()`
- Unknown values raise `ValueError`

## Backward Compatibility

Zero-config migration for existing deployments:

- If `SECRET_PROVIDER` is **not set**:
  - `VAULT_OCID` is set → infer `secret_provider = "oci"`
  - `VAULT_OCID` is not set → infer `secret_provider = "none"`
- If `SECRET_PROVIDER` is **explicitly set** → use that value regardless of `VAULT_OCID`

Existing `.env` files and OKE deployments work without changes.

## Server Integration

In `server.py` lifespan, replace:

```python
if config.vault_ocid:
    from tmi_tf.vault_client import load_secrets_from_vault
    load_secrets_from_vault(config.vault_ocid, compartment_ocid)
```

With:

```python
from tmi_tf.providers import VAULT_SECRET_MAP, get_secret_provider
provider = get_secret_provider(config)
provider.load_secrets(VAULT_SECRET_MAP)
```

The `NoneSecretProvider` handles the "no vault configured" case, so no conditional needed.

## Follow-up Issues

1. **Refactor queue client behind a provider-agnostic interface** — Extract `queue_client.py`'s OCI Queue SDK usage behind a `QueueProvider` protocol in `providers/`. The OCI signer is already available in `providers/oci.py`.

2. **Abstract LLM provider configuration behind a provider interface** — Move `get_oci_completion_kwargs()` and provider-specific credential validation out of `config.py` into provider modules. Evaluate whether LiteLLM already serves as sufficient abstraction or if a thin wrapper is needed.
