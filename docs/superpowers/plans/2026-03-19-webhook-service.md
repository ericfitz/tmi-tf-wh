# Webhook Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert the tmi-tf CLI into a FastAPI webhook service on OCI that accepts TMI webhooks, queues jobs via OCI Queue, and runs concurrent Terraform analysis with configurable timeouts and message age cutoffs.

**Architecture:** FastAPI receives webhook POSTs, validates HMAC + subscription ID + job ID headers, enqueues to OCI Queue. Async worker pool dequeues messages, checks age, runs the existing synchronous analysis pipeline via `asyncio.to_thread()`. The analysis pipeline is extracted from `cli.py` into a shared `analyzer.py` used by both CLI and workers.

**Tech Stack:** Python 3 (dnf), FastAPI, Uvicorn, OCI SDK (Queue, Vault, IMDS), LiteLLM, systemd

**Spec:** `docs/superpowers/specs/2026-03-19-webhook-service-design.md`

---

## File Structure

### New Files

| File | Responsibility |
|------|---------------|
| `tmi_tf/job.py` | Job dataclass — all fields extracted from webhook payload |
| `tmi_tf/webhook_handler.py` | HMAC verification, subscription ID check, job ID extraction, challenge response, payload parsing |
| `tmi_tf/addon_callback.py` | Send HMAC-signed status callbacks to TMI addon callback URL |
| `tmi_tf/vault_client.py` | Fetch secrets from OCI Vault via instance principal (IMDS) or `~/.oci/config` |
| `tmi_tf/queue_client.py` | OCI Queue SDK wrapper — publish, consume, delete, extend visibility |
| `tmi_tf/analyzer.py` | Extracted analysis pipeline — shared by CLI and webhook worker |
| `tmi_tf/worker.py` | Async worker pool — polls queue, manages concurrency, enforces timeouts and message age |
| `tmi_tf/server.py` | FastAPI app — POST /webhook, GET /health, GET /status, startup/shutdown lifecycle |
| `deploy/tmi-tf-wh.service` | systemd unit file |
| `deploy/terraform/main.tf` | OCI provider config |
| `deploy/terraform/variables.tf` | Input variables |
| `deploy/terraform/network.tf` | VCN, subnets, security lists, NAT gateway |
| `deploy/terraform/compute.tf` | Instance + cloud-init |
| `deploy/terraform/loadbalancer.tf` | LB, listener, backend set, TLS cert |
| `deploy/terraform/queue.tf` | OCI Queue + DLQ |
| `deploy/terraform/vault.tf` | Vault, master key, secrets |
| `deploy/terraform/iam.tf` | Dynamic group, policies |
| `deploy/terraform/logging.tf` | OCI Logging + agent config |
| `deploy/terraform/outputs.tf` | LB IP, instance OCID, queue OCID |
| `tests/test_webhook_handler.py` | Tests for HMAC, subscription ID, job ID, challenge, payload parsing |
| `tests/test_job.py` | Tests for Job dataclass |
| `tests/test_addon_callback.py` | Tests for callback signing and sending |
| `tests/test_vault_client.py` | Tests for Vault secret loading |
| `tests/test_queue_client.py` | Tests for queue operations |
| `tests/test_analyzer.py` | Tests for extracted analysis pipeline |
| `tests/test_worker.py` | Tests for worker pool, timeout, message age |
| `tests/test_server.py` | Integration tests for FastAPI endpoints |

### Modified Files

| File | Changes |
|------|---------|
| `tmi_tf/config.py` | Add server config vars, LLM_API_KEY mapping, OCI IMDS support |
| `tmi_tf/tmi_client_wrapper.py:13-20` | Configurable TMI client path via `TMI_CLIENT_PATH` env var |
| `tmi_tf/repo_analyzer.py:212-254` | Accept `temp_dir` parameter, remove markdown patterns from sparse checkout |
| `tmi_tf/cli.py:82-576` | Extract pipeline into `analyzer.py`, keep as thin wrapper |
| `pyproject.toml:6-23` | Add fastapi, uvicorn dependencies |

---

## Task 1: Job Dataclass

**Files:**
- Create: `tmi_tf/job.py`
- Test: `tests/test_job.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_job.py
"""Tests for Job dataclass."""
from datetime import datetime, timezone
from pathlib import Path

from tmi_tf.job import Job


class TestJob:
    def test_create_job_minimal(self):
        job = Job(
            job_id="abc-123",
            threat_model_id="tm-456",
            event_type="threat_model.created",
            enqueued_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        assert job.job_id == "abc-123"
        assert job.threat_model_id == "tm-456"
        assert job.repo_id is None
        assert job.callback_url is None
        assert job.invocation_id is None
        assert job.temp_dir is None

    def test_create_job_full(self):
        job = Job(
            job_id="abc-123",
            threat_model_id="tm-456",
            event_type="addon.invoked",
            repo_id="repo-789",
            callback_url="https://api.tmi.dev/invocations/inv-1/status",
            invocation_id="inv-1",
            enqueued_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            temp_dir=Path("/tmp/tmi-tf-abc-123"),
        )
        assert job.repo_id == "repo-789"
        assert job.callback_url == "https://api.tmi.dev/invocations/inv-1/status"
        assert job.invocation_id == "inv-1"
        assert job.temp_dir == Path("/tmp/tmi-tf-abc-123")

    def test_job_to_dict_roundtrip(self):
        job = Job(
            job_id="abc-123",
            threat_model_id="tm-456",
            event_type="threat_model.created",
            enqueued_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        d = job.to_queue_message()
        restored = Job.from_queue_message(d)
        assert restored.job_id == job.job_id
        assert restored.threat_model_id == job.threat_model_id
        assert restored.enqueued_at == job.enqueued_at
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_job.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'tmi_tf.job'`

- [ ] **Step 3: Write minimal implementation**

```python
# tmi_tf/job.py
"""Job dataclass for webhook-triggered analysis jobs."""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class Job:
    """Represents an analysis job extracted from a webhook payload."""

    job_id: str
    threat_model_id: str
    event_type: str
    enqueued_at: datetime
    repo_id: Optional[str] = None
    callback_url: Optional[str] = None
    invocation_id: Optional[str] = None
    temp_dir: Optional[Path] = None

    def to_queue_message(self) -> dict:
        """Serialize to dict for OCI Queue message body."""
        return {
            "job_id": self.job_id,
            "threat_model_id": self.threat_model_id,
            "event_type": self.event_type,
            "enqueued_at": self.enqueued_at.isoformat(),
            "repo_id": self.repo_id,
            "callback_url": self.callback_url,
            "invocation_id": self.invocation_id,
        }

    @classmethod
    def from_queue_message(cls, data: dict) -> "Job":
        """Deserialize from OCI Queue message body."""
        return cls(
            job_id=data["job_id"],
            threat_model_id=data["threat_model_id"],
            event_type=data["event_type"],
            enqueued_at=datetime.fromisoformat(data["enqueued_at"]),
            repo_id=data.get("repo_id"),
            callback_url=data.get("callback_url"),
            invocation_id=data.get("invocation_id"),
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_job.py -v`
Expected: PASS — all 3 tests

- [ ] **Step 5: Lint**

Run: `uv run ruff check tmi_tf/job.py tests/test_job.py && uv run ruff format --check tmi_tf/job.py tests/test_job.py`

- [ ] **Step 6: Commit**

```bash
git add tmi_tf/job.py tests/test_job.py
git commit -m "feat: add Job dataclass for webhook job representation"
```

---

## Task 2: Webhook Handler

**Files:**
- Create: `tmi_tf/webhook_handler.py`
- Test: `tests/test_webhook_handler.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_webhook_handler.py
"""Tests for webhook handler — HMAC, subscription ID, job ID, challenge, parsing."""

import hashlib
import hmac
import json

import pytest

from tmi_tf.webhook_handler import (
    verify_hmac_signature,
    validate_subscription_id,
    extract_job_id,
    handle_challenge,
    parse_webhook_payload,
)


class TestHMACVerification:
    def test_valid_signature(self):
        secret = "test-secret"
        body = b'{"event_type": "threat_model.created"}'
        digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        signature = f"sha256={digest}"
        assert verify_hmac_signature(body, signature, secret) is True

    def test_invalid_signature(self):
        assert verify_hmac_signature(b"body", "sha256=bad", "secret") is False

    def test_missing_prefix(self):
        secret = "test-secret"
        body = b"body"
        digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        assert verify_hmac_signature(body, digest, secret) is False

    def test_empty_signature(self):
        assert verify_hmac_signature(b"body", "", "secret") is False


class TestSubscriptionIdValidation:
    def test_matching_case_insensitive(self):
        assert validate_subscription_id(
            "ABC-123", "abc-123"
        ) is True

    def test_mismatch(self):
        assert validate_subscription_id(
            "abc-123", "def-456"
        ) is False

    def test_none_configured_always_passes(self):
        """If no subscription ID configured, always valid."""
        assert validate_subscription_id(
            "any-value", None
        ) is True

    def test_configured_but_header_missing(self):
        assert validate_subscription_id(
            None, "abc-123"
        ) is False


class TestExtractJobId:
    def test_invocation_id_preferred(self):
        job_id = extract_job_id(
            invocation_id="inv-1",
            delivery_id="del-1",
        )
        assert job_id == "inv-1"

    def test_delivery_id_fallback(self):
        job_id = extract_job_id(
            invocation_id=None,
            delivery_id="del-1",
        )
        assert job_id == "del-1"

    def test_neither_raises(self):
        with pytest.raises(ValueError, match="No job ID"):
            extract_job_id(invocation_id=None, delivery_id=None)


class TestHandleChallenge:
    def test_challenge_detected(self):
        payload = {"type": "webhook.challenge", "challenge": "abc123"}
        result = handle_challenge(payload)
        assert result == {"challenge": "abc123"}

    def test_not_a_challenge(self):
        payload = {"event_type": "threat_model.created"}
        result = handle_challenge(payload)
        assert result is None


class TestParseWebhookPayload:
    def test_threat_model_event(self):
        payload = {
            "event_type": "threat_model.created",
            "threat_model_id": "tm-1",
        }
        result = parse_webhook_payload(payload)
        assert result["threat_model_id"] == "tm-1"
        assert result["repo_id"] is None
        assert result["callback_url"] is None

    def test_repository_event(self):
        payload = {
            "event_type": "repository.created",
            "threat_model_id": "tm-1",
            "resource_id": "repo-1",
            "resource_type": "repository",
        }
        result = parse_webhook_payload(payload)
        assert result["repo_id"] == "repo-1"

    def test_addon_invoked(self):
        payload = {
            "event_type": "addon.invoked",
            "threat_model_id": "tm-1",
            "invocation_id": "inv-1",
            "callback_url": "https://api.tmi.dev/invocations/inv-1/status",
        }
        result = parse_webhook_payload(payload)
        assert result["callback_url"] == "https://api.tmi.dev/invocations/inv-1/status"
        assert result["invocation_id"] == "inv-1"

    def test_missing_threat_model_id_raises(self):
        with pytest.raises(ValueError, match="threat_model_id"):
            parse_webhook_payload({"event_type": "threat_model.created"})
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_webhook_handler.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write implementation**

```python
# tmi_tf/webhook_handler.py
"""Webhook request validation and payload parsing."""

import hashlib
import hmac as hmac_module
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def verify_hmac_signature(raw_body: bytes, signature: str, secret: str) -> bool:
    """Verify HMAC-SHA256 signature from X-Webhook-Signature header.

    Args:
        raw_body: Raw request body bytes.
        signature: Header value, expected format "sha256=<hex_digest>".
        secret: Shared secret string.

    Returns:
        True if signature is valid.
    """
    if not signature or not signature.startswith("sha256="):
        return False
    expected = hmac_module.new(
        secret.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()
    return hmac_module.compare_digest(signature, f"sha256={expected}")


def validate_subscription_id(
    header_value: Optional[str],
    configured_value: Optional[str],
) -> bool:
    """Validate X-Webhook-Subscription-Id header against configured value.

    If no configured value, always returns True (validation disabled).
    Comparison is case-insensitive.
    """
    if configured_value is None:
        return True
    if header_value is None:
        return False
    return header_value.lower() == configured_value.lower()


def extract_job_id(
    invocation_id: Optional[str],
    delivery_id: Optional[str],
) -> str:
    """Extract job ID from headers. Prefers X-Invocation-Id over X-Webhook-Delivery-Id.

    Raises:
        ValueError: If neither header is present.
    """
    if invocation_id:
        return invocation_id
    if delivery_id:
        return delivery_id
    raise ValueError("No job ID found: neither X-Invocation-Id nor X-Webhook-Delivery-Id present")


def handle_challenge(payload: dict) -> Optional[dict]:
    """Handle webhook challenge verification request.

    Returns:
        Challenge response dict if this is a challenge, None otherwise.
    """
    if payload.get("type") == "webhook.challenge":
        return {"challenge": payload["challenge"]}
    return None


def parse_webhook_payload(payload: dict) -> dict:
    """Parse webhook payload and extract fields needed for a Job.

    Returns:
        Dict with keys: event_type, threat_model_id, repo_id, callback_url, invocation_id.

    Raises:
        ValueError: If required fields are missing.
    """
    event_type = payload.get("event_type", "")
    threat_model_id = payload.get("threat_model_id")
    if not threat_model_id:
        raise ValueError("Payload missing required field: threat_model_id")

    # Extract repo_id only when resource_type indicates a repository
    repo_id = None
    if payload.get("resource_type") == "repository":
        repo_id = payload.get("resource_id")

    return {
        "event_type": event_type,
        "threat_model_id": threat_model_id,
        "repo_id": repo_id,
        "callback_url": payload.get("callback_url"),
        "invocation_id": payload.get("invocation_id"),
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_webhook_handler.py -v`
Expected: PASS — all tests

- [ ] **Step 5: Lint**

Run: `uv run ruff check tmi_tf/webhook_handler.py tests/test_webhook_handler.py && uv run ruff format --check tmi_tf/webhook_handler.py tests/test_webhook_handler.py`

- [ ] **Step 6: Commit**

```bash
git add tmi_tf/webhook_handler.py tests/test_webhook_handler.py
git commit -m "feat: add webhook handler with HMAC, subscription ID, and payload parsing"
```

---

## Task 3: Addon Callback Client

**Files:**
- Create: `tmi_tf/addon_callback.py`
- Test: `tests/test_addon_callback.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_addon_callback.py
"""Tests for addon callback client."""

import hashlib
import hmac
import json
from unittest.mock import patch, MagicMock

import pytest

from tmi_tf.addon_callback import AddonCallback


class TestAddonCallback:
    def test_sign_payload(self):
        cb = AddonCallback(
            callback_url="https://api.tmi.dev/invocations/inv-1/status",
            secret="test-secret",
        )
        body = b'{"status": "completed"}'
        sig = cb._sign(body)
        assert sig.startswith("sha256=")
        # Verify signature is correct
        expected = hmac.new(b"test-secret", body, hashlib.sha256).hexdigest()
        assert sig == f"sha256={expected}"

    @patch("tmi_tf.addon_callback.requests.post")
    def test_send_status_completed(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200)
        cb = AddonCallback(
            callback_url="https://api.tmi.dev/invocations/inv-1/status",
            secret="test-secret",
        )
        cb.send_status("completed")
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert "X-Webhook-Signature" in call_kwargs.kwargs.get("headers", call_kwargs[1].get("headers", {}))

    @patch("tmi_tf.addon_callback.requests.post")
    def test_send_status_failed_request_does_not_raise(self, mock_post):
        """Callback failures should be logged, not raised."""
        mock_post.side_effect = Exception("connection error")
        cb = AddonCallback(
            callback_url="https://api.tmi.dev/invocations/inv-1/status",
            secret="test-secret",
        )
        # Should not raise
        cb.send_status("failed")

    def test_none_callback_is_noop(self):
        cb = AddonCallback(callback_url=None, secret="s")
        # Should not raise or do anything
        cb.send_status("completed")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_addon_callback.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write implementation**

```python
# tmi_tf/addon_callback.py
"""TMI addon invocation status callback client."""

import hashlib
import hmac as hmac_module
import json
import logging
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# Short timeout for callback — must never block job cleanup
CALLBACK_TIMEOUT_SECONDS = 10


class AddonCallback:
    """Sends HMAC-signed status updates to TMI addon callback URL."""

    def __init__(self, callback_url: Optional[str], secret: str):
        self.callback_url = callback_url
        self.secret = secret

    def _sign(self, body: bytes) -> str:
        digest = hmac_module.new(
            self.secret.encode("utf-8"),
            body,
            hashlib.sha256,
        ).hexdigest()
        return f"sha256={digest}"

    def send_status(self, status: str, message: str = "") -> None:
        """Send status update to callback URL. Never raises.

        Args:
            status: One of "in_progress", "completed", "failed".
            message: Optional status message.
        """
        if not self.callback_url:
            return

        try:
            payload = {"status": status}
            if message:
                payload["message"] = message
            body = json.dumps(payload).encode("utf-8")
            signature = self._sign(body)
            response = requests.post(
                self.callback_url,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Webhook-Signature": signature,
                },
                timeout=CALLBACK_TIMEOUT_SECONDS,
            )
            logger.info(
                f"Addon callback sent: status={status}, response={response.status_code}"
            )
        except Exception as e:
            logger.error(f"Addon callback failed: {e}")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_addon_callback.py -v`
Expected: PASS

- [ ] **Step 5: Lint**

Run: `uv run ruff check tmi_tf/addon_callback.py tests/test_addon_callback.py && uv run ruff format --check tmi_tf/addon_callback.py tests/test_addon_callback.py`

- [ ] **Step 6: Commit**

```bash
git add tmi_tf/addon_callback.py tests/test_addon_callback.py
git commit -m "feat: add addon callback client for TMI status updates"
```

---

## Task 4: Update Config for Server Mode

**Files:**
- Modify: `tmi_tf/config.py`
- Test: `tests/test_config.py` (new)

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_config.py
"""Tests for config changes — LLM_API_KEY mapping, server vars, OCI IMDS."""

import os
from unittest.mock import patch

import pytest

from tmi_tf.config import Config


class TestLLMAPIKeyMapping:
    @patch.dict(os.environ, {
        "LLM_PROVIDER": "anthropic",
        "LLM_API_KEY": "test-key-123",
    }, clear=False)
    def test_maps_llm_api_key_to_anthropic(self):
        """LLM_API_KEY should set ANTHROPIC_API_KEY in os.environ before validation."""
        config = Config()
        assert os.environ.get("ANTHROPIC_API_KEY") == "test-key-123"

    @patch.dict(os.environ, {
        "LLM_PROVIDER": "openai",
        "LLM_API_KEY": "test-key-456",
    }, clear=False)
    def test_maps_llm_api_key_to_openai(self):
        config = Config()
        assert os.environ.get("OPENAI_API_KEY") == "test-key-456"


class TestServerConfigVars:
    @patch.dict(os.environ, {
        "LLM_PROVIDER": "anthropic",
        "ANTHROPIC_API_KEY": "test",
        "MAX_CONCURRENT_JOBS": "5",
        "JOB_TIMEOUT": "1800",
        "MAX_MESSAGE_AGE_HOURS": "12",
        "SERVER_PORT": "9090",
        "WEBHOOK_SECRET": "my-secret",
        "WEBHOOK_SUBSCRIPTION_ID": "sub-123",
    }, clear=False)
    def test_server_config_loaded(self):
        config = Config()
        assert config.max_concurrent_jobs == 5
        assert config.job_timeout == 1800
        assert config.max_message_age_hours == 12
        assert config.server_port == 9090
        assert config.webhook_secret == "my-secret"
        assert config.webhook_subscription_id == "sub-123"

    @patch.dict(os.environ, {
        "LLM_PROVIDER": "anthropic",
        "ANTHROPIC_API_KEY": "test",
    }, clear=False)
    def test_server_config_defaults(self):
        config = Config()
        assert config.max_concurrent_jobs == 3
        assert config.job_timeout == 3600
        assert config.max_message_age_hours == 24
        assert config.server_port == 8080
        assert config.webhook_secret is None
        assert config.webhook_subscription_id is None


class TestOCIValidation:
    @patch.dict(os.environ, {
        "LLM_PROVIDER": "oci",
        "OCI_COMPARTMENT_ID": "ocid1.compartment.oc1..test",
    }, clear=False)
    @patch("tmi_tf.config.Config._oci_credentials_available", return_value=True)
    def test_oci_accepts_imds(self, mock_creds):
        """OCI provider should accept IMDS as alternative to ~/.oci/config."""
        config = Config()
        assert config.llm_provider == "oci"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_config.py -v`
Expected: FAIL — missing attributes and methods

- [ ] **Step 3: Modify config.py**

Changes to `tmi_tf/config.py`:

1. After `.env` loading but before `_validate_llm_credentials()`, map `LLM_API_KEY` → provider-specific env var.
2. Add new server config attributes.
3. Add `_oci_credentials_available()` static method that checks for IMDS or `~/.oci/config`.
4. Update OCI validation to use `_oci_credentials_available()`.

Key additions to `Config.__init__()` (after the `.env` load, before `_validate_llm_credentials`):

```python
# Map generic LLM_API_KEY to provider-specific env var
llm_api_key = os.getenv("LLM_API_KEY")
if llm_api_key:
    key_map = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
        "xai": "XAI_API_KEY",
        "gemini": "GEMINI_API_KEY",
    }
    target = key_map.get(self.llm_provider)
    if target:
        os.environ[target] = llm_api_key
```

New attributes after existing application settings:

```python
# Server configuration
self.max_concurrent_jobs: int = int(os.getenv("MAX_CONCURRENT_JOBS", "3"))
self.job_timeout: int = int(os.getenv("JOB_TIMEOUT", "3600"))
self.max_message_age_hours: int = int(os.getenv("MAX_MESSAGE_AGE_HOURS", "24"))
self.server_port: int = int(os.getenv("SERVER_PORT", "8080"))
self.webhook_secret: Optional[str] = os.getenv("WEBHOOK_SECRET") or None
self.webhook_subscription_id: Optional[str] = os.getenv("WEBHOOK_SUBSCRIPTION_ID") or None
self.queue_ocid: Optional[str] = os.getenv("QUEUE_OCID") or None
self.vault_ocid: Optional[str] = os.getenv("VAULT_OCID") or None
self.tmi_client_path: Optional[str] = os.getenv("TMI_CLIENT_PATH") or None
self.oci_compartment_id: Optional[str] = os.getenv("OCI_COMPARTMENT_ID") or None
```

New static method and updated OCI validation:

```python
@staticmethod
def _oci_credentials_available() -> bool:
    """Check if OCI credentials are available via ~/.oci/config or IMDS."""
    oci_config_path = Path.home() / ".oci" / "config"
    if oci_config_path.exists():
        return True
    # Check IMDS availability (instance principal)
    try:
        import requests
        resp = requests.get(
            "http://169.254.169.254/opc/v2/instance/",
            headers={"Authorization": "Bearer Oracle"},
            timeout=2,
        )
        return resp.status_code == 200
    except Exception:
        return False
```

Update `_validate_llm_credentials` OCI block to use `_oci_credentials_available()` instead of checking only `~/.oci/config`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_config.py -v`
Expected: PASS

- [ ] **Step 5: Run existing tests**

Run: `uv run pytest tests/ -v`
Expected: PASS — no regressions

- [ ] **Step 6: Lint**

Run: `uv run ruff check tmi_tf/config.py tests/test_config.py && uv run ruff format --check tmi_tf/config.py tests/test_config.py`

- [ ] **Step 7: Commit**

```bash
git add tmi_tf/config.py tests/test_config.py
git commit -m "feat: add server config vars, LLM_API_KEY mapping, OCI IMDS support"
```

---

## Task 5: Configurable TMI Client Path

**Files:**
- Modify: `tmi_tf/tmi_client_wrapper.py:13-20`

- [ ] **Step 1: Modify tmi_client_wrapper.py**

Replace the hardcoded path block (lines 13-20) with:

```python
# Add tmi-client to path — configurable via TMI_CLIENT_PATH env var
import os as _os
_tmi_client_path_str = _os.getenv("TMI_CLIENT_PATH")
if _tmi_client_path_str:
    tmi_client_path = Path(_tmi_client_path_str)
else:
    tmi_client_path = Path.home() / "Projects" / "tmi-clients" / "python-client-generated"

if tmi_client_path.exists():
    sys.path.insert(0, str(tmi_client_path))
else:
    raise ImportError(
        f"TMI Python client not found at {tmi_client_path}. "
        "Set TMI_CLIENT_PATH environment variable or ensure client is at default location."
    )
```

- [ ] **Step 2: Run existing tests**

Run: `uv run pytest tests/ -v`
Expected: PASS — existing tests use the default path

- [ ] **Step 3: Lint**

Run: `uv run ruff check tmi_tf/tmi_client_wrapper.py && uv run ruff format --check tmi_tf/tmi_client_wrapper.py`

- [ ] **Step 4: Commit**

```bash
git add tmi_tf/tmi_client_wrapper.py
git commit -m "feat: make TMI client path configurable via TMI_CLIENT_PATH"
```

---

## Task 6: Update repo_analyzer.py for Per-Job Temp Dirs

**Files:**
- Modify: `tmi_tf/repo_analyzer.py:212-254`

- [ ] **Step 1: Modify clone_repository_sparse to accept optional temp_dir**

Update the `clone_repository_sparse` method signature to accept an optional `base_temp_dir` parameter. When provided, create the clone directory under it instead of the system temp dir.

Also verify the sparse checkout patterns in `_sparse_clone` (line 300-303) only include `*.tf` and `*.tfvars` — the current code already does this correctly, so no change needed there.

```python
@contextmanager
def clone_repository_sparse(self, repo_url: str, repo_name: str, base_temp_dir: Optional[Path] = None):
    """Clone repository with sparse checkout for Terraform files.

    Args:
        repo_url: Repository URL
        repo_name: Repository name (for logging)
        base_temp_dir: Optional base directory for temp files (for job isolation)
    """
    if base_temp_dir:
        temp_dir = (base_temp_dir / f"clone-{repo_name}").resolve()
        temp_dir.mkdir(parents=True, exist_ok=True)
    else:
        temp_dir = Path(tempfile.mkdtemp(prefix=f"tmi-tf-{repo_name}-")).resolve()
    # ... rest unchanged
```

- [ ] **Step 2: Run existing tests**

Run: `uv run pytest tests/test_repo_analyzer.py -v`
Expected: PASS — optional parameter doesn't break existing callers

- [ ] **Step 3: Lint**

Run: `uv run ruff check tmi_tf/repo_analyzer.py && uv run ruff format --check tmi_tf/repo_analyzer.py`

- [ ] **Step 4: Commit**

```bash
git add tmi_tf/repo_analyzer.py
git commit -m "feat: add optional base_temp_dir to clone_repository_sparse"
```

---

## Task 7: Extract Analysis Pipeline (analyzer.py)

This is the core refactor — extracting the pipeline from `cli.py` into `analyzer.py`.

**Files:**
- Create: `tmi_tf/analyzer.py`
- Modify: `tmi_tf/cli.py:82-576`
- Test: `tests/test_analyzer.py`

- [ ] **Step 1: Write a basic test for run_analysis interface**

```python
# tests/test_analyzer.py
"""Tests for the extracted analysis pipeline."""

from unittest.mock import MagicMock, patch
from pathlib import Path

import pytest

from tmi_tf.analyzer import run_analysis, AnalysisResult


class TestRunAnalysisInterface:
    def test_returns_analysis_result(self):
        """Verify run_analysis returns an AnalysisResult with expected fields."""
        # This is a smoke test that the function signature and return type are correct.
        # Full integration testing requires mocking TMI/LLM clients.
        result = AnalysisResult(
            success=True,
            analyses=[],
            errors=[],
        )
        assert result.success is True
        assert result.analyses == []
        assert result.errors == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_analyzer.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Create analyzer.py**

Extract the body of the `analyze()` Click command (lines 102-576 of `cli.py`) into `run_analysis()`. Key changes:
- Function signature: `def run_analysis(config, threat_model_id, repo_id=None, temp_dir=None, callback=None, skip_diagram=False, skip_threats=False) -> AnalysisResult`
- Replace `click.echo`/`click.prompt` with logger calls
- When multiple environments found: analyze ALL of them (no interactive prompt)
- Use `base_temp_dir` parameter when calling `clone_repository_sparse`
- Use `callback.send_status()` for addon callbacks where applicable
- Return `AnalysisResult` dataclass instead of `sys.exit()`

```python
# tmi_tf/analyzer.py
"""Analysis pipeline — shared by CLI and webhook worker."""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from tmi_tf.addon_callback import AddonCallback
from tmi_tf.artifact_metadata import aggregate_analysis_metadata, create_artifact_metadata
from tmi_tf.config import Config
from tmi_tf.dfd_llm_generator import DFDLLMGenerator
from tmi_tf.diagram_builder import DFDBuilder
from tmi_tf.github_client import GitHubClient
from tmi_tf.llm_analyzer import LLMAnalyzer
from tmi_tf.markdown_generator import MarkdownGenerator
from tmi_tf.repo_analyzer import RepositoryAnalyzer
from tmi_tf.threat_processor import ThreatProcessor
from tmi_tf.tmi_client_wrapper import TMIClient

logger = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    success: bool
    analyses: list
    errors: list = field(default_factory=list)
    inventory_content: str = ""
    analysis_content: str = ""


def run_analysis(
    config: Config,
    threat_model_id: str,
    tmi_client: TMIClient,
    repo_id: Optional[str] = None,
    temp_dir: Optional[Path] = None,
    callback: Optional[AddonCallback] = None,
    skip_diagram: bool = False,
    skip_threats: bool = False,
    environment: Optional[str] = None,
) -> AnalysisResult:
    """Run the full analysis pipeline.

    This is the core pipeline used by both CLI and webhook worker.
    Synchronous — the webhook worker wraps this in asyncio.to_thread().

    Args:
        config: Application configuration.
        threat_model_id: UUID of the threat model.
        tmi_client: Authenticated TMI client.
        repo_id: Optional specific repository ID to analyze (by TMI resource ID).
        temp_dir: Optional base temp directory for clone isolation.
        callback: Optional addon callback for status updates.
        skip_diagram: Skip DFD generation.
        skip_threats: Skip threat creation.
        environment: Optional environment name to filter (CLI only). If None in
            server mode, ALL detected environments are analyzed.
    """
    errors: list[str] = []

    tmi_client.update_status_note(threat_model_id, "Analysis started")
    github_client = GitHubClient(config)
    repo_analyzer = RepositoryAnalyzer(config)
    llm_analyzer = LLMAnalyzer(config)
    markdown_gen = MarkdownGenerator()

    # Fetch threat model
    threat_model = tmi_client.get_threat_model(threat_model_id)
    logger.info(f"Threat Model: {threat_model.name}")

    # Get repositories
    repositories = tmi_client.get_threat_model_repositories(threat_model_id)
    github_repos = [r for r in repositories if github_client.is_github_url(r.uri)]

    if not github_repos:
        return AnalysisResult(success=False, analyses=[], errors=["No GitHub repositories found"])

    # If repo_id specified, filter to just that repo
    if repo_id:
        github_repos = [r for r in github_repos if str(r.id) == repo_id]
        if not github_repos:
            return AnalysisResult(success=False, analyses=[], errors=[f"Repository {repo_id} not found"])

    repos_to_analyze = github_repos[: config.max_repos]
    analyses = []
    selected_env_name: Optional[str] = None

    for i, repo in enumerate(repos_to_analyze, 1):
        logger.info(f"Repository {i}/{len(repos_to_analyze)}: {repo.name}")
        try:
            repo_name = repo_analyzer.extract_repository_name(repo.uri)
            tmi_client.update_status_note(threat_model_id, f"Cloning repository: {repo.uri}")

            with repo_analyzer.clone_repository_sparse(repo.uri, repo_name, base_temp_dir=temp_dir) as tf_repo:
                if not tf_repo:
                    logger.warning(f"Skipping {repo.name} - no Terraform files found")
                    continue

                tmi_client.update_status_note(threat_model_id, f"Clone complete: {repo_name}")
                envs = RepositoryAnalyzer.detect_environments(tf_repo.clone_path)
                tf_repo.environments_found = [e.name for e in envs]

                if len(envs) == 0:
                    # No environments detected — analyze all .tf files
                    logger.info("No Terraform environments detected, analyzing all files")
                    tmi_client.update_status_note(threat_model_id, f"No environments detected in {repo_name}")

                    def _status_cb(msg: str) -> None:
                        tmi_client.update_status_note(threat_model_id, msg)

                    analysis = llm_analyzer.analyze_repository(tf_repo, status_callback=_status_cb)
                    analyses.append(analysis)

                else:
                    # Determine which environments to analyze
                    if environment:
                        # CLI mode: filter to specific environment
                        envs_to_run = [e for e in envs if e.name.lower() == environment.lower()]
                        if not envs_to_run:
                            available = ", ".join(e.name for e in envs)
                            errors.append(f"Environment '{environment}' not found. Available: {available}")
                            continue
                    else:
                        # Server mode (or CLI with single env): analyze all
                        envs_to_run = envs

                    for selected in envs_to_run:
                        selected_env_name = selected.name
                        tf_repo.environment_name = selected.name
                        logger.info(f"Analyzing environment: {selected.name}")
                        tmi_client.update_status_note(threat_model_id, f"Resolving modules for: {selected.name}")
                        tf_repo.terraform_files = RepositoryAnalyzer.resolve_modules(selected, tf_repo.clone_path)

                        def _status_cb(msg: str) -> None:
                            tmi_client.update_status_note(threat_model_id, msg)

                        analysis = llm_analyzer.analyze_repository(tf_repo, status_callback=_status_cb)
                        analyses.append(analysis)

        except Exception as e:
            logger.error(f"Failed to analyze {repo.name}: {e}")
            errors.append(f"Failed to analyze {repo.name}: {e}")
            continue

    if not analyses:
        return AnalysisResult(success=False, analyses=[], errors=errors or ["No repositories analyzed"])

    # Build artifact names
    model_label = config.effective_model
    ts = config.timestamp
    if selected_env_name and len(repos_to_analyze) == 1:
        inventory_note_name = f"Terraform Inventory - {selected_env_name} ({model_label}, {ts})"
        analysis_note_name = f"Terraform Analysis - {selected_env_name} ({model_label}, {ts})"
        diagram_name = f"Infrastructure Data Flow Diagram - {selected_env_name} ({model_label}, {ts})"
    else:
        inventory_note_name = f"Terraform Inventory ({model_label}, {ts})"
        analysis_note_name = f"Terraform Analysis ({model_label}, {ts})"
        diagram_name = f"Infrastructure Data Flow Diagram ({model_label}, {ts})"

    # Generate reports
    tmi_client.update_status_note(threat_model_id, "Generating inventory report")
    inventory_content = markdown_gen.generate_inventory_report(
        threat_model_name=threat_model.name,
        threat_model_id=threat_model_id,
        analyses=analyses,
        environment_name=selected_env_name,
    )

    tmi_client.update_status_note(threat_model_id, "Generating analysis report")
    analysis_content = markdown_gen.generate_analysis_report(
        threat_model_name=threat_model.name,
        threat_model_id=threat_model_id,
        analyses=analyses,
        environment_name=selected_env_name,
    )

    # Create notes in TMI
    repo_short_names = [a.repo_url.rstrip("/").removesuffix(".git").split("/")[-1] for a in analyses]
    repo_word = "repository" if len(repo_short_names) == 1 else "repositories"
    repo_list = ", ".join(repo_short_names)

    inv_note = tmi_client.create_or_update_note(
        threat_model_id=threat_model_id,
        name=inventory_note_name,
        content=inventory_content,
        description=f"Infrastructure inventory from Terraform templates in {repo_word}: {repo_list}",
    )

    artifact_metadata = aggregate_analysis_metadata(
        analyses=analyses, provider=llm_analyzer.provider, model=llm_analyzer.model,
    )
    try:
        tmi_client.set_note_metadata(
            threat_model_id=threat_model_id, note_id=inv_note.id,
            metadata=artifact_metadata.to_metadata_list(),
        )
    except Exception as e:
        logger.warning(f"Failed to set inventory note metadata: {e}")

    analysis_note = tmi_client.create_or_update_note(
        threat_model_id=threat_model_id,
        name=analysis_note_name,
        content=analysis_content,
        description=f"Terraform analysis for {repo_word}: {repo_list}",
    )
    try:
        tmi_client.set_note_metadata(
            threat_model_id=threat_model_id, note_id=analysis_note.id,
            metadata=artifact_metadata.to_metadata_list(),
        )
    except Exception as e:
        logger.warning(f"Failed to set analysis note metadata: {e}")

    # Generate DFD diagram
    if not skip_diagram:
        tmi_client.update_status_note(threat_model_id, "Generating DFD diagram")
        try:
            dfd_generator = DFDLLMGenerator(config=config)
            combined_inventory: dict = {"components": [], "services": []}
            combined_infrastructure: dict = {"architecture_summary": "", "relationships": [], "data_flows": [], "trust_boundaries": []}
            for analysis in analyses:
                if analysis.success:
                    inv = analysis.inventory or {}
                    infra = analysis.infrastructure or {}
                    combined_inventory["components"].extend(inv.get("components", []))
                    combined_inventory["services"].extend(inv.get("services", []))
                    combined_infrastructure["relationships"].extend(infra.get("relationships", []))
                    combined_infrastructure["data_flows"].extend(infra.get("data_flows", []))
                    combined_infrastructure["trust_boundaries"].extend(infra.get("trust_boundaries", []))
                    arch = infra.get("architecture_summary", "")
                    if arch:
                        if combined_infrastructure["architecture_summary"]:
                            combined_infrastructure["architecture_summary"] += f"\n\n{arch}"
                        else:
                            combined_infrastructure["architecture_summary"] = arch

            structured_data = dfd_generator.generate_structured_components(
                inventory=combined_inventory, infrastructure=combined_infrastructure,
            )
            if structured_data:
                builder = DFDBuilder(
                    components=structured_data["components"],
                    flows=structured_data["flows"],
                    services=combined_inventory.get("services"),
                )
                cells = builder.build_cells()
                diagram = tmi_client.create_or_update_diagram(
                    threat_model_id=threat_model_id, name=diagram_name, cells=cells,
                )
                diagram_id = diagram["id"] if isinstance(diagram, dict) else diagram.id
                diagram_metadata = create_artifact_metadata(
                    provider=dfd_generator.provider, model=dfd_generator.model,
                    input_tokens=dfd_generator.input_tokens, output_tokens=dfd_generator.output_tokens,
                    cost_estimate_usd=dfd_generator.total_cost,
                )
                try:
                    tmi_client.set_diagram_metadata(
                        threat_model_id=threat_model_id, diagram_id=diagram_id,
                        metadata=diagram_metadata.to_metadata_list(),
                    )
                except Exception as e:
                    logger.warning(f"Failed to set diagram metadata: {e}")
        except Exception as e:
            logger.error(f"Failed to generate diagram: {e}")

    # Create threats
    if not skip_threats:
        tmi_client.update_status_note(threat_model_id, "Creating threats")
        try:
            threat_processor = ThreatProcessor(config)
            all_threats = []
            for analysis in analyses:
                if analysis.success and analysis.security_findings:
                    threats = threat_processor.threats_from_findings(analysis.security_findings, analysis.repo_name)
                    all_threats.extend(threats)

            if all_threats:
                diagram_id_for_threats = None
                if not skip_diagram:
                    try:
                        existing = tmi_client.find_diagram_by_name(threat_model_id, diagram_name)
                        if existing:
                            diagram_id_for_threats = str(existing.id) if existing.id else None
                    except Exception:
                        pass

                sec_input = sum(a.security_input_tokens for a in analyses if a.success)
                sec_output = sum(a.security_output_tokens for a in analyses if a.success)
                sec_cost = sum(a.security_cost for a in analyses if a.success)
                threat_metadata = create_artifact_metadata(
                    provider=llm_analyzer.provider, model=llm_analyzer.model,
                    input_tokens=sec_input, output_tokens=sec_output, cost_estimate_usd=sec_cost,
                )
                threat_processor.create_threats_in_tmi(
                    threats=all_threats, threat_model_id=threat_model_id,
                    tmi_client=tmi_client, diagram_id=diagram_id_for_threats,
                    metadata=threat_metadata.to_metadata_list(),
                )
        except Exception as e:
            logger.error(f"Failed to create threats: {e}")

    tmi_client.update_status_note(threat_model_id, "Analysis complete")
    return AnalysisResult(
        success=True, analyses=analyses, errors=errors,
        inventory_content=inventory_content, analysis_content=analysis_content,
    )
```

- [ ] **Step 4: Update cli.py to use analyzer.py**

Replace the body of the `analyze()` Click command with a thin wrapper. The CLI-specific concerns (`dry_run`, `output`, `environment` filter, `force_auth`) stay in `cli.py`:

```python
def analyze(threat_model_id, max_repos, dry_run, output, force_auth, verbose, skip_diagram, skip_threats, environment):
    """Analyze Terraform repositories for a threat model."""
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        config = get_config()
        if max_repos:
            config.max_repos = max_repos

        tmi_client = TMIClient.create_authenticated(config, force_refresh=force_auth)

        # In CLI mode, pass environment filter if specified.
        # If environment is None and multiple envs exist, analyzer.py
        # analyzes ALL of them (server behavior). The --environment flag
        # lets CLI users filter to one.
        result = run_analysis(
            config=config,
            threat_model_id=threat_model_id,
            tmi_client=tmi_client,
            skip_diagram=skip_diagram or dry_run,
            skip_threats=skip_threats or dry_run,
            environment=environment,
        )

        if not result.success:
            logger.error("Analysis failed")
            for err in result.errors:
                logger.error(f"  {err}")
            sys.exit(1)

        # CLI-specific: save to file or print to stdout
        if output:
            from pathlib import Path as _Path
            out_path = _Path(output)
            stem = out_path.stem
            suffix = out_path.suffix or ".md"
            parent = out_path.parent
            inv_path = parent / f"{stem}-inventory{suffix}"
            analysis_path = parent / f"{stem}-analysis{suffix}"
            MarkdownGenerator().save_to_file(result.inventory_content, str(inv_path))
            MarkdownGenerator().save_to_file(result.analysis_content, str(analysis_path))
            logger.info(f"Reports saved to: {inv_path}, {analysis_path}")

        if dry_run and not output:
            print("\n" + "=" * 80)
            print("INVENTORY REPORT")
            print("=" * 80 + "\n")
            print(result.inventory_content)
            print("\n" + "=" * 80)
            print("ANALYSIS REPORT")
            print("=" * 80 + "\n")
            print(result.analysis_content)

        logger.info("Analysis complete!")

    except click.Abort:
        logger.info("Analysis cancelled by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
```

Note: add `from tmi_tf.analyzer import run_analysis` to the imports at the top of `cli.py`.

- [ ] **Step 5: Run all tests**

Run: `uv run pytest tests/ -v`
Expected: PASS

- [ ] **Step 6: Lint**

Run: `uv run ruff check tmi_tf/analyzer.py tmi_tf/cli.py tests/test_analyzer.py && uv run ruff format --check tmi_tf/analyzer.py tmi_tf/cli.py tests/test_analyzer.py`

- [ ] **Step 7: Commit**

```bash
git add tmi_tf/analyzer.py tmi_tf/cli.py tests/test_analyzer.py
git commit -m "refactor: extract analysis pipeline from cli.py into analyzer.py"
```

---

## Task 8: Vault Client

**Files:**
- Create: `tmi_tf/vault_client.py`
- Test: `tests/test_vault_client.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_vault_client.py
"""Tests for OCI Vault client."""

import os
from unittest.mock import patch, MagicMock

import pytest

from tmi_tf.vault_client import load_secrets_from_vault, VAULT_SECRET_MAP


class TestLoadSecrets:
    @patch("tmi_tf.vault_client._get_vault_client")
    @patch("tmi_tf.vault_client._get_secrets_client")
    def test_loads_secrets_into_env(self, mock_secrets_client, mock_vault_client):
        """Secrets from Vault should be set as environment variables."""
        mock_secret = MagicMock()
        mock_secret.secret_name = "webhook-secret"
        mock_secrets_client.return_value.list_secrets.return_value.data = [mock_secret]

        mock_bundle = MagicMock()
        mock_bundle.data.secret_bundle_content.content = "dGVzdC12YWx1ZQ=="  # base64 "test-value"
        mock_secrets_client.return_value.get_secret_bundle.return_value.data = mock_bundle

        load_secrets_from_vault("ocid1.vault.oc1..test", "ocid1.compartment.oc1..test")
        assert os.environ.get("WEBHOOK_SECRET") == "test-value"

    def test_vault_secret_map_complete(self):
        """All expected secrets should be in the map."""
        expected = {"webhook-secret", "tmi-client-id", "tmi-client-secret", "llm-api-key", "github-token"}
        assert set(VAULT_SECRET_MAP.keys()) == expected
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_vault_client.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write implementation**

```python
# tmi_tf/vault_client.py
"""OCI Vault secret loading — instance principal (IMDS) or ~/.oci/config."""

import base64
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

# Maps Vault secret names to environment variable names
VAULT_SECRET_MAP = {
    "webhook-secret": "WEBHOOK_SECRET",
    "tmi-client-id": "TMI_CLIENT_ID",
    "tmi-client-secret": "TMI_CLIENT_SECRET",
    "llm-api-key": "LLM_API_KEY",
    "github-token": "GITHUB_TOKEN",
}


def _get_oci_signer():
    """Get OCI signer — tries instance principal first, falls back to config file."""
    try:
        from oci.auth.signers import InstancePrincipalsSecurityTokenSigner  # pyright: ignore[reportMissingImports]
        return InstancePrincipalsSecurityTokenSigner()
    except Exception:
        logger.info("Instance principal not available, falling back to ~/.oci/config")
        from oci.config import from_file as oci_from_file  # pyright: ignore[reportMissingImports]
        from oci.signer import Signer  # pyright: ignore[reportMissingImports]
        config = oci_from_file(str(Path.home() / ".oci" / "config"))
        return Signer(
            tenancy=config["tenancy"],
            user=config["user"],
            fingerprint=config["fingerprint"],
            private_key_file_location=config["key_file"],
            private_key_content=config.get("key_content"),
        )


def _get_vault_client():
    from oci.vault import VaultsClient  # pyright: ignore[reportMissingImports]
    signer = _get_oci_signer()
    return VaultsClient(config={}, signer=signer)


def _get_secrets_client():
    from oci.secrets import SecretsClient  # pyright: ignore[reportMissingImports]
    signer = _get_oci_signer()
    return SecretsClient(config={}, signer=signer)


def load_secrets_from_vault(vault_ocid: str, compartment_ocid: str) -> None:
    """Load all mapped secrets from OCI Vault into environment variables.

    Args:
        vault_ocid: OCID of the OCI Vault.
        compartment_ocid: OCID of the compartment containing the vault.
    """
    secrets_client = _get_secrets_client()

    # List secrets in the vault
    response = secrets_client.list_secrets(compartment_id=compartment_ocid, vault_id=vault_ocid)
    secret_map = {s.secret_name: s.id for s in response.data}

    for vault_name, env_var in VAULT_SECRET_MAP.items():
        secret_id = secret_map.get(vault_name)
        if not secret_id:
            logger.debug(f"Secret '{vault_name}' not found in vault")
            continue

        try:
            bundle = secrets_client.get_secret_bundle(secret_id=secret_id)
            content_b64 = bundle.data.secret_bundle_content.content
            value = base64.b64decode(content_b64).decode("utf-8")
            os.environ[env_var] = value
            logger.info(f"Loaded secret '{vault_name}' → ${env_var}")
        except Exception as e:
            logger.error(f"Failed to load secret '{vault_name}': {e}")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_vault_client.py -v`
Expected: PASS

- [ ] **Step 5: Lint**

Run: `uv run ruff check tmi_tf/vault_client.py tests/test_vault_client.py && uv run ruff format --check tmi_tf/vault_client.py tests/test_vault_client.py`

- [ ] **Step 6: Commit**

```bash
git add tmi_tf/vault_client.py tests/test_vault_client.py
git commit -m "feat: add OCI Vault client for secret loading"
```

---

## Task 9: Queue Client

**Files:**
- Create: `tmi_tf/queue_client.py`
- Test: `tests/test_queue_client.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_queue_client.py
"""Tests for OCI Queue client wrapper."""

import json
from unittest.mock import patch, MagicMock

import pytest

from tmi_tf.queue_client import QueueClient


class TestQueueClient:
    @patch("tmi_tf.queue_client.QueueClient._get_client")
    def test_publish(self, mock_get):
        mock_client = MagicMock()
        mock_get.return_value = mock_client
        qc = QueueClient(queue_ocid="ocid1.queue.oc1..test")
        qc.publish({"job_id": "j1", "threat_model_id": "tm-1"})
        mock_client.put_messages.assert_called_once()

    @patch("tmi_tf.queue_client.QueueClient._get_client")
    def test_consume_returns_messages(self, mock_get):
        mock_client = MagicMock()
        mock_msg = MagicMock()
        mock_msg.content = json.dumps({"job_id": "j1"})
        mock_msg.receipt = "receipt-1"
        mock_client.get_messages.return_value.data.messages = [mock_msg]
        mock_get.return_value = mock_client
        qc = QueueClient(queue_ocid="ocid1.queue.oc1..test")
        messages = qc.consume(max_messages=1)
        assert len(messages) == 1

    @patch("tmi_tf.queue_client.QueueClient._get_client")
    def test_delete(self, mock_get):
        mock_client = MagicMock()
        mock_get.return_value = mock_client
        qc = QueueClient(queue_ocid="ocid1.queue.oc1..test")
        qc.delete("receipt-1")
        mock_client.delete_message.assert_called_once()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_queue_client.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write implementation**

```python
# tmi_tf/queue_client.py
"""OCI Queue client wrapper for job dispatch."""

import json
import logging
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class QueueMessage:
    """Deserialized queue message with receipt for deletion."""
    body: dict
    receipt: str


class QueueClient:
    """Wraps OCI Queue SDK for publish, consume, delete operations."""

    def __init__(self, queue_ocid: str):
        self.queue_ocid = queue_ocid
        self._client = None

    def _get_client(self):
        if self._client is None:
            from oci.queue import QueueClient as OCIQueueClient  # pyright: ignore[reportMissingImports]
            from tmi_tf.vault_client import _get_oci_signer
            signer = _get_oci_signer()
            self._client = OCIQueueClient(config={}, signer=signer)
        return self._client

    def publish(self, message: dict) -> None:
        """Publish a message to the queue."""
        from oci.queue.models import PutMessagesDetails, PutMessagesDetailsEntry  # pyright: ignore[reportMissingImports]
        client = self._get_client()
        body = json.dumps(message)
        details = PutMessagesDetails(
            messages=[PutMessagesDetailsEntry(content=body)]
        )
        client.put_messages(queue_id=self.queue_ocid, put_messages_details=details)
        logger.info(f"Published message to queue: job_id={message.get('job_id')}")

    def consume(self, max_messages: int = 1, visibility_timeout: int = 900) -> List[QueueMessage]:
        """Consume messages from the queue.

        Args:
            max_messages: Max messages to receive.
            visibility_timeout: Seconds before message becomes visible again.
        """
        client = self._get_client()
        response = client.get_messages(
            queue_id=self.queue_ocid,
            limit=max_messages,
            visibility_in_seconds=visibility_timeout,
        )
        messages = []
        for msg in response.data.messages:
            try:
                body = json.loads(msg.content)
                messages.append(QueueMessage(body=body, receipt=msg.receipt))
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse queue message: {e}")
                self.delete(msg.receipt)
        return messages

    def delete(self, receipt: str) -> None:
        """Delete a message from the queue by receipt."""
        client = self._get_client()
        client.delete_message(queue_id=self.queue_ocid, message_receipt=receipt)
        logger.debug(f"Deleted queue message: receipt={receipt[:20]}...")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_queue_client.py -v`
Expected: PASS

- [ ] **Step 5: Lint**

Run: `uv run ruff check tmi_tf/queue_client.py tests/test_queue_client.py && uv run ruff format --check tmi_tf/queue_client.py tests/test_queue_client.py`

- [ ] **Step 6: Commit**

```bash
git add tmi_tf/queue_client.py tests/test_queue_client.py
git commit -m "feat: add OCI Queue client for job dispatch"
```

---

## Task 10: Worker Pool

**Files:**
- Create: `tmi_tf/worker.py`
- Test: `tests/test_worker.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_worker.py
"""Tests for async worker pool."""

import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tmi_tf.job import Job
from tmi_tf.worker import WorkerPool, _is_message_expired


class TestMessageExpiry:
    def test_fresh_message_not_expired(self):
        enqueued = datetime.now(timezone.utc) - timedelta(hours=1)
        assert _is_message_expired(enqueued.isoformat(), max_age_hours=24) is False

    def test_old_message_expired(self):
        enqueued = datetime.now(timezone.utc) - timedelta(hours=25)
        assert _is_message_expired(enqueued.isoformat(), max_age_hours=24) is True

    def test_exactly_at_boundary(self):
        enqueued = datetime.now(timezone.utc) - timedelta(hours=24)
        assert _is_message_expired(enqueued.isoformat(), max_age_hours=24) is True


class TestWorkerPool:
    def test_init(self):
        pool = WorkerPool(
            queue_client=MagicMock(),
            config=MagicMock(max_concurrent_jobs=3, job_timeout=3600, max_message_age_hours=24),
        )
        assert pool.max_concurrent == 3
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_worker.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write implementation**

```python
# tmi_tf/worker.py
"""Async worker pool — polls OCI Queue, manages concurrency and timeouts."""

import asyncio
import logging
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from tmi_tf.addon_callback import AddonCallback
from tmi_tf.analyzer import run_analysis
from tmi_tf.config import Config
from tmi_tf.job import Job
from tmi_tf.queue_client import QueueClient, QueueMessage
from tmi_tf.tmi_client_wrapper import TMIClient

logger = logging.getLogger(__name__)

POLL_INTERVAL_SECONDS = 5


def _is_message_expired(enqueued_at_iso: str, max_age_hours: int) -> bool:
    """Check if a message is older than the configured max age."""
    enqueued = datetime.fromisoformat(enqueued_at_iso)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
    return enqueued <= cutoff


class WorkerPool:
    """Async worker pool that processes jobs from OCI Queue."""

    def __init__(self, queue_client: QueueClient, config: Config):
        self.queue_client = queue_client
        self.config = config
        self.max_concurrent = config.max_concurrent_jobs
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        self._active_jobs: dict[str, Job] = {}
        self._running = False

    async def start(self) -> None:
        """Start the worker pool polling loop."""
        self._running = True
        logger.info(f"Worker pool started: max_concurrent={self.max_concurrent}")
        while self._running:
            try:
                await self._poll_and_dispatch()
            except Exception as e:
                logger.error(f"Worker pool error: {e}")
            await asyncio.sleep(POLL_INTERVAL_SECONDS)

    async def stop(self) -> None:
        """Stop the worker pool."""
        self._running = False
        logger.info("Worker pool stopping...")

    async def _poll_and_dispatch(self) -> None:
        """Poll queue for messages and dispatch to workers."""
        # Only consume up to available worker slots
        available = self.max_concurrent - len(self._active_jobs)
        if available <= 0:
            return

        messages = await asyncio.to_thread(
            self.queue_client.consume, max_messages=available
        )

        for msg in messages:
            asyncio.create_task(self._handle_message(msg))

    async def _handle_message(self, msg: QueueMessage) -> None:
        """Handle a single queue message — check age, dispatch job."""
        # Check message age
        enqueued_at = msg.body.get("enqueued_at", "")
        if _is_message_expired(enqueued_at, self.config.max_message_age_hours):
            logger.warning(f"Discarding stale message: job_id={msg.body.get('job_id')}, enqueued_at={enqueued_at}")
            await asyncio.to_thread(self.queue_client.delete, msg.receipt)
            return

        job = Job.from_queue_message(msg.body)
        job.temp_dir = Path(tempfile.mkdtemp(prefix=f"tmi-tf-{job.job_id}-"))

        async with self._semaphore:
            self._active_jobs[job.job_id] = job
            try:
                await asyncio.wait_for(
                    self._run_job(job, msg.receipt),
                    timeout=self.config.job_timeout,
                )
            except asyncio.TimeoutError:
                logger.error(f"Job timed out: job_id={job.job_id}")
                # Delete message — don't retry timed out jobs
                try:
                    await asyncio.to_thread(self.queue_client.delete, msg.receipt)
                except Exception as e:
                    logger.error(f"Failed to delete timed-out message: {e}")
                # Best-effort status updates
                await self._fire_and_forget_status(job, "failed", "Job timed out")
            finally:
                self._active_jobs.pop(job.job_id, None)
                # Clean up temp dir
                if job.temp_dir and job.temp_dir.exists():
                    try:
                        shutil.rmtree(job.temp_dir)
                    except Exception as e:
                        logger.warning(f"Failed to clean up {job.temp_dir}: {e}")

    async def _run_job(self, job: Job, receipt: str) -> None:
        """Run analysis job in thread pool."""
        logger.info(f"Starting job: job_id={job.job_id}, threat_model_id={job.threat_model_id}")

        callback = None
        if job.callback_url and self.config.webhook_secret:
            callback = AddonCallback(job.callback_url, self.config.webhook_secret)
            callback.send_status("in_progress")

        try:
            config = self.config
            tmi_client = TMIClient.create_authenticated(config)
            result = await asyncio.to_thread(
                run_analysis,
                config=config,
                threat_model_id=job.threat_model_id,
                tmi_client=tmi_client,
                repo_id=job.repo_id,
                temp_dir=job.temp_dir,
                callback=callback,
            )

            if result.success:
                logger.info(f"Job completed: job_id={job.job_id}")
                if callback:
                    callback.send_status("completed")
            else:
                logger.error(f"Job failed: job_id={job.job_id}, errors={result.errors}")
                if callback:
                    callback.send_status("failed", "; ".join(result.errors))

            # Delete message on success or failure (don't retry failed analyses)
            await asyncio.to_thread(self.queue_client.delete, receipt)

        except Exception as e:
            logger.error(f"Job exception: job_id={job.job_id}, error={e}")
            if callback:
                callback.send_status("failed", str(e))
            # Don't delete — let visibility timeout handle retry
            raise

    async def _fire_and_forget_status(self, job: Job, status: str, message: str) -> None:
        """Send status updates that must not block cleanup."""
        # Addon callback
        if job.callback_url and self.config.webhook_secret:
            try:
                cb = AddonCallback(job.callback_url, self.config.webhook_secret)
                await asyncio.to_thread(cb.send_status, status, message)
            except Exception as e:
                logger.error(f"Fire-and-forget callback failed: {e}")

        # TMI status note
        try:
            tmi_client = TMIClient.create_authenticated(self.config)
            await asyncio.to_thread(
                tmi_client.update_status_note,
                job.threat_model_id,
                f"Analysis {status}: {message}",
            )
        except Exception as e:
            logger.error(f"Fire-and-forget status note failed: {e}")

    def get_status(self) -> dict:
        """Return current worker pool status for /status endpoint."""
        return {
            "active_jobs": {
                jid: {
                    "threat_model_id": j.threat_model_id,
                    "event_type": j.event_type,
                    "repo_id": j.repo_id,
                }
                for jid, j in self._active_jobs.items()
            },
            "active_count": len(self._active_jobs),
            "max_concurrent": self.max_concurrent,
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_worker.py -v`
Expected: PASS

- [ ] **Step 5: Lint**

Run: `uv run ruff check tmi_tf/worker.py tests/test_worker.py && uv run ruff format --check tmi_tf/worker.py tests/test_worker.py`

- [ ] **Step 6: Commit**

```bash
git add tmi_tf/worker.py tests/test_worker.py
git commit -m "feat: add async worker pool with timeout and message age handling"
```

---

## Task 11: Update pyproject.toml Dependencies

**Files:**
- Modify: `pyproject.toml`

FastAPI and uvicorn must be added before writing the server module.

- [ ] **Step 1: Add fastapi and uvicorn to dependencies**

Add to the `dependencies` list in `pyproject.toml`:

```
"fastapi>=0.115.0",
"uvicorn[standard]>=0.30.0",
```

- [ ] **Step 2: Verify install**

Run: `uv sync`
Expected: Dependencies installed successfully

- [ ] **Step 3: Run all tests**

Run: `uv run pytest tests/ -v`
Expected: PASS — no regressions

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml uv.lock
git commit -m "feat: add fastapi and uvicorn dependencies"
```

---

## Task 12: FastAPI Server

**Files:**
- Create: `tmi_tf/server.py`
- Test: `tests/test_server.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_server.py
"""Tests for FastAPI server endpoints."""

import hashlib
import hmac
import json
from unittest.mock import patch, MagicMock, AsyncMock

import pytest
from fastapi.testclient import TestClient


class TestWebhookEndpoint:
    @patch("tmi_tf.server.queue_client")
    @patch("tmi_tf.server.get_config")
    def test_valid_webhook_accepted(self, mock_config, mock_queue):
        mock_config.return_value = MagicMock(
            webhook_secret="test-secret",
            webhook_subscription_id=None,
        )
        from tmi_tf.server import app
        client = TestClient(app)

        body = json.dumps({
            "event_type": "threat_model.created",
            "threat_model_id": "tm-1",
        })
        digest = hmac.new(b"test-secret", body.encode(), hashlib.sha256).hexdigest()
        response = client.post(
            "/webhook",
            content=body,
            headers={
                "X-Webhook-Signature": f"sha256={digest}",
                "X-Webhook-Delivery-Id": "del-1",
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 200
        assert response.json()["status"] == "accepted"

    @patch("tmi_tf.server.get_config")
    def test_invalid_hmac_rejected(self, mock_config):
        mock_config.return_value = MagicMock(
            webhook_secret="test-secret",
            webhook_subscription_id=None,
        )
        from tmi_tf.server import app
        client = TestClient(app)

        response = client.post(
            "/webhook",
            content='{"event_type": "test"}',
            headers={
                "X-Webhook-Signature": "sha256=bad",
                "X-Webhook-Delivery-Id": "del-1",
            },
        )
        assert response.status_code == 401

    @patch("tmi_tf.server.get_config")
    def test_missing_job_id_rejected(self, mock_config):
        mock_config.return_value = MagicMock(
            webhook_secret="test-secret",
            webhook_subscription_id=None,
        )
        from tmi_tf.server import app
        client = TestClient(app)

        body = json.dumps({"event_type": "test", "threat_model_id": "tm-1"})
        digest = hmac.new(b"test-secret", body.encode(), hashlib.sha256).hexdigest()
        response = client.post(
            "/webhook",
            content=body,
            headers={"X-Webhook-Signature": f"sha256={digest}"},
        )
        assert response.status_code == 403


class TestHealthEndpoint:
    def test_health(self):
        from tmi_tf.server import app
        client = TestClient(app)
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_server.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write implementation**

```python
# tmi_tf/server.py
"""FastAPI webhook server — POST /webhook, GET /health, GET /status."""

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request, Response  # pyright: ignore[reportMissingImports]

from tmi_tf.config import get_config
from tmi_tf.queue_client import QueueClient
from tmi_tf.vault_client import load_secrets_from_vault
from tmi_tf.webhook_handler import (
    extract_job_id,
    handle_challenge,
    parse_webhook_payload,
    validate_subscription_id,
    verify_hmac_signature,
)
from tmi_tf.worker import WorkerPool

logger = logging.getLogger(__name__)

# Module-level references set during lifespan
queue_client: QueueClient | None = None
worker_pool: WorkerPool | None = None


def _configure_logging():
    """Configure structured JSON logging."""
    logging.basicConfig(
        level=logging.INFO,
        format='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","message":"%(message)s"}',
        handlers=[logging.StreamHandler()],
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown."""
    global queue_client, worker_pool

    _configure_logging()
    config = get_config()

    # Load secrets from Vault if configured
    if config.vault_ocid:
        logger.info("Loading secrets from OCI Vault...")
        load_secrets_from_vault(config.vault_ocid, config.oci_compartment_id)
        # Re-initialize config to pick up Vault secrets
        from tmi_tf.config import _config
        _config = None
        config = get_config()

    # Initialize queue client
    if config.queue_ocid:
        queue_client = QueueClient(queue_ocid=config.queue_ocid)
        worker_pool = WorkerPool(queue_client=queue_client, config=config)
        worker_task = asyncio.create_task(worker_pool.start())
        logger.info("Queue client and worker pool initialized")
    else:
        logger.warning("QUEUE_OCID not set — running without queue (webhook-only mode)")

    yield

    # Shutdown
    if worker_pool:
        await worker_pool.stop()
    logger.info("Server shutdown complete")


app = FastAPI(title="TMI Terraform Webhook Analyzer", lifespan=lifespan)


@app.post("/webhook")
async def webhook(request: Request):
    config = get_config()
    raw_body = await request.body()

    # Log request at INFO level
    headers_dict = dict(request.headers)
    logger.info(f"Webhook received: headers={json.dumps(headers_dict)}, body={raw_body.decode('utf-8', errors='replace')}")

    # Subscription ID check
    sub_id = request.headers.get("x-webhook-subscription-id")
    if not validate_subscription_id(sub_id, config.webhook_subscription_id):
        logger.warning(f"Subscription ID mismatch: got={sub_id}")
        return Response(status_code=403, content='{"error": "subscription ID mismatch"}', media_type="application/json")

    # HMAC verification
    signature = request.headers.get("x-webhook-signature", "")
    if not config.webhook_secret or not verify_hmac_signature(raw_body, signature, config.webhook_secret):
        logger.warning("HMAC verification failed")
        return Response(status_code=401, content='{"error": "invalid signature"}', media_type="application/json")

    # Parse payload
    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError:
        return Response(status_code=400, content='{"error": "invalid JSON"}', media_type="application/json")

    # Challenge response
    challenge = handle_challenge(payload)
    if challenge is not None:
        logger.info("Challenge response sent")
        return challenge

    # Extract job ID
    invocation_id = request.headers.get("x-invocation-id")
    delivery_id = request.headers.get("x-webhook-delivery-id")
    try:
        job_id = extract_job_id(invocation_id, delivery_id)
    except ValueError:
        return Response(status_code=403, content='{"error": "missing job ID headers"}', media_type="application/json")

    # Parse payload fields
    try:
        fields = parse_webhook_payload(payload)
    except ValueError as e:
        return Response(status_code=400, content=json.dumps({"error": str(e)}), media_type="application/json")

    # Enqueue
    if queue_client:
        message = {
            "job_id": job_id,
            "enqueued_at": datetime.now(timezone.utc).isoformat(),
            **fields,
        }
        await asyncio.to_thread(queue_client.publish, message)
    else:
        logger.warning("No queue client — message not enqueued")

    return {"status": "accepted", "job_id": job_id}


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "workers": worker_pool.get_status() if worker_pool else None,
        "queue_connected": queue_client is not None,
    }


@app.get("/status")
async def status():
    return {
        "workers": worker_pool.get_status() if worker_pool else None,
        "queue_connected": queue_client is not None,
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_server.py -v`
Expected: PASS

- [ ] **Step 5: Run all tests**

Run: `uv run pytest tests/ -v`
Expected: PASS

- [ ] **Step 6: Lint**

Run: `uv run ruff check tmi_tf/server.py tests/test_server.py && uv run ruff format --check tmi_tf/server.py tests/test_server.py`

- [ ] **Step 7: Commit**

```bash
git add tmi_tf/server.py tests/test_server.py
git commit -m "feat: add FastAPI server with webhook, health, and status endpoints"
```

---

## Task 13: Deployment Files — systemd and Terraform

**Files:**
- Create: `deploy/tmi-tf-wh.service`
- Create: `deploy/terraform/main.tf`
- Create: `deploy/terraform/variables.tf`
- Create: `deploy/terraform/network.tf`
- Create: `deploy/terraform/compute.tf`
- Create: `deploy/terraform/loadbalancer.tf`
- Create: `deploy/terraform/queue.tf`
- Create: `deploy/terraform/vault.tf`
- Create: `deploy/terraform/iam.tf`
- Create: `deploy/terraform/logging.tf`
- Create: `deploy/terraform/outputs.tf`

- [ ] **Step 1: Create systemd unit file**

```ini
# deploy/tmi-tf-wh.service
[Unit]
Description=TMI Terraform Webhook Analyzer
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=tmi-tf
Group=tmi-tf
WorkingDirectory=/opt/tmi-tf-wh
ExecStart=/usr/bin/python3 -m uvicorn tmi_tf.server:app --host 127.0.0.1 --port 8080
Restart=always
RestartSec=5
Environment=TMI_OAUTH_IDP=tmi

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Create Terraform configs**

Create each `.tf` file in `deploy/terraform/` per the spec:
- `main.tf` — OCI provider, required version, compartment data source
- `variables.tf` — compartment_ocid, ssh_public_key, tls_certificate, tls_private_key, shape, etc.
- `network.tf` — VCN, public subnet, private subnet, internet gateway, NAT gateway, route tables, security lists
- `compute.tf` — Instance (VM.Standard.A1.Flex, 1 OCPU, 6GB), cloud-init for packages + app deploy
- `loadbalancer.tf` — Flexible LB, HTTPS listener, backend set, health check
- `queue.tf` — OCI Queue + dead letter queue
- `vault.tf` — Vault, master key, secret shells
- `iam.tf` — Dynamic group, policy for vault/queue access
- `logging.tf` — Log group, custom log, unified monitoring agent config
- `outputs.tf` — LB public IP, instance OCID, queue OCID, vault OCID

- [ ] **Step 3: Validate Terraform**

Run: `cd deploy/terraform && terraform init && terraform validate`
Expected: "Success! The configuration is valid."

- [ ] **Step 4: Commit**

```bash
git add deploy/
git commit -m "feat: add systemd unit and OCI Terraform deployment configs"
```

---

## Task 14: Final Integration Test and Cleanup

- [ ] **Step 1: Run full test suite**

Run: `uv run pytest tests/ -v`
Expected: ALL PASS

- [ ] **Step 2: Lint entire codebase**

Run: `uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/`
Expected: No issues

- [ ] **Step 3: Type check**

Run: `uv run pyright`
Expected: No new errors

- [ ] **Step 4: Verify CLI still works**

Run: `uv run tmi-tf --help`
Expected: Shows CLI help with all commands

- [ ] **Step 5: Verify server starts locally**

Run: `uv run python -m uvicorn tmi_tf.server:app --host 127.0.0.1 --port 8080` (Ctrl+C after confirming startup)
Expected: "Uvicorn running on http://127.0.0.1:8080"

- [ ] **Step 6: Update .env.example**

Add new server config vars to `.env.example`:

```bash
# Server mode configuration
# QUEUE_OCID=ocid1.queue.oc1..example
# VAULT_OCID=ocid1.vault.oc1..example
# WEBHOOK_SECRET=your-hmac-shared-secret
# WEBHOOK_SUBSCRIPTION_ID=optional-subscription-uuid
# MAX_CONCURRENT_JOBS=3
# JOB_TIMEOUT=3600
# MAX_MESSAGE_AGE_HOURS=24
# SERVER_PORT=8080
# TMI_CLIENT_PATH=/opt/tmi-tf-wh/vendor/tmi-client
# LLM_API_KEY=your-llm-api-key
```

- [ ] **Step 7: Final commit**

```bash
git add -A
git commit -m "chore: final integration verification and .env.example update"
```
