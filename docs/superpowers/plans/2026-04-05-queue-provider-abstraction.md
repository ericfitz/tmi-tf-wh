# Queue Provider Abstraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the OCI-coupled `QueueClient` behind a `QueueProvider` protocol so queue backends can be swapped via configuration.

**Architecture:** Define a `QueueProvider` protocol and `QueueMessage` dataclass in `providers/__init__.py`, move the OCI implementation to `providers/oci.py` as `OciQueueProvider`, add a factory function `get_queue_provider()`, add `queue_provider` config field, update consumers (server.py, worker.py), delete `queue_client.py`.

**Tech Stack:** Python, Protocol (typing), dataclasses, OCI Queue SDK (lazy-imported), pytest

---

## File Map

| Action | File | Responsibility |
|--------|------|---------------|
| Modify | `tmi_tf/providers/__init__.py` | Add `QueueMessage` dataclass, `QueueProvider` protocol, `get_queue_provider()` factory |
| Modify | `tmi_tf/providers/oci.py` | Add `OciQueueProvider` class (moved from `queue_client.py`) |
| Modify | `tmi_tf/config.py` | Add `queue_provider` field with backward-compatible inference |
| Modify | `tmi_tf/server.py` | Import from providers, use factory for initialization |
| Modify | `tmi_tf/worker.py` | Import `QueueProvider`/`QueueMessage` from providers |
| Delete | `tmi_tf/queue_client.py` | Replaced by providers |
| Modify | `tests/test_providers.py` | Add queue protocol, factory, OciQueueProvider, and config tests |
| Modify | `tests/test_queue_client.py` | Update to test `OciQueueProvider` from `providers.oci` |
| Modify | `tests/test_server.py` | Update mock config to include `queue_provider` |
| Modify | `tests/test_worker.py` | No import changes needed (uses MagicMock), but verify still passes |

---

### Task 1: Add QueueMessage and QueueProvider to providers/__init__.py

**Files:**
- Modify: `tmi_tf/providers/__init__.py`
- Test: `tests/test_providers.py`

- [ ] **Step 1: Write failing tests for QueueMessage and QueueProvider**

Add to `tests/test_providers.py`:

```python
from dataclasses import fields

from tmi_tf.providers import QueueMessage, QueueProvider


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
```

Also update the existing import line at the top of `tests/test_providers.py`:

```python
from tmi_tf.providers import VAULT_SECRET_MAP, QueueMessage, QueueProvider, SecretProvider, get_secret_provider  # noqa: F401
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_providers.py::TestQueueMessage tests/test_providers.py::TestQueueProviderProtocol -v`
Expected: FAIL with `ImportError: cannot import name 'QueueMessage'`

- [ ] **Step 3: Implement QueueMessage and QueueProvider in providers/__init__.py**

Add to `tmi_tf/providers/__init__.py` after the existing imports and before `VAULT_SECRET_MAP`:

```python
from dataclasses import dataclass


@dataclass
class QueueMessage:
    body: dict
    receipt: str


class QueueProvider(Protocol):
    def publish(self, message: dict) -> None:
        """Serialize message and publish it to the queue."""
        ...

    def consume(
        self, max_messages: int = 1, visibility_timeout: int = 900
    ) -> list["QueueMessage"]:
        """Get messages from the queue and return parsed QueueMessage objects."""
        ...

    def delete(self, receipt: str) -> None:
        """Delete a message from the queue by its receipt."""
        ...
```

The full file should have this import/declaration order:
1. `from __future__ import annotations` (not needed — use string annotation for forward ref)
2. `from dataclasses import dataclass`
3. `from typing import TYPE_CHECKING, Protocol`
4. `TYPE_CHECKING` block
5. `QueueMessage` dataclass
6. `SecretProvider` protocol
7. `QueueProvider` protocol
8. `VAULT_SECRET_MAP`
9. `get_secret_provider()` factory

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_providers.py::TestQueueMessage tests/test_providers.py::TestQueueProviderProtocol -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tmi_tf/providers/__init__.py tests/test_providers.py
git commit -m "feat(providers): add QueueMessage dataclass and QueueProvider protocol"
```

---

### Task 2: Add OciQueueProvider to providers/oci.py

**Files:**
- Modify: `tmi_tf/providers/oci.py`
- Modify: `tests/test_providers.py`

- [ ] **Step 1: Write failing tests for OciQueueProvider**

Add to `tests/test_providers.py`:

```python
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
```

Add `import json` to the top of the test file if not already present.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_providers.py::TestOciQueueProvider -v`
Expected: FAIL with `ImportError: cannot import name 'OciQueueProvider'`

- [ ] **Step 3: Implement OciQueueProvider in providers/oci.py**

Add to the end of `tmi_tf/providers/oci.py`:

```python
class OciQueueProvider:
    """OCI Queue SDK wrapper for publish/consume/delete operations."""

    def __init__(self, queue_ocid: str, queue_endpoint: Optional[str] = None) -> None:
        self._queue_ocid = queue_ocid
        self._queue_endpoint = queue_endpoint
        self._client = None

    def _get_client(self):  # type: ignore[return]
        """Lazy-initialize and return the OCI QueueClient."""
        if self._client is None:
            from oci.queue import QueueClient as OCIQueueClient  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

            signer = get_oci_signer()
            kwargs: dict = {"config": {}, "signer": signer}
            if self._queue_endpoint:
                kwargs["service_endpoint"] = self._queue_endpoint
            self._client = OCIQueueClient(**kwargs)
        return self._client

    def publish(self, message: dict) -> None:
        """Serialize message to JSON and publish it to the queue."""
        from oci.queue.models import PutMessagesDetails, PutMessagesDetailsEntry  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

        client = self._get_client()
        body = json.dumps(message)
        entry = PutMessagesDetailsEntry(content=body)
        details = PutMessagesDetails(messages=[entry])
        client.put_messages(queue_id=self._queue_ocid, put_messages_details=details)
        job_id = message.get("job_id", "<unknown>")
        logger.info(
            "Published message for job_id=%s to queue %s", job_id, self._queue_ocid
        )

    def consume(
        self, max_messages: int = 1, visibility_timeout: int = 900
    ) -> list:
        """Get messages from the queue and return parsed QueueMessage objects.

        If JSON parsing fails for a message, it is deleted from the queue and skipped.
        """
        from tmi_tf.providers import QueueMessage

        client = self._get_client()
        response = client.get_messages(
            queue_id=self._queue_ocid,
            visibility_in_seconds=visibility_timeout,
            limit=max_messages,
        )
        raw_messages = response.data.messages or []
        result: list = []
        for msg in raw_messages:
            try:
                body = json.loads(msg.content)
            except (json.JSONDecodeError, TypeError) as e:
                logger.warning(
                    "Failed to parse message body (receipt=%s): %s — deleting",
                    msg.receipt,
                    e,
                )
                try:
                    self.delete(msg.receipt)
                except Exception as del_err:
                    logger.error(
                        "Failed to delete unparseable message (receipt=%s): %s",
                        msg.receipt,
                        del_err,
                    )
                continue
            result.append(QueueMessage(body=body, receipt=msg.receipt))
        return result

    def delete(self, receipt: str) -> None:
        """Delete a message from the queue by its receipt."""
        client = self._get_client()
        client.delete_message(queue_id=self._queue_ocid, message_receipt=receipt)
        logger.debug(
            "Deleted message with receipt=%s from queue %s", receipt, self._queue_ocid
        )
```

Also add `import json` to the imports at the top of `tmi_tf/providers/oci.py`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_providers.py::TestOciQueueProvider -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tmi_tf/providers/oci.py tests/test_providers.py
git commit -m "feat(providers): add OciQueueProvider to providers/oci.py"
```

---

### Task 3: Add get_queue_provider factory and config field

**Files:**
- Modify: `tmi_tf/providers/__init__.py`
- Modify: `tmi_tf/config.py`
- Test: `tests/test_providers.py`

- [ ] **Step 1: Write failing tests for factory and config**

Add to `tests/test_providers.py`:

```python
from tmi_tf.providers import get_queue_provider


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
```

Update the import line at the top:

```python
from tmi_tf.providers import VAULT_SECRET_MAP, QueueMessage, QueueProvider, SecretProvider, get_queue_provider, get_secret_provider  # noqa: F401
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_providers.py::TestGetQueueProvider tests/test_providers.py::TestQueueProviderConfig -v`
Expected: FAIL with `ImportError: cannot import name 'get_queue_provider'`

- [ ] **Step 3: Implement get_queue_provider factory**

Add to `tmi_tf/providers/__init__.py` after `get_secret_provider()`:

```python
def get_queue_provider(config: "Config") -> QueueProvider:
    """Create a QueueProvider based on configuration."""
    if config.queue_provider == "oci":
        from tmi_tf.providers.oci import OciQueueProvider

        return OciQueueProvider(
            queue_ocid=config.queue_ocid or "",
            queue_endpoint=config.queue_endpoint,
        )
    else:
        raise ValueError(
            f"Unknown queue provider: {config.queue_provider!r}. "
            f"Must be 'oci'."
        )
```

- [ ] **Step 4: Implement queue_provider config field**

In `tmi_tf/config.py`, add after the `secret_provider` block (after line 127):

```python
        # Queue provider selection (inferred from QUEUE_OCID if not explicit)
        explicit_queue_provider = os.getenv("QUEUE_PROVIDER")
        if explicit_queue_provider:
            self.queue_provider: str = explicit_queue_provider
        elif self.queue_ocid:
            self.queue_provider = "oci"
        else:
            self.queue_provider = "none"
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_providers.py::TestGetQueueProvider tests/test_providers.py::TestQueueProviderConfig -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add tmi_tf/providers/__init__.py tmi_tf/config.py tests/test_providers.py
git commit -m "feat(providers): add get_queue_provider factory and queue_provider config field"
```

---

### Task 4: Update server.py and worker.py to use providers

**Files:**
- Modify: `tmi_tf/server.py`
- Modify: `tmi_tf/worker.py`
- Modify: `tests/test_server.py`

- [ ] **Step 1: Update server.py imports and initialization**

In `tmi_tf/server.py`, replace:

```python
from tmi_tf.queue_client import QueueClient
```

with:

```python
from tmi_tf.providers import QueueProvider, get_queue_provider
```

Change the module-level type annotation (line 28):

```python
queue_client: Optional[QueueProvider] = None
```

In the `lifespan()` function, replace the queue initialization block (lines 62-64):

```python
    if config.queue_ocid:
        queue_client = QueueClient(config.queue_ocid)
        logger.info("Queue client initialized for %s", config.queue_ocid)
```

with:

```python
    if config.queue_provider != "none":
        queue_client = get_queue_provider(config)
        logger.info("Queue provider initialized: %s", config.queue_provider)
```

- [ ] **Step 2: Update worker.py imports**

In `tmi_tf/worker.py`, replace:

```python
from tmi_tf.queue_client import QueueClient, QueueMessage
```

with:

```python
from tmi_tf.providers import QueueMessage, QueueProvider
```

Change the `WorkerPool.__init__` type annotation (line 48):

```python
    def __init__(self, queue_client: QueueProvider, config: Config) -> None:
```

- [ ] **Step 3: Update test_server.py mock config**

In `tests/test_server.py`, add `queue_provider` to the `_make_config` function:

```python
    cfg.queue_provider = overrides.get("queue_provider", "oci")
```

- [ ] **Step 4: Run all tests to verify everything passes**

Run: `uv run pytest tests/test_server.py tests/test_worker.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tmi_tf/server.py tmi_tf/worker.py tests/test_server.py
git commit -m "refactor: update server and worker to use QueueProvider from providers package"
```

---

### Task 5: Delete queue_client.py and update tests

**Files:**
- Delete: `tmi_tf/queue_client.py`
- Modify: `tests/test_queue_client.py`

- [ ] **Step 1: Update test_queue_client.py to test OciQueueProvider**

Replace the entire contents of `tests/test_queue_client.py` with:

```python
"""Tests for OCI Queue provider (legacy test file, kept for coverage continuity).

Primary OciQueueProvider tests are in test_providers.py::TestOciQueueProvider.
This file tests the service endpoint configuration via env var.
"""

import json
import os
from unittest.mock import MagicMock, patch

from tmi_tf.providers.oci import OciQueueProvider


class TestOciQueueProviderServiceEndpoint:
    @patch("tmi_tf.providers.oci.get_oci_signer")
    @patch("oci.queue.QueueClient", create=True)
    def test_get_client_uses_service_endpoint(
        self, mock_oci_cls: MagicMock, mock_signer: MagicMock
    ) -> None:
        """When queue_endpoint is set, _get_client passes service_endpoint to OCI SDK."""
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
        """When queue_endpoint is None, _get_client does not pass service_endpoint."""
        mock_signer.return_value = MagicMock()
        provider = OciQueueProvider(
            queue_ocid="ocid1.queue.oc1..test",
            queue_endpoint=None,
        )
        provider._get_client()
        mock_oci_cls.assert_called_once_with(
            config={},
            signer=mock_signer.return_value,
        )
```

- [ ] **Step 2: Delete queue_client.py**

```bash
git rm tmi_tf/queue_client.py
```

- [ ] **Step 3: Run full test suite**

Run: `uv run pytest tests/ -v`
Expected: All tests PASS

- [ ] **Step 4: Run linter and type checker**

Run: `uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright`
Expected: No errors (pyright may have pre-existing warnings for runtime imports — those are expected)

- [ ] **Step 5: Commit**

```bash
git rm tmi_tf/queue_client.py
git add tests/test_queue_client.py
git commit -m "refactor: remove queue_client.py, replaced by providers package"
```
