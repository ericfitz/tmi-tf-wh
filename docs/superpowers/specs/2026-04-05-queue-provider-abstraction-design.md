# Queue Provider Abstraction Design

**Issue:** [#8 — Refactor queue client behind a provider-agnostic interface](https://github.com/ericfitz/tmi-tf-wh/issues/8)
**Date:** 2026-04-05

## Problem

`queue_client.py` is tightly coupled to OCI Queue SDK. The `QueueClient` class directly imports `oci.queue.QueueClient`, `oci.queue.models`, and uses `get_oci_signer()`. Deploying to a different cloud provider would require rewriting the queue integration rather than swapping a configuration value.

## Decision: No NoneQueueProvider

The queue is only used in webhook server mode. The CLI path never touches it. Server.py already handles the "no queue" case via `Optional` checks (2 places). A no-op provider would add unnecessary abstraction. The existing `Optional[QueueProvider]` pattern in server.py is sufficient.

## Design

### Protocol & Shared Types (`providers/__init__.py`)

Add `QueueMessage` dataclass (moved from `queue_client.py`) and `QueueProvider` protocol:

```python
@dataclass
class QueueMessage:
    body: dict
    receipt: str

class QueueProvider(Protocol):
    def publish(self, message: dict) -> None: ...
    def consume(self, max_messages: int = 1, visibility_timeout: int = 900) -> list[QueueMessage]: ...
    def delete(self, receipt: str) -> None: ...
```

Add factory function:

```python
def get_queue_provider(config: "Config") -> QueueProvider:
    if config.queue_provider == "oci":
        from tmi_tf.providers.oci import OciQueueProvider
        return OciQueueProvider(
            queue_ocid=config.queue_ocid or "",
            queue_endpoint=config.queue_endpoint,
        )
    else:
        raise ValueError(
            f"Unknown queue provider: {config.queue_provider!r}. Must be 'oci'."
        )
```

### Config Changes (`config.py`)

Add `queue_provider` field with backward-compatible inference, matching the `secret_provider` pattern:

```python
explicit_queue_provider = os.getenv("QUEUE_PROVIDER")
if explicit_queue_provider:
    self.queue_provider: str = explicit_queue_provider
elif self.queue_ocid:
    self.queue_provider = "oci"
else:
    self.queue_provider = "none"
```

When `queue_provider == "none"`, the factory is never called — server.py skips queue initialization entirely.

### OCI Implementation (`providers/oci.py`)

Add `OciQueueProvider` class — the current `QueueClient` renamed and moved. Same lazy-init pattern, same publish/consume/delete logic. No behavioral changes.

### Consumer Changes

**`server.py`:**
- Import `QueueProvider` and `get_queue_provider` from `tmi_tf.providers` instead of `QueueClient` from `tmi_tf.queue_client`
- Type annotation: `Optional[QueueProvider]` instead of `Optional[QueueClient]`
- Initialization: `if config.queue_provider != "none": queue_client = get_queue_provider(config)` instead of checking `config.queue_ocid`

**`worker.py`:**
- Import `QueueProvider, QueueMessage` from `tmi_tf.providers` instead of from `tmi_tf.queue_client`
- Type annotation in `WorkerPool.__init__`: `QueueProvider` instead of `QueueClient`

### File Deletion

`tmi_tf/queue_client.py` is deleted after its contents are moved to `providers/oci.py` and `providers/__init__.py`.

### Test Changes

- `test_queue_client.py`: Update to test `OciQueueProvider` from `tmi_tf.providers.oci`, same test logic
- `test_server.py` and `test_worker.py`: Update mock paths from `tmi_tf.queue_client` to `tmi_tf.providers`
