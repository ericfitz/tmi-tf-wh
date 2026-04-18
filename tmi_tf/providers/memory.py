"""In-memory queue provider for local development and testing.

Not for production use: messages are lost when the process exits.
"""

import json
import logging
import threading
import time
import uuid
from collections import deque
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from tmi_tf.providers import QueueMessage

logger = logging.getLogger(__name__)


class MemoryQueueProvider:
    """Thread-safe in-memory queue with visibility-timeout semantics."""

    def __init__(self) -> None:
        self._ready: deque[dict[str, Any]] = deque()
        # receipt -> (body, visibility_deadline_monotonic)
        self._in_flight: dict[str, tuple[dict[str, Any], float]] = {}
        self._lock = threading.Lock()

    def publish(self, message: dict[str, Any]) -> None:
        # Round-trip through JSON to catch non-serializable payloads early,
        # matching OCI semantics where messages are JSON-encoded.
        serialized = json.loads(json.dumps(message))
        with self._lock:
            self._ready.append(serialized)
        job_id = message.get("job_id", "<unknown>")
        logger.info("Published in-memory message for job_id=%s", job_id)

    def consume(
        self, max_messages: int = 1, visibility_timeout: int = 900
    ) -> list["QueueMessage"]:
        from tmi_tf.providers import QueueMessage

        now = time.monotonic()
        result: list[QueueMessage] = []
        with self._lock:
            # Requeue messages whose visibility window has expired.
            expired = [
                receipt
                for receipt, (_, deadline) in self._in_flight.items()
                if deadline <= now
            ]
            for receipt in expired:
                body, _ = self._in_flight.pop(receipt)
                self._ready.appendleft(body)
                logger.debug("Visibility expired; requeued receipt=%s", receipt)

            for _ in range(max_messages):
                if not self._ready:
                    break
                body = self._ready.popleft()
                receipt = uuid.uuid4().hex
                self._in_flight[receipt] = (body, now + visibility_timeout)
                result.append(QueueMessage(body=body, receipt=receipt))
        return result

    def delete(self, receipt: str) -> None:
        with self._lock:
            self._in_flight.pop(receipt, None)
        logger.debug("Deleted in-memory message receipt=%s", receipt)
