"""OCI Queue SDK wrapper for job dispatch."""

import json
import logging
import os
from dataclasses import dataclass
from typing import List

logger = logging.getLogger(__name__)


@dataclass
class QueueMessage:
    body: dict
    receipt: str


class QueueClient:
    """Wraps the OCI Queue SDK for publish/consume/delete operations."""

    def __init__(self, queue_ocid: str) -> None:
        self._queue_ocid = queue_ocid
        self._client = None

    def _get_client(self):  # type: ignore[return]
        """Lazy-initialize and return the OCI QueueClient."""
        if self._client is None:
            from oci.queue import QueueClient as OCIQueueClient  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

            from tmi_tf.providers.oci import get_oci_signer

            signer = get_oci_signer()
            kwargs: dict = {"config": {}, "signer": signer}
            endpoint = os.getenv("QUEUE_ENDPOINT")
            if endpoint:
                kwargs["service_endpoint"] = endpoint
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
    ) -> List[QueueMessage]:
        """Get messages from the queue and return parsed QueueMessage objects.

        If JSON parsing fails for a message, it is deleted from the queue and skipped.
        """
        client = self._get_client()
        response = client.get_messages(
            queue_id=self._queue_ocid,
            visibility_in_seconds=visibility_timeout,
            limit=max_messages,
        )
        raw_messages = response.data.messages or []
        result: List[QueueMessage] = []
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
