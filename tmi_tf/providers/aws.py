"""AWS provider: SQS queue.

Credentials come from the default boto3 chain. In EKS the ServiceAccount's
IRSA annotation injects AWS_ROLE_ARN / AWS_WEB_IDENTITY_TOKEN_FILE, so no
explicit configuration is needed inside the pod.
"""

import json
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from tmi_tf.providers import QueueMessage

logger = logging.getLogger(__name__)

# SQS rejects MaxNumberOfMessages > 10.
_SQS_MAX_BATCH = 10
# Long-poll briefly so an idle worker does not spin on empty receives.
# Runs inside asyncio.to_thread, so it never blocks the event loop.
_WAIT_SECONDS = 5


class AwsQueueProvider:
    """SQS wrapper for publish/consume/delete operations."""

    def __init__(self, queue_url: str, region: str | None = None) -> None:
        self._queue_url = queue_url
        self._region = region
        self._client = None

    def _get_client(self):  # type: ignore[return]
        """Lazy-initialize and return the boto3 SQS client."""
        if self._client is None:
            import boto3  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

            self._client = boto3.client("sqs", region_name=self._region)
        return self._client

    def publish(self, message: dict[str, Any]) -> None:
        """Serialize message to JSON and send it to the queue."""
        self._get_client().send_message(
            QueueUrl=self._queue_url, MessageBody=json.dumps(message)
        )
        logger.info(
            "Published message for job_id=%s to %s",
            message.get("job_id", "<unknown>"),
            self._queue_url,
        )

    def consume(
        self, max_messages: int = 1, visibility_timeout: int = 900
    ) -> list["QueueMessage"]:
        """Receive messages and return parsed QueueMessage objects.

        Messages whose body is not valid JSON are deleted and skipped.
        """
        from tmi_tf.providers import QueueMessage

        response = self._get_client().receive_message(
            QueueUrl=self._queue_url,
            MaxNumberOfMessages=min(max_messages, _SQS_MAX_BATCH),
            VisibilityTimeout=visibility_timeout,
            WaitTimeSeconds=_WAIT_SECONDS,
        )
        result: list[QueueMessage] = []
        for msg in response.get("Messages", []):
            receipt = msg["ReceiptHandle"]
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, TypeError) as e:
                logger.warning(
                    "Failed to parse message body (receipt=%s): %s — deleting",
                    receipt,
                    e,
                )
                try:
                    self.delete(receipt)
                except Exception as del_err:
                    logger.error(
                        "Failed to delete unparseable message (receipt=%s): %s",
                        receipt,
                        del_err,
                    )
                continue
            result.append(QueueMessage(body=body, receipt=receipt))
        return result

    def delete(self, receipt: str) -> None:
        """Delete a message from the queue by its receipt handle."""
        self._get_client().delete_message(
            QueueUrl=self._queue_url, ReceiptHandle=receipt
        )
        logger.debug("Deleted message receipt=%s from %s", receipt, self._queue_url)
