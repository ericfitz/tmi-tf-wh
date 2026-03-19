"""Tests for OCI Queue client."""

import json
from unittest.mock import MagicMock, patch

from tmi_tf.queue_client import QueueClient


class TestQueueClient:
    @patch("tmi_tf.queue_client.QueueClient._get_client")
    def test_publish(self, mock_get: MagicMock) -> None:
        mock_client = MagicMock()
        mock_get.return_value = mock_client
        qc = QueueClient(queue_ocid="ocid1.queue.oc1..test")
        qc.publish({"job_id": "j1", "threat_model_id": "tm-1"})
        mock_client.put_messages.assert_called_once()

    @patch("tmi_tf.queue_client.QueueClient._get_client")
    def test_consume_returns_messages(self, mock_get: MagicMock) -> None:
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
    def test_delete(self, mock_get: MagicMock) -> None:
        mock_client = MagicMock()
        mock_get.return_value = mock_client
        qc = QueueClient(queue_ocid="ocid1.queue.oc1..test")
        qc.delete("receipt-1")
        mock_client.delete_message.assert_called_once()
