"""Tests for OCI Queue client."""

import json
import os
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


class TestQueueServiceEndpoint:
    @patch("tmi_tf.vault_client._get_oci_signer")
    @patch("oci.queue.QueueClient", create=True)
    def test_get_client_uses_service_endpoint(
        self, mock_oci_cls: MagicMock, mock_signer: MagicMock
    ) -> None:
        """When QUEUE_ENDPOINT is set, _get_client passes service_endpoint to OCI SDK."""
        mock_signer.return_value = MagicMock()
        with patch.dict(
            os.environ,
            {
                "QUEUE_ENDPOINT": "https://cell-1.queue.oc1.us-ashburn-1.oci.oraclecloud.com"
            },
        ):
            qc = QueueClient(queue_ocid="ocid1.queue.oc1..test")
            qc._get_client()
            mock_oci_cls.assert_called_once_with(
                config={},
                signer=mock_signer.return_value,
                service_endpoint="https://cell-1.queue.oc1.us-ashburn-1.oci.oraclecloud.com",
            )

    @patch("tmi_tf.vault_client._get_oci_signer")
    @patch("oci.queue.QueueClient", create=True)
    def test_get_client_no_endpoint_when_unset(
        self, mock_oci_cls: MagicMock, mock_signer: MagicMock
    ) -> None:
        """When QUEUE_ENDPOINT is not set, _get_client does not pass service_endpoint."""
        mock_signer.return_value = MagicMock()
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("QUEUE_ENDPOINT", None)
            qc = QueueClient(queue_ocid="ocid1.queue.oc1..test")
            qc._get_client()
            mock_oci_cls.assert_called_once_with(
                config={},
                signer=mock_signer.return_value,
            )
