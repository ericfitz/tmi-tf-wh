"""Tests for OCI Queue provider (legacy test file, kept for coverage continuity).

Primary OciQueueProvider tests are in test_providers.py::TestOciQueueProvider.
This file tests the service endpoint configuration via env var.
"""

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
