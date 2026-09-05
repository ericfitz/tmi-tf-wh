"""Tests for the AWS SQS queue provider."""

import json
from unittest.mock import MagicMock, patch

from tmi_tf.providers.aws import AwsQueueProvider

QUEUE_URL = "https://sqs.us-east-1.amazonaws.com/123456789012/tmi-tf-wh-jobs"


class TestAwsQueueProvider:
    @patch("tmi_tf.providers.aws.AwsQueueProvider._get_client")
    def test_publish_sends_json_body(self, mock_get: MagicMock) -> None:
        client = MagicMock()
        mock_get.return_value = client
        provider = AwsQueueProvider(queue_url=QUEUE_URL)
        provider.publish({"job_id": "j1", "threat_model_id": "tm-1"})
        client.send_message.assert_called_once_with(
            QueueUrl=QUEUE_URL,
            MessageBody=json.dumps({"job_id": "j1", "threat_model_id": "tm-1"}),
        )

    @patch("tmi_tf.providers.aws.AwsQueueProvider._get_client")
    def test_consume_returns_messages(self, mock_get: MagicMock) -> None:
        client = MagicMock()
        client.receive_message.return_value = {
            "Messages": [{"Body": json.dumps({"job_id": "j1"}), "ReceiptHandle": "r-1"}]
        }
        mock_get.return_value = client
        provider = AwsQueueProvider(queue_url=QUEUE_URL)
        messages = provider.consume(max_messages=2, visibility_timeout=600)
        assert len(messages) == 1
        assert messages[0].body == {"job_id": "j1"}
        assert messages[0].receipt == "r-1"
        client.receive_message.assert_called_once_with(
            QueueUrl=QUEUE_URL,
            MaxNumberOfMessages=2,
            VisibilityTimeout=600,
            WaitTimeSeconds=5,
        )

    @patch("tmi_tf.providers.aws.AwsQueueProvider._get_client")
    def test_consume_caps_batch_at_sqs_limit(self, mock_get: MagicMock) -> None:
        client = MagicMock()
        client.receive_message.return_value = {}
        mock_get.return_value = client
        AwsQueueProvider(queue_url=QUEUE_URL).consume(max_messages=25)
        assert client.receive_message.call_args.kwargs["MaxNumberOfMessages"] == 10

    @patch("tmi_tf.providers.aws.AwsQueueProvider._get_client")
    def test_consume_empty_when_no_messages_key(self, mock_get: MagicMock) -> None:
        client = MagicMock()
        client.receive_message.return_value = {}
        mock_get.return_value = client
        assert AwsQueueProvider(queue_url=QUEUE_URL).consume() == []

    @patch("tmi_tf.providers.aws.AwsQueueProvider._get_client")
    def test_consume_deletes_unparseable_messages(self, mock_get: MagicMock) -> None:
        client = MagicMock()
        client.receive_message.return_value = {
            "Messages": [
                {"Body": "not-json", "ReceiptHandle": "bad"},
                {"Body": json.dumps({"job_id": "j2"}), "ReceiptHandle": "good"},
            ]
        }
        mock_get.return_value = client
        messages = AwsQueueProvider(queue_url=QUEUE_URL).consume()
        assert [m.receipt for m in messages] == ["good"]
        client.delete_message.assert_called_once_with(
            QueueUrl=QUEUE_URL, ReceiptHandle="bad"
        )

    @patch("tmi_tf.providers.aws.AwsQueueProvider._get_client")
    def test_delete(self, mock_get: MagicMock) -> None:
        client = MagicMock()
        mock_get.return_value = client
        AwsQueueProvider(queue_url=QUEUE_URL).delete("r-1")
        client.delete_message.assert_called_once_with(
            QueueUrl=QUEUE_URL, ReceiptHandle="r-1"
        )

    @patch("boto3.client")
    def test_get_client_passes_region_and_caches(self, mock_boto: MagicMock) -> None:
        provider = AwsQueueProvider(queue_url=QUEUE_URL, region="us-east-1")
        first = provider._get_client()
        second = provider._get_client()
        assert first is second
        mock_boto.assert_called_once_with("sqs", region_name="us-east-1")
