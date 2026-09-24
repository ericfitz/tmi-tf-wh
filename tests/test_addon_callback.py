"""Tests for addon_callback module."""

import hashlib
import hmac
import json
from unittest.mock import MagicMock, patch

import requests  # ty:ignore[unresolved-import]

from tmi_tf.addon_callback import AddonCallback


class TestAddonCallback:
    def test_sign_payload(self):
        """Verify _sign returns correct sha256= prefixed HMAC."""
        secret = "test-secret"
        body = b'{"status": "completed", "message": ""}'
        cb = AddonCallback(callback_url="https://example.com/callback", secret=secret)

        expected_digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        expected_sig = f"sha256={expected_digest}"

        assert cb._sign(body) == expected_sig

    def test_send_status_completed(self):
        """Mock requests.post, verify it's called with X-Webhook-Signature header."""
        callback_url = "https://example.com/callback"
        secret = "test-secret"
        cb = AddonCallback(callback_url=callback_url, secret=secret)

        with patch("tmi_tf.addon_callback.requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.raise_for_status.return_value = None
            mock_post.return_value = mock_response

            cb.send_status("completed", "Job finished successfully")

            assert mock_post.called
            call_kwargs = mock_post.call_args
            # Verify URL
            assert call_kwargs[0][0] == callback_url
            assert json.loads(call_kwargs[1]["data"]) == {
                "status": "completed",
                "status_message": "Job finished successfully",
            }
            # Verify signature header is present
            headers = call_kwargs[1]["headers"]
            assert "X-Webhook-Signature" in headers
            sig = headers["X-Webhook-Signature"]
            assert sig.startswith("sha256=")

    def test_send_status_failed_request_does_not_raise(self):
        """Mock requests.post to raise, verify no exception propagates."""
        callback_url = "https://example.com/callback"
        secret = "test-secret"
        cb = AddonCallback(callback_url=callback_url, secret=secret)

        with patch("tmi_tf.addon_callback.requests.post") as mock_post:
            mock_post.side_effect = requests.exceptions.ConnectionError("Network error")

            # Must not raise
            cb.send_status("failed", "Something went wrong")

    def test_none_callback_is_noop(self):
        """callback_url=None, verify send_status does nothing."""
        cb = AddonCallback(callback_url=None, secret="test-secret")

        with patch("tmi_tf.addon_callback.requests.post") as mock_post:
            cb.send_status("completed", "Done")
            mock_post.assert_not_called()


def test_send_status_409_is_logged_not_raised(caplog):
    """TMI returns 409 once a delivery is terminal (cancelled/completed)."""
    cb = AddonCallback(callback_url="https://example.com/callback", secret="s")
    with patch("tmi_tf.addon_callback.requests.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=409)
        cb.send_status("failed", "aborted")
    mock_post.return_value.raise_for_status.assert_not_called()
    assert not any(r.exc_info for r in caplog.records)


def test_send_status_omits_empty_message_and_caps_length():
    """TMI's UpdateWebhookDeliveryStatusRequest: status_message maxLength 1024."""
    cb = AddonCallback(callback_url="https://example.com/cb", secret="s")
    with patch("tmi_tf.addon_callback.requests.post") as mock_post:
        cb.send_status("in_progress")
        cb.send_status("failed", "x" * 2000)
    bodies = [json.loads(c.kwargs["data"]) for c in mock_post.call_args_list]
    assert bodies[0] == {"status": "in_progress"}
    assert len(bodies[1]["status_message"]) == 1024


def test_send_status_404_stops_further_callbacks(caplog):
    """TMI expires active deliveries after 4 h; later callbacks 404."""
    cb = AddonCallback(callback_url="https://example.com/callback", secret="s")
    with patch("tmi_tf.addon_callback.requests.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=404)
        cb.send_status("in_progress", "phase 2")
        cb.send_status("completed", "done")
    mock_post.assert_called_once()
    mock_post.return_value.raise_for_status.assert_not_called()
    assert not any(r.exc_info for r in caplog.records)
