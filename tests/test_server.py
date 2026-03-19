"""Tests for FastAPI server module."""

import hashlib
import hmac
import json
from unittest.mock import MagicMock, patch

import pytest  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]
from fastapi.testclient import TestClient  # ty:ignore[unresolved-import]

import tmi_tf.server as server_module


def _make_sig(body: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _make_config(**overrides):
    cfg = MagicMock()
    cfg.webhook_secret = overrides.get("webhook_secret", "test-secret")
    cfg.webhook_subscription_id = overrides.get("webhook_subscription_id", None)
    cfg.queue_ocid = overrides.get("queue_ocid", "ocid1.queue.oc1..test")
    cfg.server_port = overrides.get("server_port", 8080)
    cfg.max_concurrent_jobs = overrides.get("max_concurrent_jobs", 3)
    cfg.job_timeout = overrides.get("job_timeout", 3600)
    cfg.max_message_age_hours = overrides.get("max_message_age_hours", 24)
    return cfg


@pytest.fixture()
def client():
    mock_queue = MagicMock()
    mock_config = _make_config()

    server_module.queue_client = mock_queue
    server_module.worker_pool = MagicMock()

    with patch("tmi_tf.server.get_config", return_value=mock_config):
        yield TestClient(server_module.app, raise_server_exceptions=False)

    # Clean up
    server_module.queue_client = None
    server_module.worker_pool = None


class TestWebhookEndpoint:
    def test_valid_webhook_returns_200(self, client):
        payload = {
            "type": "addon.invoked",
            "threat_model_id": "tm-001",
            "resource_type": "addon",
            "resource_id": "addon-1",
            "callback_url": "https://api.tmi.dev/cb",
            "invocation_id": "inv-001",
        }
        body = json.dumps(payload).encode()
        sig = _make_sig(body, "test-secret")

        response = client.post(
            "/webhook",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Webhook-Signature": sig,
                "X-Invocation-Id": "inv-001",
                "X-Delivery-Id": "del-001",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "accepted"
        assert data["job_id"] == "inv-001"
        # Verify publish was called
        assert server_module.queue_client.publish.called  # type: ignore[union-attr]

    def test_invalid_hmac_returns_401(self, client):
        payload = {"type": "addon.invoked", "threat_model_id": "tm-001"}
        body = json.dumps(payload).encode()
        sig = _make_sig(body, "wrong-secret")

        response = client.post(
            "/webhook",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Webhook-Signature": sig,
                "X-Invocation-Id": "inv-001",
            },
        )

        assert response.status_code == 401

    def test_missing_job_id_headers_returns_403(self, client):
        payload = {"type": "addon.invoked", "threat_model_id": "tm-001"}
        body = json.dumps(payload).encode()
        sig = _make_sig(body, "test-secret")

        response = client.post(
            "/webhook",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Webhook-Signature": sig,
                # No X-Invocation-Id or X-Delivery-Id
            },
        )

        assert response.status_code == 403

    def test_challenge_returns_challenge_response(self, client):
        payload = {"type": "webhook.challenge", "challenge": "abc123"}
        body = json.dumps(payload).encode()
        sig = _make_sig(body, "test-secret")

        response = client.post(
            "/webhook",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Webhook-Signature": sig,
            },
        )

        assert response.status_code == 200
        assert response.json() == {"challenge": "abc123"}


class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"


class TestStatusEndpoint:
    def test_status_returns_200(self, client):
        server_module.worker_pool.get_status.return_value = {  # type: ignore[union-attr]
            "active_jobs": {},
            "active_count": 0,
            "max_concurrent": 3,
        }
        response = client.get("/status")
        assert response.status_code == 200
        data = response.json()
        assert "active_jobs" in data
