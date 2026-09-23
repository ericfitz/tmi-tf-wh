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
    cfg.queue_provider = overrides.get("queue_provider", "oci")
    return cfg


@pytest.fixture()
def client():
    from tmi_tf.invocation import Debouncer, InvocationState

    mock_queue = MagicMock()
    mock_config = _make_config()

    server_module.queue_client = mock_queue
    server_module.worker_pool = MagicMock()
    server_module.debouncer = Debouncer(0)

    with (
        patch("tmi_tf.server.get_config", return_value=mock_config),
        patch(
            "tmi_tf.server.read_state", return_value=InvocationState(None, False, None)
        ),
        patch("tmi_tf.server.TMIClient"),
    ):
        yield TestClient(server_module.app, raise_server_exceptions=False)

    # Clean up
    server_module.queue_client = None
    server_module.worker_pool = None
    server_module.debouncer = Debouncer(0)


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
                "X-Webhook-Delivery-Id": "del-001",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "accepted"
        assert data["job_id"] == "inv-001"
        # Verify publish was called
        assert server_module.queue_client.publish.called  # type: ignore[union-attr]

    def test_addon_user_data_environments_sets_scope(self, client):
        payload = {
            "type": "addon.invoked",
            "threat_model_id": "tm-001",
            "resource_type": "addon",
            "resource_id": "addon-1",
            "callback_url": "https://api.tmi.dev/cb",
            "invocation_id": "inv-001",
            "data": {"user_data": {"environments": "aws-*, oci-public"}},
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
            },
        )

        assert response.status_code == 200
        publish_call = server_module.queue_client.publish.call_args  # type: ignore[union-attr]
        message = publish_call.args[0]
        assert message["scope"] == "aws-*, oci-public"

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
                # No X-Invocation-Id or X-Webhook-Delivery-Id
            },
        )

        assert response.status_code == 403

    def test_challenge_returns_challenge_response(self, client):
        # TMI sends challenges unsigned (no X-Webhook-Signature header)
        payload = {"type": "webhook.challenge", "challenge": "abc123"}
        body = json.dumps(payload).encode()

        response = client.post(
            "/webhook",
            content=body,
            headers={"Content-Type": "application/json"},
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


class TestUrlPrefix:
    def test_routes_served_under_prefix(self, monkeypatch):
        import importlib

        monkeypatch.setenv("URL_PREFIX", "/tf")
        importlib.reload(server_module)
        try:
            c = TestClient(server_module.app, raise_server_exceptions=False)
            assert c.get("/tf/health").status_code == 200
            assert c.get("/health").status_code == 404
        finally:
            monkeypatch.delenv("URL_PREFIX")
            importlib.reload(server_module)

    def test_no_prefix_by_default(self, client):
        assert client.get("/health").status_code == 200


class TestIgnoredEvents:
    def test_metadata_updated_is_acknowledged_not_enqueued(self, client):
        payload = {"type": "metadata.updated", "threat_model_id": "tm-001"}
        body = json.dumps(payload).encode()
        response = client.post(
            "/webhook",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Webhook-Signature": _make_sig(body, "test-secret"),
                "X-Webhook-Delivery-Id": "del-002",
            },
        )
        assert response.status_code == 200
        assert response.json()["status"] == "ignored"
        assert not server_module.queue_client.publish.called  # type: ignore[union-attr]

    def test_delegation_token_header_is_redacted_in_log(self, client, caplog):
        payload = {"type": "addon.invoked", "threat_model_id": "tm-001"}
        body = json.dumps(payload).encode()
        with caplog.at_level("INFO", logger="tmi_tf.server"):
            client.post(
                "/webhook",
                content=body,
                headers={
                    "X-Webhook-Signature": _make_sig(body, "test-secret"),
                    "X-Webhook-Delivery-Id": "del-003",
                    "X-TMI-Delegation-Token": "eyJsecret",
                },
            )
        assert "eyJsecret" not in caplog.text
        assert "<redacted>" in caplog.text

    def test_event_type_taken_from_header_when_body_lacks_type(self, client):
        payload = {"threat_model_id": "tm-001", "resource_type": "addon"}
        body = json.dumps(payload).encode()
        response = client.post(
            "/webhook",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Webhook-Signature": _make_sig(body, "test-secret"),
                "X-Webhook-Delivery-Id": "del-004",
                "X-Webhook-Event": "addon.invoked",
            },
        )
        assert response.status_code == 200
        assert response.json()["status"] == "accepted"
        message = server_module.queue_client.publish.call_args.args[0]  # type: ignore[union-attr]
        assert message["event_type"] == "addon.invoked"


def _post(client, invocation_id="inv-001", event="addon.invoked", callback=True):
    payload = {
        "type": event,
        "threat_model_id": "tm-001",
        "invocation_id": invocation_id,
    }
    if callback:
        payload["callback_url"] = "https://api.tmi.dev/cb"
    body = json.dumps(payload).encode()
    return client.post(
        "/webhook",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Webhook-Signature": _make_sig(body, "test-secret"),
            "X-Webhook-Event": event,
            "X-Invocation-Id": invocation_id,
            "X-Webhook-Delivery-Id": "del-" + invocation_id,
        },
    )


class TestDedup:
    def test_second_trigger_in_debounce_window_is_dropped(self, client):
        from tmi_tf.invocation import Debouncer, InvocationState

        server_module.debouncer = Debouncer(30)
        with (
            patch(
                "tmi_tf.server.read_state",
                return_value=InvocationState(None, False, None),
            ),
            patch("tmi_tf.server.TMIClient"),
        ):
            assert _post(client, "a").json()["status"] == "accepted"
            r = _post(client, "b")
        assert r.status_code == 200
        assert r.json()["status"] == "deduplicated"
        assert server_module.queue_client.publish.call_count == 1  # type: ignore[union-attr]

    def test_open_invocation_drops_and_calls_back(self, client):
        from datetime import datetime, timedelta, timezone

        from tmi_tf.invocation import Debouncer, InvocationState

        server_module.debouncer = Debouncer(0)
        state = InvocationState(
            "x", True, datetime.now(timezone.utc) + timedelta(hours=1), {}
        )
        tmi = MagicMock()
        with (
            patch("tmi_tf.server.read_state", return_value=state),
            patch("tmi_tf.server.TMIClient.create_authenticated", return_value=tmi),
            patch("tmi_tf.server.AddonCallback") as cb_cls,
        ):
            r = _post(client, "c")
        assert r.json()["status"] == "deduplicated"
        server_module.queue_client.publish.assert_not_called()  # type: ignore[union-attr]
        tmi.append_status_line.assert_called_once()
        assert "already running" in tmi.append_status_line.call_args.args[1]
        cb_cls.return_value.send_status.assert_called_once_with(
            "failed", "analysis already running"
        )

    def test_open_but_past_deadline_is_accepted(self, client):
        from datetime import datetime, timedelta, timezone

        from tmi_tf.invocation import Debouncer, InvocationState

        server_module.debouncer = Debouncer(0)
        state = InvocationState(
            "x", True, datetime.now(timezone.utc) - timedelta(seconds=1), {}
        )
        with (
            patch("tmi_tf.server.read_state", return_value=state),
            patch("tmi_tf.server.TMIClient"),
        ):
            assert _post(client, "d").json()["status"] == "accepted"

    def test_tmi_lookup_failure_accepts(self, client):
        from tmi_tf.invocation import Debouncer

        server_module.debouncer = Debouncer(0)
        with (
            patch("tmi_tf.server.read_state", side_effect=RuntimeError("tmi down")),
            patch("tmi_tf.server.TMIClient"),
        ):
            assert _post(client, "e").json()["status"] == "accepted"

    def test_threat_model_updated_drop_has_no_callback(self, client):
        from datetime import datetime, timedelta, timezone

        from tmi_tf.invocation import Debouncer, InvocationState

        server_module.debouncer = Debouncer(0)
        state = InvocationState(
            "x", True, datetime.now(timezone.utc) + timedelta(hours=1), {}
        )
        with (
            patch("tmi_tf.server.read_state", return_value=state),
            patch(
                "tmi_tf.server.TMIClient.create_authenticated", return_value=MagicMock()
            ),
            patch("tmi_tf.server.AddonCallback") as cb_cls,
        ):
            r = _post(client, "f", event="threat_model.updated", callback=False)
        assert r.json()["status"] == "deduplicated"
        cb_cls.assert_not_called()

    def test_publish_failure_releases_debounce(self, client):
        from tmi_tf.invocation import Debouncer

        server_module.debouncer = Debouncer(30)
        server_module.queue_client.publish.side_effect = [  # type: ignore[union-attr]
            RuntimeError("sqs down"),
            None,
        ]
        r1 = _post(client, "g")
        assert r1.status_code != 200
        r2 = _post(client, "h")
        assert r2.status_code == 200
        assert r2.json()["status"] == "accepted"
        assert server_module.queue_client.publish.call_count == 2  # type: ignore[union-attr]


class TestLifespanProfiles:
    def test_loads_profile_secrets_and_logs_status(self, caplog):
        import asyncio
        import logging

        from tmi_tf.llm_profiles import LLMProfile

        cfg = _make_config(queue_provider="none")
        cfg.secret_provider = "none"
        cfg.dedup_debounce_seconds = 0
        cfg.llm_profiles = {
            "gpt56cyber": LLMProfile(
                "gpt56cyber", "openai", "m", "api_key", "T_LIFESPAN_ABSENT_KEY"
            )
        }
        secrets = MagicMock()

        async def run():
            async with server_module.lifespan(server_module.app):
                pass

        with (
            patch("tmi_tf.server.get_config", return_value=cfg),
            patch("tmi_tf.providers.get_secret_provider", return_value=secrets),
            caplog.at_level(logging.INFO, logger="tmi_tf.server"),
        ):
            asyncio.run(run())
        secret_map = secrets.load_secrets.call_args.args[0]
        assert secret_map["t-lifespan-absent-key"] == "T_LIFESPAN_ABSENT_KEY"
        assert secret_map["github-token"] == "GITHUB_TOKEN"
        assert "LLM profile gpt56cyber: missing key T_LIFESPAN_ABSENT_KEY" in (
            caplog.text
        )
