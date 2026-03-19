"""Tests for webhook_handler module."""

import hashlib
import hmac

import pytest

from tmi_tf.webhook_handler import (
    extract_job_id,
    handle_challenge,
    parse_webhook_payload,
    validate_subscription_id,
    verify_hmac_signature,
)


class TestHMACVerification:
    def _make_sig(self, body: bytes, secret: str) -> str:
        digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        return f"sha256={digest}"

    def test_valid_signature(self):
        body = b'{"event": "test"}'
        secret = "my-secret"
        sig = self._make_sig(body, secret)
        assert verify_hmac_signature(body, sig, secret) is True

    def test_invalid_signature(self):
        body = b'{"event": "test"}'
        secret = "my-secret"
        sig = self._make_sig(body, "wrong-secret")
        assert verify_hmac_signature(body, sig, secret) is False

    def test_missing_prefix(self):
        body = b'{"event": "test"}'
        secret = "my-secret"
        # Provide just the hex digest without the "sha256=" prefix
        digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        assert verify_hmac_signature(body, digest, secret) is False

    def test_empty_signature(self):
        body = b'{"event": "test"}'
        secret = "my-secret"
        assert verify_hmac_signature(body, "", secret) is False


class TestSubscriptionIdValidation:
    def test_matching_case_insensitive(self):
        assert validate_subscription_id("Sub-ABC-123", "sub-abc-123") is True

    def test_mismatch(self):
        assert validate_subscription_id("sub-abc-123", "sub-xyz-999") is False

    def test_none_configured(self):
        # If no configured value, always True regardless of header
        assert validate_subscription_id("any-value", None) is True
        assert validate_subscription_id(None, None) is True

    def test_configured_but_header_missing(self):
        assert validate_subscription_id(None, "sub-abc-123") is False


class TestExtractJobId:
    def test_invocation_preferred(self):
        result = extract_job_id(invocation_id="inv-001", delivery_id="del-999")
        assert result == "inv-001"

    def test_delivery_fallback(self):
        result = extract_job_id(invocation_id=None, delivery_id="del-999")
        assert result == "del-999"

    def test_neither_raises(self):
        with pytest.raises(ValueError):
            extract_job_id(invocation_id=None, delivery_id=None)


class TestHandleChallenge:
    def test_challenge_detected(self):
        payload = {"type": "webhook.challenge", "challenge": "abc123"}
        result = handle_challenge(payload)
        assert result == {"challenge": "abc123"}

    def test_not_a_challenge(self):
        payload = {"type": "threat_model.created", "threat_model_id": "tm-1"}
        result = handle_challenge(payload)
        assert result is None


class TestParseWebhookPayload:
    def test_threat_model_event(self):
        payload = {
            "type": "threat_model.created",
            "threat_model_id": "tm-001",
            "callback_url": "https://api.tmi.dev/cb",
            "invocation_id": "inv-001",
        }
        result = parse_webhook_payload(payload)
        assert result["event_type"] == "threat_model.created"
        assert result["threat_model_id"] == "tm-001"
        assert result["callback_url"] == "https://api.tmi.dev/cb"
        assert result["invocation_id"] == "inv-001"
        assert "repo_id" not in result

    def test_repo_event(self):
        payload = {
            "type": "repository.updated",
            "threat_model_id": "tm-002",
            "resource_type": "repository",
            "resource_id": "repo-42",
        }
        result = parse_webhook_payload(payload)
        assert result["event_type"] == "repository.updated"
        assert result["threat_model_id"] == "tm-002"
        assert result["repo_id"] == "repo-42"

    def test_addon_event(self):
        payload = {
            "type": "addon.invoked",
            "threat_model_id": "tm-003",
            "resource_type": "addon",
            "resource_id": "addon-7",
            "callback_url": "https://api.tmi.dev/invocations/inv-2/status",
            "invocation_id": "inv-2",
        }
        result = parse_webhook_payload(payload)
        assert result["event_type"] == "addon.invoked"
        assert result["threat_model_id"] == "tm-003"
        assert "repo_id" not in result
        assert result["callback_url"] == "https://api.tmi.dev/invocations/inv-2/status"
        assert result["invocation_id"] == "inv-2"

    def test_missing_threat_model_id(self):
        payload = {"type": "threat_model.created"}
        with pytest.raises(ValueError):
            parse_webhook_payload(payload)
