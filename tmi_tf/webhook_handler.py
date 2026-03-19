"""Webhook request validation and payload parsing."""

import hashlib
import hmac
from typing import Optional


def verify_hmac_signature(raw_body: bytes, signature: str, secret: str) -> bool:
    """Verify HMAC-SHA256 signature from X-Webhook-Signature header.

    The signature must be in the format "sha256=<hex_digest>".
    Returns False if the signature is empty or lacks the required prefix.
    """
    if not signature or not signature.startswith("sha256="):
        return False
    expected_digest = hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    expected = f"sha256={expected_digest}"
    return hmac.compare_digest(signature, expected)


def validate_subscription_id(
    header_value: Optional[str], configured_value: Optional[str]
) -> bool:
    """Validate the subscription ID from the request header against the configured value.

    If configured_value is None, always returns True (no restriction configured).
    If header_value is None but configured_value is set, returns False.
    Comparison is case-insensitive.
    """
    if configured_value is None:
        return True
    if header_value is None:
        return False
    return header_value.lower() == configured_value.lower()


def extract_job_id(invocation_id: Optional[str], delivery_id: Optional[str]) -> str:
    """Extract a job ID from invocation_id or delivery_id.

    Prefers invocation_id; falls back to delivery_id.
    Raises ValueError if neither is provided.
    """
    if invocation_id is not None:
        return invocation_id
    if delivery_id is not None:
        return delivery_id
    raise ValueError("Neither invocation_id nor delivery_id was provided")


def handle_challenge(payload: dict) -> Optional[dict]:
    """Handle a webhook challenge request.

    If the payload has type "webhook.challenge", returns {"challenge": <value>}.
    Otherwise returns None.
    """
    if payload.get("type") == "webhook.challenge":
        return {"challenge": payload.get("challenge")}
    return None


def parse_webhook_payload(payload: dict) -> dict:
    """Parse and extract fields from a webhook payload.

    Extracts: event_type, threat_model_id (required), repo_id (only when
    resource_type == "repository"), callback_url, and invocation_id.

    Raises ValueError if threat_model_id is missing.
    """
    threat_model_id = payload.get("threat_model_id")
    if not threat_model_id:
        raise ValueError("threat_model_id is required but was not present in payload")

    result: dict = {
        "event_type": payload.get("type"),
        "threat_model_id": threat_model_id,
    }

    if payload.get("resource_type") == "repository":
        result["repo_id"] = payload.get("resource_id")

    callback_url = payload.get("callback_url")
    if callback_url is not None:
        result["callback_url"] = callback_url

    invocation_id = payload.get("invocation_id")
    if invocation_id is not None:
        result["invocation_id"] = invocation_id

    return result
