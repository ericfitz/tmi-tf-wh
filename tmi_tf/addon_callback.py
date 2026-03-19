"""Addon callback client for sending HMAC-signed status updates to TMI."""

import hashlib
import hmac
import json
import logging
from typing import Optional

import requests  # ty:ignore[unresolved-import]

logger = logging.getLogger(__name__)

CALLBACK_TIMEOUT_SECONDS = 10


class AddonCallback:
    """Sends HMAC-signed status updates to a TMI addon callback URL.

    send_status() must never raise — failures are logged and swallowed
    because this runs during job cleanup paths that must not block.
    """

    def __init__(self, callback_url: Optional[str], secret: str) -> None:
        self.callback_url = callback_url
        self._secret = secret

    def _sign(self, body: bytes) -> str:
        """Return 'sha256=<hex_digest>' using HMAC-SHA256."""
        digest = hmac.new(self._secret.encode(), body, hashlib.sha256).hexdigest()
        return f"sha256={digest}"

    def send_status(self, status: str, message: str = "") -> None:
        """Post JSON status update to callback_url with HMAC signature header.

        Never raises — logs errors and returns on any failure.
        If callback_url is None, returns immediately (noop).
        """
        if self.callback_url is None:
            return

        try:
            payload = {"status": status, "message": message}
            body = json.dumps(payload).encode()
            signature = self._sign(body)
            headers = {
                "Content-Type": "application/json",
                "X-Webhook-Signature": signature,
            }
            response = requests.post(
                self.callback_url,
                data=body,
                headers=headers,
                timeout=CALLBACK_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
        except Exception:
            logger.exception(
                "Failed to send addon callback status=%r to %s",
                status,
                self.callback_url,
            )
