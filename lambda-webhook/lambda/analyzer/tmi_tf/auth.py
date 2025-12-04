"""Authentication module for TMI OAuth flow."""

import json
import logging
import webbrowser
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

import requests

from tmi_tf.config import Config

logger = logging.getLogger(__name__)


class OAuthCallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler for OAuth callback."""

    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    expires_in: Optional[int] = None
    error: Optional[str] = None

    def do_GET(self):
        """Handle GET request for OAuth callback."""
        # Parse query parameters
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        # Extract tokens from callback (TMI sends tokens directly when using client_callback)
        OAuthCallbackHandler.access_token = params.get("access_token", [None])[0]
        OAuthCallbackHandler.refresh_token = params.get("refresh_token", [None])[0]
        expires_in_str = params.get("expires_in", [None])[0]
        OAuthCallbackHandler.expires_in = (
            int(expires_in_str) if expires_in_str else None
        )
        OAuthCallbackHandler.error = params.get("error", [None])[0]

        # Send response
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        if OAuthCallbackHandler.access_token:
            self.wfile.write(
                b"<html><body><h1>Authentication successful!</h1>"
                b"<p>You can close this window and return to the terminal.</p>"
                b"</body></html>"
            )
        else:
            error_msg = OAuthCallbackHandler.error or "No access token received"
            self.wfile.write(
                f"<html><body><h1>Authentication failed!</h1>"
                f"<p>{error_msg}</p>"
                f"</body></html>".encode()
            )

    def log_message(self, format, *args):
        """Suppress HTTP server logs."""
        pass


class TokenCache:
    """Manages JWT token caching."""

    def __init__(self, cache_file: Path):
        """Initialize token cache."""
        self.cache_file = cache_file

    def save_token(self, token: str, expires_in: int):
        """Save token to cache file."""
        expires_at = datetime.now() + timedelta(seconds=expires_in)
        cache_data = {"token": token, "expires_at": expires_at.isoformat()}

        with open(self.cache_file, "w") as f:
            json.dump(cache_data, f)

        logger.info(f"Token cached to {self.cache_file}")

    def load_token(self) -> Optional[str]:
        """Load token from cache if valid."""
        if not self.cache_file.exists():
            return None

        try:
            with open(self.cache_file, "r") as f:
                cache_data = json.load(f)

            expires_at = datetime.fromisoformat(cache_data["expires_at"])
            if datetime.now() < expires_at:
                logger.info("Using cached token")
                return cache_data["token"]
            else:
                logger.info("Cached token expired")
                return None
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Failed to load cached token: {e}")
            return None

    def clear_token(self):
        """Clear cached token."""
        if self.cache_file.exists():
            self.cache_file.unlink()
            logger.info("Token cache cleared")


class TMIAuthenticator:
    """Handles OAuth authentication with TMI server."""

    def __init__(self, config: Config):
        """Initialize authenticator."""
        self.config = config
        self.token_cache = TokenCache(config.token_cache_file)
        self.callback_port = 8888
        self.redirect_uri = f"http://localhost:{self.callback_port}/callback"

    def get_token(self, force_refresh: bool = False) -> str:
        """
        Get authentication token (from cache or by performing OAuth flow).

        Args:
            force_refresh: Force new authentication even if cached token exists

        Returns:
            JWT access token
        """
        if not force_refresh:
            cached_token = self.token_cache.load_token()
            if cached_token:
                return cached_token

        logger.info("Starting OAuth authentication flow")
        return self._perform_oauth_flow()

    def _perform_oauth_flow(self) -> str:
        """
        Perform OAuth 2.0 authorization code flow.

        Returns:
            JWT access token
        """
        # Step 1: Get authorization URL
        auth_url = self._get_authorization_url()
        logger.info(f"Opening browser for authentication: {auth_url}")

        # Open browser
        webbrowser.open(auth_url)

        # Step 2: Start local server to receive callback with tokens
        # TMI will exchange the OAuth code and redirect to us with tokens
        access_token = self._wait_for_callback()

        if not access_token:
            raise RuntimeError("Failed to receive access token from callback")

        return access_token

    def _get_authorization_url(self) -> str:
        """
        Get OAuth authorization URL from TMI server.

        Returns:
            Authorization URL to open in browser
        """
        url = f"{self.config.tmi_server_url}/oauth2/authorize"
        params = {
            "idp": self.config.tmi_oauth_idp,
            "client_callback": self.redirect_uri,
            "scope": "openid profile email",
        }

        try:
            response = requests.get(url, params=params, allow_redirects=False)
            response.raise_for_status()

            # TMI server should redirect to OAuth provider
            if response.status_code == 302:
                return response.headers["Location"]
            else:
                # Or return the authorization URL directly
                return response.json().get("authorization_url", response.url)

        except requests.RequestException as e:
            raise RuntimeError(f"Failed to get authorization URL: {e}")

    def _wait_for_callback(self) -> Optional[str]:
        """
        Start local HTTP server and wait for OAuth callback.

        Returns:
            Access token from callback
        """
        # Reset class variables
        OAuthCallbackHandler.access_token = None
        OAuthCallbackHandler.refresh_token = None
        OAuthCallbackHandler.expires_in = None
        OAuthCallbackHandler.error = None

        # Start server
        server = HTTPServer(("localhost", self.callback_port), OAuthCallbackHandler)
        logger.info(f"Waiting for OAuth callback on port {self.callback_port}...")

        # Handle one request (the callback)
        server.handle_request()

        # Check if we received an access token
        if OAuthCallbackHandler.access_token:
            # Cache the token
            expires_in = OAuthCallbackHandler.expires_in or 3600
            self.token_cache.save_token(OAuthCallbackHandler.access_token, expires_in)
            logger.info("Successfully obtained and cached access token")
            return OAuthCallbackHandler.access_token
        else:
            error = OAuthCallbackHandler.error or "No access token in callback"
            logger.error(f"OAuth callback failed: {error}")
            return None

    def clear_cached_token(self):
        """Clear cached authentication token."""
        self.token_cache.clear_token()
