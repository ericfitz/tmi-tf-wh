"""Tests for authentication helpers."""

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest  # type: ignore

from tmi_tf.auth import TokenCache


@pytest.fixture()
def cache_file(tmp_path: Path) -> Path:
    """Path to a token cache file inside an isolated temp directory."""
    return tmp_path / "token.json"


class TestTokenCache:
    """Round-trip and expiry behaviour of the on-disk token cache."""

    def test_round_trips_a_valid_token(self, cache_file: Path):
        cache = TokenCache(cache_file)
        cache.save_token("tok-abc", 3600)
        assert cache.load_token() == "tok-abc"

    def test_returns_none_for_expired_token(self, cache_file: Path):
        cache = TokenCache(cache_file)
        cache.save_token("tok-old", -10)
        assert cache.load_token() is None

    def test_returns_none_when_no_cache_file_exists(self, cache_file: Path):
        assert TokenCache(cache_file).load_token() is None

    def test_persists_expiry_as_timezone_aware(self, cache_file: Path):
        """Expiries are stored in UTC so a cache stays valid across TZ changes."""
        cache = TokenCache(cache_file)
        cache.save_token("tok-abc", 3600)

        stored = json.loads(cache_file.read_text())
        expires_at = datetime.fromisoformat(stored["expires_at"])
        assert expires_at.tzinfo is not None
        assert expires_at.utcoffset() == timedelta(0)

    def test_discards_legacy_naive_expiry_instead_of_raising(self, cache_file: Path):
        """A cache written by an older build stored a naive local timestamp.

        Comparing that against an aware "now" would raise TypeError, which
        load_token does not catch, so the entry is discarded to force one
        re-authentication rather than crashing the caller.
        """
        cache_file.write_text(
            json.dumps(
                {
                    "token": "tok-legacy",
                    "expires_at": (
                        datetime.now() + timedelta(hours=1)  # noqa: DTZ005
                    ).isoformat(),
                }
            )
        )
        assert TokenCache(cache_file).load_token() is None

    def test_returns_none_for_corrupt_cache(self, cache_file: Path):
        cache_file.write_text("{not json")
        assert TokenCache(cache_file).load_token() is None

    def test_clear_token_removes_the_cache_file(self, cache_file: Path):
        cache = TokenCache(cache_file)
        cache.save_token("tok-abc", 3600)
        assert cache_file.exists()

        cache.clear_token()
        assert not cache_file.exists()
        assert cache.load_token() is None
