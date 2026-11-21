"""Tests for TMIClient._call_with_retry backoff."""

from unittest.mock import MagicMock

import pytest  # pyright: ignore[reportMissingImports] # ty:ignore[unresolved-import]

from tmi_tf.tmi_client_wrapper import (
    ApiException,  # pyright: ignore[reportAttributeAccessIssue]
    TMIClient,
)


@pytest.fixture
def sleeps(monkeypatch):
    waits: list[float] = []
    monkeypatch.setattr("tmi_tf.tmi_client_wrapper.time.sleep", waits.append)
    monkeypatch.setattr("tmi_tf.tmi_client_wrapper.random.random", lambda: 0.0)
    return waits


@pytest.fixture
def client(sleeps):
    c = TMIClient.__new__(TMIClient)
    c._reauthenticate = MagicMock()  # type: ignore[method-assign]
    return c


def api(status, headers=None):
    e = ApiException(status=status, reason="r")
    e.headers = headers
    return e


def test_429_is_retried_with_backoff_until_it_succeeds(client, sleeps):
    call = MagicMock(side_effect=[api(429), api(429), api(429), "ok"])
    assert client._call_with_retry(call) == "ok"
    assert sleeps == [3.0, 6.0, 12.0]


def test_429_gives_up_after_four_attempts(client, sleeps):
    call = MagicMock(side_effect=[api(429)] * 4)
    with pytest.raises(ApiException):
        client._call_with_retry(call)
    assert call.call_count == 4 and len(sleeps) == 3


def test_retry_after_header_is_honored(client, sleeps):
    call = MagicMock(side_effect=[api(429, {"Retry-After": "7"}), "ok"])
    client._call_with_retry(call)
    assert sleeps == [7.0]


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_5xx_is_retried_exactly_once(client, sleeps, status):
    call = MagicMock(side_effect=[api(status), api(status)])
    with pytest.raises(ApiException):
        client._call_with_retry(call)
    assert call.call_count == 2 and sleeps == [3.0]


def test_401_reauthenticates_once_without_sleeping(client, sleeps):
    call = MagicMock(side_effect=[api(401), "ok"])
    assert client._call_with_retry(call) == "ok"
    client._reauthenticate.assert_called_once()
    assert sleeps == []


def test_second_401_is_raised(client, sleeps):
    call = MagicMock(side_effect=[api(401), api(401)])
    with pytest.raises(ApiException):
        client._call_with_retry(call)
    assert call.call_count == 2


def test_429_after_reauthentication_still_backs_off(client, sleeps):
    call = MagicMock(side_effect=[api(401), api(429), "ok"])
    assert client._call_with_retry(call) == "ok"
    assert sleeps == [3.0]


@pytest.mark.parametrize("status", [400, 403, 404, 409, 422])
def test_other_statuses_are_not_retried(client, sleeps, status):
    call = MagicMock(side_effect=[api(status)])
    with pytest.raises(ApiException):
        client._call_with_retry(call)
    assert call.call_count == 1 and sleeps == []


def test_429_then_5xx_is_not_retried(client, sleeps):
    # One attempt counter serves both: a 5xx after a 429 is already attempt 2.
    call = MagicMock(side_effect=[api(429), api(503)])
    with pytest.raises(ApiException):
        client._call_with_retry(call)
    assert call.call_count == 2 and sleeps == [3.0]


def test_5xx_then_429_continues_the_shared_backoff(client, sleeps):
    call = MagicMock(side_effect=[api(503), api(429), api(429), "ok"])
    assert client._call_with_retry(call) == "ok"
    assert sleeps == [3.0, 6.0, 12.0]
