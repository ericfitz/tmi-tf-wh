"""Tests for TMIClient note-metadata helpers."""

import threading
from unittest.mock import MagicMock, patch

import pytest

from tmi_tf.tmi_client_wrapper import STATUS_NOTE_NAME, AnalysisAborted, TMIClient


def _client():
    client = TMIClient.__new__(TMIClient)
    client.sub_resources_api = MagicMock()
    client._call_with_retry = lambda api_call: api_call()
    return client


def test_get_note_metadata_returns_dict():
    client = _client()
    m1, m2 = MagicMock(key="tf_open"), MagicMock(key="tf_child_p1_aws")
    m1.value, m2.value = "true", "success"
    client.sub_resources_api.get_note_metadata.return_value = [m1, m2]
    assert client.get_note_metadata("tm1", "n1") == {
        "tf_open": "true",
        "tf_child_p1_aws": "success",
    }
    client.sub_resources_api.get_note_metadata.assert_called_once_with(
        threat_model_id="tm1", note_id="n1"
    )


def test_upsert_note_metadata_sends_key_value_pairs():
    client = _client()
    client.upsert_note_metadata("tm1", "n1", {"tf_open": "false"})
    call = client.sub_resources_api.bulk_upsert_note_metadata.call_args
    assert call.kwargs["threat_model_id"] == "tm1"
    assert call.kwargs["note_id"] == "n1"
    sent = call.kwargs["metadata"]
    assert [(m.key, m.value) for m in sent] == [("tf_open", "false")]


def test_delete_note_metadata_sends_key():
    client = _client()
    client.delete_note_metadata("tm1", "n1", "tf_child_old")
    client.sub_resources_api.delete_note_metadata_by_key.assert_called_once_with(
        threat_model_id="tm1", note_id="n1", key="tf_child_old"
    )


def test_append_status_line_updates_existing_note():
    client = _client()
    # The list endpoint returns NoteListItem, which has no content (#70).
    client.find_note_by_name = MagicMock(
        return_value=MagicMock(spec=["id"], id="note-1")
    )
    client.get_note = MagicMock(return_value=MagicMock(content="old content"))
    client.update_note = MagicMock()
    client.create_note = MagicMock()

    client.append_status_line("tm1", "hello")

    client.update_note.assert_called_once()
    call = client.update_note.call_args
    assert call.kwargs["note_id"] == "note-1"
    content = call.kwargs["content"]
    assert content.startswith("old content")
    assert "\n" in content
    assert content.endswith("] hello")
    client.create_note.assert_not_called()


def test_append_status_line_creates_note_when_missing():
    client = _client()
    client.find_note_by_name = MagicMock(return_value=None)
    client.update_note = MagicMock()
    client.create_note = MagicMock()

    client.append_status_line("tm1", "hello")

    client.create_note.assert_called_once()
    call = client.create_note.call_args
    assert call.kwargs["name"] == STATUS_NOTE_NAME
    assert call.kwargs["content"].endswith("] hello")
    client.update_note.assert_not_called()


def test_update_status_note_raises_when_cancelled():
    client = _client()
    client._status_note_initialized = True
    client._status_note_id = "n1"
    client._status_note_content = ""
    client.status_note_name = "x"
    client.update_note = MagicMock()
    client.cancel_event = threading.Event()
    client.cancel_event.set()
    with pytest.raises(AnalysisAborted):
        client.update_status_note("tm1", "Phase 2 started")
    client.update_note.assert_not_called()


def test_analysis_aborted_is_not_an_exception():
    assert not issubclass(AnalysisAborted, Exception)


def _polling_client(status=None, exc=None):
    client = _client()
    client._status_note_initialized = True
    client._status_note_id = "n1"
    client._status_note_content = ""
    client.status_note_name = "x"
    client.update_note = update_note = MagicMock()
    client.config = MagicMock(tmi_server_url="https://tmi")
    client.api_client = MagicMock()
    client.api_client.configuration.get_api_key_with_prefix.return_value = "Bearer t"
    client.cancel_event = event = threading.Event()
    client.delivery_id = "d1"
    resp = MagicMock()
    resp.json.return_value = {"status": status}
    get = MagicMock(return_value=resp, side_effect=exc)
    return client, get, update_note, event


def test_update_status_note_aborts_when_delivery_cancelled_in_tmi():
    client, get, update_note, event = _polling_client(status="cancelled")
    with (
        patch("tmi_tf.tmi_client_wrapper.requests.get", get),
        pytest.raises(AnalysisAborted),
    ):
        client.update_status_note("tm1", "Phase 2 started")
    assert get.call_args.args[0] == "https://tmi/webhook-deliveries/d1"
    assert event.is_set()
    update_note.assert_not_called()


def test_update_status_note_continues_when_poll_fails():
    client, get, update_note, event = _polling_client(exc=RuntimeError("boom"))
    with patch("tmi_tf.tmi_client_wrapper.requests.get", get):
        client.update_status_note("tm1", "Phase 2 started")
    update_note.assert_called_once()
    assert not event.is_set()
    assert client._last_cancel_poll is None  # retried at the next checkpoint


def test_delivery_poll_is_rate_limited():
    client, get, _, _ = _polling_client(status="in_progress")
    with patch("tmi_tf.tmi_client_wrapper.requests.get", get):
        client.update_status_note("tm1", "a")
        client.update_status_note("tm1", "b")
    get.assert_called_once()


def test_no_poll_without_delivery_id():
    client, get, _, _ = _polling_client(status="cancelled")
    client.delivery_id = None
    with patch("tmi_tf.tmi_client_wrapper.requests.get", get):
        client.update_status_note("tm1", "a")
    get.assert_not_called()
