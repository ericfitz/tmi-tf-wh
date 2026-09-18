"""Tests for TMIClient note-metadata helpers."""

from unittest.mock import MagicMock

from tmi_tf.tmi_client_wrapper import STATUS_NOTE_NAME, TMIClient


def _client():
    client = TMIClient.__new__(TMIClient)
    client.sub_resources_api = MagicMock()
    client._call_with_retry = lambda api_call: api_call()
    return client


def test_get_note_metadata_returns_dict():
    client = _client()
    m1, m2 = MagicMock(key="tf_open"), MagicMock(key="tf_child:p1:aws")
    m1.value, m2.value = "true", "success"
    client.sub_resources_api.get_note_metadata.return_value = [m1, m2]
    assert client.get_note_metadata("tm1", "n1") == {
        "tf_open": "true",
        "tf_child:p1:aws": "success",
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
    client.delete_note_metadata("tm1", "n1", "tf_child:old")
    client.sub_resources_api.delete_note_metadata_by_key.assert_called_once_with(
        threat_model_id="tm1", note_id="n1", key="tf_child:old"
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
