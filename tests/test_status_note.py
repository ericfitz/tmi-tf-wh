"""Tests for the status note tracking in TMIClient."""

from typing import cast
from unittest.mock import MagicMock, patch

from tmi_tf.tmi_client_wrapper import TMIClient


class TestUpdateStatusNote:
    """Test update_status_note method."""

    def _make_client(self) -> TMIClient:
        """Create a TMIClient with mocked internals."""
        with patch.object(TMIClient, "__init__", lambda self, *a, **kw: None):
            client = TMIClient.__new__(TMIClient)
            client._status_note_id = None
            client._status_note_initialized = False
            client._status_note_content = ""
            # Mock the methods used internally
            client.find_note_by_name = MagicMock(return_value=None)  # type: ignore[method-assign]
            client.create_note = MagicMock()  # type: ignore[method-assign]
            client.update_note = MagicMock()  # type: ignore[method-assign]
            return client

    def test_first_call_creates_note(self):
        client = self._make_client()
        mock_note = MagicMock()
        mock_note.id = "note-123"
        cast(MagicMock, client.create_note).return_value = mock_note

        client.update_status_note("tm-1", "Analysis started")

        cast(MagicMock, client.create_note).assert_called_once()
        assert (
            cast(MagicMock, client.create_note).call_args.kwargs["name"]
            == "TMI-TF Analysis Status"
        )
        assert client._status_note_initialized is True
        assert client._status_note_id == "note-123"

    def test_subsequent_call_appends(self):
        client = self._make_client()
        mock_note = MagicMock()
        mock_note.id = "note-123"
        cast(MagicMock, client.create_note).return_value = mock_note

        client.update_status_note("tm-1", "Analysis started")
        client.update_status_note("tm-1", "Cloning repo")

        # Second call should update, not create
        cast(MagicMock, client.update_note).assert_called_once()
        content = cast(MagicMock, client.update_note).call_args.kwargs["content"]
        # Content should contain both messages
        assert "Analysis started" in content
        assert "Cloning repo" in content

    def test_existing_note_overwrites_on_first_call(self):
        client = self._make_client()
        existing_note = MagicMock()
        existing_note.id = "existing-note-456"
        cast(MagicMock, client.find_note_by_name).return_value = existing_note

        client.update_status_note("tm-1", "Analysis started")

        # Should update existing note, not create new
        cast(MagicMock, client.create_note).assert_not_called()
        cast(MagicMock, client.update_note).assert_called_once()
        assert client._status_note_id == "existing-note-456"

    def test_failure_does_not_raise(self):
        client = self._make_client()
        cast(MagicMock, client.find_note_by_name).side_effect = Exception("API error")

        # Should not raise
        client.update_status_note("tm-1", "Analysis started")

    def test_content_has_timestamp(self):
        client = self._make_client()
        mock_note = MagicMock()
        mock_note.id = "note-123"
        cast(MagicMock, client.create_note).return_value = mock_note

        client.update_status_note("tm-1", "Test message")

        content = cast(MagicMock, client.create_note).call_args.kwargs["content"]
        assert "[" in content and "]" in content  # Timestamp brackets
        assert "Test message" in content
