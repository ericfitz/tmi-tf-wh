"""Tests for invocation state kept as metadata on the parent status note."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from tmi_tf import invocation as inv
from tmi_tf.tmi_client_wrapper import STATUS_NOTE_NAME


class FakeTMI:
    """Stores one status note per threat model with a metadata dict."""

    def __init__(self):
        self.metadata: dict[str, str] = {}
        self.lines: list[str] = []
        self.note: MagicMock | None = MagicMock(id="note-1", name=STATUS_NOTE_NAME)

    def find_note_by_name(self, tm, name):
        return self.note if name == STATUS_NOTE_NAME else None

    def append_status_line(self, tm, message):
        self.lines.append(message)

    def get_note_metadata(self, tm, note_id):
        assert note_id == "note-1"
        return dict(self.metadata)

    def upsert_note_metadata(self, tm, note_id, metadata):
        assert note_id == "note-1"
        self.metadata.update(metadata)

    def delete_note_metadata(self, tm, note_id, key):
        assert note_id == "note-1"
        self.metadata.pop(key, None)


NOW = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)


def test_compute_deadline_rounds_up_batches():
    # 7 children, 3 at a time -> 3 batches * 3600 + 300 slack
    assert inv.compute_deadline(NOW, 7, 3, 3600) == NOW + timedelta(seconds=11100)


def test_child_key_sanitizes_disallowed_chars():
    assert inv.child_key("p1:aws-public") == "tf_child:p1:aws-public"
    assert inv.child_key("p1:env (x)") == "tf_child:p1:env__x_"


def test_open_then_read():
    tmi = FakeTMI()
    inv.open_invocation(tmi, "tm1", "inv1", ["a", "b"], NOW)
    state = inv.read_state(tmi, "tm1")
    assert state.invocation_id == "inv1"
    assert state.open is True
    assert state.deadline == NOW
    assert state.children == {}
    assert tmi.lines[-1].startswith("Invocation inv1 opened")


def test_open_clears_previous_child_marks():
    tmi = FakeTMI()
    tmi.metadata = {"tf_child:old": "success", "tf_open": "false"}
    inv.open_invocation(tmi, "tm1", "inv2", ["a"], NOW)
    assert inv.read_state(tmi, "tm1").children == {}
    assert "tf_child:old" not in tmi.metadata


def test_mark_child_and_all_reported():
    tmi = FakeTMI()
    inv.open_invocation(tmi, "tm1", "inv1", ["a", "b"], NOW)
    state = inv.mark_child(tmi, "tm1", "a", "success")
    assert state.children == {"a": "success"}
    assert inv.all_reported(state, ["a", "b"]) is False
    state = inv.mark_child(tmi, "tm1", "b", "failed")
    assert inv.all_reported(state, ["a", "b"]) is True


def test_outcome_of_returns_marked_outcome_for_sanitized_job_id():
    tmi = FakeTMI()
    inv.open_invocation(tmi, "tm1", "inv1", ["p1:env (x)"], NOW)
    state = inv.mark_child(tmi, "tm1", "p1:env (x)", "success")
    assert inv.outcome_of(state, "p1:env (x)") == "success"
    assert inv.outcome_of(state, "p1:other") is None


def test_close_sets_open_false_and_writes_summary():
    tmi = FakeTMI()
    inv.open_invocation(tmi, "tm1", "inv1", ["a"], NOW)
    inv.close_invocation(tmi, "tm1", "Invocation complete: 1 succeeded, 0 failed")
    assert tmi.metadata["tf_open"] == "false"
    assert tmi.lines[-1] == "Invocation complete: 1 succeeded, 0 failed"


def test_read_state_without_note_is_closed():
    tmi = FakeTMI()
    tmi.note = None
    state = inv.read_state(tmi, "tm1")
    assert state.open is False and state.invocation_id is None


def test_is_open_respects_deadline():
    state = inv.InvocationState("inv1", True, NOW, {})
    assert inv.is_open(state, NOW - timedelta(seconds=1)) is True
    assert inv.is_open(state, NOW + timedelta(seconds=1)) is False
    assert inv.is_open(inv.InvocationState("inv1", False, NOW, {}), NOW) is False


def test_debouncer():
    d = inv.Debouncer(30)
    assert d.accept("tm1", now=100.0) is True
    assert d.accept("tm1", now=110.0) is False
    assert d.accept("tm2", now=110.0) is True
    assert d.accept("tm1", now=131.0) is True


def test_debouncer_zero_window_accepts_everything():
    d = inv.Debouncer(0)
    assert d.accept("tm1", now=1.0) and d.accept("tm1", now=1.0)


def test_lock_for_is_per_threat_model():
    assert inv.lock_for("tm1") is inv.lock_for("tm1")
    assert inv.lock_for("tm1") is not inv.lock_for("tm2")
