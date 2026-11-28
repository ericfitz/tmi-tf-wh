"""Tests for invocation state kept as metadata on the parent status note."""

import uuid
from datetime import UTC, datetime, timedelta
from itertools import product
from unittest.mock import MagicMock

import pytest

from tmi_tf import invocation as inv
from tmi_tf.tmi_client_wrapper import STATUS_NOTE_NAME


class FakeTMI:
    """Stores one status note per threat model with a metadata dict."""

    def __init__(self):
        self.metadata: dict[str, str] = {}
        self.upserts: list[dict[str, str]] = []
        self.reject_prefix: str | None = None  # upserts with such a key raise
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
        if self.reject_prefix and any(
            k.startswith(self.reject_prefix) for k in metadata
        ):
            raise RuntimeError("TMI rejected the value")
        self.upserts.append(dict(metadata))
        self.metadata.update(metadata)

    def delete_note_metadata(self, tm, note_id, key):
        assert note_id == "note-1"
        self.metadata.pop(key, None)


NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)


def test_compute_deadline_rounds_up_batches():
    # 7 children, 3 at a time -> 3 batches * 3600 + 300 slack
    assert inv.compute_deadline(NOW, 7, 3, 3600) == NOW + timedelta(seconds=11100)


def test_child_key_sanitizes_disallowed_chars():
    assert inv.child_key("p1:aws-public") == "tf_child_p1_aws-public"
    assert inv.child_key("p1:env (x.y)") == "tf_child_p1_env__x_y_"


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
    tmi.metadata = {"tf_child_old": "success", "tf_open": "false"}
    inv.open_invocation(tmi, "tm1", "inv2", ["a"], NOW)
    assert inv.read_state(tmi, "tm1").children == {}
    assert "tf_child_old" not in tmi.metadata


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


def test_read_state_tolerates_corrupt_deadline():
    tmi = FakeTMI()
    tmi.metadata = {"tf_open": "true", "tf_deadline": "garbage"}
    state = inv.read_state(tmi, "tm1")
    assert state.deadline is None
    assert inv.is_open(state, NOW) is False


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


def test_debouncer_forget_allows_immediate_reaccept():
    d = inv.Debouncer(30)
    assert d.accept("tm1", now=100.0) is True
    d.forget("tm1")
    assert d.accept("tm1", now=101.0) is True


def test_lock_for_is_per_threat_model():
    assert inv.lock_for("tm1") is inv.lock_for("tm1")
    assert inv.lock_for("tm1") is not inv.lock_for("tm2")


def st(children, gaps=None):
    return inv.InvocationState(
        "p1", True, NOW, dict(_keyed(children)), dict(_keyed(gaps or {}))
    )


def _keyed(d):
    return {inv.child_key(j)[len(inv.CHILD_PREFIX) :]: v for j, v in d.items()}


def test_mark_child_gaps_stores_outcome_first_then_text():
    tmi = FakeTMI()
    state = inv.mark_child(
        tmi, "tm1", "p1:aws", "gaps", "DFD not generated (HTTP 429 rate_limit_error)"
    )
    assert inv.outcome_of(state, "p1:aws") == "gaps"
    assert (
        inv.gaps_of(state, "p1:aws") == "DFD not generated (HTTP 429 rate_limit_error)"
    )
    assert [set(u) for u in tmi.upserts] == [{"tf_child_p1_aws"}, {"tf_gaps_p1_aws"}]


def test_outcome_survives_a_rejected_gap_text():
    """TMI refusing the free text must not turn `completed with gaps` into `failed`."""
    tmi = FakeTMI()
    tmi.reject_prefix = "tf_gaps_"
    state = inv.mark_child(tmi, "tm1", "p1:aws", "gaps", "some text")
    assert inv.outcome_of(state, "p1:aws") == "gaps"
    assert inv.gaps_of(state, "p1:aws") is None
    assert inv.invocation_summary(state, ["p1:aws"]) == (
        "completed",
        "completed with gaps: p1:aws: gaps not recorded (1 succeeded, 0 failed)",
    )


def test_gap_text_is_cut_to_the_limit():
    tmi = FakeTMI()
    state = inv.mark_child(tmi, "tm1", "p1:aws", "gaps", "x" * 2000)
    text = inv.gaps_of(state, "p1:aws")
    assert text is not None
    assert len(text) == inv.GAP_TEXT_MAX == 300


@pytest.mark.parametrize(
    ("outcome", "gaps"), [("gaps", ""), ("success", "text"), ("failed", "text")]
)
def test_gap_text_must_match_outcome(outcome, gaps):
    tmi = FakeTMI()
    with pytest.raises(ValueError):
        inv.mark_child(tmi, "tm1", "p1:aws", outcome, gaps)
    assert tmi.upserts == []


def test_unknown_outcome_is_rejected():
    tmi = FakeTMI()
    with pytest.raises(ValueError):
        inv.mark_child(tmi, "tm1", "p1:aws", "partial")
    assert tmi.upserts == []


def test_read_state_ignores_unknown_stored_outcome():
    tmi = FakeTMI()
    tmi.metadata = {"tf_child_p1_aws": "partial", "tf_child_p1_gcp": "gaps"}
    assert inv.read_state(tmi, "tm1").children == {"p1_gcp": "gaps"}


def test_open_invocation_clears_old_gap_keys():
    tmi = FakeTMI()
    tmi.metadata = {
        "tf_gaps_p1_aws": "old text",
        "tf_child_p1_aws": "gaps",
        "tf_other": "keep",
    }
    inv.open_invocation(tmi, "tm1", "inv2", ["a"], NOW)
    assert not any(k.startswith(("tf_gaps_", "tf_child_")) for k in tmi.metadata)
    assert tmi.metadata["tf_other"] == "keep"


@pytest.mark.parametrize(
    ("children", "gaps", "expected"),
    [
        (
            {"p1:a": "success", "p1:b": "success"},
            {},
            ("completed", "2 succeeded, 0 failed"),
        ),
        (
            {"p1:a": "success", "p1:b": "failed"},
            {},
            ("failed", "1 succeeded, 1 failed (p1:b)"),
        ),
        ({"p1:a": "success"}, {}, ("failed", "1 succeeded, 1 failed (p1:b)")),
        (
            {"p1:a": "aborted", "p1:b": "success"},
            {},
            ("failed", "1 succeeded, 1 failed (p1:a)"),
        ),
        (
            {"p1:a": "gaps", "p1:b": "success"},
            {"p1:a": "25 of 28 threats not analyzed (HTTP 429 rate_limit_error)"},
            (
                "completed",
                (
                    "completed with gaps: p1:a: 25 of 28 threats not analyzed "
                    "(HTTP 429 rate_limit_error) (2 succeeded, 0 failed)"
                ),
            ),
        ),
        (
            {"p1:a": "gaps", "p1:b": "gaps"},
            {"p1:a": "A", "p1:b": "B"},
            (
                "completed",
                "completed with gaps: p1:a: A | p1:b: B (2 succeeded, 0 failed)",
            ),
        ),
        (
            {"p1:a": "gaps", "p1:b": "failed"},
            {"p1:a": "A"},
            ("failed", "1 succeeded, 1 failed (p1:b); gaps: p1:a: A"),
        ),
        (
            {"p1:a": "gaps", "p1:b": "success"},
            {},
            (
                "completed",
                "completed with gaps: p1:a: gaps not recorded (2 succeeded, 0 failed)",
            ),
        ),
    ],
)
def test_invocation_summary(children, gaps, expected):
    assert inv.invocation_summary(st(children, gaps), ["p1:a", "p1:b"]) == expected


def test_invocation_summary_status_is_only_completed_or_failed():
    """TMI's callback status enums accept nothing else; `gaps` is note-metadata only."""
    outcomes = [None, *inv.OUTCOMES]
    for a, b in product(outcomes, outcomes):
        children = {j: o for j, o in (("p1:a", a), ("p1:b", b)) if o is not None}
        gaps = {j: "t" for j, o in children.items() if o == "gaps"}
        status, _ = inv.invocation_summary(st(children, gaps), ["p1:a", "p1:b"])
        assert status in ("completed", "failed")


# --- run ids and invocation id on the status note (#115) ---------------------

RUN_1 = "11111111-1111-4111-8111-111111111111"
RUN_2 = "22222222-2222-4222-8222-222222222222"


def _opened(tmi=None):
    tmi = tmi or FakeTMI()
    inv.open_invocation(tmi, "tm1", "inv1", ["inv1:a", "inv1:b"], NOW)
    return tmi


def _text(tmi):
    return "\n".join(tmi.lines)


def test_open_records_the_invocation_id_in_metadata_and_text():
    tmi = _opened()
    assert tmi.metadata["invocation_id"] == "inv1"
    assert "inv1" in tmi.lines[-1]
    assert "run_ids" not in tmi.metadata  # no jobs have started yet


def test_job_start_records_run_id_in_metadata_and_text():
    tmi = _opened()
    assert inv.record_run_id(tmi, "tm1", "inv1:a", RUN_1) == RUN_1
    assert tmi.metadata["run_ids"] == RUN_1
    assert _text(tmi).count(RUN_1) == 1


def test_list_grows_as_jobs_start_and_each_job_appears_once():
    tmi = _opened()
    inv.record_run_id(tmi, "tm1", "inv1:a", RUN_1)
    inv.record_run_id(tmi, "tm1", "inv1:b", RUN_2)
    assert tmi.metadata["run_ids"].split(",") == [RUN_1, RUN_2]
    assert _text(tmi).count(RUN_1) == 1
    assert _text(tmi).count(RUN_2) == 1


def test_duplicate_start_is_idempotent_and_keeps_the_first_run_id():
    tmi = _opened()
    inv.record_run_id(tmi, "tm1", "inv1:a", RUN_1)
    lines_before = list(tmi.lines)
    assert inv.record_run_id(tmi, "tm1", "inv1:a", RUN_2) == RUN_1
    assert tmi.metadata["run_ids"] == RUN_1
    assert tmi.lines == lines_before
    assert RUN_2 not in _text(tmi)


def test_run_id_for_a_job_outside_the_open_invocation_is_not_recorded():
    tmi = _opened()
    assert inv.record_run_id(tmi, "tm1", "other:a", RUN_1) == RUN_1
    assert "run_ids" not in tmi.metadata
    assert RUN_1 not in _text(tmi)


def test_run_id_without_a_status_note_is_returned_unrecorded():
    tmi = FakeTMI()
    tmi.note = None
    assert inv.record_run_id(tmi, "tm1", "inv1:a", RUN_1) == RUN_1


def test_open_clears_the_previous_invocations_run_ids():
    tmi = _opened()
    inv.record_run_id(tmi, "tm1", "inv1:a", RUN_1)
    inv.open_invocation(tmi, "tm1", "inv2", ["inv2:a"], NOW)
    assert "run_ids" not in tmi.metadata
    assert not any(k.startswith("tf_run_") for k in tmi.metadata)
    assert inv.record_run_id(tmi, "tm1", "inv2:a", RUN_2) == RUN_2
    assert tmi.metadata["run_ids"] == RUN_2


def test_run_id_keys_do_not_count_as_child_outcomes():
    tmi = _opened()
    inv.record_run_id(tmi, "tm1", "inv1:a", RUN_1)
    assert inv.read_state(tmi, "tm1").children == {}


def test_bound_run_ids_keeps_whole_ids_up_to_the_limit():
    ids = [str(uuid.uuid4()) for _ in range(40)]
    value, kept = inv.bound_run_ids(ids)
    assert kept == 27  # 27 * 36 + 26 commas = 998; a 28th would need 1035
    assert len(value) <= inv.RUN_IDS_MAX
    assert value.split(",") == ids[:27]


def test_bound_run_ids_untouched_when_it_fits():
    ids = [RUN_1, RUN_2]
    assert inv.bound_run_ids(ids) == (f"{RUN_1},{RUN_2}", 2)


def test_over_limit_text_stays_complete_and_states_the_metadata_bound():
    tmi = _opened()
    ids = [str(uuid.uuid4()) for _ in range(30)]
    for i, rid in enumerate(ids):
        inv.record_run_id(tmi, "tm1", f"inv1:j{i:02d}", rid)
    assert len(tmi.metadata["run_ids"]) <= inv.RUN_IDS_MAX
    assert len(tmi.metadata["run_ids"].split(",")) == 27
    for rid in ids:
        assert _text(tmi).count(rid) == 1  # visible text lists every job
    assert "first 27 of 30" in tmi.lines[-1]
    assert "1024" in tmi.lines[-1]
