"""Invocation record: which fan-out children belong to a trigger and how they ended.

Durable state is metadata on the parent "TMI-TF Analysis Status" note in TMI;
the in-process lock serializes read-modify-write (one replica, see spec).
"""

import asyncio
import logging
import math
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol

from tmi_tf.tmi_client_wrapper import STATUS_NOTE_NAME

logger = logging.getLogger(__name__)


class _NoteLike(Protocol):
    id: str


class TMILike(Protocol):
    """The subset of TMIClient this module depends on (also satisfied by test doubles)."""

    def find_note_by_name(
        self, threat_model_id: str, note_name: str, /
    ) -> _NoteLike | None: ...
    def append_status_line(self, threat_model_id: str, message: str, /) -> None: ...
    def get_note_metadata(
        self, threat_model_id: str, note_id: str, /
    ) -> dict[str, str]: ...
    def upsert_note_metadata(
        self, threat_model_id: str, note_id: str, metadata: dict[str, str], /
    ) -> None: ...
    def delete_note_metadata(
        self, threat_model_id: str, note_id: str, key: str, /
    ) -> None: ...


KEY_INVOCATION = "tf_invocation"
KEY_OPEN = "tf_open"
KEY_DEADLINE = "tf_deadline"
CHILD_PREFIX = "tf_child:"
DEADLINE_SLACK_SECONDS = 300
OUTCOMES = ("success", "failed", "aborted")

_KEY_BAD_CHARS = re.compile(r"[^a-zA-Z0-9_./:-]")
_locks: dict[str, asyncio.Lock] = {}


@dataclass
class InvocationState:
    invocation_id: str | None
    open: bool
    deadline: datetime | None
    children: dict[str, str] = field(default_factory=dict)


def lock_for(threat_model_id: str) -> asyncio.Lock:
    return _locks.setdefault(threat_model_id, asyncio.Lock())


def child_key(job_id: str) -> str:
    return CHILD_PREFIX + _KEY_BAD_CHARS.sub("_", job_id)


def compute_deadline(
    now: datetime, n_children: int, max_concurrent: int, job_timeout: int
) -> datetime:
    batches = math.ceil(max(n_children, 1) / max(max_concurrent, 1))
    return now + timedelta(seconds=batches * job_timeout + DEADLINE_SLACK_SECONDS)


def _note_id(tmi: TMILike, threat_model_id: str) -> str | None:
    note = tmi.find_note_by_name(threat_model_id, STATUS_NOTE_NAME)
    return note.id if note else None


def open_invocation(
    tmi: TMILike,
    threat_model_id: str,
    invocation_id: str,
    siblings: list[str],
    deadline: datetime,
) -> None:
    tmi.append_status_line(
        threat_model_id,
        f"Invocation {invocation_id} opened: {len(siblings)} environment jobs, "
        f"deadline {deadline.isoformat()}",
    )
    note_id = _note_id(tmi, threat_model_id)
    if note_id is None:
        raise RuntimeError("status note missing after append_status_line")
    # Old child marks would make a fresh invocation look complete; delete them
    # rather than blanking, so the note's metadata count doesn't grow unbounded
    # (parent job ids are per-delivery, so every invocation would otherwise add
    # ~N new keys and eventually hit TMI's metadata cap).
    for key in tmi.get_note_metadata(threat_model_id, note_id):
        if key.startswith(CHILD_PREFIX):
            tmi.delete_note_metadata(threat_model_id, note_id, key)
    tmi.upsert_note_metadata(
        threat_model_id,
        note_id,
        {
            KEY_INVOCATION: invocation_id,
            KEY_OPEN: "true",
            KEY_DEADLINE: deadline.isoformat(),
        },
    )


def read_state(tmi: TMILike, threat_model_id: str) -> InvocationState:
    note_id = _note_id(tmi, threat_model_id)
    if note_id is None:
        return InvocationState(None, False, None)
    meta = tmi.get_note_metadata(threat_model_id, note_id)
    deadline_raw = meta.get(KEY_DEADLINE)
    return InvocationState(
        invocation_id=meta.get(KEY_INVOCATION),
        open=meta.get(KEY_OPEN) == "true",
        deadline=datetime.fromisoformat(deadline_raw) if deadline_raw else None,
        children={
            k[len(CHILD_PREFIX) :]: v
            for k, v in meta.items()
            if k.startswith(CHILD_PREFIX) and v in OUTCOMES
        },
    )


def mark_child(
    tmi: TMILike, threat_model_id: str, job_id: str, outcome: str
) -> InvocationState:
    assert outcome in OUTCOMES, outcome
    note_id = _note_id(tmi, threat_model_id)
    if note_id is None:
        logger.warning("No status note for %s; cannot mark %s", threat_model_id, job_id)
        return InvocationState(None, False, None)
    tmi.upsert_note_metadata(threat_model_id, note_id, {child_key(job_id): outcome})
    return read_state(tmi, threat_model_id)


def outcome_of(state: InvocationState, job_id: str) -> str | None:
    return state.children.get(child_key(job_id)[len(CHILD_PREFIX) :])


def all_reported(state: InvocationState, siblings: list[str]) -> bool:
    marked = {child_key(j) for j in state.children}
    return all(child_key(s) in marked for s in siblings)


def close_invocation(tmi: TMILike, threat_model_id: str, summary: str) -> None:
    note_id = _note_id(tmi, threat_model_id)
    if note_id is not None:
        tmi.upsert_note_metadata(threat_model_id, note_id, {KEY_OPEN: "false"})
    tmi.append_status_line(threat_model_id, summary)


def is_open(state: InvocationState, now: datetime) -> bool:
    return state.open and state.deadline is not None and state.deadline > now


class Debouncer:
    """Accept the first key in a window, reject repeats within it."""

    def __init__(self, window_seconds: float) -> None:
        self.window = window_seconds
        self._last: dict[str, float] = {}

    def accept(self, key: str, now: float | None = None) -> bool:
        if self.window <= 0:
            return True
        t = time.monotonic() if now is None else now
        last = self._last.get(key)
        if last is not None and t - last < self.window:
            return False
        self._last[key] = t
        return True

    def forget(self, key: str) -> None:
        self._last.pop(key, None)
