"""Invocation record: which fan-out children belong to a trigger and how they ended.

Durable state is metadata on the parent "TMI-TF Analysis Status" note in TMI;
the in-process lock serializes read-modify-write (one replica, see spec).
"""

import asyncio
import hashlib
import logging
import math
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol

from tmi_tf.artifact_metadata import validate_run_id
from tmi_tf.cell_schema import METADATA_VALUE_MAX
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
# #115: the invocation id and the run ids of its jobs, readable on the note.
KEY_INVOCATION_ID = "invocation_id"
KEY_RUN_IDS = "run_ids"
RUN_PREFIX = "tf_run_"
# TMI caps a metadata value at 1024 characters (cell_schema.METADATA_VALUE_MAX).
RUN_IDS_MAX = METADATA_VALUE_MAX
CHILD_PREFIX = "tf_child_"
GAPS_PREFIX = "tf_gaps_"
GAP_TEXT_MAX = 300
DEADLINE_SLACK_SECONDS = 300
OUTCOMES = ("success", "gaps", "failed", "aborted")

# TMI 500s on bulk metadata keys containing ":" or "." (#71, probed 2026-09-18).
_KEY_BAD_CHARS = re.compile(r"[^a-zA-Z0-9_-]")
_locks: dict[str, asyncio.Lock] = {}


@dataclass
class InvocationState:
    invocation_id: str | None
    open: bool
    deadline: datetime | None
    children: dict[str, str] = field(default_factory=dict)
    gaps: dict[str, str] = field(default_factory=dict)


def lock_for(threat_model_id: str) -> asyncio.Lock:
    return _locks.setdefault(threat_model_id, asyncio.Lock())


def child_key(job_id: str) -> str:
    return CHILD_PREFIX + _KEY_BAD_CHARS.sub("_", job_id)


def run_key(job_id: str, repo: str = "") -> str:
    """Collision-free metadata key for one job's run record.

    Sibling child jobs can share a job id (same environment name in two
    repositories, or "all"), so the repository is part of the identity. A hash
    keeps the key inside TMI's key alphabet and length whatever the ids hold.
    """
    digest = hashlib.sha256(f"{job_id}\0{repo}".encode()).hexdigest()[:32]
    return RUN_PREFIX + digest


def compute_deadline(
    now: datetime, n_children: int, max_concurrent: int, job_timeout: int
) -> datetime:
    batches = math.ceil(max(n_children, 1) / max(max_concurrent, 1))
    return now + timedelta(seconds=batches * job_timeout + DEADLINE_SLACK_SECONDS)


def _note_id(tmi: TMILike, threat_model_id: str) -> str | None:
    note = tmi.find_note_by_name(threat_model_id, STATUS_NOTE_NAME)
    return note.id if note else None


def _clear_run_state(tmi: TMILike, threat_model_id: str, note_id: str) -> None:
    """Delete a previous invocation's (or run's) run ids and invocation id."""
    for key in tmi.get_note_metadata(threat_model_id, note_id):
        if key.startswith(RUN_PREFIX) or key in (
            KEY_RUN_IDS,
            KEY_INVOCATION_ID,
            "run_id",  # a CLI run's id on the shared note
        ):
            tmi.delete_note_metadata(threat_model_id, note_id, key)


def begin_invocation(tmi: TMILike, threat_model_id: str, invocation_id: str) -> None:
    """Mark the start of an invocation before any fan-out work (#115).

    Writes the invocation id and drops the previous invocation's run ids, so an
    invocation that ends up with no jobs (nothing matched, bad profile, an
    error while resolving targets) never shows stale ids. Call under
    lock_for(threat_model_id).
    """
    tmi.append_status_line(threat_model_id, f"Invocation {invocation_id} started")
    note_id = _note_id(tmi, threat_model_id)
    if note_id is None:
        raise RuntimeError("status note missing after append_status_line")
    _clear_run_state(tmi, threat_model_id, note_id)
    tmi.upsert_note_metadata(
        threat_model_id, note_id, {KEY_INVOCATION_ID: invocation_id}
    )


def begin_cli_run(tmi: TMILike, threat_model_id: str, run_id: str) -> None:
    """Prepare the shared status note for a CLI run (no invocation, one job).

    Removes a previous addon invocation's invocation id and run ids and records
    this run's id as ``run_ids``. The note text carries the run id through the
    "Run ID" status row that run_analysis writes.
    """
    validate_run_id(run_id)
    if _note_id(tmi, threat_model_id) is None:
        tmi.append_status_line(threat_model_id, f"CLI run started: run id {run_id}")
    note_id = _note_id(tmi, threat_model_id)
    if note_id is None:
        raise RuntimeError("status note missing after append_status_line")
    _clear_run_state(tmi, threat_model_id, note_id)
    tmi.upsert_note_metadata(threat_model_id, note_id, {KEY_RUN_IDS: run_id})


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
    # rather than blanking, so the note's metadata does not grow without bound
    # (parent job ids are per-delivery, so every invocation would otherwise add
    # ~N new keys; TMI caps the entries per bulk request, not per note).
    for key in tmi.get_note_metadata(threat_model_id, note_id):
        if key.startswith((CHILD_PREFIX, GAPS_PREFIX)):
            tmi.delete_note_metadata(threat_model_id, note_id, key)
    _clear_run_state(tmi, threat_model_id, note_id)
    tmi.upsert_note_metadata(
        threat_model_id,
        note_id,
        {
            KEY_INVOCATION: invocation_id,
            KEY_INVOCATION_ID: invocation_id,
            KEY_OPEN: "true",
            KEY_DEADLINE: deadline.isoformat(),
        },
    )


def _valid_run_id(value: str | None) -> bool:
    try:
        validate_run_id(value)
    except ValueError:
        return False
    return True


def bound_run_ids(run_ids: list[str]) -> tuple[str, int]:
    """Comma-separated run ids for the metadata value, and how many fit.

    Rule: whole ids in the given order, as many as fit in RUN_IDS_MAX
    characters; an id is never cut in half.
    """
    value = ""
    kept = 0
    for rid in run_ids:
        candidate = f"{value},{rid}" if kept else rid
        if len(candidate) > RUN_IDS_MAX:
            break
        value, kept = candidate, kept + 1
    return value, kept


def record_run_id(
    tmi: TMILike, threat_model_id: str, job_id: str, run_id: str, repo: str = ""
) -> str:
    """Record a starting job's run id on the invocation status note.

    Call under lock_for(threat_model_id). Returns the run id the job must use:
    the one already recorded when the job's start is processed twice (nothing
    is written then, so a job is listed exactly once), else ``run_id``. A job
    that does not belong to the note's invocation is not recorded. A job is
    identified by its id and repository (``repo``), since siblings can share an id.
    """
    note_id = _note_id(tmi, threat_model_id)
    if note_id is None:
        logger.warning("No status note for %s; run id not recorded", threat_model_id)
        return run_id
    meta = tmi.get_note_metadata(threat_model_id, note_id)
    invocation_id = meta.get(KEY_INVOCATION)
    if not invocation_id or not job_id.startswith(f"{invocation_id}:"):
        logger.warning(
            "Job %s is not in the open invocation; run id not recorded", job_id
        )
        return run_id
    existing = meta.get(run_key(job_id, repo))
    if existing is not None and _valid_run_id(existing):
        return existing
    # A corrupt recorded value is skipped here and replaced for this job below.
    recorded = {
        k: v
        for k, v in meta.items()
        if k.startswith(RUN_PREFIX) and k != run_key(job_id, repo) and _valid_run_id(v)
    }
    already_truncated = bound_run_ids(list(recorded.values()))[1] < len(recorded)
    recorded[run_key(job_id, repo)] = run_id
    ordered = [recorded[k] for k in sorted(recorded)]
    value, kept = bound_run_ids(ordered)
    tmi.upsert_note_metadata(
        threat_model_id, note_id, {run_key(job_id, repo): run_id, KEY_RUN_IDS: value}
    )
    who = f"{job_id} ({repo})" if repo else job_id
    tmi.append_status_line(threat_model_id, f"Job {who} started: run id {run_id}")
    if kept < len(ordered) and not already_truncated:
        # Once, when the bound is first exceeded; later starts add no repeat.
        tmi.append_status_line(
            threat_model_id,
            f"Metadata {KEY_RUN_IDS} is bounded: whole run ids in an arbitrary but stable order (sorted by hashed key), "
            f"at most {RUN_IDS_MAX} characters, so later jobs may be missing from "
            "it; the text of this note lists every run id",
        )
    return run_id


def read_state(tmi: TMILike, threat_model_id: str) -> InvocationState:
    note_id = _note_id(tmi, threat_model_id)
    if note_id is None:
        return InvocationState(None, False, None)
    meta = tmi.get_note_metadata(threat_model_id, note_id)
    deadline_raw = meta.get(KEY_DEADLINE)
    deadline = None
    if deadline_raw:
        try:
            deadline = datetime.fromisoformat(deadline_raw)
        except ValueError:
            logger.warning(
                "Corrupt %s metadata for %s: %r",
                KEY_DEADLINE,
                threat_model_id,
                deadline_raw,
            )
    return InvocationState(
        invocation_id=meta.get(KEY_INVOCATION),
        open=meta.get(KEY_OPEN) == "true",
        deadline=deadline,
        children={
            k[len(CHILD_PREFIX) :]: v
            for k, v in meta.items()
            if k.startswith(CHILD_PREFIX) and v in OUTCOMES
        },
        gaps={
            k[len(GAPS_PREFIX) :]: v
            for k, v in meta.items()
            if k.startswith(GAPS_PREFIX)
        },
    )


def mark_child(
    tmi: TMILike, threat_model_id: str, job_id: str, outcome: str, gaps: str = ""
) -> InvocationState:
    if outcome not in OUTCOMES:
        raise ValueError(f"unknown child outcome: {outcome!r}")
    if (outcome == "gaps") != bool(gaps):
        raise ValueError(
            f"gap text must be given exactly when the outcome is 'gaps' (outcome={outcome!r})"
        )
    note_id = _note_id(tmi, threat_model_id)
    if note_id is None:
        logger.warning("No status note for %s; cannot mark %s", threat_model_id, job_id)
        return InvocationState(None, False, None)
    tmi.upsert_note_metadata(threat_model_id, note_id, {child_key(job_id): outcome})
    if outcome == "gaps":
        # The outcome decides completed versus failed, so it is stored first and
        # must not depend on TMI accepting the free text.
        gaps_key = GAPS_PREFIX + child_key(job_id)[len(CHILD_PREFIX) :]
        try:
            tmi.upsert_note_metadata(
                threat_model_id, note_id, {gaps_key: gaps[:GAP_TEXT_MAX]}
            )
        except Exception as e:
            logger.warning(
                "Could not store gap text for %s: %s", job_id, type(e).__name__
            )
    return read_state(tmi, threat_model_id)


def outcome_of(state: InvocationState, job_id: str) -> str | None:
    return state.children.get(child_key(job_id)[len(CHILD_PREFIX) :])


def gaps_of(state: InvocationState, job_id: str) -> str | None:
    return state.gaps.get(child_key(job_id)[len(CHILD_PREFIX) :])


def invocation_summary(state: InvocationState, siblings: list[str]) -> tuple[str, str]:
    """Callback status (`completed` or `failed`) and message for a finished invocation."""
    failed = sorted(
        j for j in siblings if outcome_of(state, j) not in ("success", "gaps")
    )
    base = f"{len(siblings) - len(failed)} succeeded, {len(failed)} failed"
    if failed:
        base += f" ({', '.join(failed)})"
    gapped = [j for j in siblings if outcome_of(state, j) == "gaps"]
    if not gapped:
        return ("failed" if failed else "completed", base)
    details = " | ".join(
        f"{j}: {gaps_of(state, j) or 'gaps not recorded'}" for j in gapped
    )
    if failed:
        return ("failed", f"{base}; gaps: {details}")
    return ("completed", f"completed with gaps: {details} ({base})")


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
