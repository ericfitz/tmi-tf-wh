# Invocation Tracking Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Track each fan-out invocation so the addon callback fires when every child finishes (#55), duplicate triggers are dropped while an invocation is open (#52), and an invocation can be aborted (#54, local mechanics only).

**Architecture:** A new `tmi_tf/invocation.py` owns the invocation record: metadata on the parent `TMI-TF Analysis Status` note in TMI (durable) plus an in-process lock. The worker opens the record in the parent job, marks children as they finish, and closes it (callback + summary) from the last child or a deadline watchdog. The webhook consults the record before enqueueing. Abort sets a `threading.Event` that `TMIClient.update_status_note` checks, which every phase boundary calls.

**Tech Stack:** Python 3.13, asyncio, FastAPI, pytest, generated TMI client (`bulk_upsert_note_metadata`, `get_note_metadata`).

**Spec:** `docs/superpowers/specs/2026-09-17-invocation-tracking-design.md`

## Global Constraints

- One pod replica; in-process `asyncio.Lock` per threat model serializes metadata read-modify-write. Do not add a shared lock or datastore.
- Metadata keys must match `^[a-zA-Z0-9_./:-]+$` (max 256 chars); values are 1..1024 chars; max 100 entries per note. Keys: `tf_invocation`, `tf_open`, `tf_deadline`, `tf_child:<job_id>`.
- Deadline = child enqueue time + `ceil(N / MAX_CONCURRENT_JOBS) * JOB_TIMEOUT` + 300 s.
- `DEDUP_DEBOUNCE_SECONDS` default 30; `0` disables the debounce.
- Dedup fails open: if the TMI lookup raises, accept the trigger.
- No admin endpoints, no admin token; `/status` unchanged.
- Gates before every commit: `uv run ruff check tmi_tf/ tests/`, `uv run ruff format --check tmi_tf/ tests/`, `uv run pyright`, `uv run pytest tests/`.
- The TMI client is loaded from `~/Projects/tmi-clients/python-client-generated`; new wrapper methods go in `tmi_tf/tmi_client_wrapper.py` and carry `# type: ignore` on `tmi_client` imports like the existing ones.
- Branch: `feat/invocation-tracking` (PR 1 = Tasks 1-8, closes #55 and #52). Tasks 9-10 go on `feat/abort-job` branched from PR 1 (PR 2, partial #54).

---

## File map

| File | Responsibility |
| --- | --- |
| `tmi_tf/job.py` | `Job` gains `siblings: list[str] \| None` and `deadline: datetime \| None`; serialized in `to_queue_message` / `from_queue_message`. |
| `tmi_tf/tmi_client_wrapper.py` | `get_note_metadata`, `upsert_note_metadata`; `cancel_event` attribute and `AnalysisAborted` raised from `update_status_note`. |
| `tmi_tf/invocation.py` (new) | `InvocationState`, `compute_deadline`, `open_invocation`, `read_state`, `mark_child`, `close_invocation`, `is_open`, `Debouncer`. Sync functions; callers use `asyncio.to_thread`. |
| `tmi_tf/config.py` | `dedup_debounce_seconds`. |
| `tmi_tf/worker.py` | Parent opens the invocation; children mark; last child or watchdog closes; `abort()`. |
| `tmi_tf/server.py` | Dedup check before publish. |
| `tests/test_job.py`, `tests/test_invocation.py` (new), `tests/test_worker.py`, `tests/test_server.py`, `tests/test_tmi_client_wrapper.py` (new if absent) | Tests. |
| `README.md` | Operator notes: env vars, metadata keys, abort runbook. |

---

### Task 1: Job carries siblings and deadline

**Files:**
- Modify: `tmi_tf/job.py`
- Test: `tests/test_job.py`

**Interfaces:**
- Produces: `Job.siblings: list[str] | None = None`, `Job.deadline: datetime | None = None`; both round-trip through `to_queue_message()` (deadline as ISO string) and `from_queue_message()`; absent keys in old messages deserialize to `None`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_job.py`:

```python
from datetime import datetime, timezone

from tmi_tf.job import Job


def test_siblings_and_deadline_round_trip():
    deadline = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)
    job = Job(
        job_id="p1:aws",
        threat_model_id="tm1",
        event_type="addon.invoked",
        enqueued_at=datetime.now(timezone.utc),
        siblings=["p1:aws", "p1:gcp"],
        deadline=deadline,
    )
    body = job.to_queue_message()
    assert body["siblings"] == ["p1:aws", "p1:gcp"]
    assert body["deadline"] == deadline.isoformat()
    back = Job.from_queue_message(body)
    assert back.siblings == ["p1:aws", "p1:gcp"]
    assert back.deadline == deadline


def test_old_message_without_siblings_or_deadline():
    body = {
        "job_id": "p1",
        "threat_model_id": "tm1",
        "event_type": "addon.invoked",
        "enqueued_at": datetime.now(timezone.utc).isoformat(),
    }
    job = Job.from_queue_message(body)
    assert job.siblings is None
    assert job.deadline is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_job.py -v`
Expected: FAIL with `TypeError: Job.__init__() got an unexpected keyword argument 'siblings'`

- [ ] **Step 3: Implement**

In `tmi_tf/job.py` add two fields after `repo_name`:

```python
    siblings: list[str] | None = None
    deadline: datetime | None = None
```

In `to_queue_message` add:

```python
            "siblings": self.siblings,
            "deadline": self.deadline.isoformat() if self.deadline else None,
```

In `from_queue_message` add:

```python
            siblings=data.get("siblings"),
            deadline=(
                datetime.fromisoformat(data["deadline"])
                if data.get("deadline")
                else None
            ),
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_job.py -v`
Expected: PASS

- [ ] **Step 5: Gates and commit**

```bash
uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright && uv run pytest tests/ -q
git add tmi_tf/job.py tests/test_job.py
git commit -m "feat: job carries sibling list and deadline (#55)"
```

---

### Task 2: TMI client metadata read/upsert

**Files:**
- Modify: `tmi_tf/tmi_client_wrapper.py` (next to `set_note_metadata`, ~line 861)
- Test: `tests/test_tmi_client_wrapper.py` (create if it does not exist; otherwise append)

**Interfaces:**
- Produces: `TMIClient.get_note_metadata(threat_model_id: str, note_id: str) -> dict[str, str]` and `TMIClient.upsert_note_metadata(threat_model_id: str, note_id: str, metadata: dict[str, str]) -> None`. Both go through `self._call_with_retry` and `self.sub_resources_api`.

- [ ] **Step 1: Write the failing tests**

```python
"""Tests for TMIClient note-metadata helpers."""

from unittest.mock import MagicMock

from tmi_tf.tmi_client_wrapper import TMIClient


def _client():
    client = TMIClient.__new__(TMIClient)
    client.sub_resources_api = MagicMock()
    client._call_with_retry = lambda fn: fn()
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_tmi_client_wrapper.py -v`
Expected: FAIL with `AttributeError: 'TMIClient' object has no attribute 'get_note_metadata'`

- [ ] **Step 3: Implement**

Add to `TMIClient` after `set_note_metadata`:

```python
    def get_note_metadata(self, threat_model_id: str, note_id: str) -> dict[str, str]:
        """Return a note's metadata as a key -> value dict."""
        items = self._call_with_retry(
            lambda: self.sub_resources_api.get_note_metadata(
                threat_model_id=threat_model_id, note_id=note_id
            )
        )
        return {m.key: m.value for m in items}

    def upsert_note_metadata(
        self, threat_model_id: str, note_id: str, metadata: dict[str, str]
    ) -> None:
        """Create or update the given metadata keys on a note (merge)."""
        objects = [Metadata(key=k, value=v) for k, v in metadata.items()]
        self._call_with_retry(
            lambda: self.sub_resources_api.bulk_upsert_note_metadata(
                threat_model_id=threat_model_id, note_id=note_id, metadata=objects
            )
        )
```

`Metadata` is already imported in this module (used by `set_note_metadata`).

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_tmi_client_wrapper.py -v`
Expected: PASS

- [ ] **Step 5: Gates and commit**

```bash
uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright && uv run pytest tests/ -q
git add tmi_tf/tmi_client_wrapper.py tests/test_tmi_client_wrapper.py
git commit -m "feat: TMIClient note metadata get/upsert"
```

---

### Task 3: `invocation.py` state module

**Files:**
- Create: `tmi_tf/invocation.py`
- Modify: `tmi_tf/config.py:100` (add `dedup_debounce_seconds`)
- Test: `tests/test_invocation.py`

**Interfaces:**
- Consumes: `TMIClient.find_note_by_name`, `update_status_note`, `get_note_metadata`, `upsert_note_metadata` (Task 2), `STATUS_NOTE_NAME`.
- Produces:

```python
@dataclass
class InvocationState:
    invocation_id: str | None
    open: bool
    deadline: datetime | None
    children: dict[str, str]          # job_id -> "success" | "failed" | "aborted"

def child_key(job_id: str) -> str                     # "tf_child:" + sanitized id
def compute_deadline(now: datetime, n_children: int, max_concurrent: int, job_timeout: int) -> datetime
def open_invocation(tmi: TMIClient, threat_model_id: str, invocation_id: str, siblings: list[str], deadline: datetime) -> None
def read_state(tmi: TMIClient, threat_model_id: str) -> InvocationState
def mark_child(tmi: TMIClient, threat_model_id: str, job_id: str, outcome: str) -> InvocationState   # returns state AFTER the mark
def all_reported(state: InvocationState, siblings: list[str]) -> bool
def close_invocation(tmi: TMIClient, threat_model_id: str, summary: str) -> None
def is_open(state: InvocationState, now: datetime) -> bool   # open and deadline in the future
class Debouncer:
    def __init__(self, window_seconds: float) -> None
    def accept(self, key: str, now: float | None = None) -> bool   # True = first in window
```

Locks: `lock_for(threat_model_id) -> asyncio.Lock` (module-level dict). Callers hold it around `mark_child` + `close_invocation`.

- [ ] **Step 1: Write the failing tests**

```python
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
        self.note = MagicMock(id="note-1", name=STATUS_NOTE_NAME)

    def find_note_by_name(self, tm, name):
        return self.note if name == STATUS_NOTE_NAME else None

    def update_status_note(self, tm, message):
        self.lines.append(message)

    def get_note_metadata(self, tm, note_id):
        assert note_id == "note-1"
        return dict(self.metadata)

    def upsert_note_metadata(self, tm, note_id, metadata):
        assert note_id == "note-1"
        self.metadata.update(metadata)


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


def test_mark_child_and_all_reported():
    tmi = FakeTMI()
    inv.open_invocation(tmi, "tm1", "inv1", ["a", "b"], NOW)
    state = inv.mark_child(tmi, "tm1", "a", "success")
    assert state.children == {"a": "success"}
    assert inv.all_reported(state, ["a", "b"]) is False
    state = inv.mark_child(tmi, "tm1", "b", "failed")
    assert inv.all_reported(state, ["a", "b"]) is True


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_invocation.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'tmi_tf.invocation'`

- [ ] **Step 3: Implement `tmi_tf/invocation.py`**

```python
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

from tmi_tf.tmi_client_wrapper import STATUS_NOTE_NAME, TMIClient

logger = logging.getLogger(__name__)

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


def _note_id(tmi: TMIClient, threat_model_id: str) -> str | None:
    note = tmi.find_note_by_name(threat_model_id, STATUS_NOTE_NAME)
    return note.id if note else None


def open_invocation(
    tmi: TMIClient,
    threat_model_id: str,
    invocation_id: str,
    siblings: list[str],
    deadline: datetime,
) -> None:
    tmi.update_status_note(
        threat_model_id,
        f"Invocation {invocation_id} opened: {len(siblings)} environment jobs, "
        f"deadline {deadline.isoformat()}",
    )
    note_id = _note_id(tmi, threat_model_id)
    if note_id is None:
        raise RuntimeError("status note missing after update_status_note")
    # Old child marks would make a fresh invocation look complete; blank them
    # (the metadata API has no delete-by-prefix, upsert to "-" instead).
    stale = {
        k: "-"
        for k in tmi.get_note_metadata(threat_model_id, note_id)
        if k.startswith(CHILD_PREFIX)
    }
    tmi.upsert_note_metadata(
        threat_model_id,
        note_id,
        {
            **stale,
            KEY_INVOCATION: invocation_id,
            KEY_OPEN: "true",
            KEY_DEADLINE: deadline.isoformat(),
        },
    )


def read_state(tmi: TMIClient, threat_model_id: str) -> InvocationState:
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
    tmi: TMIClient, threat_model_id: str, job_id: str, outcome: str
) -> InvocationState:
    assert outcome in OUTCOMES, outcome
    note_id = _note_id(tmi, threat_model_id)
    if note_id is None:
        logger.warning("No status note for %s; cannot mark %s", threat_model_id, job_id)
        return InvocationState(None, False, None)
    tmi.upsert_note_metadata(threat_model_id, note_id, {child_key(job_id): outcome})
    return read_state(tmi, threat_model_id)


def all_reported(state: InvocationState, siblings: list[str]) -> bool:
    marked = {child_key(j) for j in state.children}
    return all(child_key(s) in marked for s in siblings)


def close_invocation(tmi: TMIClient, threat_model_id: str, summary: str) -> None:
    note_id = _note_id(tmi, threat_model_id)
    if note_id is not None:
        tmi.upsert_note_metadata(threat_model_id, note_id, {KEY_OPEN: "false"})
    tmi.update_status_note(threat_model_id, summary)


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
```

Note on `read_state.children`: keys are stored sanitized, so `children` is keyed by the sanitized suffix; `all_reported` compares sanitized forms on both sides. The test `test_mark_child_and_all_reported` uses ids without special characters, so `state.children == {"a": "success"}` holds.

In `tmi_tf/config.py` after `self.job_timeout` add:

```python
        self.dedup_debounce_seconds: float = float(
            os.getenv("DEDUP_DEBOUNCE_SECONDS", "30")
        )
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_invocation.py -v`
Expected: PASS

- [ ] **Step 5: Gates and commit**

```bash
uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright && uv run pytest tests/ -q
git add tmi_tf/invocation.py tmi_tf/config.py tests/test_invocation.py
git commit -m "feat: invocation record as status-note metadata (#55, #52)"
```

---

### Task 4: Parent job opens the invocation

**Files:**
- Modify: `tmi_tf/worker.py:163-208` (`_run_parent`)
- Test: `tests/test_worker.py` (`TestFanout`)

**Interfaces:**
- Consumes: `compute_deadline`, `open_invocation`, `mark_child` from `tmi_tf.invocation`; `Job.siblings`, `Job.deadline`.
- Produces: children carry `callback_url=job.callback_url`, `siblings`, `deadline`; parent callback is `in_progress` "enqueued N of M environment jobs"; zero targets -> `completed` "no environments matched" and no invocation; a child that fails to publish is marked `failed`. `WorkerPool._arm_watchdog(...)` is added in Task 6; here call nothing else.

- [ ] **Step 1: Update and add tests**

In `tests/test_worker.py::TestFanout::test_parent_enqueues_children_and_completes` change:

```python
        assert all(b["callback_url"] is None for b in bodies)
```
to
```python
        assert all(b["callback_url"] == "https://cb" for b in bodies)
        assert all(sorted(b["siblings"]) == ["p1:aws-public", "p1:gcp-public"] for b in bodies)
        assert all(b["deadline"] for b in bodies)
```
and
```python
        cb_cls.return_value.send_status.assert_any_call(
            "completed", "enqueued 2 of 2 environment jobs"
        )
```
to
```python
        cb_cls.return_value.send_status.assert_any_call(
            "in_progress", "enqueued 2 of 2 environment jobs"
        )
```

Also wrap the `with` block's patches so `open_invocation` and `mark_child` are mocked; add to each `with (...)` in `TestFanout`:

```python
            patch("tmi_tf.worker.open_invocation") as open_inv,
            patch("tmi_tf.worker.mark_child") as mark,
```

Add assertions:

- `test_parent_enqueues_children_and_completes`: `open_inv.assert_called_once()`; `args = open_inv.call_args.args; assert args[1:4] == ("tm1", "p1", ["p1:aws-public", "p1:gcp-public"]) or sorted(args[3]) == [...]` (order follows `targets`; assert `sorted(args[3])`).
- `test_parent_publish_failure_continues_and_completes`: the failing child is marked: `mark.assert_any_call(ANY, "tm1", "p1:aws-public", "failed")` (adjust the env name to whichever target the test makes fail) and the callback is `in_progress`, "enqueued 1 of 2 environment jobs".
- `test_parent_with_no_targets_completes_without_enqueue`: `open_inv.assert_not_called()` and callback `completed`, "no environments matched".

Import `ANY` from `unittest.mock`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_worker.py -k TestFanout -v`
Expected: FAIL (`AttributeError: module tmi_tf.worker has no attribute open_invocation`)

- [ ] **Step 3: Implement**

In `tmi_tf/worker.py` add imports:

```python
import math  # noqa: F401  (remove if unused after implementation)
from tmi_tf.invocation import (
    all_reported,
    close_invocation,
    compute_deadline,
    is_open,
    lock_for,
    mark_child,
    open_invocation,
    read_state,
)
```

(Remove the `math` line; `compute_deadline` does the rounding. `all_reported`, `close_invocation`, `is_open`, `lock_for`, `read_state` are used by Tasks 5-6; ruff will flag unused imports until then, so add them in the task that uses them.)

Replace `_run_parent` body from `enqueued = 0` to the end with:

```python
        if not targets:
            logger.info("Parent job %s: no environments matched", job.job_id)
            if callback:
                callback.send_status("completed", "no environments matched")
            return
        now = datetime.now(timezone.utc)
        deadline = compute_deadline(
            now, len(targets), self.max_concurrent, self.config.job_timeout
        )
        children = [
            Job(
                job_id=f"{job.job_id}:{t.environment or 'all'}",
                threat_model_id=job.threat_model_id,
                event_type=job.event_type,
                enqueued_at=now,
                repo_id=t.repo_id,
                callback_url=job.callback_url,
                invocation_id=job.invocation_id,
                environment=t.environment,
                repo_name=repository_name(t.repo_url),
                deadline=deadline,
            )
            for t in targets
        ]
        siblings = [c.job_id for c in children]
        for c in children:
            c.siblings = siblings
        await asyncio.to_thread(
            open_invocation, tmi_client, job.threat_model_id, job.job_id, siblings, deadline
        )
        enqueued = 0
        for child in children:
            try:
                await asyncio.to_thread(
                    self.queue_client.publish, child.to_queue_message()
                )
                enqueued += 1
            except Exception as e:
                msg = f"Failed to enqueue environment {child.environment!r}: {e}"
                logger.error(msg)
                try:
                    tmi_client.update_status_note(job.threat_model_id, msg)
                    mark_child(tmi_client, job.threat_model_id, child.job_id, "failed")
                except Exception as note_err:
                    logger.error(f"Failed to record enqueue failure: {note_err}")
        summary = f"enqueued {enqueued} of {len(targets)} environment jobs"
        logger.info("Parent job %s: %s", job.job_id, summary)
        if callback:
            callback.send_status("in_progress", summary)
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_worker.py -v`
Expected: PASS

- [ ] **Step 5: Gates and commit**

```bash
uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright && uv run pytest tests/ -q
git add tmi_tf/worker.py tests/test_worker.py
git commit -m "feat: parent job opens the invocation record (#55)"
```

---

### Task 5: Children mark themselves; last one closes

**Files:**
- Modify: `tmi_tf/worker.py` (`_run_job`, `_handle_message` timeout path)
- Test: `tests/test_worker.py` (new class `TestCompletion`)

**Interfaces:**
- Consumes: `mark_child`, `all_reported`, `close_invocation`, `lock_for`, `read_state`.
- Produces: `WorkerPool._finish_child(job: Job, outcome: str) -> None` (async): marks the child under the threat model lock; if every sibling reported and the invocation is still open, closes it, writes the summary, sends the callback. Idempotent: a mark after close never sends a second callback. Child jobs no longer send their own `completed`/`failed` callbacks.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_worker.py`:

```python
from unittest.mock import ANY

from tmi_tf import invocation as inv
from tmi_tf.invocation import InvocationState


def _child(job_id, siblings, **kw):
    return _job(
        job_id=job_id,
        environment=job_id.split(":")[1],
        siblings=siblings,
        deadline=datetime.now(timezone.utc) + timedelta(hours=1),
        **kw,
    )


class TestCompletion:
    def _run_child(self, pool, job, result_success=True, raise_exc=None):
        tmi = MagicMock()
        result = AnalysisResult(success=result_success, errors=["boom"] if not result_success else [])
        with (
            patch("tmi_tf.worker.TMIClient.create_authenticated", return_value=tmi),
            patch("tmi_tf.worker.run_analysis", return_value=result, side_effect=raise_exc),
            patch("tmi_tf.worker.AddonCallback") as cb_cls,
        ):
            asyncio.run(pool._run_job(job, receipt="rc"))
        return cb_cls.return_value

    def test_all_children_succeed_sends_completed_once(self):
        pool, queue = _pool()
        sibs = ["p1:aws", "p1:gcp"]
        states = iter([
            InvocationState("p1", True, None, {"p1:aws": "success"}),
            InvocationState("p1", True, None, {"p1:aws": "success", "p1:gcp": "success"}),
        ])
        with (
            patch("tmi_tf.worker.mark_child", side_effect=lambda *a: next(states)) as mark,
            patch("tmi_tf.worker.close_invocation") as close,
        ):
            cb1 = self._run_child(pool, _child("p1:aws", sibs))
            cb2 = self._run_child(pool, _child("p1:gcp", sibs))
        mark.assert_any_call(ANY, "tm1", "p1:aws", "success")
        mark.assert_any_call(ANY, "tm1", "p1:gcp", "success")
        close.assert_called_once_with(
            ANY, "tm1", "Invocation complete: 2 succeeded, 0 failed"
        )
        cb1.send_status.assert_not_called()  # first child: not complete yet
        cb2.send_status.assert_called_once_with("completed", "2 succeeded, 0 failed")

    def test_one_child_fails_sends_failed_with_environment(self):
        pool, queue = _pool()
        sibs = ["p1:aws", "p1:gcp"]
        states = iter([
            InvocationState("p1", True, None, {"p1:aws": "failed"}),
            InvocationState("p1", True, None, {"p1:aws": "failed", "p1:gcp": "success"}),
        ])
        with (
            patch("tmi_tf.worker.mark_child", side_effect=lambda *a: next(states)),
            patch("tmi_tf.worker.close_invocation") as close,
        ):
            self._run_child(pool, _child("p1:aws", sibs), result_success=False)
            cb = self._run_child(pool, _child("p1:gcp", sibs))
        close.assert_called_once_with(
            ANY, "tm1", "Invocation complete: 1 succeeded, 1 failed (p1:aws)"
        )
        cb.send_status.assert_called_once_with("failed", "1 succeeded, 1 failed (p1:aws)")

    def test_late_mark_after_close_sends_nothing(self):
        pool, queue = _pool()
        sibs = ["p1:aws"]
        closed = InvocationState("p1", False, None, {"p1:aws": "success"})
        with (
            patch("tmi_tf.worker.mark_child", return_value=closed),
            patch("tmi_tf.worker.close_invocation") as close,
        ):
            cb = self._run_child(pool, _child("p1:aws", sibs))
        close.assert_not_called()
        cb.send_status.assert_not_called()

    def test_exception_marks_failed_and_keeps_message(self):
        pool, queue = _pool()
        queue.delete = MagicMock()
        state = InvocationState("p1", True, None, {"p1:aws": "failed"})
        with (
            patch("tmi_tf.worker.mark_child", return_value=state) as mark,
            patch("tmi_tf.worker.close_invocation"),
        ):
            self._run_child(pool, _child("p1:aws", ["p1:aws", "p1:gcp"]), raise_exc=RuntimeError("x"))
        mark.assert_called_once_with(ANY, "tm1", "p1:aws", "failed")
        queue.delete.assert_not_called()

    def test_timeout_marks_failed(self):
        pool, queue = _pool()
        pool.config.job_timeout = 0.01
        job = _child("p1:aws", ["p1:aws"])

        async def slow(*a, **k):
            await asyncio.sleep(1)

        with (
            patch.object(pool, "_run_job", side_effect=slow),
            patch("tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()),
            patch("tmi_tf.worker.mark_child", return_value=InvocationState("p1", True, None, {"p1:aws": "failed"})) as mark,
            patch("tmi_tf.worker.close_invocation") as close,
            patch("tmi_tf.worker.AddonCallback"),
        ):
            queue.publish(job.to_queue_message())
            msg = queue.consume(max_messages=1)[0]
            asyncio.run(pool._handle_message(msg))
        mark.assert_called_once_with(ANY, "tm1", "p1:aws", "failed")
        close.assert_called_once()
```

Note: `_job` must accept `siblings`/`deadline` (it forwards `**kw` to `Job`, so no change). Import `timedelta` is already present.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_worker.py -k TestCompletion -v`
Expected: FAIL (callbacks still sent per child; `mark_child` never called)

- [ ] **Step 3: Implement**

In `tmi_tf/worker.py`:

Replace the child branch of `_run_job` (`if result.success: ... else: ...`) with:

```python
                await self._finish_child(job, "success" if result.success else "failed")
```

In the `except Exception` of `_run_job`, after the log line, add (keep the existing `callback.send_status("failed", str(e))` only for parent jobs):

```python
            if job.is_child:
                await self._finish_child(job, "failed")
            elif callback:
                callback.send_status("failed", str(e))
```

In `_handle_message`'s `except asyncio.TimeoutError`, replace `await self._fire_and_forget_status(job, "failed", "Job timed out")` with:

```python
                if job.is_child:
                    await self._finish_child(job, "failed")
                else:
                    await self._fire_and_forget_status(job, "failed", "Job timed out")
```

Add the method:

```python
    async def _finish_child(self, job: Job, outcome: str) -> None:
        """Mark a child done; the last sibling closes the invocation."""
        siblings = job.siblings or [job.job_id]
        try:
            tmi_client = TMIClient.create_authenticated(self.config)
            async with lock_for(job.threat_model_id):
                state = await asyncio.to_thread(
                    mark_child, tmi_client, job.threat_model_id, job.job_id, outcome
                )
                if not state.open or not all_reported(state, siblings):
                    return
                failed = sorted(
                    j for j in siblings if state.children.get(j) != "success"
                )
                ok = len(siblings) - len(failed)
                summary = f"{ok} succeeded, {len(failed)} failed"
                if failed:
                    summary += f" ({', '.join(failed)})"
                await asyncio.to_thread(
                    close_invocation,
                    tmi_client,
                    job.threat_model_id,
                    f"Invocation complete: {summary}",
                )
            wd = self._watchdogs.pop(job.threat_model_id, None)
            if wd:
                wd.cancel()
            if job.callback_url and self.config.webhook_secret:
                cb = AddonCallback(job.callback_url, self.config.webhook_secret)
                await asyncio.to_thread(
                    cb.send_status, "completed" if not failed else "failed", summary
                )
        except Exception as e:
            logger.error(f"Completion bookkeeping failed for {job.job_id}: {e}")
```

Add `self._watchdogs: dict[str, asyncio.Task] = {}  # type: ignore[type-arg]` to `__init__` (Task 6 fills it; here the `pop` finds nothing).

`state.children` is keyed by sanitized ids (Task 3); `siblings` here are raw. Compare with `child_key`: import it and use `state.children.get(child_key(j)[len("tf_child:"):])`. Simpler: add to `invocation.py` a helper `outcome_of(state, job_id) -> str | None` returning `state.children.get(child_key(job_id)[len(CHILD_PREFIX):])`, test it in `tests/test_invocation.py` (`assert inv.outcome_of(state, "p1:env (x)") == "success"` after marking), and use it here: `state.children.get(j)` -> `outcome_of(state, j)`.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_worker.py tests/test_invocation.py -v`
Expected: PASS. Also fix `test_child_runs_analysis_with_environment_and_note_name` / `test_child_whole_repo_note_named_after_repo` if they asserted a per-child callback (they should now patch `mark_child`).

- [ ] **Step 5: Gates and commit**

```bash
uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright && uv run pytest tests/ -q
git add tmi_tf/worker.py tmi_tf/invocation.py tests/test_worker.py tests/test_invocation.py
git commit -m "feat: last child closes the invocation and sends the callback (#55)"
```

---

### Task 6: Deadline watchdog

**Files:**
- Modify: `tmi_tf/worker.py` (`_run_parent`, `_handle_message`, new `_arm_watchdog`, `_watchdog`)
- Test: `tests/test_worker.py` (`TestWatchdog`)

**Interfaces:**
- Consumes: `read_state`, `close_invocation`, `mark_child`, `lock_for`.
- Produces: `WorkerPool._arm_watchdog(threat_model_id: str, invocation_id: str, siblings: list[str], deadline: datetime, callback_url: str | None) -> None`. One task per threat model in `self._watchdogs`; re-arming replaces nothing if a task is already running for the same invocation. At the deadline: unreported siblings are marked `failed`, the invocation is closed with "Invocation timed out: N succeeded, M failed (...)", callback `failed`.

- [ ] **Step 1: Write the failing tests**

```python
class TestWatchdog:
    def test_watchdog_marks_missing_children_failed_and_closes(self):
        pool, _ = _pool()
        state = InvocationState("p1", True, None, {"p1:aws": "success"})
        after = InvocationState("p1", True, None, {"p1:aws": "success", "p1:gcp": "failed"})
        with (
            patch("tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()),
            patch("tmi_tf.worker.read_state", return_value=state),
            patch("tmi_tf.worker.mark_child", return_value=after) as mark,
            patch("tmi_tf.worker.close_invocation") as close,
            patch("tmi_tf.worker.AddonCallback") as cb_cls,
        ):
            async def go():
                pool._arm_watchdog(
                    "tm1", "p1", ["p1:aws", "p1:gcp"],
                    datetime.now(timezone.utc) + timedelta(milliseconds=20),
                    "https://cb",
                )
                await asyncio.sleep(0.2)
            asyncio.run(go())
        mark.assert_called_once_with(ANY, "tm1", "p1:gcp", "failed")
        close.assert_called_once_with(
            ANY, "tm1", "Invocation timed out: 1 succeeded, 1 failed (p1:gcp)"
        )
        cb_cls.return_value.send_status.assert_called_once_with(
            "failed", "1 succeeded, 1 failed (p1:gcp)"
        )

    def test_watchdog_does_nothing_if_already_closed(self):
        pool, _ = _pool()
        closed = InvocationState("p1", False, None, {"p1:aws": "success"})
        with (
            patch("tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()),
            patch("tmi_tf.worker.read_state", return_value=closed),
            patch("tmi_tf.worker.close_invocation") as close,
        ):
            async def go():
                pool._arm_watchdog("tm1", "p1", ["p1:aws"], datetime.now(timezone.utc), None)
                await asyncio.sleep(0.05)
            asyncio.run(go())
        close.assert_not_called()

    def test_child_dequeue_rearms_watchdog(self):
        pool, queue = _pool()
        job = _child("p1:aws", ["p1:aws"])
        with (
            patch.object(pool, "_run_job", return_value=None),
            patch.object(pool, "_arm_watchdog") as arm,
        ):
            queue.publish(job.to_queue_message())
            msg = queue.consume(max_messages=1)[0]
            asyncio.run(pool._handle_message(msg))
        arm.assert_called_once_with("tm1", "p1", ["p1:aws"], job.deadline, "https://cb")

    def test_parent_arms_watchdog(self):
        pool, queue = _pool()
        with (
            patch("tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()),
            patch("tmi_tf.worker.resolve_fanout_targets", return_value=[FanoutTarget("r1", "u", "aws")]),
            patch("tmi_tf.worker.open_invocation"),
            patch("tmi_tf.worker.AddonCallback"),
            patch.object(pool, "_arm_watchdog") as arm,
        ):
            asyncio.run(pool._run_job(_job(scope="all"), receipt="rc"))
        arm.assert_called_once()
        assert arm.call_args.args[:3] == ("tm1", "p1", ["p1:aws"])
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_worker.py -k TestWatchdog -v`
Expected: FAIL (`AttributeError: 'WorkerPool' object has no attribute '_arm_watchdog'`)

- [ ] **Step 3: Implement**

In `worker.py`:

```python
    def _arm_watchdog(
        self,
        threat_model_id: str,
        invocation_id: str,
        siblings: list[str],
        deadline: datetime,
        callback_url: str | None,
    ) -> None:
        """Ensure one watchdog task per open invocation; survives restarts because
        every child message carries siblings + deadline."""
        existing = self._watchdogs.get(threat_model_id)
        if existing and not existing.done():
            return
        self._watchdogs[threat_model_id] = asyncio.create_task(
            self._watchdog(threat_model_id, invocation_id, siblings, deadline, callback_url)
        )

    async def _watchdog(
        self,
        threat_model_id: str,
        invocation_id: str,
        siblings: list[str],
        deadline: datetime,
        callback_url: str | None,
    ) -> None:
        delay = (deadline - datetime.now(timezone.utc)).total_seconds()
        if delay > 0:
            await asyncio.sleep(delay)
        try:
            tmi_client = TMIClient.create_authenticated(self.config)
            async with lock_for(threat_model_id):
                state = await asyncio.to_thread(read_state, tmi_client, threat_model_id)
                if not state.open or state.invocation_id != invocation_id:
                    return
                for j in siblings:
                    if outcome_of(state, j) is None:
                        state = await asyncio.to_thread(
                            mark_child, tmi_client, threat_model_id, j, "failed"
                        )
                failed = sorted(j for j in siblings if outcome_of(state, j) != "success")
                summary = f"{len(siblings) - len(failed)} succeeded, {len(failed)} failed"
                if failed:
                    summary += f" ({', '.join(failed)})"
                await asyncio.to_thread(
                    close_invocation, tmi_client, threat_model_id,
                    f"Invocation timed out: {summary}",
                )
            if callback_url and self.config.webhook_secret:
                cb = AddonCallback(callback_url, self.config.webhook_secret)
                await asyncio.to_thread(cb.send_status, "failed", summary)
        except Exception as e:
            logger.error(f"Watchdog failed for {threat_model_id}: {e}")
```

Wire it:

- End of `_run_parent` (after `open_invocation`, before publishing): `self._arm_watchdog(job.threat_model_id, job.job_id, siblings, deadline, job.callback_url)`.
- In `_handle_message` after `job = Job.from_queue_message(msg.body)`:

```python
        if job.is_child and job.siblings and job.deadline:
            self._arm_watchdog(
                job.threat_model_id,
                job.job_id.rsplit(":", 1)[0],
                job.siblings,
                job.deadline,
                job.callback_url,
            )
```

(The invocation id is the parent job id = child id minus its `:<env>` suffix.)

Import `outcome_of` from `tmi_tf.invocation` (added in Task 5).

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_worker.py -v`
Expected: PASS

- [ ] **Step 5: Gates and commit**

```bash
uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright && uv run pytest tests/ -q
git add tmi_tf/worker.py tests/test_worker.py
git commit -m "feat: deadline watchdog closes invocations whose children never report (#55)"
```

---

### Task 7: Webhook dedup (#52)

**Files:**
- Modify: `tmi_tf/server.py:173-196` (between the trigger-event check and `Job(...)`)
- Test: `tests/test_server.py`

**Interfaces:**
- Consumes: `Debouncer`, `read_state`, `is_open` from `tmi_tf.invocation`; `TMIClient.create_authenticated`; `AddonCallback`.
- Produces: module-level `debouncer: Debouncer` created in `lifespan` from `config.dedup_debounce_seconds` (default `Debouncer(30)` at import so tests without lifespan work); response `{"status": "deduplicated", "job_id": ...}`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_server.py`, using the existing `client` fixture and `_make_sig`:

```python
def _post(client, invocation_id="inv-001", event="addon.invoked", callback=True):
    payload = {
        "type": event,
        "threat_model_id": "tm-001",
        "invocation_id": invocation_id,
    }
    if callback:
        payload["callback_url"] = "https://api.tmi.dev/cb"
    body = json.dumps(payload).encode()
    return client.post(
        "/webhook",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Webhook-Signature": _make_sig(body, "test-secret"),
            "X-Webhook-Event": event,
            "X-Invocation-Id": invocation_id,
            "X-Webhook-Delivery-Id": "del-" + invocation_id,
        },
    )


class TestDedup:
    def test_second_trigger_in_debounce_window_is_dropped(self, client):
        from tmi_tf.invocation import Debouncer, InvocationState
        server_module.debouncer = Debouncer(30)
        with patch("tmi_tf.server.read_state", return_value=InvocationState(None, False, None)), \
             patch("tmi_tf.server.TMIClient"):
            assert _post(client, "a").json()["status"] == "accepted"
            r = _post(client, "b")
        assert r.status_code == 200
        assert r.json()["status"] == "deduplicated"
        assert server_module.queue_client.publish.call_count == 1

    def test_open_invocation_drops_and_calls_back(self, client):
        from datetime import datetime, timedelta, timezone
        from tmi_tf.invocation import Debouncer, InvocationState
        server_module.debouncer = Debouncer(0)
        state = InvocationState("x", True, datetime.now(timezone.utc) + timedelta(hours=1), {})
        tmi = MagicMock()
        with patch("tmi_tf.server.read_state", return_value=state), \
             patch("tmi_tf.server.TMIClient.create_authenticated", return_value=tmi), \
             patch("tmi_tf.server.AddonCallback") as cb_cls:
            r = _post(client, "c")
        assert r.json()["status"] == "deduplicated"
        server_module.queue_client.publish.assert_not_called()
        tmi.update_status_note.assert_called_once()
        assert "already running" in tmi.update_status_note.call_args.args[1]
        cb_cls.return_value.send_status.assert_called_once_with("failed", "analysis already running")

    def test_open_but_past_deadline_is_accepted(self, client):
        from datetime import datetime, timedelta, timezone
        from tmi_tf.invocation import Debouncer, InvocationState
        server_module.debouncer = Debouncer(0)
        state = InvocationState("x", True, datetime.now(timezone.utc) - timedelta(seconds=1), {})
        with patch("tmi_tf.server.read_state", return_value=state), \
             patch("tmi_tf.server.TMIClient"):
            assert _post(client, "d").json()["status"] == "accepted"

    def test_tmi_lookup_failure_accepts(self, client):
        from tmi_tf.invocation import Debouncer
        server_module.debouncer = Debouncer(0)
        with patch("tmi_tf.server.read_state", side_effect=RuntimeError("tmi down")), \
             patch("tmi_tf.server.TMIClient"):
            assert _post(client, "e").json()["status"] == "accepted"

    def test_threat_model_updated_drop_has_no_callback(self, client):
        from datetime import datetime, timedelta, timezone
        from tmi_tf.invocation import Debouncer, InvocationState
        server_module.debouncer = Debouncer(0)
        state = InvocationState("x", True, datetime.now(timezone.utc) + timedelta(hours=1), {})
        with patch("tmi_tf.server.read_state", return_value=state), \
             patch("tmi_tf.server.TMIClient.create_authenticated", return_value=MagicMock()), \
             patch("tmi_tf.server.AddonCallback") as cb_cls:
            r = _post(client, "f", event="threat_model.updated", callback=False)
        assert r.json()["status"] == "deduplicated"
        cb_cls.assert_not_called()
```

Existing tests that post twice for `tm-001` inside one test (if any) must set `server_module.debouncer = Debouncer(0)` first; also set it in the `client` fixture teardown to `Debouncer(0)` to keep tests independent, and patch `tmi_tf.server.read_state` in the fixture to return a closed state by default:

```python
    with patch("tmi_tf.server.get_config", return_value=mock_config), \
         patch("tmi_tf.server.read_state", return_value=InvocationState(None, False, None)), \
         patch("tmi_tf.server.TMIClient"):
        server_module.debouncer = Debouncer(0)
        yield TestClient(...)
```

(`TestDedup` tests re-patch inside; nested patches override.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_server.py -v`
Expected: FAIL (`AttributeError: module 'tmi_tf.server' has no attribute 'read_state'`)

- [ ] **Step 3: Implement**

In `server.py` add imports and a module global:

```python
from tmi_tf.addon_callback import AddonCallback
from tmi_tf.invocation import Debouncer, InvocationState, is_open, read_state
from tmi_tf.tmi_client_wrapper import TMIClient

debouncer: Debouncer = Debouncer(30)
```

In `lifespan`, after config is final: `global debouncer; debouncer = Debouncer(config.dedup_debounce_seconds)`.

Add a helper above the `webhook` route:

```python
async def _is_duplicate(threat_model_id: str) -> bool:
    """Drop triggers while an invocation is open (fails open on TMI errors)."""
    if not debouncer.accept(threat_model_id):
        return True
    try:
        tmi = TMIClient.create_authenticated(get_config())
        state: InvocationState = await asyncio.to_thread(read_state, tmi, threat_model_id)
    except Exception as e:
        logger.warning("Dedup lookup failed for %s; accepting: %s", threat_model_id, e)
        return False
    return is_open(state, datetime.now(timezone.utc))


async def _report_duplicate(parsed: dict, event_type: str, job_id: str) -> None:
    config = get_config()
    tm = parsed["threat_model_id"]
    logger.info("Duplicate trigger %s for %s dropped (job_id=%s)", event_type, tm, job_id)
    try:
        tmi = TMIClient.create_authenticated(config)
        await asyncio.to_thread(
            tmi.update_status_note, tm,
            f"Trigger {event_type} ignored: analysis already running",
        )
    except Exception as e:
        logger.warning("Could not record duplicate on status note: %s", e)
    if event_type == "addon.invoked" and parsed.get("callback_url") and config.webhook_secret:
        cb = AddonCallback(parsed["callback_url"], config.webhook_secret)
        await asyncio.to_thread(cb.send_status, "failed", "analysis already running")
```

In `webhook`, right after the `is_trigger_event` block:

```python
    if await _is_duplicate(parsed["threat_model_id"]):
        await _report_duplicate(parsed, event_type, job_id)
        return JSONResponse(content={"status": "deduplicated", "job_id": job_id})
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_server.py -v`
Expected: PASS

- [ ] **Step 5: Gates and commit**

```bash
uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright && uv run pytest tests/ -q
git add tmi_tf/server.py tests/test_server.py
git commit -m "feat: drop duplicate triggers while an invocation is open (#52)"
```

---

### Task 8: Docs and PR 1

**Files:**
- Modify: `README.md` (server/operations section; find it with `rg -n 'MAX_CONCURRENT_JOBS|JOB_TIMEOUT' README.md`)
- Modify: `infra/aws/k8s.tf` env block (~line 120) and the OCI equivalent (`rg -n MAX_CONCURRENT_JOBS infra/`): add `DEDUP_DEBOUNCE_SECONDS` with value `"30"` next to `MAX_CONCURRENT_JOBS` in both.

- [ ] **Step 1: Document**

Add to the README env-var table:

```
| `DEDUP_DEBOUNCE_SECONDS` | `30` | Triggers for the same threat model within this window are dropped (`0` disables). |
```

Add a subsection "Invocation tracking" (5-8 lines): parent status note metadata keys `tf_invocation`, `tf_open`, `tf_deadline`, `tf_child:<job_id>`; deadline formula; callback semantics (`in_progress` on enqueue, `completed`/`failed` from the last child or the watchdog); a duplicate trigger returns `{"status":"deduplicated"}` and, for `addon.invoked`, a `failed` callback "analysis already running"; a stuck `tf_open=true` past `tf_deadline` is ignored by dedup. Keep the existing purge + restart runbook and label it "last resort".

- [ ] **Step 2: Terraform format check**

Run: `cd infra/aws && terraform fmt -check && terraform validate` (needs `AWS_PROFILE=tmi`; `validate` may need `terraform init -backend=false`). Same for `infra/oci`.

- [ ] **Step 3: Gates, commit, PR**

```bash
uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright && uv run pytest tests/ -q
git add README.md infra/aws/k8s.tf infra/oci/*.tf
git commit -m "docs: invocation tracking and dedup operator notes"
git push -u origin feat/invocation-tracking
gh pr create --title "feat: invocation tracking: completion callback (#55) and duplicate-trigger drop (#52)" --body "..."
```

PR body: link the spec, list the four behaviours (parent `in_progress`, last child closes, watchdog, dedup), note the single-replica constraint, `Closes #55`, `Closes #52`, and the attribution lines.

---

### Task 9: Abort signal in the analysis thread (PR 2)

Branch: `git switch -c feat/abort-job` from `feat/invocation-tracking` (or from `main` after PR 1 merges).

**Files:**
- Modify: `tmi_tf/tmi_client_wrapper.py` (`__init__` ~line 307, `update_status_note` ~line 564)
- Test: `tests/test_tmi_client_wrapper.py`

**Interfaces:**
- Produces: `class AnalysisAborted(BaseException)` in `tmi_tf/tmi_client_wrapper.py` (BaseException so the `except Exception` blocks in `analyzer.py` do not swallow it); `TMIClient.cancel_event: threading.Event | None = None`; `update_status_note` raises `AnalysisAborted` when the event is set, before any network call. Every phase boundary in `analyzer.py`/`llm_analyzer.py` calls `update_status_note`, so no LLM call starts after the event is set.

- [ ] **Step 1: Write the failing test**

```python
import threading

import pytest

from tmi_tf.tmi_client_wrapper import AnalysisAborted


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
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_tmi_client_wrapper.py -v`
Expected: FAIL (`ImportError: cannot import name 'AnalysisAborted'`)

- [ ] **Step 3: Implement**

In `tmi_client_wrapper.py`, near `STATUS_NOTE_NAME`:

```python
class AnalysisAborted(BaseException):
    """Raised from update_status_note when the job's cancel event is set.

    BaseException on purpose: analyzer.py catches Exception per repository
    and would otherwise carry on to the next LLM call.
    """
```

In `TMIClient.__init__` next to `_status_note_initialized`: `self.cancel_event: threading.Event | None = None` (add `import threading`).

At the top of `update_status_note`:

```python
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise AnalysisAborted(f"aborted before: {message}")
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/ -q`
Expected: PASS

- [ ] **Step 5: Gates and commit**

```bash
uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright && uv run pytest tests/ -q
git add tmi_tf/tmi_client_wrapper.py tests/test_tmi_client_wrapper.py
git commit -m "feat: cancel event stops the analysis at the next phase boundary (#54)"
```

---

### Task 10: `WorkerPool.abort`

**Files:**
- Modify: `tmi_tf/worker.py`
- Test: `tests/test_worker.py` (`TestAbort`)

**Interfaces:**
- Consumes: `AnalysisAborted`, `TMIClient.cancel_event`, `mark_child`, `close_invocation`, `lock_for`, `read_state`.
- Produces: `WorkerPool.abort(invocation_id: str, reason: str) -> int` (async; returns the number of running jobs cancelled). Internals: `self._cancelled: set[str]` of invocation ids; `self._tasks: dict[str, asyncio.Task]` job_id -> task; `self._cancel_events: dict[str, threading.Event]` job_id -> event; `self._receipts: dict[str, str]` job_id -> receipt. `Job.invocation_key` property = `job_id.rsplit(":", 1)[0]` for children, `job_id` for parents.

- [ ] **Step 1: Write the failing tests**

```python
import threading


class TestAbort:
    def test_abort_running_child(self):
        pool, queue = _pool()
        queue.delete = MagicMock()
        started = threading.Event()
        tmi = MagicMock()

        def fake_run_analysis(**kw):
            started.set()
            kw["tmi_client"].cancel_event.wait(5)
            raise AnalysisAborted("x")

        state_after = InvocationState("p1", True, None, {"p1:aws": "aborted"})
        with (
            patch("tmi_tf.worker.TMIClient.create_authenticated", return_value=tmi),
            patch("tmi_tf.worker.run_analysis", side_effect=fake_run_analysis),
            patch("tmi_tf.worker.mark_child", return_value=state_after) as mark,
            patch("tmi_tf.worker.close_invocation") as close,
            patch("tmi_tf.worker.AddonCallback") as cb_cls,
        ):
            job = _child("p1:aws", ["p1:aws"])

            async def go():
                queue.publish(job.to_queue_message())
                msg = queue.consume(max_messages=1)[0]
                t = asyncio.create_task(pool._handle_message(msg))
                await asyncio.to_thread(started.wait, 5)
                n = await pool.abort("p1", "operator")
                await asyncio.sleep(0.2)
                return n, t

            n, _ = asyncio.run(go())
        assert n == 1
        assert tmi.cancel_event.is_set()
        queue.delete.assert_called_once()
        mark.assert_any_call(ANY, "tm1", "p1:aws", "aborted")
        close.assert_called_once_with(ANY, "tm1", "Aborted: operator")
        cb_cls.return_value.send_status.assert_called_with("failed", "aborted: operator")
        assert not job.temp_dir or not job.temp_dir.exists()

    def test_queued_child_of_aborted_invocation_is_dropped(self):
        pool, queue = _pool()
        queue.delete = MagicMock(wraps=queue.delete)
        pool._cancelled.add("p1")
        state = InvocationState("p1", False, None, {"p1:aws": "aborted"})
        with (
            patch("tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()),
            patch("tmi_tf.worker.run_analysis") as run,
            patch("tmi_tf.worker.mark_child", return_value=state) as mark,
            patch("tmi_tf.worker.close_invocation"),
        ):
            job = _child("p1:aws", ["p1:aws", "p1:gcp"])
            queue.publish(job.to_queue_message())
            msg = queue.consume(max_messages=1)[0]
            asyncio.run(pool._handle_message(msg))
        run.assert_not_called()
        queue.delete.assert_called_once_with(msg.receipt)
        mark.assert_called_once_with(ANY, "tm1", "p1:aws", "aborted")

    def test_abort_unknown_invocation_returns_zero(self):
        pool, _ = _pool()
        with (
            patch("tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()),
            patch("tmi_tf.worker.read_state", return_value=InvocationState(None, False, None)),
            patch("tmi_tf.worker.close_invocation") as close,
        ):
            assert asyncio.run(pool.abort("nope", "r")) == 0
        close.assert_not_called()
```

Import `AnalysisAborted` from `tmi_tf.tmi_client_wrapper` in the test module.

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_worker.py -k TestAbort -v`
Expected: FAIL (`AttributeError: 'WorkerPool' object has no attribute '_cancelled'`)

- [ ] **Step 3: Implement**

`tmi_tf/job.py`:

```python
    @property
    def invocation_key(self) -> str:
        """Parent job id: children are "<parent>:<env>"."""
        return self.job_id.rsplit(":", 1)[0] if self.is_child else self.job_id
```

`tmi_tf/worker.py`:

`__init__` additions:

```python
        self._cancelled: set[str] = set()
        self._tasks: dict[str, asyncio.Task] = {}  # type: ignore[type-arg]
        self._cancel_events: dict[str, threading.Event] = {}
        self._receipts: dict[str, str] = {}
```

`_handle_message`, after the stale check and `Job.from_queue_message`:

```python
        if job.invocation_key in self._cancelled:
            logger.info("Dropping queued job %s: invocation aborted", job.job_id)
            await asyncio.to_thread(self.queue_client.delete, msg.receipt)
            if job.is_child:
                await self._finish_child(job, "aborted")
            return
```

Inside `async with self._semaphore:` after `self._active_jobs[job.job_id] = job`:

```python
            self._receipts[job.job_id] = msg.receipt
            self._cancel_events[job.job_id] = threading.Event()
            self._tasks[job.job_id] = asyncio.current_task()  # type: ignore[assignment]
```

and in the `finally`, pop all three. Add `except asyncio.CancelledError: logger.info("Job cancelled: %s", job.job_id)` between the timeout handler and `finally` (do not re-raise; the abort path did the bookkeeping).

In `_run_job`, after `tmi_client = TMIClient.create_authenticated(self.config)`: `tmi_client.cancel_event = self._cancel_events.get(job.job_id)`.

In `_run_job`'s `except Exception` keep as is; `AnalysisAborted` is a BaseException and propagates out of `asyncio.to_thread` into the task, which `abort()` has already cancelled; add `except AnalysisAborted: logger.info("Job %s aborted", job.job_id)` in `_run_job` before `except Exception` so nothing else runs.

The method:

```python
    async def abort(self, invocation_id: str, reason: str) -> int:
        """Stop every job of an invocation; queued children are dropped when dequeued."""
        self._cancelled.add(invocation_id)
        victims = [
            j for j in list(self._active_jobs.values())
            if j.invocation_key == invocation_id
        ]
        for job in victims:
            ev = self._cancel_events.get(job.job_id)
            if ev:
                ev.set()
            task = self._tasks.get(job.job_id)
            if task:
                task.cancel()
            receipt = self._receipts.get(job.job_id)
            if receipt:
                try:
                    await asyncio.to_thread(self.queue_client.delete, receipt)
                except Exception as e:
                    logger.error(f"Failed to delete message for {job.job_id}: {e}")
            if job.temp_dir and job.temp_dir.exists():
                shutil.rmtree(job.temp_dir, ignore_errors=True)
        wd = self._watchdogs.pop(next((j.threat_model_id for j in victims), ""), None)
        if wd:
            wd.cancel()
        threat_model_id = victims[0].threat_model_id if victims else None
        callback_url = next((j.callback_url for j in victims if j.callback_url), None)
        try:
            tmi_client = TMIClient.create_authenticated(self.config)
            if threat_model_id is None:
                return 0
            async with lock_for(threat_model_id):
                for job in victims:
                    if job.is_child:
                        await asyncio.to_thread(
                            mark_child, tmi_client, threat_model_id, job.job_id, "aborted"
                        )
                await asyncio.to_thread(
                    close_invocation, tmi_client, threat_model_id, f"Aborted: {reason}"
                )
            if callback_url and self.config.webhook_secret:
                cb = AddonCallback(callback_url, self.config.webhook_secret)
                await asyncio.to_thread(cb.send_status, "failed", f"aborted: {reason}")
        except Exception as e:
            logger.error(f"Abort bookkeeping failed for {invocation_id}: {e}")
        return len(victims)
```

`_finish_child` (Task 5) must not re-close an invocation that `abort` closed: it already returns when `state.open` is false. For a child dropped at dequeue with `outcome="aborted"`, `_finish_child` marks and returns because the invocation is closed. `test_abort_unknown_invocation_returns_zero` needs the early `return 0` before any TMI write when there are no victims; keep `read_state` unused there (the test patches it defensively).

Add `import threading` to `worker.py`.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/ -q`
Expected: PASS

- [ ] **Step 5: Gates, commit, PR**

```bash
uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright && uv run pytest tests/ -q
git add tmi_tf/worker.py tmi_tf/job.py tests/test_worker.py
git commit -m "feat: WorkerPool.abort cancels an invocation's jobs (#54, local mechanics)"
```

README: under "Invocation tracking" add "Abort: `WorkerPool.abort(invocation_id, reason)` exists but has no external trigger until TMI ships delivery cancel (tmi issue link); purge + restart remains the runbook." Commit as `docs: abort mechanics note`, push, open PR 2 titled "feat: abort mechanics for invocations (#54, part 1)" with `Refs #54` (not `Closes`).

---

## Not in this plan (PR 3, after TMI ships)

Polling `GET /webhook-deliveries/{id}` at phase boundaries and the `addon.invocation_cancelled` event handler that calls `abort()`. Needs the TMI endpoints from the spec; tracked on the tmi issue and #54.

---

## Self-review

- **Spec coverage:** §1 record → Tasks 1-4; §2 completion (parent `in_progress`, last child, watchdog, re-arm, late mark) → Tasks 4-6; §3 dedup (debounce, open check, stale deadline, fail-open, status line, callback only for addon.invoked) → Tasks 3, 7; §4 local abort (event, task cancel, cancelled set, message delete, temp dir, marks, callback) → Tasks 9-10; TMI side and polling → explicitly deferred. Testing list in spec → each bullet has a test above.
- **Placeholders:** the PR body in Task 8 says "..." with an explicit content list beside it; acceptable. No TBD/TODO.
- **Type consistency:** `mark_child(tmi, tm, job_id, outcome) -> InvocationState`; `close_invocation(tmi, tm, summary)`; `outcome_of(state, job_id)` added in Task 5 and used in Task 6; `_arm_watchdog(tm, invocation_id, siblings, deadline, callback_url)` consistent across Tasks 5-6; `Job.invocation_key` defined in Task 10 and used only there and later.
