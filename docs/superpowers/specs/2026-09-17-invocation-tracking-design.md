# Invocation tracking: dedup (#52), completion monitoring (#55), abort (#54)

Date: 2026-09-17. Status: approved by Eric 2026-09-17.

## Problem

Per-environment fan-out (#51) splits one trigger into a short parent job and N long child jobs. Nothing tracks the set:

- #52: two triggers for one threat model run two full analyses (edit + revert cost ~$10 on 2026-09-07).
- #55: the parent reports `completed` as soon as children are enqueued; nobody reports when the repository is actually done.
- #54: the only way to stop a job is `sqs purge-queue` + `rollout restart`, which kills everything.

All three need the same fact: which invocation is open for a threat model, and which children belong to it.

## Human-made decisions (Eric, 2026-09-17)

| Decision | Choice | Rejected |
| --- | --- | --- |
| Duplicate trigger while an invocation is open | **Drop it** (200 `deduplicated`, status-note line, `failed` callback for `addon.invoked`) | re-run once after; configurable mode |
| Where completion state lives | **Metadata on the parent TMI status note**; no new datastore | DynamoDB table; in-memory only |
| Abort interface | **TMI is the job registry**: automation apps GET and DELETE their own deliveries in TMI; tmi-tf-wh consumes the cancel signal. No admin endpoints or admin token on this service. | `ADMIN_TOKEN` bearer endpoints on the pod; validating TMI tokens on the pod |

## Constraints

- One replica (`infra/aws/k8s.tf`). Metadata read-modify-write is serialized by an in-process lock. Running more than one replica requires replacing the lock with a shared one (SQS FIFO group per threat model, or a conditional write); out of scope.
- TMI's delivery records live in Redis and can be lost (Redis pod recreated 2026-09-17). Cancel detection must not depend on a webhook being delivered.
- Note-metadata writes emit `metadata.updated`; the webhook already ignores it and the addon-linked credential suppresses it.

## 1. Invocation record

An invocation is one accepted trigger. Its id is the parent `job_id` (invocation id or delivery id).

**Queue message (child)** gains three fields; `Job` gains the same, all optional so old messages still parse:

- `callback_url`: copied from the parent (was `None`).
- `siblings`: list of all child job ids of the invocation.
- `deadline`: ISO timestamp = enqueue time + `ceil(N / MAX_CONCURRENT_JOBS) * JOB_TIMEOUT` + 300 s.

**Durable state** is metadata on the parent `TMI-TF Analysis Status` note (written with `bulk_upsert_note_metadata`):

| key | value |
| --- | --- |
| `tf_invocation` | invocation id |
| `tf_open` | `true` / `false` |
| `tf_deadline` | ISO timestamp |
| `tf_child:<job_id>` | `success` / `failed` / `aborted` |

A new module `tmi_tf/invocation.py` owns this: `open_invocation`, `mark_child`, `read_state`, `close_invocation`, plus the per-threat-model `asyncio.Lock`. Worker and webhook call it; nothing else touches the keys.

## 2. Completion monitoring (#55)

- Parent: after enqueueing, calls `open_invocation` and sends callback `in_progress` with "enqueued N of M environment jobs" (was `completed`). Zero targets: callback `completed`, "no environments matched", no invocation opened. Children that failed to enqueue are marked `failed` immediately.
- Child: on finish (success, failure, exception, timeout) calls `mark_child`, which re-reads state under the lock. If every sibling has a mark, it closes the invocation: `tf_open=false`, summary line on the parent status note ("Invocation complete: 7 succeeded, 1 failed"), callback `completed` if all succeeded, else `failed` with the failed environments.
- A child that raises is currently left on the queue for redelivery. That stays, but it is marked `failed` now; a successful redelivery overwrites the mark. If the invocation already closed, the late result only updates its mark (no second callback).
- Watchdog: one asyncio task per open invocation sleeps until `deadline`, then marks unreported siblings `failed` and closes. It is armed by the parent, and re-armed after a pod restart by the first dequeued child of that invocation (the message carries `siblings` and `deadline`).
- Known gap: pod dies and no child of the invocation is ever redelivered. The invocation stays `tf_open=true` with no callback; the staleness rule in section 3 stops it from blocking new runs.

## 3. Dedup (#52)

In the webhook handler, after `is_trigger_event` and before publish. Drop when either holds:

1. **Debounce**: a trigger for the same `threat_model_id` was accepted within `DEDUP_DEBOUNCE_SECONDS` (default 30, `0` disables). In-memory dict; covers the window before the parent job opens the invocation.
2. **Open invocation**: status-note metadata has `tf_open=true` and `tf_deadline` is in the future. A past deadline counts as closed.

On drop: 200 `{"status": "deduplicated", "job_id": ...}`, log line, status-note line "Trigger <event> ignored: analysis already running"; for `addon.invoked`, callback `failed` "analysis already running". If the TMI lookup itself fails, accept the trigger (fail open: a duplicate run is cheaper than a lost one).

Repository-scoped triggers (`repository.*`) dedup on `threat_model_id` like the rest.

## 4. Abort (#54)

### TMI side (issue filed against ericfitz/tmi; not built here)

- `GET /webhook-deliveries`: list the caller's own deliveries (owner of the subscription / addon credential), with status and timestamps.
- `DELETE /webhook-deliveries/{delivery_id}`: set status `cancelled`. Allowed for the owning automation identity and the invoker.
- `GET /webhook-deliveries/{delivery_id}` reports `cancelled`.
- Optional: emit `addon.invocation_cancelled` to the subscription.

### This service

- `WorkerPool.abort(invocation_id, reason)`: set the invocation's `threading.Event`, cancel its asyncio tasks, add the id to a cancelled set (children dequeued later are deleted unrun and marked `aborted`), delete SQS messages, remove temp dirs, mark running children `aborted`, close the invocation with "Aborted: <reason>", callback `failed` "aborted".
- `run_analysis` runs in a thread, which task cancellation cannot stop. It takes an optional `cancel_event` and checks it between phases and before each LLM call, raising `AnalysisAborted`. No LLM call starts after abort; one already streaming finishes.
- **Cancel signal, primary: polling.** At each phase boundary the worker GETs `/webhook-deliveries/{id}`; status `cancelled` triggers `abort()`. Works when webhook deliveries are lost. **Secondary:** `addon.invocation_cancelled` event calls the same `abort()`.
- Until TMI ships, `abort()` has no external trigger and the purge + restart runbook stays documented as the fallback.
- `/status` is unchanged.

## Error handling

- Every TMI metadata call goes through the existing `_call_with_retry`. If `mark_child` still fails, log it; the watchdog reports that child as failed at the deadline.
- Callback failures are logged, never raised (existing behavior).

## Testing

Unit tests with the in-memory queue provider and a fake TMI client:

- #55: all children succeed; one fails; one never reports (watchdog closes, failed); late mark after close sends no second callback; watchdog re-armed from a child message.
- #52: second trigger inside the debounce window; trigger while invocation open; open but past deadline is accepted; TMI lookup failure is accepted.
- #54: abort during a phase (no further LLM call, message deleted, temp dir gone, mark `aborted`, callback sent); abort of a queued child; polling sees `cancelled`.

## Rollout

1. PR 1: `invocation.py`, #55 and #52.
2. PR 2: `abort()` and `cancel_event` plumbing (#54 local mechanics). File the TMI issue.
3. PR 3, after TMI ships: polling + cancel event wiring; closes #54.
