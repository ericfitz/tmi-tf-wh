# Per-Environment Fan-Out for Multi-Root-Module Repositories

**Date:** 2026-09-13
**Issue:** #51
**Status:** Approved (Eric, 2026-09-13)

## Problem

A repository with several Terraform root modules ("environments") is analyzed
sequentially inside one queue job. Each environment costs roughly 14 minutes and
$4 (gpt-daybreak-blue-latest). `ericfitz/tmi` has 8 environments, so the job
needs about 2 hours against a `JOB_TIMEOUT` of 3600 s. When the timeout fires
the worker deletes the SQS message and nothing is written back to TMI, so every
dollar spent is lost. The multi-environment path also merges all environments
into one inventory, one DFD, and one threat list, and mislabels those artifacts
with whichever environment ran last.

## Decisions (human-made, Eric, 2026-09-13)

| Decision | Choice | Alternatives rejected |
|---|---|---|
| What lands in TMI for an N-environment repo | One set of artifacts per environment (notes, DFD, threats). No merged overview. | Merged set (today); per-env plus merged overview |
| How per-environment work is scheduled | Fan out: the webhook job enqueues one queue message per environment; each runs the existing single-environment path with its own timeout and retry. | In-process bounded concurrency inside one job |
| Who chooses the environments | The security reviewer, via the addon invocation payload (`environments` parameter). Default `latest` = most recently modified environment. | Deployment-wide env var; always all |
| Addon completion signal | Parent reports `completed` with "enqueued N environment jobs" after fan-out. Children report progress via status notes only. Completion monitoring across children is a backlog item. | Shared completion state across child jobs |
| Commit window for `latest` | 200 commits, configurable (`LATEST_COMMIT_DEPTH`). | Full history; GitHub commits API |

## Scope model

`scope` is a string with three forms:

| Value | Meaning |
|---|---|
| `latest` (default) | The single environment with the newest commit touching its own `.tf`/`.tfvars` files or the files of its resolved relative modules. |
| `all` | Every detected environment. |
| comma-separated names/globs, e.g. `aws-*,oci-public` | Environments whose short name matches any pattern (`fnmatch`, case-insensitive). |

Sources, in priority order:

1. `addon.invoked` payload: `data.user_data.environments`. The addon is
   registered in TMI (operator task, not code) with one string parameter
   `environments`, default `latest`, description explaining the three forms.
2. Any other event: `latest`.

Resolution happens in the parent job after environment detection. If a repo has
exactly one environment, scope is irrelevant and that environment is used. If
no environments are detected, the existing "analyze all files" fallback runs
inline (no fan-out).

`latest` selection: the sparse clone is currently `--depth=1`. The parent
instead pulls with `--depth=<LATEST_COMMIT_DEPTH>` (default 200), then runs
`git log -1 --format=%ct -- <paths>` per environment, where `<paths>` are the
environment directory plus its resolved relative module directories. Highest
timestamp wins. If no environment has a commit in the window, the first
environment in sorted order is chosen and the status note says so.

## Job model

`Job` gains two optional fields, both serialized in the queue message:

- `scope: str | None` — set by the webhook handler on the parent message.
- `environment: str | None` — set by the parent on each child message.

A message with `environment` set is a **child job**. Everything else is a
**parent job**.

### Parent job

1. Authenticate, fetch repositories for the threat model (existing steps).
2. For each repository: sparse clone, detect environments.
3. Resolve scope to a concrete environment list.
4. Write one status note per repository: environments found, matched, skipped
   (with the reason: not in scope, or unmatched pattern), and for `latest`,
   which one won and its commit date.
5. Enqueue one child message per matched environment, copying `threat_model_id`,
   `repo_id` (the repository being fanned out), `callback_url`, `invocation_id`,
   and setting `environment`. `job_id` is `<parent job_id>:<env name>`.
6. Addon callback: `completed` with message "enqueued N environment jobs".
7. Delete the parent message.

The parent does no LLM work.

### Child job

Runs `run_analysis(..., repo_id=..., environment=<name>)`, which is the
existing single-environment path. Artifacts are already named with the
environment. Each child has the full `JOB_TIMEOUT`, its own SQS visibility
timeout, and the existing retry-on-exception behaviour.

If the named environment no longer exists on the default branch (repo changed
between parent and child), the child writes a status note saying so and exits
successfully (no retry).

### Removed code

- The "analyze ALL environments" sequential branch in `analyzer.py`.
- The merged `combined_inventory` / `combined_infrastructure` aggregation
  before DFD generation; `analyses` for a child always has exactly one entry.
- The `selected_env_name` last-writer-wins naming bug disappears with it.

`run_analysis` keeps its `environment` argument and the CLI keeps `--environment`.
When the CLI is run without `--environment` against a multi-environment repo it
uses the same scope resolution with `latest` (no fan-out from the CLI; the CLI
runs the resolved environment inline). A `--scope` CLI option is not added.

## Status note

The parent's note lists every environment and its disposition. Each child then
updates the same note with its own progress lines prefixed by the environment
name, so concurrent children stay readable, e.g. `[aws-public] Phase 2 ...`.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `LATEST_COMMIT_DEPTH` | `200` | Commit window used by `latest`. |

`JOB_TIMEOUT` and `MAX_CONCURRENT_JOBS` are unchanged; they now bound a single
environment and the number of environments in flight per pod.

## Error handling

- Scope resolves to zero environments: status note explains it, addon callback
  `completed` with "no environments matched", nothing enqueued.
- Enqueue fails for one child: log, record in the status note, continue with the
  rest; parent still completes.
- Clone or detection failure in the parent: existing behaviour (error, callback
  `failed`).

## Testing

Unit tests, no network:

- Scope parsing: default, `all`, list, glob, case-insensitivity, whitespace.
- `latest` selection with a fixture git repo built in `tmp_path` (commits
  touching different environment dirs and a shared module dir); fallback when
  nothing is in the window.
- Webhook handler extracts `user_data.environments` from an `addon.invoked`
  envelope and ignores it elsewhere.
- Worker dispatches parent vs child by the `environment` field; parent enqueues
  one message per matched environment with the expected fields, using the
  in-memory queue provider.
- Analyzer: multi-environment repo with `environment=None` in CLI mode picks
  `latest`; child path still produces per-environment artifact names.

## Out of scope

- Large single environments that overflow a phase (issue #53 territory). A
  separate spec will revive the static HCL design (2026-04-06).
- Duplicate-job deduplication (#52).
- Cross-child completion monitoring (new backlog issue).
