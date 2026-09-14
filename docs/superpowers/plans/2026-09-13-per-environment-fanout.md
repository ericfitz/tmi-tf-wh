# Per-Environment Fan-Out Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn each Terraform root module ("environment") of a repository into its own queue job, with the set of environments chosen by a `scope` string carried in the webhook payload (default `latest`).

**Architecture:** The webhook enqueues a *parent* job (as today, plus `scope`). The worker recognises a parent by `environment is None`, resolves the scope against the detected environments, and publishes one *child* message per environment. A child (`environment` set) runs the existing single-environment path in `run_analysis`. Parent does no LLM work and reports the addon callback `completed` after enqueueing.

**Tech Stack:** Python 3.13, `uv`, pytest, click, `git` subprocess, existing `QueueProvider` protocol (`publish`/`consume`/`delete`), `MemoryQueueProvider` for tests.

**Spec:** `docs/superpowers/specs/2026-09-13-per-environment-fanout-design.md`

## Global Constraints

- Run gates before every commit: `uv run ruff check tmi_tf/ tests/`, `uv run ruff format tmi_tf/ tests/`, `uv run pyright`, `uv run pytest tests/ -q`.
- `tmi_client` imports carry `# type: ignore`; `pytest` import in tests carries `# pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]` (copy from an existing test file).
- New env var: `LATEST_COMMIT_DEPTH`, default `200`.
- Scope values: `latest` (default), `all`, comma-separated names/globs matched with `fnmatch`, case-insensitive.
- Child job id: `<parent job_id>:<env name>`; a no-environment repo gets one child with `environment=""`.
- Child status note name: `Analysis Status - <env>` (module constant `STATUS_NOTE_NAME` is `Analysis Status`; verify with `rg -n STATUS_NOTE_NAME tmi_tf/tmi_client_wrapper.py`).
- Commit messages end with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- No `git add -A`; stage only files named in the task.

---

### Task 1: Config knob `LATEST_COMMIT_DEPTH`

**Files:**
- Modify: `tmi_tf/config.py` (after the `clone_timeout` line, ~line 87)
- Test: `tests/test_config.py`

**Interfaces:**
- Produces: `Config.latest_commit_depth: int` (default 200).

- [ ] **Step 1: Write the failing test** (append to `tests/test_config.py`, follow the file's existing `patch.dict(os.environ, ...)` style)

```python
class TestLatestCommitDepth:
    def test_default(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("LATEST_COMMIT_DEPTH", None)
            assert Config().latest_commit_depth == 200

    def test_override(self):
        with patch.dict(os.environ, {"LATEST_COMMIT_DEPTH": "50"}):
            assert Config().latest_commit_depth == 50
```

- [ ] **Step 2: Run** `uv run pytest tests/test_config.py -q -k LatestCommitDepth` — expect AttributeError.
- [ ] **Step 3: Implement** in `Config.__init__` next to `clone_timeout`:

```python
        self.latest_commit_depth: int = int(os.getenv("LATEST_COMMIT_DEPTH", "200"))
```

- [ ] **Step 4: Run** the test again — PASS. Run gates.
- [ ] **Step 5: Commit** `feat(config): LATEST_COMMIT_DEPTH`.

---

### Task 2: `Job` gains `scope` and `environment`

**Files:**
- Modify: `tmi_tf/job.py`
- Test: `tests/test_job.py`

**Interfaces:**
- Produces: `Job.scope: str | None = None`, `Job.environment: str | None = None`, both round-tripped by `to_queue_message` / `from_queue_message`. `Job.is_child` property: `self.environment is not None`.

- [ ] **Step 1: Failing test** (append to `tests/test_job.py`)

```python
class TestScopeAndEnvironment:
    def _job(self, **kw):
        return Job(
            job_id="j1",
            threat_model_id="tm1",
            event_type="addon.invoked",
            enqueued_at=datetime(2026, 9, 13, tzinfo=timezone.utc),
            **kw,
        )

    def test_defaults_are_parent(self):
        job = self._job()
        assert job.scope is None
        assert job.environment is None
        assert job.is_child is False

    def test_round_trip(self):
        job = self._job(scope="aws-*", environment="aws-public")
        data = job.to_queue_message()
        assert data["scope"] == "aws-*"
        assert data["environment"] == "aws-public"
        back = Job.from_queue_message(data)
        assert back.scope == "aws-*"
        assert back.environment == "aws-public"
        assert back.is_child is True

    def test_empty_environment_is_child(self):
        assert Job.from_queue_message(
            {**self._job(environment="").to_queue_message()}
        ).is_child is True

    def test_missing_keys_default_to_none(self):
        data = self._job().to_queue_message()
        data.pop("scope")
        data.pop("environment")
        back = Job.from_queue_message(data)
        assert back.scope is None and back.environment is None
```

- [ ] **Step 2: Run** `uv run pytest tests/test_job.py -q` — FAIL (unexpected kwarg).
- [ ] **Step 3: Implement**: add the two fields after `temp_dir`, add them to `to_queue_message`, read with `.get()` in `from_queue_message`, and add:

```python
    @property
    def is_child(self) -> bool:
        """A child job analyzes exactly one environment ("" = whole repo)."""
        return self.environment is not None
```

- [ ] **Step 4: Run** tests — PASS. Gates.
- [ ] **Step 5: Commit** `feat(job): scope and environment fields`.

---

### Task 3: Webhook handler extracts scope; server passes it

**Files:**
- Modify: `tmi_tf/webhook_handler.py` (`parse_webhook_payload`)
- Modify: `tmi_tf/server.py` (`Job(...)` construction, ~line 166)
- Test: `tests/test_webhook_handler.py`, `tests/test_server.py`

**Interfaces:**
- Produces: `parse_webhook_payload` result may contain `"scope": str` when the payload has `data.user_data.environments` (non-empty string). Absent otherwise.

- [ ] **Step 1: Failing tests** (append to `tests/test_webhook_handler.py`)

```python
class TestScopeExtraction:
    def test_addon_user_data_environments(self):
        payload = {
            "type": "addon.invoked",
            "threat_model_id": "tm1",
            "data": {"addon_id": "a1", "user_data": {"environments": "aws-*, oci-public"}},
        }
        assert parse_webhook_payload(payload)["scope"] == "aws-*, oci-public"

    def test_no_user_data(self):
        payload = {"type": "threat_model.updated", "threat_model_id": "tm1"}
        assert "scope" not in parse_webhook_payload(payload)

    def test_user_data_without_environments(self):
        payload = {"type": "addon.invoked", "threat_model_id": "tm1", "data": {"user_data": {}}}
        assert "scope" not in parse_webhook_payload(payload)

    def test_non_string_environments_ignored(self):
        payload = {"type": "addon.invoked", "threat_model_id": "tm1", "data": {"user_data": {"environments": 5}}}
        assert "scope" not in parse_webhook_payload(payload)
```

- [ ] **Step 2: Run** `uv run pytest tests/test_webhook_handler.py -q -k Scope` — FAIL.
- [ ] **Step 3: Implement** at the end of `parse_webhook_payload` before `return result`:

```python
    data = payload.get("data")
    user_data = data.get("user_data") if isinstance(data, dict) else None
    scope = user_data.get("environments") if isinstance(user_data, dict) else None
    if isinstance(scope, str) and scope.strip():
        result["scope"] = scope.strip()
```

In `server.py` add `scope=parsed.get("scope"),` to the `Job(...)` call. In `tests/test_server.py` find the existing test that posts a signed valid event and asserts the published message; add one assertion-bearing test that a payload with `data.user_data.environments` produces a queue message with `"scope"` set (copy the existing signing helper from that file).

- [ ] **Step 4: Run** both test files — PASS. Gates.
- [ ] **Step 5: Commit** `feat(webhook): carry environments scope from addon user_data`.

---

### Task 4: Pure scope matching module

**Files:**
- Create: `tmi_tf/scope.py`
- Test: `tests/test_scope.py`

**Interfaces:**
- Produces:

```python
LATEST = "latest"
ALL = "all"

def normalize_scope(value: str | None) -> str:
    """None/blank -> "latest"; otherwise stripped, lower-cased."""

def match_environments(scope: str, names: list[str]) -> tuple[list[str], list[tuple[str, str]]]:
    """Return (matched, skipped) where skipped is [(name, reason)].
    scope "all": every name matched. scope "latest": raises ValueError (caller
    resolves latest with git; see Task 5). Otherwise: comma-separated
    fnmatch patterns, case-insensitive; a name is matched if any pattern
    matches; reason for skipped names is "not in scope"; patterns that
    matched nothing are returned as skipped entries ("<pattern>", "pattern matched no environment")."""
```

- [ ] **Step 1: Failing tests** (`tests/test_scope.py`)

```python
import pytest  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

from tmi_tf.scope import ALL, LATEST, match_environments, normalize_scope

NAMES = ["aws-private", "aws-public", "gcp-public", "oci-public"]


class TestNormalize:
    def test_none_is_latest(self):
        assert normalize_scope(None) == LATEST

    def test_blank_is_latest(self):
        assert normalize_scope("   ") == LATEST

    def test_case_and_whitespace(self):
        assert normalize_scope("  ALL ") == ALL


class TestMatch:
    def test_all(self):
        matched, skipped = match_environments(ALL, NAMES)
        assert matched == NAMES and skipped == []

    def test_latest_raises(self):
        with pytest.raises(ValueError):
            match_environments(LATEST, NAMES)

    def test_glob_and_name(self):
        matched, skipped = match_environments("aws-*, OCI-PUBLIC", NAMES)
        assert matched == ["aws-private", "aws-public", "oci-public"]
        assert skipped == [("gcp-public", "not in scope")]

    def test_unmatched_pattern_reported(self):
        matched, skipped = match_environments("azure-*", NAMES)
        assert matched == []
        assert ("azure-*", "pattern matched no environment") in skipped
        assert ("aws-public", "not in scope") in skipped

    def test_preserves_input_order(self):
        matched, _ = match_environments("oci-public,aws-public", NAMES)
        assert matched == ["aws-public", "oci-public"]
```

- [ ] **Step 2: Run** `uv run pytest tests/test_scope.py -q` — FAIL (module missing).
- [ ] **Step 3: Implement** `tmi_tf/scope.py`

```python
"""Environment scope parsing and matching (see spec 2026-09-13)."""

from fnmatch import fnmatchcase

LATEST = "latest"
ALL = "all"


def normalize_scope(value: str | None) -> str:
    if value is None or not value.strip():
        return LATEST
    return value.strip().lower()


def match_environments(
    scope: str, names: list[str]
) -> tuple[list[str], list[tuple[str, str]]]:
    scope = normalize_scope(scope)
    if scope == LATEST:
        raise ValueError("latest scope must be resolved with git history")
    if scope == ALL:
        return list(names), []

    patterns = [p.strip() for p in scope.split(",") if p.strip()]
    matched: list[str] = []
    skipped: list[tuple[str, str]] = []
    used: set[str] = set()
    for name in names:
        hits = [p for p in patterns if fnmatchcase(name.lower(), p)]
        if hits:
            matched.append(name)
            used.update(hits)
        else:
            skipped.append((name, "not in scope"))
    for p in patterns:
        if p not in used:
            skipped.append((p, "pattern matched no environment"))
    return matched, skipped
```

- [ ] **Step 4: Run** tests — PASS. Gates.
- [ ] **Step 5: Commit** `feat(scope): parse and match environment scope`.

---

### Task 5: Git-based `latest` selection and configurable clone depth

**Files:**
- Modify: `tmi_tf/repo_analyzer.py` (`_sparse_clone` pull line ~324; add two static methods on `RepositoryAnalyzer`)
- Test: `tests/test_repo_analyzer.py`

**Interfaces:**
- Consumes: `Config.latest_commit_depth` (Task 1), `RepositoryAnalyzer.resolve_modules`.
- Produces:

```python
@staticmethod
def last_commit_timestamp(clone_path: Path, paths: list[Path]) -> int | None:
    """Unix time of the newest commit touching any of paths (relative or absolute under clone_path); None if no commit in the available history."""

@staticmethod
def select_latest_environment(
    clone_path: Path, environments: list[TerraformEnvironment]
) -> tuple[TerraformEnvironment, int | None]:
    """Pick the environment with the newest commit over its own directory plus
    the directories of its resolved relative modules. Ties/None fall back to
    the first environment in `environments` order; the int is that
    environment's timestamp (None when nothing had history)."""
```

- [ ] **Step 1: Failing tests** (append to `tests/test_repo_analyzer.py`; build a real git repo in `tmp_path`)

```python
import subprocess
import time


def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def _commit(cwd, relpath, content, when):
    p = cwd / relpath
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    _git(cwd, "add", relpath)
    env_date = f"@{when} +0000"
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@x", "commit", "-q", "-m", relpath],
        cwd=cwd, check=True, capture_output=True,
        env={**os.environ, "GIT_AUTHOR_DATE": env_date, "GIT_COMMITTER_DATE": env_date},
    )


class TestLatestEnvironment:
    def _repo(self, tmp_path):
        _git(tmp_path, "init", "-q")
        _commit(tmp_path, "envs/a/main.tf", 'module "m" { source = "../../modules/m" }', 1000)
        _commit(tmp_path, "envs/b/main.tf", "# b", 2000)
        _commit(tmp_path, "modules/m/main.tf", "# m", 3000)
        return tmp_path

    def test_last_commit_timestamp(self, tmp_path):
        repo = self._repo(tmp_path)
        assert RepositoryAnalyzer.last_commit_timestamp(repo, [Path("envs/b")]) == 2000
        assert RepositoryAnalyzer.last_commit_timestamp(repo, [Path("nope")]) is None

    def test_module_commit_counts_for_environment(self, tmp_path):
        repo = self._repo(tmp_path)
        envs = RepositoryAnalyzer.detect_environments(repo)
        chosen, ts = RepositoryAnalyzer.select_latest_environment(repo, envs)
        assert chosen.name == "a"  # a's module changed at 3000 > b at 2000
        assert ts == 3000

    def test_no_history_falls_back_to_first(self, tmp_path):
        (tmp_path / "x").mkdir()
        (tmp_path / "x" / "main.tf").write_text("# x")
        (tmp_path / "y").mkdir()
        (tmp_path / "y" / "main.tf").write_text("# y")
        _git(tmp_path, "init", "-q")
        envs = RepositoryAnalyzer.detect_environments(tmp_path)
        chosen, ts = RepositoryAnalyzer.select_latest_environment(tmp_path, envs)
        assert chosen.name == "x" and ts is None


class TestCloneDepth:
    def test_pull_uses_configured_depth(self, tmp_path):
        config = Config()
        config.latest_commit_depth = 7
        analyzer = RepositoryAnalyzer(config)
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            class R: stdout = b""; stderr = b""; returncode = 0
            return R()

        with patch("tmi_tf.repo_analyzer.subprocess.run", side_effect=fake_run):
            (tmp_path / "main.tf").write_text("# keep rglob non-empty")
            analyzer._sparse_clone("https://github.com/o/r", tmp_path, "r")
        pull = next(c for c in calls if c[:2] == ["git", "pull"])
        assert "--depth=7" in pull
```

Add `import os` and `from unittest.mock import patch` and `from tmi_tf.config import Config` at the top of the test file if missing.

- [ ] **Step 2: Run** `uv run pytest tests/test_repo_analyzer.py -q -k "Latest or CloneDepth"` — FAIL.
- [ ] **Step 3: Implement** in `repo_analyzer.py`. Change the pull command to `["git", "pull", f"--depth={self.config.latest_commit_depth}", "origin", "HEAD"]`. Add the two static methods to `RepositoryAnalyzer`:

```python
    @staticmethod
    def last_commit_timestamp(clone_path: Path, paths: list[Path]) -> int | None:
        rel = [
            str(p.relative_to(clone_path)) if p.is_absolute() else str(p)
            for p in paths
        ]
        try:
            out = subprocess.run(
                ["git", "log", "-1", "--format=%ct", "--", *rel],
                cwd=clone_path,
                check=True,
                capture_output=True,
                timeout=30,
            ).stdout.decode().strip()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            logger.debug("git log failed for %s", rel, exc_info=True)
            return None
        return int(out) if out else None

    @staticmethod
    def select_latest_environment(
        clone_path: Path, environments: list[TerraformEnvironment]
    ) -> tuple[TerraformEnvironment, int | None]:
        best = environments[0]
        best_ts: int | None = None
        for env in environments:
            files = RepositoryAnalyzer.resolve_modules(env, clone_path)
            dirs = sorted({f.resolve().parent for f in files})
            ts = RepositoryAnalyzer.last_commit_timestamp(clone_path, dirs)
            if ts is not None and (best_ts is None or ts > best_ts):
                best, best_ts = env, ts
        return best, best_ts
```

`resolve_modules` returns absolute-or-relative paths depending on input; `.resolve()` then `relative_to` in `last_commit_timestamp` handles both. If `relative_to` raises because `tmp_path` is a symlinked temp dir on macOS, resolve `clone_path` too: use `clone_path.resolve()` on both sides.

- [ ] **Step 4: Run** tests — PASS. Gates.
- [ ] **Step 5: Commit** `feat(repo): latest-environment selection via git log; configurable pull depth`.

---

### Task 6: Per-client status note name

**Files:**
- Modify: `tmi_tf/tmi_client_wrapper.py` (`update_status_note`, `__init__`)
- Test: `tests/test_status_note.py`

**Interfaces:**
- Produces: `TMIClient.status_note_name: str` instance attribute, default `STATUS_NOTE_NAME`. `update_status_note` uses it everywhere it currently uses `STATUS_NOTE_NAME`.

- [ ] **Step 1: Failing test** (append to `tests/test_status_note.py`, mirror the file's existing mocking of `find_note_by_name` / `create_note` / `update_note`)

```python
    def test_custom_status_note_name(self):
        client = self._client()            # use the file's existing helper/fixture
        client.status_note_name = "Analysis Status - aws-public"
        client.find_note_by_name = MagicMock(return_value=None)
        client.create_note = MagicMock(return_value=MagicMock(id="n1"))
        client.update_status_note("tm1", "hello")
        client.find_note_by_name.assert_called_once_with("tm1", "Analysis Status - aws-public")
        assert client.create_note.call_args.kwargs["name"] == "Analysis Status - aws-public"
```

- [ ] **Step 2: Run** `uv run pytest tests/test_status_note.py -q` — FAIL.
- [ ] **Step 3: Implement**: in `__init__` next to `_status_note_initialized`, add `self.status_note_name: str = STATUS_NOTE_NAME`; replace the three `STATUS_NOTE_NAME` uses inside `update_status_note` with `self.status_note_name`.
- [ ] **Step 4: Run** — PASS. Gates.
- [ ] **Step 5: Commit** `feat(tmi): per-client status note name`.

---

### Task 7: Analyzer — `resolve_fanout_targets` and single-environment `run_analysis`

**Files:**
- Modify: `tmi_tf/analyzer.py`
- Test: `tests/test_analyzer.py`

**Interfaces:**
- Consumes: `scope.normalize_scope`, `scope.match_environments`, `RepositoryAnalyzer.select_latest_environment`, `Config.latest_commit_depth`.
- Produces:

```python
@dataclass
class FanoutTarget:
    repo_id: str
    repo_url: str
    environment: str          # "" = whole repo (no environments detected)


def resolve_fanout_targets(
    config: Config,
    threat_model_id: str,
    tmi_client: TMIClient,
    scope: str | None,
    repo_id: str | None = None,
    temp_dir: Path | None = None,
) -> list[FanoutTarget]:
    """Clone each GitHub repo of the threat model (respecting repo_id and
    config.max_repos), detect environments, apply scope, write the status
    note, return targets. Never runs the LLM."""
```

`run_analysis` changes:
- `environment: str | None` semantics: `None` on a multi-environment repo → `select_latest_environment` (log + status note "Selected latest environment: <name> (last commit <iso>)"); `""` → treated as `None`.
- A named environment that is not found → status note `Environment '<name>' not found in <repo>; skipping` and `return AnalysisResult(success=True, errors=[msg])` (no retry).
- Delete the `else: # Analyze ALL environments` loop.
- Stop reading `selected_env_name` from the loop; artifact names use the chosen environment name.

- [ ] **Step 1: Failing tests** (append to `tests/test_analyzer.py`). Mock the clone with a context manager yielding a fake `tf_repo` whose `clone_path` is a `tmp_path` tree; mock `tmi_client` with `MagicMock()`; mock `GitHubClient` to accept any URL.

```python
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

from tmi_tf.analyzer import FanoutTarget, resolve_fanout_targets, run_analysis
from tmi_tf.config import Config


def _tree(tmp_path: Path, envs: list[str]) -> Path:
    for e in envs:
        (tmp_path / "envs" / e).mkdir(parents=True)
        (tmp_path / "envs" / e / "main.tf").write_text(f"# {e}")
    return tmp_path


def _fake_clone(tree: Path):
    @contextmanager
    def _cm(repo_url, repo_name, base_temp_dir=None):
        repo = MagicMock()
        repo.clone_path = tree
        repo.terraform_files = list(tree.rglob("*.tf"))
        yield repo
    return _cm


def _tmi_with_repo(repo_id="r1", url="https://github.com/o/r"):
    tmi = MagicMock()
    repo = MagicMock(id=repo_id, uri=url, name="r")
    tmi.get_threat_model_repositories.return_value = [repo]
    return tmi


class TestResolveFanoutTargets:
    def _run(self, tmp_path, envs, scope, latest=("b", 100)):
        tree = _tree(tmp_path, envs)
        tmi = _tmi_with_repo()
        with (
            patch("tmi_tf.analyzer.RepositoryAnalyzer.clone_repository_sparse", _fake_clone(tree)),
            patch("tmi_tf.analyzer.GitHubClient.is_github_url", return_value=True),
            patch(
                "tmi_tf.analyzer.RepositoryAnalyzer.select_latest_environment",
                side_effect=lambda cp, es: (next(e for e in es if e.name == latest[0]), latest[1]),
            ),
        ):
            targets = resolve_fanout_targets(Config(), "tm1", tmi, scope)
        return targets, tmi

    def test_default_latest(self, tmp_path):
        targets, tmi = self._run(tmp_path, ["a", "b", "c"], None)
        assert targets == [FanoutTarget("r1", "https://github.com/o/r", "b")]
        note = " ".join(str(c) for c in tmi.update_status_note.call_args_list)
        assert "latest" in note and "b" in note

    def test_all(self, tmp_path):
        targets, _ = self._run(tmp_path, ["a", "b"], "all")
        assert [t.environment for t in targets] == ["a", "b"]

    def test_glob_reports_skipped(self, tmp_path):
        targets, tmi = self._run(tmp_path, ["aws-a", "gcp-b"], "aws-*")
        assert [t.environment for t in targets] == ["aws-a"]
        note = " ".join(str(c) for c in tmi.update_status_note.call_args_list)
        assert "gcp-b" in note and "not in scope" in note

    def test_single_environment_ignores_scope(self, tmp_path):
        targets, _ = self._run(tmp_path, ["only"], "zzz-*")
        assert [t.environment for t in targets] == ["only"]

    def test_no_environments_yields_whole_repo_target(self, tmp_path):
        (tmp_path / "loose.tf").write_text("# loose")
        tmi = _tmi_with_repo()
        with (
            patch("tmi_tf.analyzer.RepositoryAnalyzer.clone_repository_sparse", _fake_clone(tmp_path)),
            patch("tmi_tf.analyzer.GitHubClient.is_github_url", return_value=True),
        ):
            targets = resolve_fanout_targets(Config(), "tm1", tmi, "all")
        assert targets == [FanoutTarget("r1", "https://github.com/o/r", "")]


class TestRunAnalysisEnvironmentSelection:
    def test_none_on_multi_env_selects_latest(self, tmp_path):
        tree = _tree(tmp_path, ["a", "b"])
        tmi = _tmi_with_repo()
        tmi.get_threat_model.return_value = MagicMock(name="TM")
        analyze = MagicMock(return_value=MagicMock(success=False, errors=["stub"]))
        with (
            patch("tmi_tf.analyzer.RepositoryAnalyzer.clone_repository_sparse", _fake_clone(tree)),
            patch("tmi_tf.analyzer.GitHubClient.is_github_url", return_value=True),
            patch("tmi_tf.analyzer.RepositoryAnalyzer.select_latest_environment",
                  side_effect=lambda cp, es: (es[1], 5)),
            patch("tmi_tf.analyzer.LLMAnalyzer") as llm_cls,
            patch("tmi_tf.analyzer.validate_and_sanitize",
                  side_effect=lambda files, root: MagicMock(valid_files=files, sanitization_log=[])),
        ):
            llm_cls.return_value.analyze_repository = analyze
            run_analysis(Config(), "tm1", tmi, skip_diagram=True, skip_threats=True)
        assert analyze.call_args.args[0].environment_name == "b"

    def test_named_environment_missing_is_success_no_retry(self, tmp_path):
        tree = _tree(tmp_path, ["a", "b"])
        tmi = _tmi_with_repo()
        with (
            patch("tmi_tf.analyzer.RepositoryAnalyzer.clone_repository_sparse", _fake_clone(tree)),
            patch("tmi_tf.analyzer.GitHubClient.is_github_url", return_value=True),
            patch("tmi_tf.analyzer.LLMAnalyzer"),
        ):
            result = run_analysis(Config(), "tm1", tmi, environment="gone")
        assert result.success is True
        assert any("gone" in e for e in result.errors)
        assert result.analyses == []
```

Adjust the constructor names in the test to the real ones by reading `run_analysis` lines 120-170 (`LLMAnalyzer(...)`, `GitHubClient(config)`, `tmi_client.get_threat_model(...)`) before finalising. If `run_analysis` builds an `LLMProvider` first, patch that factory too (`rg -n "LLMAnalyzer\(|create_llm_provider|get_llm_provider" tmi_tf/analyzer.py`).

- [ ] **Step 2: Run** `uv run pytest tests/test_analyzer.py -q` — FAIL (import error).
- [ ] **Step 3: Implement** in `analyzer.py`:

```python
from dataclasses import dataclass, field
from datetime import datetime, timezone

from tmi_tf.scope import LATEST, match_environments, normalize_scope


@dataclass(frozen=True)
class FanoutTarget:
    repo_id: str
    repo_url: str
    environment: str


def _github_repos(config, tmi_client, threat_model_id, repo_id):
    """Shared by run_analysis and resolve_fanout_targets."""
    github_client = GitHubClient(config)
    repositories = tmi_client.get_threat_model_repositories(threat_model_id)
    repos = [r for r in repositories if github_client.is_github_url(r.uri)]
    if repo_id is not None:
        repos = [r for r in repos if str(r.id) == repo_id]
    return repos[: config.max_repos]


def resolve_fanout_targets(
    config: Config,
    threat_model_id: str,
    tmi_client: TMIClient,
    scope: str | None,
    repo_id: str | None = None,
    temp_dir: Path | None = None,
) -> list[FanoutTarget]:
    scope = normalize_scope(scope)
    repo_analyzer = RepositoryAnalyzer(config)
    targets: list[FanoutTarget] = []
    for repo in _github_repos(config, tmi_client, threat_model_id, repo_id):
        repo_name = repo_analyzer.extract_repository_name(repo.uri)
        tmi_client.update_status_note(threat_model_id, f"Cloning repository: {repo.uri}")
        with repo_analyzer.clone_repository_sparse(
            repo.uri, repo_name, base_temp_dir=temp_dir
        ) as tf_repo:
            if not tf_repo:
                tmi_client.update_status_note(
                    threat_model_id, f"No Terraform files in {repo_name}; skipping"
                )
                continue
            envs = RepositoryAnalyzer.detect_environments(tf_repo.clone_path)
            names = [e.name for e in envs]
            if not envs:
                tmi_client.update_status_note(
                    threat_model_id,
                    f"{repo_name}: no environments detected; analyzing all files",
                )
                targets.append(FanoutTarget(str(repo.id), repo.uri, ""))
                continue
            if len(envs) == 1:
                matched, skipped = names, []
            elif scope == LATEST:
                chosen, ts = RepositoryAnalyzer.select_latest_environment(
                    tf_repo.clone_path, envs
                )
                when = (
                    datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
                    if ts is not None
                    else "no commit in window; first environment chosen"
                )
                matched = [chosen.name]
                skipped = [(n, "not latest") for n in names if n != chosen.name]
                tmi_client.update_status_note(
                    threat_model_id,
                    f"{repo_name}: scope latest -> {chosen.name} (last commit {when})",
                )
            else:
                matched, skipped = match_environments(scope, names)
            tmi_client.update_status_note(
                threat_model_id,
                f"{repo_name}: environments found: {', '.join(names)}; "
                f"analyzing: {', '.join(matched) or 'none'}",
            )
            for name, reason in skipped:
                tmi_client.update_status_note(
                    threat_model_id, f"{repo_name}: skipping {name} ({reason})"
                )
            targets.extend(FanoutTarget(str(repo.id), repo.uri, n) for n in matched)
    return targets
```

Then edit `run_analysis`:
1. Replace its inline GitHub-repo filtering (lines ~150-170) with `repos_to_analyze = _github_repos(config, tmi_client, threat_model_id, repo_id)`; keep the "not found" error path when `repo_id` is given and the list is empty, and keep the "limiting to max_repos" log if you can do it cheaply, otherwise drop it.
2. At the top of the multi-environment branch: `environment = environment or None`.
3. Replace the `if environment: ... else: # Analyze ALL environments ...` block with:

```python
                            if environment:
                                matches = [e for e in envs if e.name.lower() == environment.lower()]
                                if not matches:
                                    msg = (
                                        f"Environment '{environment}' not found in {repo_name}; "
                                        f"available: {', '.join(e.name for e in envs)}; skipping"
                                    )
                                    logger.warning(msg)
                                    tmi_client.update_status_note(threat_model_id, msg)
                                    errors.append(msg)
                                    continue
                                selected = matches[0]
                            else:
                                selected, ts = RepositoryAnalyzer.select_latest_environment(
                                    tf_repo.clone_path, envs
                                )
                                tmi_client.update_status_note(
                                    threat_model_id,
                                    f"Selected latest environment: {selected.name}",
                                )
                            selected_env_name = selected.name
                            analysis = _analyze_single_environment(
                                tf_repo, selected, repo_analyzer, llm_analyzer,
                                tmi_client, threat_model_id, repo_name,
                            )
                            analyses.append(analysis)
```

4. After the repo loop, where `if not analyses:` returns `success=False`: if `errors` contains only "not found ... skipping" messages (i.e. every repo was skipped for a missing named environment), return `AnalysisResult(success=True, errors=errors)` instead. Implement by tracking a local `skipped_missing_env = True` set in the branch above and checking `if not analyses and skipped_missing_env and len(errors) == n_skipped`.

- [ ] **Step 4: Run** `uv run pytest tests/ -q` — PASS (fix `tests/test_cli_environment.py` if it asserted the ALL-environments behaviour: it should now expect latest selection). Gates.
- [ ] **Step 5: Commit** `feat(analyzer): resolve_fanout_targets; run_analysis analyzes one environment`.

---

### Task 8: Worker dispatches parent vs child

**Files:**
- Modify: `tmi_tf/worker.py` (`_run_job`)
- Test: `tests/test_worker.py`

**Interfaces:**
- Consumes: `Job.is_child`, `Job.scope`, `Job.environment`, `resolve_fanout_targets`, `TMIClient.status_note_name`, `STATUS_NOTE_NAME`.

Behaviour:
- Child (`job.is_child`): `tmi_client.status_note_name = f"{STATUS_NOTE_NAME} - {job.environment}"` when `job.environment` is non-empty; call `run_analysis(..., repo_id=job.repo_id, environment=job.environment)`; existing callback/delete logic unchanged.
- Parent: `targets = resolve_fanout_targets(config, job.threat_model_id, tmi_client, job.scope, repo_id=job.repo_id, temp_dir=job.temp_dir)` in a thread; for each target publish `Job(job_id=f"{job.job_id}:{target.environment or 'all'}", threat_model_id=job.threat_model_id, event_type=job.event_type, enqueued_at=now, repo_id=target.repo_id, callback_url=job.callback_url, invocation_id=job.invocation_id, environment=target.environment).to_queue_message()`; a publish exception is logged and written to the status note, and the loop continues; then `callback.send_status("completed", f"enqueued {n} environment jobs")` (or `"no environments matched"` when `n == 0`); then delete the message.

- [ ] **Step 1: Failing tests** (append to `tests/test_worker.py`)

```python
import asyncio
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from tmi_tf.analyzer import AnalysisResult, FanoutTarget
from tmi_tf.job import Job
from tmi_tf.providers.memory import MemoryQueueProvider
from tmi_tf.worker import WorkerPool


def _pool():
    config = Config()
    config.webhook_secret = "s"
    queue = MemoryQueueProvider()
    return WorkerPool(queue, config), queue


def _job(**kw):
    return Job(job_id="p1", threat_model_id="tm1", event_type="addon.invoked",
               enqueued_at=datetime.now(timezone.utc), callback_url="https://cb", **kw)


class TestFanout:
    def test_parent_enqueues_children_and_completes(self):
        pool, queue = _pool()
        targets = [FanoutTarget("r1", "u", "aws-public"), FanoutTarget("r1", "u", "gcp-public")]
        with (
            patch("tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()),
            patch("tmi_tf.worker.resolve_fanout_targets", return_value=targets),
            patch("tmi_tf.worker.AddonCallback") as cb_cls,
        ):
            asyncio.run(pool._run_job(_job(scope="all"), receipt="rc"))
        bodies = [m.body for m in queue.consume(max_messages=10)]
        assert sorted(b["environment"] for b in bodies) == ["aws-public", "gcp-public"]
        assert all(b["job_id"].startswith("p1:") and b["repo_id"] == "r1" for b in bodies)
        assert all(b["callback_url"] == "https://cb" for b in bodies)
        cb_cls.return_value.send_status.assert_any_call("completed", "enqueued 2 environment jobs")

    def test_parent_with_no_targets_completes_without_enqueue(self):
        pool, queue = _pool()
        with (
            patch("tmi_tf.worker.TMIClient.create_authenticated", return_value=MagicMock()),
            patch("tmi_tf.worker.resolve_fanout_targets", return_value=[]),
            patch("tmi_tf.worker.AddonCallback") as cb_cls,
        ):
            asyncio.run(pool._run_job(_job(scope="zzz"), receipt="rc"))
        assert queue.consume(max_messages=10) == []
        cb_cls.return_value.send_status.assert_any_call("completed", "no environments matched")

    def test_child_runs_analysis_with_environment_and_note_name(self):
        pool, _ = _pool()
        tmi = MagicMock()
        with (
            patch("tmi_tf.worker.TMIClient.create_authenticated", return_value=tmi),
            patch("tmi_tf.worker.run_analysis", return_value=AnalysisResult(success=True)) as ra,
            patch("tmi_tf.worker.AddonCallback"),
        ):
            asyncio.run(pool._run_job(_job(job_id="p1:aws-public", repo_id="r1",
                                           environment="aws-public"), receipt="rc"))
        assert ra.call_args.kwargs["environment"] == "aws-public"
        assert ra.call_args.kwargs["repo_id"] == "r1"
        assert tmi.status_note_name == "Analysis Status - aws-public"

    def test_child_whole_repo_keeps_default_note_name(self):
        pool, _ = _pool()
        tmi = MagicMock(status_note_name="Analysis Status")
        with (
            patch("tmi_tf.worker.TMIClient.create_authenticated", return_value=tmi),
            patch("tmi_tf.worker.run_analysis", return_value=AnalysisResult(success=True)),
            patch("tmi_tf.worker.AddonCallback"),
        ):
            asyncio.run(pool._run_job(_job(environment=""), receipt="rc"))
        assert tmi.status_note_name == "Analysis Status"
```

(`Config` is already imported in this file; check and add if not. `_run_job` is awaited directly, bypassing the semaphore, which is fine.)

- [ ] **Step 2: Run** `uv run pytest tests/test_worker.py -q -k Fanout` — FAIL.
- [ ] **Step 3: Implement** in `worker.py`: import `resolve_fanout_targets` from `tmi_tf.analyzer`, `STATUS_NOTE_NAME` from `tmi_tf.tmi_client_wrapper`, `datetime, timezone`. Split `_run_job` into the existing body for the child case and a new `_run_parent(job, tmi_client, callback)` coroutine for the parent case, both inside the same `try` so exception handling is unchanged:

```python
    async def _run_parent(self, job: Job, tmi_client: TMIClient, callback) -> None:
        targets = await asyncio.to_thread(
            resolve_fanout_targets,
            self.config,
            job.threat_model_id,
            tmi_client,
            job.scope,
            repo_id=job.repo_id,
            temp_dir=job.temp_dir,
        )
        enqueued = 0
        for t in targets:
            child = Job(
                job_id=f"{job.job_id}:{t.environment or 'all'}",
                threat_model_id=job.threat_model_id,
                event_type=job.event_type,
                enqueued_at=datetime.now(timezone.utc),
                repo_id=t.repo_id,
                callback_url=job.callback_url,
                invocation_id=job.invocation_id,
                environment=t.environment,
            )
            try:
                await asyncio.to_thread(self.queue_client.publish, child.to_queue_message())
                enqueued += 1
            except Exception as e:
                msg = f"Failed to enqueue environment {t.environment!r}: {e}"
                logger.error(msg)
                tmi_client.update_status_note(job.threat_model_id, msg)
        summary = (
            f"enqueued {enqueued} environment jobs" if enqueued else "no environments matched"
        )
        logger.info("Parent job %s: %s", job.job_id, summary)
        if callback:
            callback.send_status("completed", summary)
```

In `_run_job`, inside the `try` after `tmi_client = ...`:

```python
            if job.is_child:
                if job.environment:
                    tmi_client.status_note_name = f"{STATUS_NOTE_NAME} - {job.environment}"
                result = await asyncio.to_thread(
                    run_analysis,
                    config=self.config,
                    threat_model_id=job.threat_model_id,
                    tmi_client=tmi_client,
                    repo_id=job.repo_id,
                    temp_dir=job.temp_dir,
                    callback=callback,
                    environment=job.environment,
                )
                ...existing success/failed callback handling...
            else:
                await self._run_parent(job, tmi_client, callback)
            await asyncio.to_thread(self.queue_client.delete, receipt)
```

Check `AddonCallback.send_status` signature accepts `(status, message)`; `rg -n "def send_status" tmi_tf/addon_callback.py`.

- [ ] **Step 4: Run** `uv run pytest tests/ -q` — PASS. Gates.
- [ ] **Step 5: Commit** `feat(worker): fan out parent jobs into per-environment child jobs`.

---

### Task 9: Docs and operator notes

**Files:**
- Modify: `README.md` (configuration table and webhook section), `.env.example` if present (`ls -a | rg env`), `docs/superpowers/specs/2026-03-19-webhook-service-design.md` (append a "Superseded in part by 2026-09-13 fan-out spec" note under the job model section), `PROGRESS.md`.

- [ ] **Step 1**: Add `LATEST_COMMIT_DEPTH` (default 200) to the README config table and `.env.example`.
- [ ] **Step 2**: In the README webhook/addon section, document: scope forms (`latest` default, `all`, comma-separated names/globs), that it is read from the addon invocation parameter `environments`, that each environment becomes its own job with its own `JOB_TIMEOUT`, and that each environment writes `Analysis Status - <env>`. Add the operator step: register the addon in TMI with a string parameter named `environments`, default `latest`.
- [ ] **Step 3**: `PROGRESS.md`: one entry "2026-09-13 per-environment fan-out (#51): spec, plan, implementation on branch feat/per-environment-fanout; follow-up #55 completion monitoring".
- [ ] **Step 4**: Gates (ruff on tests/tmi_tf only). Commit `docs: per-environment fan-out and scope parameter`.

---

## Self-review

- Spec coverage: scope model (T4, T7), sources (T3), latest selection + depth (T1, T5), job model (T2), parent (T7 targets, T8 enqueue/callback), child (T8, T7 missing-env), removed ALL branch (T7), status notes (T6, T8), config (T1), error handling (T7 zero targets, T8 publish failure), tests per section, docs (T9). No gap found.
- Placeholder scan: "existing success/failed callback handling" in T8 refers to code already in `_run_job`; implementer keeps it verbatim.
- Type consistency: `FanoutTarget(repo_id, repo_url, environment)` used identically in T7 and T8; `resolve_fanout_targets(config, threat_model_id, tmi_client, scope, repo_id=, temp_dir=)` identical in T7 signature and T8 call; `Job.is_child`, `status_note_name` consistent across T2, T6, T8.
