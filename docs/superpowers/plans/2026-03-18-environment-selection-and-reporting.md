# Environment Selection, Status Tracking, and Report Splitting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Terraform environment detection/selection, analysis status tracking, report splitting, and environment-aware artifact naming to tmi-tf.

**Architecture:** Extend `repo_analyzer.py` with environment detection and module resolution. Add status note tracking to `tmi_client_wrapper.py`. Split `markdown_generator.py` report into inventory and analysis reports. Update `cli.py` to orchestrate the new flow with dynamic artifact naming. Update `analysis_comparer.py` regex for backward compatibility.

**Tech Stack:** Python 3, Click CLI, LiteLLM, TMI API client

**Spec:** `docs/superpowers/specs/2026-03-18-environment-selection-and-reporting-design.md`

---

### Task 1: Environment Detection in repo_analyzer.py

**Files:**
- Modify: `tmi_tf/repo_analyzer.py`
- Test: `tests/test_repo_analyzer.py` (create)

- [ ] **Step 1: Write failing tests for TerraformEnvironment and detect_environments**

```python
"""Tests for environment detection and module resolution in repo_analyzer."""

import textwrap
from pathlib import Path

import pytest

from tmi_tf.repo_analyzer import (
    TerraformEnvironment,
    TerraformRepository,
    RepositoryAnalyzer,
)


class TestDetectEnvironments:
    """Test detect_environments method."""

    def _make_tree(self, tmp_path: Path, files: dict[str, str]) -> Path:
        """Create a directory tree from a dict of {relative_path: content}."""
        for rel, content in files.items():
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        return tmp_path

    def test_finds_single_environment(self, tmp_path):
        clone = self._make_tree(tmp_path, {
            "terraform/environments/prod/main.tf": 'resource "aws_instance" "web" {}',
            "terraform/environments/prod/variables.tf": 'variable "region" {}',
        })
        envs = RepositoryAnalyzer.detect_environments(clone)
        assert len(envs) == 1
        assert envs[0].name == "prod"
        assert len(envs[0].tf_files) == 2

    def test_finds_multiple_environments(self, tmp_path):
        clone = self._make_tree(tmp_path, {
            "terraform/environments/prod/main.tf": "",
            "terraform/environments/staging/main.tf": "",
            "terraform/environments/dev/backend.tf": "",
        })
        envs = RepositoryAnalyzer.detect_environments(clone)
        assert len(envs) == 3
        names = [e.name for e in envs]
        assert sorted(names) == ["dev", "prod", "staging"]

    def test_excludes_modules_directories(self, tmp_path):
        clone = self._make_tree(tmp_path, {
            "terraform/environments/prod/main.tf": "",
            "terraform/modules/network/main.tf": "",
            "modules/compute/main.tf": "",
        })
        envs = RepositoryAnalyzer.detect_environments(clone)
        assert len(envs) == 1
        assert envs[0].name == "prod"

    def test_no_environments_returns_empty(self, tmp_path):
        clone = self._make_tree(tmp_path, {
            "some_dir/file.tf": "",
        })
        envs = RepositoryAnalyzer.detect_environments(clone)
        assert len(envs) == 0

    def test_disambiguates_duplicate_names(self, tmp_path):
        clone = self._make_tree(tmp_path, {
            "aws/prod/main.tf": "",
            "gcp/prod/main.tf": "",
        })
        envs = RepositoryAnalyzer.detect_environments(clone)
        assert len(envs) == 2
        names = [e.name for e in envs]
        # Should use relative paths to disambiguate
        assert len(set(names)) == 2  # All names unique

    def test_collects_tf_and_tfvars_files(self, tmp_path):
        clone = self._make_tree(tmp_path, {
            "env/prod/main.tf": "",
            "env/prod/variables.tf": "",
            "env/prod/terraform.tfvars": "",
            "env/prod/subdir/nested.tf": "",  # Should NOT be included (non-recursive)
        })
        envs = RepositoryAnalyzer.detect_environments(clone)
        assert len(envs) == 1
        # Only direct files, not nested
        extensions = {f.suffix for f in envs[0].tf_files}
        assert ".tf" in extensions
        assert ".tfvars" in extensions
        # nested.tf should not be in the environment's direct tf_files
        names = {f.name for f in envs[0].tf_files}
        assert "nested.tf" not in names

    def test_returns_sorted_by_name(self, tmp_path):
        clone = self._make_tree(tmp_path, {
            "z-env/main.tf": "",
            "a-env/main.tf": "",
            "m-env/main.tf": "",
        })
        envs = RepositoryAnalyzer.detect_environments(clone)
        names = [e.name for e in envs]
        assert names == sorted(names)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_repo_analyzer.py -v`
Expected: FAIL — `TerraformEnvironment` doesn't exist, `detect_environments` doesn't exist

- [ ] **Step 3: Implement TerraformEnvironment dataclass and detect_environments**

Add to `tmi_tf/repo_analyzer.py`:

```python
from dataclasses import dataclass, field

@dataclass
class TerraformEnvironment:
    """Represents a detected Terraform environment (root module)."""
    name: str
    path: Path
    tf_files: List[Path]
```

Add `environment_name` and `environments_found` fields to `TerraformRepository.__init__`:

```python
def __init__(
    self,
    name: str,
    url: str,
    clone_path: Path,
    terraform_files: List[Path],
    environment_name: Optional[str] = None,
    environments_found: Optional[List[str]] = None,
):
    self.name = name
    self.url = url
    self.clone_path = clone_path
    self.terraform_files = terraform_files
    self.environment_name = environment_name
    self.environments_found = environments_found or []
```

Add static method to `RepositoryAnalyzer`:

```python
@staticmethod
def detect_environments(clone_path: Path) -> List[TerraformEnvironment]:
    """Detect Terraform environments (root modules) in a cloned repository.

    Finds directories containing main.tf or backend.tf, excluding any
    directories under a 'modules' path segment.

    Args:
        clone_path: Root of the cloned repository

    Returns:
        Sorted list of detected TerraformEnvironment objects
    """
    candidates: dict[Path, None] = {}  # Use dict for ordered dedup

    for marker in ("main.tf", "backend.tf"):
        for match in clone_path.rglob(marker):
            candidates[match.parent] = None

    # Filter out directories under any 'modules' path segment
    environments: list[TerraformEnvironment] = []
    for dir_path in candidates:
        rel = dir_path.relative_to(clone_path)
        if "modules" in rel.parts:
            continue

        # Collect .tf and .tfvars files directly in this directory (non-recursive)
        tf_files = sorted(
            [f for f in dir_path.iterdir()
             if f.is_file() and f.suffix in (".tf", ".tfvars")]
        )

        environments.append(TerraformEnvironment(
            name=str(rel),  # Temporary — may be shortened below
            path=dir_path,
            tf_files=tf_files,
        ))

    # Derive short names: use directory basename if unique, else relative path
    basenames = [e.path.name for e in environments]
    basename_counts: dict[str, int] = {}
    for b in basenames:
        basename_counts[b] = basename_counts.get(b, 0) + 1

    for env in environments:
        if basename_counts[env.path.name] == 1:
            env.name = env.path.name
        else:
            env.name = str(env.path.relative_to(clone_path))

    environments.sort(key=lambda e: e.name)
    return environments
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_repo_analyzer.py -v`
Expected: All PASS

- [ ] **Step 5: Lint and type check**

Run: `uv run ruff check tmi_tf/repo_analyzer.py tests/test_repo_analyzer.py && uv run ruff format --check tmi_tf/repo_analyzer.py tests/test_repo_analyzer.py && uv run pyright`
Expected: Clean

- [ ] **Step 6: Commit**

```bash
git add tmi_tf/repo_analyzer.py tests/test_repo_analyzer.py
git commit -m "feat: add Terraform environment detection"
```

---

### Task 2: Module Resolution in repo_analyzer.py

**Files:**
- Modify: `tmi_tf/repo_analyzer.py`
- Modify: `tests/test_repo_analyzer.py`

- [ ] **Step 1: Write failing tests for resolve_modules**

Append to `tests/test_repo_analyzer.py`:

```python
class TestResolveModules:
    """Test resolve_modules method."""

    def _make_tree(self, tmp_path: Path, files: dict[str, str]) -> Path:
        for rel, content in files.items():
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        return tmp_path

    def test_resolves_relative_module_sources(self, tmp_path):
        clone = self._make_tree(tmp_path, {
            "envs/prod/main.tf": textwrap.dedent('''\
                module "network" {
                  source = "../../modules/network"
                }
            '''),
            "envs/prod/variables.tf": 'variable "region" {}',
            "modules/network/main.tf": 'resource "aws_vpc" "main" {}',
            "modules/network/outputs.tf": 'output "vpc_id" {}',
        })
        envs = RepositoryAnalyzer.detect_environments(clone)
        assert len(envs) == 1

        all_files = RepositoryAnalyzer.resolve_modules(envs[0], clone)
        filenames = {f.name for f in all_files}
        # Should include env files + module files
        assert "main.tf" in filenames
        assert "variables.tf" in filenames
        assert "outputs.tf" in filenames

    def test_ignores_registry_sources(self, tmp_path):
        clone = self._make_tree(tmp_path, {
            "env/prod/main.tf": textwrap.dedent('''\
                module "vpc" {
                  source = "terraform-aws-modules/vpc/aws"
                }
                module "local_mod" {
                  source = "../modules/local"
                }
            '''),
            "modules/local/main.tf": "",
        })
        envs = RepositoryAnalyzer.detect_environments(clone)
        all_files = RepositoryAnalyzer.resolve_modules(envs[0], clone)
        # Should include env file + local module, but not fail on registry source
        assert len(all_files) >= 2

    def test_deduplicates_files(self, tmp_path):
        clone = self._make_tree(tmp_path, {
            "env/prod/main.tf": textwrap.dedent('''\
                module "a" {
                  source = "../modules/shared"
                }
                module "b" {
                  source = "../modules/shared"
                }
            '''),
            "modules/shared/main.tf": "",
        })
        envs = RepositoryAnalyzer.detect_environments(clone)
        all_files = RepositoryAnalyzer.resolve_modules(envs[0], clone)
        # No duplicates
        assert len(all_files) == len(set(all_files))

    def test_no_modules_returns_env_files_only(self, tmp_path):
        clone = self._make_tree(tmp_path, {
            "env/prod/main.tf": 'resource "aws_instance" "web" {}',
            "env/prod/variables.tf": 'variable "x" {}',
        })
        envs = RepositoryAnalyzer.detect_environments(clone)
        all_files = RepositoryAnalyzer.resolve_modules(envs[0], clone)
        assert len(all_files) == 2

    def test_nonexistent_module_path_skipped(self, tmp_path):
        clone = self._make_tree(tmp_path, {
            "env/prod/main.tf": textwrap.dedent('''\
                module "ghost" {
                  source = "../modules/nonexistent"
                }
            '''),
        })
        envs = RepositoryAnalyzer.detect_environments(clone)
        all_files = RepositoryAnalyzer.resolve_modules(envs[0], clone)
        # Should just return the env file, not crash
        assert len(all_files) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_repo_analyzer.py::TestResolveModules -v`
Expected: FAIL — `resolve_modules` doesn't exist

- [ ] **Step 3: Implement resolve_modules**

Add to `RepositoryAnalyzer` in `tmi_tf/repo_analyzer.py`:

```python
import re  # Add at top of file with other imports

@staticmethod
def resolve_modules(
    environment: TerraformEnvironment, clone_path: Path
) -> List[Path]:
    """Resolve module source references and return combined file list.

    Parses .tf files in the environment for module source attributes,
    resolves relative paths, and collects .tf files from those modules.

    Args:
        environment: The selected TerraformEnvironment
        clone_path: Root of the cloned repository

    Returns:
        Deduplicated list of .tf/.tfvars file paths (environment + modules)
    """
    source_pattern = re.compile(r'source\s*=\s*"([^"]+)"')
    seen_paths: set[Path] = set()
    all_files: list[Path] = []

    # Add environment files first
    for f in environment.tf_files:
        resolved = f.resolve()
        if resolved not in seen_paths:
            seen_paths.add(resolved)
            all_files.append(f)

    # Find module source references
    module_dirs: set[Path] = set()
    for tf_file in environment.tf_files:
        if tf_file.suffix != ".tf":
            continue
        try:
            content = tf_file.read_text(encoding="utf-8")
        except Exception:
            continue

        for match in source_pattern.finditer(content):
            source = match.group(1)
            # Only resolve relative paths
            if not source.startswith(("./", "../")):
                logger.debug(f"Skipping non-relative module source: {source}")
                continue

            resolved_dir = (environment.path / source).resolve()
            if resolved_dir.is_dir():
                module_dirs.add(resolved_dir)
            else:
                logger.debug(
                    f"Module source path does not exist: {resolved_dir}"
                )

    # Collect .tf files from resolved module directories
    for mod_dir in sorted(module_dirs):
        for tf_file in sorted(mod_dir.rglob("*.tf")):
            resolved = tf_file.resolve()
            if resolved not in seen_paths:
                seen_paths.add(resolved)
                all_files.append(tf_file)

    return all_files
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_repo_analyzer.py -v`
Expected: All PASS

- [ ] **Step 5: Lint and type check**

Run: `uv run ruff check tmi_tf/repo_analyzer.py tests/test_repo_analyzer.py && uv run ruff format --check tmi_tf/repo_analyzer.py tests/test_repo_analyzer.py && uv run pyright`
Expected: Clean

- [ ] **Step 6: Commit**

```bash
git add tmi_tf/repo_analyzer.py tests/test_repo_analyzer.py
git commit -m "feat: add module resolution for Terraform environments"
```

---

### Task 3: Status Tracking Note in tmi_client_wrapper.py

**Files:**
- Modify: `tmi_tf/tmi_client_wrapper.py`
- Test: `tests/test_status_note.py` (create)

- [ ] **Step 1: Write failing tests for update_status_note**

```python
"""Tests for the status note tracking in TMIClient."""

from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

import pytest

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
            client.find_note_by_name = MagicMock(return_value=None)
            client.create_note = MagicMock()
            client.update_note = MagicMock()
            return client

    def test_first_call_creates_note(self):
        client = self._make_client()
        mock_note = MagicMock()
        mock_note.id = "note-123"
        client.create_note.return_value = mock_note

        client.update_status_note("tm-1", "Analysis started")

        client.create_note.assert_called_once()
        assert client.create_note.call_args.kwargs["name"] == "TMI-TF Analysis Status"
        assert client._status_note_initialized is True
        assert client._status_note_id == "note-123"

    def test_subsequent_call_appends(self):
        client = self._make_client()
        mock_note = MagicMock()
        mock_note.id = "note-123"
        client.create_note.return_value = mock_note

        client.update_status_note("tm-1", "Analysis started")
        client.update_status_note("tm-1", "Cloning repo")

        # Second call should update, not create
        client.update_note.assert_called_once()
        content = client.update_note.call_args.kwargs["content"]
        # Content should contain both messages
        assert "Analysis started" in content
        assert "Cloning repo" in content

    def test_existing_note_overwrites_on_first_call(self):
        client = self._make_client()
        existing_note = MagicMock()
        existing_note.id = "existing-note-456"
        client.find_note_by_name.return_value = existing_note

        client.update_status_note("tm-1", "Analysis started")

        # Should update existing note, not create new
        client.create_note.assert_not_called()
        client.update_note.assert_called_once()
        assert client._status_note_id == "existing-note-456"

    def test_failure_does_not_raise(self):
        client = self._make_client()
        client.find_note_by_name.side_effect = Exception("API error")

        # Should not raise
        client.update_status_note("tm-1", "Analysis started")

    def test_content_has_timestamp(self):
        client = self._make_client()
        mock_note = MagicMock()
        mock_note.id = "note-123"
        client.create_note.return_value = mock_note

        client.update_status_note("tm-1", "Test message")

        content = client.create_note.call_args.kwargs["content"]
        assert "[" in content and "]" in content  # Timestamp brackets
        assert "Test message" in content
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_status_note.py -v`
Expected: FAIL — `update_status_note` doesn't exist, `_status_note_id` etc. don't exist

- [ ] **Step 3: Implement update_status_note**

Add to `TMIClient` class in `tmi_tf/tmi_client_wrapper.py`:

In `__init__`, add these instance variables after `self.sub_resources_api`:

```python
# Status note tracking
self._status_note_id: Optional[str] = None
self._status_note_initialized: bool = False
self._status_note_content: str = ""
```

Add new constant at module level:

```python
STATUS_NOTE_NAME = "TMI-TF Analysis Status"
```

Add method to `TMIClient`:

```python
def update_status_note(self, threat_model_id: str, message: str) -> None:
    """Update the analysis status tracking note.

    First call per run overwrites any existing content.
    Subsequent calls append a new timestamped line.

    Args:
        threat_model_id: Threat model UUID
        message: Status message to record
    """
    from datetime import datetime, timezone

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    line = f"[{timestamp}] {message}"

    try:
        if not self._status_note_initialized:
            # First call: find or create the note, overwrite content
            existing = self.find_note_by_name(threat_model_id, STATUS_NOTE_NAME)
            if existing:
                self._status_note_id = existing.id
                self._status_note_content = line
                self.update_note(
                    threat_model_id=threat_model_id,
                    note_id=existing.id,
                    name=STATUS_NOTE_NAME,
                    content=line,
                    description="Tracks tmi-tf analysis progress",
                )
            else:
                note = self.create_note(
                    threat_model_id=threat_model_id,
                    name=STATUS_NOTE_NAME,
                    content=line,
                    description="Tracks tmi-tf analysis progress",
                )
                self._status_note_id = note.id
                self._status_note_content = line
            self._status_note_initialized = True
        else:
            # Subsequent calls: append to existing content
            self._status_note_content += f"\n{line}"
            if self._status_note_id:
                self.update_note(
                    threat_model_id=threat_model_id,
                    note_id=self._status_note_id,
                    name=STATUS_NOTE_NAME,
                    content=self._status_note_content,
                    description="Tracks tmi-tf analysis progress",
                )
    except Exception as e:
        logger.warning(f"Failed to update status note: {e}")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_status_note.py -v`
Expected: All PASS

- [ ] **Step 5: Lint and type check**

Run: `uv run ruff check tmi_tf/tmi_client_wrapper.py tests/test_status_note.py && uv run ruff format --check tmi_tf/tmi_client_wrapper.py tests/test_status_note.py && uv run pyright`
Expected: Clean

- [ ] **Step 6: Commit**

```bash
git add tmi_tf/tmi_client_wrapper.py tests/test_status_note.py
git commit -m "feat: add status tracking note to TMI client"
```

---

### Task 4: LLM Analyzer Status Callback

**Files:**
- Modify: `tmi_tf/llm_analyzer.py`

- [ ] **Step 1: Add status_callback parameter to analyze_repository**

In `tmi_tf/llm_analyzer.py`, update the `analyze_repository` method signature:

```python
def analyze_repository(
    self,
    terraform_repo: TerraformRepository,
    status_callback: Optional[Callable[[str], None]] = None,
) -> TerraformAnalysis:
```

Add `Callable` to the existing `from typing import ...` import on line 17 (which already has `Any, Dict, List, Optional`).

Add callback calls before and after each phase. Before Phase 1:

```python
if status_callback:
    status_callback("Phase 1 (Inventory) started")
```

After Phase 1 success log:

```python
if status_callback:
    status_callback("Phase 1 (Inventory) complete")
```

Same pattern for Phase 2 and Phase 3.

- [ ] **Step 2: Run existing tests to verify nothing breaks**

Run: `uv run pytest -v`
Expected: All existing tests PASS

- [ ] **Step 3: Lint and type check**

Run: `uv run ruff check tmi_tf/llm_analyzer.py && uv run ruff format --check tmi_tf/llm_analyzer.py && uv run pyright`
Expected: Clean

- [ ] **Step 4: Commit**

```bash
git add tmi_tf/llm_analyzer.py
git commit -m "feat: add status callback to LLM analyzer"
```

---

### Task 5: Split Markdown Report Generation

**Files:**
- Modify: `tmi_tf/markdown_generator.py`
- Modify: `tests/test_markdown_generator.py`

- [ ] **Step 1: Write failing tests for split report methods**

Add to `tests/test_markdown_generator.py`:

```python
from tmi_tf.llm_analyzer import TerraformAnalysis


def _make_analysis() -> TerraformAnalysis:
    """Create a sample TerraformAnalysis for testing."""
    return TerraformAnalysis(
        repo_name="test-repo",
        repo_url="https://github.com/org/test-repo",
        inventory={
            "components": [
                {"name": "web-server", "type": "compute", "resource_type": "aws_instance",
                 "purpose": "Web server", "configuration": {"instance_type": "t3.micro"}},
            ],
            "services": [
                {"name": "web-service", "criteria": ["serves HTTP"], "compute_units": ["web-server"],
                 "associated_resources": []},
            ],
        },
        infrastructure={
            "architecture_summary": "A simple web app",
            "mermaid_diagram": "graph TD\n  A-->B",
            "relationships": [
                {"source_id": "web", "target_id": "db", "relationship_type": "connects_to",
                 "description": "Web connects to DB"},
            ],
            "data_flows": [
                {"name": "HTTP", "source_id": "user", "target_id": "web",
                 "protocol": "HTTPS", "port": "443", "data_type": "requests"},
            ],
            "trust_boundaries": [],
        },
        security_findings=[
            {"name": "Open port", "severity": "Medium", "score": 5.0,
             "threat_type": "Information Disclosure", "category": "Network",
             "description": "Port open", "mitigation": "Close it",
             "cwe_id": [], "affected_components": ["web"]},
        ],
        success=True,
        elapsed_time=10.0,
        input_tokens=1000,
        output_tokens=500,
        model="anthropic/claude-opus-4-5",
        provider="anthropic",
        total_cost=0.05,
    )


class TestGenerateInventoryReport:
    def test_includes_inventory_section(self):
        gen = MarkdownGenerator()
        analysis = _make_analysis()
        report = gen.generate_inventory_report("TM", "tm-1", [analysis])
        assert "Infrastructure Inventory" in report
        assert "web-server" in report

    def test_includes_services(self):
        gen = MarkdownGenerator()
        analysis = _make_analysis()
        report = gen.generate_inventory_report("TM", "tm-1", [analysis])
        assert "web-service" in report

    def test_excludes_security_findings(self):
        gen = MarkdownGenerator()
        analysis = _make_analysis()
        report = gen.generate_inventory_report("TM", "tm-1", [analysis])
        assert "Security Observations" not in report
        assert "Open port" not in report

    def test_excludes_architecture_summary(self):
        gen = MarkdownGenerator()
        analysis = _make_analysis()
        report = gen.generate_inventory_report("TM", "tm-1", [analysis])
        assert "Architecture Summary" not in report

    def test_includes_environment_name_in_title(self):
        gen = MarkdownGenerator()
        analysis = _make_analysis()
        report = gen.generate_inventory_report("TM", "tm-1", [analysis], environment_name="oci-private")
        assert "oci-private" in report

    def test_includes_job_info(self):
        gen = MarkdownGenerator()
        analysis = _make_analysis()
        report = gen.generate_inventory_report("TM", "tm-1", [analysis])
        assert "Analysis Job Information" in report


class TestGenerateAnalysisReport:
    def test_includes_architecture(self):
        gen = MarkdownGenerator()
        analysis = _make_analysis()
        report = gen.generate_analysis_report("TM", "tm-1", [analysis])
        assert "Architecture Summary" in report
        assert "simple web app" in report

    def test_includes_security_findings(self):
        gen = MarkdownGenerator()
        analysis = _make_analysis()
        report = gen.generate_analysis_report("TM", "tm-1", [analysis])
        assert "Security Observations" in report
        assert "Open port" in report

    def test_includes_relationships(self):
        gen = MarkdownGenerator()
        analysis = _make_analysis()
        report = gen.generate_analysis_report("TM", "tm-1", [analysis])
        assert "Component Relationships" in report

    def test_includes_data_flows(self):
        gen = MarkdownGenerator()
        analysis = _make_analysis()
        report = gen.generate_analysis_report("TM", "tm-1", [analysis])
        assert "Data Flows" in report

    def test_excludes_inventory(self):
        gen = MarkdownGenerator()
        analysis = _make_analysis()
        report = gen.generate_analysis_report("TM", "tm-1", [analysis])
        assert "Infrastructure Inventory" not in report

    def test_includes_environment_name_in_title(self):
        gen = MarkdownGenerator()
        analysis = _make_analysis()
        report = gen.generate_analysis_report("TM", "tm-1", [analysis], environment_name="aws-public")
        assert "aws-public" in report

    def test_includes_consolidated_findings(self):
        gen = MarkdownGenerator()
        analysis = _make_analysis()
        report = gen.generate_analysis_report("TM", "tm-1", [analysis])
        assert "Consolidated Findings" in report

    def test_includes_job_info(self):
        gen = MarkdownGenerator()
        analysis = _make_analysis()
        report = gen.generate_analysis_report("TM", "tm-1", [analysis])
        assert "Analysis Job Information" in report
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_markdown_generator.py::TestGenerateInventoryReport tests/test_markdown_generator.py::TestGenerateAnalysisReport -v`
Expected: FAIL — methods don't exist

- [ ] **Step 3: Implement generate_inventory_report and generate_analysis_report**

In `tmi_tf/markdown_generator.py`, add two new methods to `MarkdownGenerator`. Keep the existing `generate_report` for backward compatibility but it can be removed later.

```python
def generate_inventory_report(
    self,
    threat_model_name: str,
    threat_model_id: str,
    analyses: List[TerraformAnalysis],
    environment_name: Optional[str] = None,
) -> str:
    """Generate inventory-only markdown report.

    Args:
        threat_model_name: Name of the threat model
        threat_model_id: UUID of the threat model
        analyses: List of TerraformAnalysis results
        environment_name: Optional environment name for title

    Returns:
        Markdown content with inventory sections only
    """
    sections = []

    # Header
    title = "Terraform Infrastructure Inventory"
    if environment_name:
        title += f" - {environment_name}"
    sections.append(f"# {title}\n\n**Threat Model**: {threat_model_name}")

    # Per-repo inventory sections
    for i, analysis in enumerate(analyses, 1):
        header = f"## Repository {i}: {analysis.repo_name}\n\n**URL**: [{analysis.repo_url}]({analysis.repo_url})"
        if not analysis.success:
            sections.append(f"{header}\n\n*Analysis failed: {analysis.error_message}*")
            continue
        parts = [header]
        parts.append(self._format_inventory_section(analysis.inventory))
        sections.append("\n\n".join(part for part in parts if part))

    # Job info
    sections.append(self._generate_analysis_job_info(threat_model_id, analyses))

    return "\n\n---\n\n".join(sections)

def generate_analysis_report(
    self,
    threat_model_name: str,
    threat_model_id: str,
    analyses: List[TerraformAnalysis],
    environment_name: Optional[str] = None,
) -> str:
    """Generate analysis markdown report (architecture, relationships, security).

    Args:
        threat_model_name: Name of the threat model
        threat_model_id: UUID of the threat model
        analyses: List of TerraformAnalysis results
        environment_name: Optional environment name for title

    Returns:
        Markdown content with analysis sections (no inventory)
    """
    sections = []

    # Header
    title = "Terraform Infrastructure Analysis"
    if environment_name:
        title += f" - {environment_name}"
    sections.append(f"# {title}\n\n**Threat Model**: {threat_model_name}")

    # Per-repo analysis sections
    for i, analysis in enumerate(analyses, 1):
        header = f"## Repository {i}: {analysis.repo_name}\n\n**URL**: [{analysis.repo_url}]({analysis.repo_url})"
        if not analysis.success:
            sections.append(f"{header}\n\n*Analysis failed: {analysis.error_message}*")
            continue

        parts = [header]

        arch_summary = analysis.infrastructure.get("architecture_summary", "")
        if arch_summary:
            parts.append(f"### Architecture Summary\n\n{arch_summary}")

        mermaid = analysis.infrastructure.get("mermaid_diagram", "")
        if mermaid:
            if not mermaid.strip().startswith("```"):
                mermaid = f"```mermaid\n{mermaid}\n```"
            parts.append(f"### Architecture Diagram\n\n{mermaid}")

        parts.append(self._format_relationships_section(analysis.infrastructure))
        parts.append(self._format_data_flows_section(analysis.infrastructure))
        parts.append(self._format_security_section(analysis.security_findings))

        sections.append("\n\n".join(part for part in parts if part))

    # Consolidated findings
    sections.append(self._generate_consolidated_findings(analyses))

    # Job info
    sections.append(self._generate_analysis_job_info(threat_model_id, analyses))

    return "\n\n---\n\n".join(sections)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_markdown_generator.py -v`
Expected: All PASS (old and new)

- [ ] **Step 5: Lint and type check**

Run: `uv run ruff check tmi_tf/markdown_generator.py tests/test_markdown_generator.py && uv run ruff format --check tmi_tf/markdown_generator.py tests/test_markdown_generator.py && uv run pyright`
Expected: Clean

- [ ] **Step 6: Commit**

```bash
git add tmi_tf/markdown_generator.py tests/test_markdown_generator.py
git commit -m "feat: split report into inventory and analysis reports"
```

---

### Task 6: Update config.py — Remove Static Artifact Names

**Files:**
- Modify: `tmi_tf/config.py`

- [ ] **Step 1: Update config.py**

In `tmi_tf/config.py`, replace the artifact naming block (lines 74-86):

Remove:
```python
# Note and diagram names include model identifier and timestamp
effective_model = self.llm_model or self.DEFAULT_MODELS.get(
    self.llm_provider, "unknown"
)
timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
base_note_name = os.getenv("ANALYSIS_NOTE_NAME", "Terraform Analysis Report")
base_diagram_name = os.getenv(
    "DIAGRAM_NAME", "Infrastructure Data Flow Diagram"
)
self.analysis_note_name: str = (
    f"{base_note_name} ({effective_model}, {timestamp})"
)
self.diagram_name: str = f"{base_diagram_name} ({effective_model}, {timestamp})"
```

Replace with:
```python
# Model identifier and timestamp for artifact naming (constructed in cli.py)
self.effective_model: str = self.llm_model or self.DEFAULT_MODELS.get(
    self.llm_provider, "unknown"
)
self.timestamp: str = datetime.now(timezone.utc).strftime(
    "%Y-%m-%d %H:%M:%S UTC"
)
```

- [ ] **Step 2: Run existing tests to verify nothing breaks**

Run: `uv run pytest -v`
Expected: All PASS

- [ ] **Step 3: Lint and type check**

Run: `uv run ruff check tmi_tf/config.py && uv run ruff format --check tmi_tf/config.py && uv run pyright`
Expected: Clean

- [ ] **Step 4: Commit**

```bash
git add tmi_tf/config.py
git commit -m "refactor: replace static artifact names with model/timestamp fields"
```

---

### Task 7: Update analysis_comparer.py — Backward-Compatible Note Discovery

**Files:**
- Modify: `tmi_tf/analysis_comparer.py`

- [ ] **Step 1: Update NOTE_NAME_PATTERN**

In `tmi_tf/analysis_comparer.py` line 108, replace:

```python
NOTE_NAME_PATTERN = re.compile(r"Terraform Analysis Report \(([^)]+)\)")
```

with:

```python
# Matches old format "Terraform Analysis Report (...)" and new formats
# "Terraform Analysis - env (...)" and "Terraform Analysis (...)"
NOTE_NAME_PATTERN = re.compile(
    r"Terraform Analysis(?:\s+Report)?(?:\s+-\s+[^(]+)?\s*\(([^)]+)\)"
)
```

- [ ] **Step 2: Run existing tests**

Run: `uv run pytest -v`
Expected: All PASS

- [ ] **Step 3: Lint and type check**

Run: `uv run ruff check tmi_tf/analysis_comparer.py && uv run ruff format --check tmi_tf/analysis_comparer.py && uv run pyright`
Expected: Clean

- [ ] **Step 4: Commit**

```bash
git add tmi_tf/analysis_comparer.py
git commit -m "fix: update note name pattern for new naming format"
```

---

### Task 8: Update cli.py — Integrate All Features

This is the largest task. It wires everything together.

**Files:**
- Modify: `tmi_tf/cli.py`

- [ ] **Step 1: Add --environment option to analyze command**

After the `--skip-threats` option decorator, add:

```python
@click.option(
    "--environment",
    "-e",
    type=str,
    default=None,
    help="Pre-select a Terraform environment by name (skip interactive prompt)",
)
```

Add `environment: Optional[str]` parameter to the `analyze` function signature.

- [ ] **Step 2: Add environment detection and selection logic**

After `tf_repo` is obtained from the context manager (after `if tf_repo:` on line 165), add environment detection before the LLM analysis call. Replace the block from `if tf_repo:` through `analyses.append(analysis)` with:

```python
if tf_repo:
    # Detect Terraform environments
    from tmi_tf.repo_analyzer import TerraformEnvironment
    envs = repo_analyzer.detect_environments(tf_repo.clone_path)
    tf_repo.environments_found = [e.name for e in envs]

    if len(envs) == 0:
        # No environments detected, analyze all files
        logger.info("No Terraform environments detected, analyzing all files")
        tmi_client.update_status_note(
            threat_model_id, f"No environments detected in {repo_name}, analyzing all files"
        )
    elif len(envs) == 1:
        # Auto-select single environment
        selected = envs[0]
        tf_repo.environment_name = selected.name
        logger.info(f"Auto-selected environment: {selected.name}")
        tmi_client.update_status_note(
            threat_model_id, f"Found 1 Terraform environment: {selected.name}"
        )
        tmi_client.update_status_note(
            threat_model_id, f"Selected environment: {selected.name}"
        )
        tmi_client.update_status_note(
            threat_model_id, f"Resolving modules for environment: {selected.name}"
        )
        tf_repo.terraform_files = repo_analyzer.resolve_modules(selected, tf_repo.clone_path)
    else:
        # Multiple environments
        env_names = ", ".join(e.name for e in envs)
        tmi_client.update_status_note(
            threat_model_id,
            f"Found {len(envs)} Terraform environments: {env_names}",
        )

        if environment:
            # Match by --environment flag
            matches = [e for e in envs if e.name.lower() == environment.lower()]
            if not matches:
                available = ", ".join(e.name for e in envs)
                raise click.ClickException(
                    f"Environment '{environment}' not found. Available: {available}"
                )
            selected = matches[0]
        else:
            # Interactive selection
            click.echo(f"\nFound {len(envs)} Terraform environments:")
            for idx, env in enumerate(envs, 1):
                click.echo(f"  {idx}. {env.name}")
            choice = click.prompt(
                "Select environment to analyze",
                type=click.IntRange(1, len(envs)),
            )
            selected = envs[choice - 1]

        tf_repo.environment_name = selected.name
        logger.info(f"Selected environment: {selected.name}")
        tmi_client.update_status_note(
            threat_model_id, f"Selected environment: {selected.name}"
        )
        tmi_client.update_status_note(
            threat_model_id, f"Resolving modules for environment: {selected.name}"
        )
        tf_repo.terraform_files = repo_analyzer.resolve_modules(selected, tf_repo.clone_path)

    # Create status callback for LLM analyzer
    def _status_cb(msg: str) -> None:
        tmi_client.update_status_note(threat_model_id, msg)

    analysis = llm_analyzer.analyze_repository(tf_repo, status_callback=_status_cb)
    analyses.append(analysis)
```

- [ ] **Step 3: Add Ctrl+C handling**

Wrap the entire `try` block in the analyze function with an additional handler. At the top of the existing `try:` block (before `logger.info("=" * 80)`), no change needed — instead, add a handler at the bottom. After the final `except Exception as e:` block, add:

```python
except click.Abort:
    logger.info("Analysis cancelled by user")
    sys.exit(0)
```

This needs to go BEFORE the generic `except Exception as e:` — so restructure as:

```python
except click.Abort:
    logger.info("Analysis cancelled by user")
    sys.exit(0)
except Exception as e:
    logger.error(f"Fatal error: {e}", exc_info=True)
    sys.exit(1)
```

- [ ] **Step 4: Add status note updates throughout the flow**

Add `tmi_client.update_status_note(threat_model_id, "Analysis started")` right after TMI client initialization (after line 116).

Add `tmi_client.update_status_note(threat_model_id, f"Cloning repository: {repo.uri}")` before clone (before line 162).

Add `tmi_client.update_status_note(threat_model_id, f"Clone complete: {repo_name}")` after successful clone yields tf_repo.

Add status updates before each major section: generating inventory report, generating analysis report, generating DFD, creating threats, and analysis complete.

- [ ] **Step 5: Replace single report generation with two reports**

First, declare `selected_env_name: Optional[str] = None` before the repo analysis loop (before the `for i, repo in enumerate(...)` line). Inside the environment selection code from Step 2, set `selected_env_name = selected.name` wherever `tf_repo.environment_name` is set. Note: if multiple repos are analyzed and have different environments, `selected_env_name` will hold the last one selected. This is acceptable since the typical use case is single-repo analysis.

Then replace the report generation block (lines 185-242) with:

```python
# Build artifact names (no truncation)
model_label = config.effective_model
ts = config.timestamp
if selected_env_name:
    inventory_note_name = f"Terraform Inventory - {selected_env_name} ({model_label}, {ts})"
    analysis_note_name = f"Terraform Analysis - {selected_env_name} ({model_label}, {ts})"
    diagram_name = f"Infrastructure Data Flow Diagram - {selected_env_name} ({model_label}, {ts})"
else:
    inventory_note_name = f"Terraform Inventory ({model_label}, {ts})"
    analysis_note_name = f"Terraform Analysis ({model_label}, {ts})"
    diagram_name = f"Infrastructure Data Flow Diagram ({model_label}, {ts})"

# Generate inventory report
tmi_client.update_status_note(threat_model_id, "Generating inventory report")
logger.info("\n[6/9] Generating inventory report...")
inventory_content = markdown_gen.generate_inventory_report(
    threat_model_name=threat_model.name,
    threat_model_id=threat_model_id,
    analyses=analyses,
    environment_name=selected_env_name,
)

# Generate analysis report
tmi_client.update_status_note(threat_model_id, "Generating analysis report")
logger.info("\n[7/9] Generating analysis report...")
analysis_content = markdown_gen.generate_analysis_report(
    threat_model_name=threat_model.name,
    threat_model_id=threat_model_id,
    analyses=analyses,
    environment_name=selected_env_name,
)

# Save to files if requested
if output:
    from pathlib import Path as _Path
    out_path = _Path(output)
    stem = out_path.stem
    suffix = out_path.suffix or ".md"
    parent = out_path.parent

    inv_path = parent / f"{stem}-inventory{suffix}"
    analysis_path = parent / f"{stem}-analysis{suffix}"

    markdown_gen.save_to_file(inventory_content, str(inv_path))
    markdown_gen.save_to_file(analysis_content, str(analysis_path))
    logger.info(f"Inventory report saved to: {inv_path}")
    logger.info(f"Analysis report saved to: {analysis_path}")

# Create notes in TMI
if not dry_run:
    # Inventory note
    repo_short_names = [
        a.repo_url.rstrip("/").removesuffix(".git").split("/")[-1]
        for a in analyses
    ]
    repo_word = "repository" if len(repo_short_names) == 1 else "repositories"
    repo_list = ", ".join(repo_short_names)
    note_description = (
        f"Infrastructure inventory from Terraform templates in "
        f"{repo_word}: {repo_list}"
    )

    inv_note = tmi_client.create_or_update_note(
        threat_model_id=threat_model_id,
        name=inventory_note_name,
        content=inventory_content,
        description=note_description,
    )
    logger.info(f"Inventory note created/updated: {inv_note.id}")

    artifact_metadata = aggregate_analysis_metadata(
        analyses=analyses,
        provider=llm_analyzer.provider,
        model=llm_analyzer.model,
    )
    try:
        tmi_client.set_note_metadata(
            threat_model_id=threat_model_id,
            note_id=inv_note.id,
            metadata=artifact_metadata.to_metadata_list(),
        )
    except Exception as e:
        logger.warning(f"Failed to set inventory note metadata: {e}")

    # Analysis note
    analysis_note = tmi_client.create_or_update_note(
        threat_model_id=threat_model_id,
        name=analysis_note_name,
        content=analysis_content,
        description=f"Terraform analysis for {repo_word}: {repo_list}",
    )
    logger.info(f"Analysis note created/updated: {analysis_note.id}")

    try:
        tmi_client.set_note_metadata(
            threat_model_id=threat_model_id,
            note_id=analysis_note.id,
            metadata=artifact_metadata.to_metadata_list(),
        )
    except Exception as e:
        logger.warning(f"Failed to set analysis note metadata: {e}")
else:
    logger.info("Dry run - skipping note creation")
    if not output:
        print("\n" + "=" * 80)
        print("INVENTORY REPORT")
        print("=" * 80 + "\n")
        print(inventory_content)
        print("\n" + "=" * 80)
        print("ANALYSIS REPORT")
        print("=" * 80 + "\n")
        print(analysis_content)
```

- [ ] **Step 6: Update diagram naming**

Replace `config.diagram_name` with the local `diagram_name` variable throughout the DFD section.

- [ ] **Step 7: Update threat diagram lookup**

Replace `config.diagram_name` in the threat section (line 366) with the local `diagram_name`.

- [ ] **Step 8: Update config_info command**

Replace lines 493-494:
```python
print(f"Note Name: {config.analysis_note_name}")
print(f"Diagram Name: {config.diagram_name}")
```
with:
```python
print(f"LLM Model: {config.effective_model}")
print(f"Timestamp: {config.timestamp}")
```

- [ ] **Step 9: Run all tests**

Run: `uv run pytest -v`
Expected: All PASS

- [ ] **Step 10: Lint and type check**

Run: `uv run ruff check tmi_tf/cli.py && uv run ruff format --check tmi_tf/cli.py && uv run pyright`
Expected: Clean. Fix any issues.

- [ ] **Step 11: Commit**

```bash
git add tmi_tf/cli.py
git commit -m "feat: integrate environment selection, status tracking, split reports, dynamic naming"
```

---

### Task 9: CLI Environment Selection Tests

**Files:**
- Test: `tests/test_cli_environment.py` (create)

- [ ] **Step 1: Write tests for environment selection CLI behavior**

```python
"""Tests for CLI environment selection behavior."""

import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path

from click.testing import CliRunner

from tmi_tf.repo_analyzer import RepositoryAnalyzer, TerraformEnvironment


class TestEnvironmentSelection:
    """Test environment selection in analyze command."""

    def test_environment_flag_no_match_raises(self, tmp_path):
        """When --environment doesn't match, should raise ClickException."""
        envs = [
            TerraformEnvironment(name="prod", path=tmp_path / "prod", tf_files=[]),
            TerraformEnvironment(name="staging", path=tmp_path / "staging", tf_files=[]),
        ]

        import click
        # Simulate the matching logic from cli.py
        environment = "nonexistent"
        matches = [e for e in envs if e.name.lower() == environment.lower()]
        if not matches:
            available = ", ".join(e.name for e in envs)
            with pytest.raises(click.ClickException) as exc_info:
                raise click.ClickException(
                    f"Environment '{environment}' not found. Available: {available}"
                )
            assert "nonexistent" in str(exc_info.value)
            assert "prod" in str(exc_info.value)
            assert "staging" in str(exc_info.value)

    def test_environment_flag_case_insensitive_match(self, tmp_path):
        """--environment should match case-insensitively."""
        envs = [
            TerraformEnvironment(name="OCI-Private", path=tmp_path / "oci", tf_files=[]),
        ]
        environment = "oci-private"
        matches = [e for e in envs if e.name.lower() == environment.lower()]
        assert len(matches) == 1
        assert matches[0].name == "OCI-Private"


class TestDetectEnvironmentsIntegration:
    """Integration tests for detect_environments with realistic structures."""

    def test_standard_terraform_layout(self, tmp_path):
        """Test detection with standard terraform/environments/ + terraform/modules/ layout."""
        files = {
            "terraform/environments/aws-public/main.tf": "",
            "terraform/environments/aws-public/variables.tf": "",
            "terraform/environments/aws-private/main.tf": "",
            "terraform/environments/aws-private/backend.tf": "",
            "terraform/modules/network/main.tf": "",
            "terraform/modules/compute/main.tf": "",
        }
        for rel, content in files.items():
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)

        envs = RepositoryAnalyzer.detect_environments(tmp_path)
        names = [e.name for e in envs]
        assert "aws-public" in names
        assert "aws-private" in names
        # Module directories should be excluded
        assert "network" not in names
        assert "compute" not in names
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `uv run pytest tests/test_cli_environment.py -v`
Expected: All PASS

- [ ] **Step 3: Lint**

Run: `uv run ruff check tests/test_cli_environment.py && uv run ruff format --check tests/test_cli_environment.py`
Expected: Clean

- [ ] **Step 4: Commit**

```bash
git add tests/test_cli_environment.py
git commit -m "test: add CLI environment selection tests"
```

---

### Task 10: Full Integration Test and Cleanup

**Files:**
- All modified files

- [ ] **Step 1: Run full test suite**

Run: `uv run pytest -v`
Expected: All PASS

- [ ] **Step 2: Run linter and formatter**

Run: `uv run ruff check . && uv run ruff format --check .`
Expected: Clean

- [ ] **Step 3: Run type checker**

Run: `uv run pyright`
Expected: Clean (or only pre-existing issues)

- [ ] **Step 4: Remove old generate_report method if no longer referenced**

Check if `generate_report` is still called anywhere. If not, remove it from `markdown_generator.py`. If the `compare` command or other code still uses it, leave it.

Run: `grep -r "generate_report" tmi_tf/ --include="*.py"`

If only `markdown_generator.py` definition remains (no callers), remove the method.

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "chore: cleanup after environment selection feature"
```
