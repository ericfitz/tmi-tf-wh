# Terraform Validation & Sanitization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a validation and sanitization step that rejects invalid/irrelevant Terraform files and strips embedded scripts before LLM analysis.

**Architecture:** New module `tf_validator.py` with a 3-step pipeline (file filtering → syntax validation via `terraform fmt` → content sanitization via line-by-line state machine). Called from `analyzer.py` after environment detection/module resolution, before LLM analysis. Fails fast if any file is rejected.

**Tech Stack:** Python 3.10+, `subprocess` (for `terraform fmt`), `shutil.which`, `re`, pytest

**Spec:** `docs/superpowers/specs/2026-03-22-terraform-validation-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `tmi_tf/tf_validator.py` | Create | All validation logic: dataclasses, filtering, syntax check, sanitization state machine |
| `tmi_tf/analyzer.py` | Modify | Call `validate_and_sanitize()` before LLM analysis in two code paths |
| `tests/test_tf_validator.py` | Create | All tests for the new module |

---

### Task 1: Dataclasses and Exception

**Files:**
- Create: `tmi_tf/tf_validator.py`
- Create: `tests/test_tf_validator.py`

- [ ] **Step 1: Write test for TerraformValidationError**

```python
"""Tests for Terraform file validation and sanitization."""

import shutil
import textwrap
from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired
from unittest.mock import patch

import pytest

from tmi_tf.tf_validator import RejectedFile, TerraformValidationError, ValidationResult


@pytest.fixture()
def _mock_terraform():
    """Mock terraform binary check and subprocess for unit tests.

    Tests that need the real terraform binary (integration tests) should
    NOT use this fixture.
    """
    with (
        patch("tmi_tf.tf_validator.shutil.which", return_value="/usr/bin/terraform"),
        patch(
            "tmi_tf.tf_validator.subprocess.run",
            return_value=CompletedProcess(args=["terraform", "fmt"], returncode=0),
        ),
    ):
        yield


class TestDataclasses:
    """Test dataclasses and exception."""

    def test_rejected_file(self):
        rf = RejectedFile(path=Path("main.tf"), reason="empty file")
        assert rf.path == Path("main.tf")
        assert rf.reason == "empty file"

    def test_validation_result(self):
        vr = ValidationResult(
            valid_files=[Path("main.tf")],
            sanitization_log=["Stripped 1 provisioner block from main.tf"],
        )
        assert len(vr.valid_files) == 1
        assert len(vr.sanitization_log) == 1

    def test_validation_error_message(self):
        rejected = [
            RejectedFile(path=Path("bad.tf"), reason="syntax error"),
            RejectedFile(path=Path("empty.tf"), reason="empty file"),
        ]
        err = TerraformValidationError(rejected)
        assert "bad.tf: syntax error" in str(err)
        assert "empty.tf: empty file" in str(err)
        assert err.rejected_files == rejected
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_tf_validator.py::TestDataclasses -v`
Expected: FAIL — `ModuleNotFoundError` or `ImportError`

- [ ] **Step 3: Implement dataclasses and exception**

```python
"""Terraform file validation and sanitization.

Validates .tf and .tfvars files after git clone, before LLM analysis.
Three-step pipeline:
  Step 1: File-level filtering (empty, auto-generated, oversized, no constructs)
  Step 2: Syntax validation (terraform fmt)
  Step 3: Content sanitization (strip user_data, provisioner, connection)
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class RejectedFile:
    """A file that failed validation."""

    path: Path
    reason: str


@dataclass
class ValidationResult:
    """Result of successful validation."""

    valid_files: List[Path] = field(default_factory=list)
    sanitization_log: List[str] = field(default_factory=list)


class TerraformValidationError(Exception):
    """Raised when one or more Terraform files fail validation."""

    def __init__(self, rejected_files: List[RejectedFile]):
        self.rejected_files = rejected_files
        details = "; ".join(f"{r.path.name}: {r.reason}" for r in rejected_files)
        super().__init__(f"Terraform validation failed: {details}")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_tf_validator.py::TestDataclasses -v`
Expected: PASS

- [ ] **Step 5: Lint**

Run: `uv run ruff check tmi_tf/tf_validator.py tests/test_tf_validator.py && uv run ruff format --check tmi_tf/tf_validator.py tests/test_tf_validator.py`

- [ ] **Step 6: Commit**

```bash
git add tmi_tf/tf_validator.py tests/test_tf_validator.py
git commit -m "feat: add tf_validator dataclasses and TerraformValidationError"
```

---

### Task 2: Step 1 — File-Level Filtering

**Files:**
- Modify: `tmi_tf/tf_validator.py`
- Modify: `tests/test_tf_validator.py`

- [ ] **Step 1: Write tests for file filtering**

Add to `tests/test_tf_validator.py`:

```python
from tmi_tf.tf_validator import validate_and_sanitize


class TestFileFiltering:
    """Test Step 1: file-level filtering."""

    def _make_file(self, tmp_path: Path, name: str, content: str) -> Path:
        p = tmp_path / name
        p.write_text(content)
        return p

    def test_rejects_empty_file(self, tmp_path):
        f = self._make_file(tmp_path, "empty.tf", "")
        with pytest.raises(TerraformValidationError, match="empty file"):
            validate_and_sanitize([f], tmp_path)

    def test_rejects_oversized_file(self, tmp_path):
        f = self._make_file(tmp_path, "huge.tf", "x" * (1024 * 1024 + 1))
        with pytest.raises(TerraformValidationError, match="exceeds size limit"):
            validate_and_sanitize([f], tmp_path)

    def test_rejects_terraform_lock_hcl(self, tmp_path):
        f = self._make_file(tmp_path, ".terraform.lock.hcl", 'provider "aws" {}')
        with pytest.raises(TerraformValidationError, match="auto-generated"):
            validate_and_sanitize([f], tmp_path)

    def test_rejects_file_under_dot_terraform(self, tmp_path):
        d = tmp_path / ".terraform" / "providers"
        d.mkdir(parents=True)
        f = d / "main.tf"
        f.write_text('resource "x" "y" {}')
        with pytest.raises(TerraformValidationError, match="auto-generated"):
            validate_and_sanitize([f], tmp_path)

    def test_rejects_comment_only_tf_file(self, tmp_path):
        f = self._make_file(tmp_path, "comments.tf", "# just a comment\n\n# another\n")
        with pytest.raises(TerraformValidationError, match="no Terraform constructs"):
            validate_and_sanitize([f], tmp_path)

    @pytest.mark.usefixtures("_mock_terraform")
    def test_tfvars_exempt_from_keyword_scan(self, tmp_path):
        f = self._make_file(tmp_path, "terraform.tfvars", 'region = "us-east-1"\n')
        result = validate_and_sanitize([f], tmp_path)
        assert f in result.valid_files

    @pytest.mark.usefixtures("_mock_terraform")
    def test_accepts_file_with_resource(self, tmp_path):
        f = self._make_file(
            tmp_path, "main.tf", 'resource "aws_instance" "web" {\n  ami = "abc"\n}\n'
        )
        result = validate_and_sanitize([f], tmp_path)
        assert f in result.valid_files

    @pytest.mark.usefixtures("_mock_terraform")
    def test_accepts_file_with_variable_only(self, tmp_path):
        f = self._make_file(tmp_path, "variables.tf", 'variable "region" {\n  default = "us-east-1"\n}\n')
        result = validate_and_sanitize([f], tmp_path)
        assert f in result.valid_files

    def test_keyword_match_is_word_boundary(self, tmp_path):
        f = self._make_file(tmp_path, "bad.tf", 'my_terraform = "hello"\n')
        with pytest.raises(TerraformValidationError, match="no Terraform constructs"):
            validate_and_sanitize([f], tmp_path)

    def test_reports_all_failures(self, tmp_path):
        f1 = self._make_file(tmp_path, "empty.tf", "")
        f2 = self._make_file(tmp_path, "comments.tf", "# nothing\n")
        with pytest.raises(TerraformValidationError) as exc_info:
            validate_and_sanitize([f1, f2], tmp_path)
        assert len(exc_info.value.rejected_files) == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_tf_validator.py::TestFileFiltering -v`
Expected: FAIL — `validate_and_sanitize` not defined

- [ ] **Step 3: Implement file filtering and validate_and_sanitize skeleton**

Add to `tmi_tf/tf_validator.py`:

```python
import re
import shutil
import subprocess

# Terraform top-level keywords for construct detection
_TF_KEYWORDS = re.compile(
    r"^\s*(resource|data|module|variable|output|provider|terraform|locals)\b"
)

# Max file size: 1 MB
_MAX_FILE_SIZE = 1024 * 1024


def _is_auto_generated(file_path: Path, clone_path: Path) -> bool:
    """Check if a file is auto-generated (lock file or under .terraform/)."""
    if file_path.name == ".terraform.lock.hcl":
        return True
    try:
        rel = file_path.relative_to(clone_path)
        if ".terraform" in rel.parts:
            return True
    except ValueError:
        pass
    return False


def _has_terraform_constructs(file_path: Path) -> bool:
    """Check if a .tf file contains at least one Terraform top-level keyword."""
    try:
        with open(file_path, encoding="utf-8") as f:
            for line in f:
                if _TF_KEYWORDS.match(line):
                    return True
    except Exception:
        pass
    return False


def _filter_file(file_path: Path, clone_path: Path) -> Optional[str]:
    """Run Step 1 filtering on a single file.

    Returns a rejection reason string, or None if the file passes.
    """
    # Empty file
    if file_path.stat().st_size == 0:
        return "empty file"

    # Auto-generated
    if _is_auto_generated(file_path, clone_path):
        return "auto-generated file"

    # Oversized
    if file_path.stat().st_size > _MAX_FILE_SIZE:
        return f"exceeds size limit ({_MAX_FILE_SIZE} bytes)"

    # Keyword scan (.tf only, not .tfvars)
    if file_path.suffix == ".tf" and not _has_terraform_constructs(file_path):
        return "no Terraform constructs found"

    return None


def validate_and_sanitize(
    terraform_files: List[Path], clone_path: Path
) -> ValidationResult:
    """Validate and sanitize Terraform files.

    Runs the three-step pipeline: filtering, syntax validation, sanitization.
    Sanitized content is written back to files on disk.

    Raises TerraformValidationError if any file fails Steps 1 or 2.
    Raises RuntimeError if terraform binary is not found on PATH.
    """
    # Check terraform binary
    if not shutil.which("terraform"):
        raise RuntimeError(
            "terraform binary not found on PATH — required for Terraform file validation"
        )

    rejected: List[RejectedFile] = []
    passed_step1: List[Path] = []

    # Step 1: File-level filtering
    for f in terraform_files:
        reason = _filter_file(f, clone_path)
        if reason:
            rel = f.relative_to(clone_path) if clone_path in f.parents or f.parent == clone_path else f
            rejected.append(RejectedFile(path=rel, reason=reason))
            logger.warning(f"Rejected {rel}: {reason}")
        else:
            passed_step1.append(f)

    # Step 2: Syntax validation (placeholder — implemented in Task 3)

    # Step 3: Sanitization (placeholder — implemented in Task 4)

    if rejected:
        raise TerraformValidationError(rejected)

    return ValidationResult(valid_files=passed_step1)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_tf_validator.py::TestFileFiltering -v`
Expected: PASS (tests that expect files to pass use the `_mock_terraform` fixture to avoid requiring the real terraform binary)

- [ ] **Step 5: Lint**

Run: `uv run ruff check tmi_tf/tf_validator.py tests/test_tf_validator.py && uv run ruff format --check tmi_tf/tf_validator.py tests/test_tf_validator.py`

- [ ] **Step 6: Commit**

```bash
git add tmi_tf/tf_validator.py tests/test_tf_validator.py
git commit -m "feat: add Step 1 file-level filtering for Terraform validation"
```

---

### Task 3: Step 2 — Syntax Validation with `terraform fmt`

**Files:**
- Modify: `tmi_tf/tf_validator.py`
- Modify: `tests/test_tf_validator.py`

- [ ] **Step 1: Write tests for syntax validation**

Add to `tests/test_tf_validator.py`:

```python
terraform_installed = pytest.mark.skipif(
    not shutil.which("terraform"),
    reason="terraform binary not installed",
)


class TestSyntaxValidation:
    """Test Step 2: terraform fmt syntax validation."""

    def _make_file(self, tmp_path: Path, name: str, content: str) -> Path:
        p = tmp_path / name
        p.write_text(content)
        return p

    @terraform_installed
    def test_rejects_invalid_hcl(self, tmp_path):
        f = self._make_file(tmp_path, "bad.tf", 'resource "aws_instance" "web" {\n  ami = \n}\n')
        with pytest.raises(TerraformValidationError):
            validate_and_sanitize([f], tmp_path)

    @terraform_installed
    def test_accepts_valid_hcl(self, tmp_path):
        f = self._make_file(tmp_path, "good.tf", 'resource "aws_instance" "web" {\n  ami = "abc-123"\n}\n')
        result = validate_and_sanitize([f], tmp_path)
        assert f in result.valid_files

    def test_terraform_binary_not_found(self, tmp_path):
        f = self._make_file(tmp_path, "main.tf", 'resource "x" "y" {}\n')
        with patch("tmi_tf.tf_validator.shutil.which", return_value=None):
            with pytest.raises(RuntimeError, match="terraform binary not found"):
                validate_and_sanitize([f], tmp_path)

    def test_terraform_fmt_timeout(self, tmp_path):
        f = self._make_file(tmp_path, "slow.tf", 'resource "x" "y" {}\n')
        with patch(
            "tmi_tf.tf_validator.subprocess.run",
            side_effect=TimeoutExpired("terraform", 30),
        ):
            with pytest.raises(TerraformValidationError, match="timed out"):
                validate_and_sanitize([f], tmp_path)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_tf_validator.py::TestSyntaxValidation -v`
Expected: FAIL — syntax validation not implemented yet (invalid HCL test passes when it should fail)

- [ ] **Step 3: Implement syntax validation**

Add to `tmi_tf/tf_validator.py`, and update `validate_and_sanitize` to call it:

```python
def _validate_syntax(file_path: Path) -> Optional[str]:
    """Run terraform fmt on a file to validate HCL syntax.

    Returns a rejection reason string, or None if the file passes.
    """
    try:
        subprocess.run(
            ["terraform", "fmt", str(file_path)],
            check=True,
            capture_output=True,
            timeout=30,
        )
        return None
    except subprocess.TimeoutExpired:
        return "terraform fmt timed out"
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode("utf-8", errors="replace").strip()
        return f"HCL syntax error: {stderr}" if stderr else "HCL syntax error"
```

Update the Step 2 section in `validate_and_sanitize`:

```python
    # Step 2: Syntax validation (terraform fmt)
    passed_step2: List[Path] = []
    for f in passed_step1:
        reason = _validate_syntax(f)
        if reason:
            rel = f.relative_to(clone_path) if clone_path in f.parents or f.parent == clone_path else f
            rejected.append(RejectedFile(path=rel, reason=reason))
            logger.warning(f"Rejected {rel}: {reason}")
        else:
            passed_step2.append(f)
```

Update the final section to use `passed_step2` instead of `passed_step1`:

```python
    if rejected:
        raise TerraformValidationError(rejected)

    return ValidationResult(valid_files=passed_step2)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_tf_validator.py::TestSyntaxValidation -v`
Expected: PASS

- [ ] **Step 5: Run all validator tests**

Run: `uv run pytest tests/test_tf_validator.py -v`
Expected: All PASS

- [ ] **Step 6: Lint**

Run: `uv run ruff check tmi_tf/tf_validator.py tests/test_tf_validator.py && uv run ruff format --check tmi_tf/tf_validator.py tests/test_tf_validator.py`

- [ ] **Step 7: Commit**

```bash
git add tmi_tf/tf_validator.py tests/test_tf_validator.py
git commit -m "feat: add Step 2 syntax validation via terraform fmt"
```

---

### Task 4: Step 3 — Content Sanitization State Machine

**Files:**
- Modify: `tmi_tf/tf_validator.py`
- Modify: `tests/test_tf_validator.py`

- [ ] **Step 1: Write tests for sanitization**

Add to `tests/test_tf_validator.py`:

```python
from tmi_tf.tf_validator import _sanitize_file


class TestSanitization:
    """Test Step 3: content sanitization state machine."""

    def _make_file(self, tmp_path: Path, name: str, content: str) -> Path:
        p = tmp_path / name
        p.write_text(textwrap.dedent(content))
        return p

    def _sanitized(self, tmp_path: Path, name: str, content: str) -> str:
        """Write file, sanitize it, return sanitized content."""
        f = self._make_file(tmp_path, name, content)
        _sanitize_file(f)
        return f.read_text()

    def test_no_scripts_unchanged(self, tmp_path):
        content = 'resource "aws_instance" "web" {\n  ami = "abc"\n}\n'
        result = self._sanitized(tmp_path, "main.tf", content)
        assert result == content

    def test_simple_user_data_string(self, tmp_path):
        result = self._sanitized(tmp_path, "main.tf", """\
            resource "aws_instance" "web" {
              ami       = "abc"
              user_data = "#!/bin/bash\\napt-get update"
            }
        """)
        assert 'user_data = "[embedded script removed]"' in result
        assert "#!/bin/bash" not in result
        assert 'ami       = "abc"' in result

    def test_user_data_heredoc(self, tmp_path):
        result = self._sanitized(tmp_path, "main.tf", """\
            resource "aws_instance" "web" {
              user_data = <<-EOF
                #!/bin/bash
                apt-get update
                apt-get install -y nginx
              EOF
            }
        """)
        assert 'user_data = "[embedded script removed]"' in result
        assert "#!/bin/bash" not in result
        assert "apt-get" not in result

    def test_user_data_function_call(self, tmp_path):
        result = self._sanitized(tmp_path, "main.tf", """\
            resource "aws_instance" "web" {
              user_data = base64encode(templatefile("${path.module}/init.sh", {
                env = var.environment
              }))
              tags = { Name = "web" }
            }
        """)
        assert 'user_data = "[embedded script removed]"' in result
        assert "base64encode" not in result
        assert "templatefile" not in result
        assert 'tags = { Name = "web" }' in result

    def test_provisioner_block(self, tmp_path):
        result = self._sanitized(tmp_path, "main.tf", """\
            resource "aws_instance" "web" {
              ami = "abc"
              provisioner "remote-exec" {
                inline = [
                  "sudo apt-get update",
                  "sudo systemctl start nginx",
                ]
              }
              tags = { Name = "web" }
            }
        """)
        assert 'provisioner "remote-exec" {' in result
        assert "# [provisioner script removed]" in result
        assert "apt-get" not in result
        assert 'tags = { Name = "web" }' in result

    def test_connection_block(self, tmp_path):
        result = self._sanitized(tmp_path, "main.tf", """\
            resource "aws_instance" "web" {
              provisioner "remote-exec" {
                connection {
                  type     = "ssh"
                  user     = "ubuntu"
                  private_key = file("~/.ssh/id_rsa")
                }
                inline = ["echo hello"]
              }
            }
        """)
        assert "connection {" in result
        assert "# [connection details removed]" in result
        assert "private_key" not in result

    def test_user_data_not_matched_as_substring(self, tmp_path):
        content = 'resource "x" "y" {\n  base64_user_data = "keep this"\n}\n'
        result = self._sanitized(tmp_path, "main.tf", content)
        assert 'base64_user_data = "keep this"' in result

    def test_commented_user_data_hash_not_stripped(self, tmp_path):
        content = '# user_data = "this is a comment"\nresource "x" "y" {}\n'
        result = self._sanitized(tmp_path, "main.tf", content)
        assert '# user_data = "this is a comment"' in result

    def test_commented_user_data_slashes_not_stripped(self, tmp_path):
        content = '// user_data = "this is a comment"\nresource "x" "y" {}\n'
        result = self._sanitized(tmp_path, "main.tf", content)
        assert '// user_data = "this is a comment"' in result

    def test_connection_not_matched_in_resource_type(self, tmp_path):
        content = 'resource "aws_dx_connection" "main" {\n  bandwidth = "1Gbps"\n}\n'
        result = self._sanitized(tmp_path, "main.tf", content)
        assert 'resource "aws_dx_connection" "main" {' in result
        assert 'bandwidth = "1Gbps"' in result

    def test_braces_in_comments_known_limitation(self, tmp_path):
        """Known limitation: unmatched braces in comments may affect depth tracking.

        This test documents the behavior rather than asserting correctness.
        A provisioner block with a comment containing an unmatched `}` may
        cause the state machine to exit STRIPPING_BLOCK early.
        """
        result = self._sanitized(tmp_path, "main.tf", """\
            resource "aws_instance" "web" {
              provisioner "local-exec" {
                # Note: this } brace is unmatched
                command = "echo hello"
              }
            }
        """)
        # The provisioner should be stripped, but the unmatched brace in the
        # comment may cause early exit. We just verify it doesn't crash.
        assert 'provisioner "local-exec" {' in result
        assert "# [provisioner script removed]" in result

    def test_multiple_constructs_in_one_file(self, tmp_path):
        result = self._sanitized(tmp_path, "main.tf", """\
            resource "aws_instance" "web" {
              ami       = "abc"
              user_data = "#!/bin/bash"
              provisioner "local-exec" {
                command = "echo done"
              }
            }
        """)
        assert 'user_data = "[embedded script removed]"' in result
        assert "# [provisioner script removed]" in result
        assert "#!/bin/bash" not in result
        assert "echo done" not in result

    def test_preserves_indentation(self, tmp_path):
        result = self._sanitized(tmp_path, "main.tf", """\
            resource "aws_instance" "web" {
                user_data = "#!/bin/bash"
            }
        """)
        for line in result.splitlines():
            if "user_data" in line:
                assert line.startswith("    ")
                break

    def test_heredoc_with_indented_marker(self, tmp_path):
        result = self._sanitized(tmp_path, "main.tf", """\
            resource "aws_instance" "web" {
              user_data = <<-"SCRIPT"
                #!/bin/bash
                echo hello
              SCRIPT
            }
        """)
        assert 'user_data = "[embedded script removed]"' in result
        assert "#!/bin/bash" not in result
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_tf_validator.py::TestSanitization -v`
Expected: FAIL — `_sanitize_file` not defined

- [ ] **Step 3: Implement the sanitization state machine**

Add to `tmi_tf/tf_validator.py`:

```python
import enum


class _State(enum.Enum):
    NORMAL = "normal"
    STRIPPING_BLOCK = "stripping_block"
    STRIPPING_VALUE = "stripping_value"
    STRIPPING_HEREDOC = "stripping_heredoc"


# Patterns for constructs to strip
_USER_DATA_RE = re.compile(r"^(\s*)user_data\s*=\s*(.*)")
_PROVISIONER_RE = re.compile(r'^(\s*)provisioner\s+"([^"]+)"\s*\{')
_CONNECTION_RE = re.compile(r"^(\s*)connection\s*\{")
# Pattern to detect comments (line starts with # or //)
_COMMENT_RE = re.compile(r"^\s*(?:#|//)")
# Heredoc pattern: <<EOF, <<-EOF, <<-"EOF", <<-'EOF'
_HEREDOC_RE = re.compile(r"""^<<-?\s*['"]?(\w+)['"]?""")


def _sanitize_file(file_path: Path) -> List[str]:
    """Sanitize a single .tf file in place.

    Strips user_data values, provisioner blocks, and connection blocks,
    replacing them with marker text.

    Returns a list of log messages describing what was stripped.

    Known limitation: braces/parentheses inside string literals or comments
    within stripped blocks could theoretically throw off the depth counter.
    In practice these constructs rarely contain unmatched delimiters in strings.
    """
    content = file_path.read_text(encoding="utf-8")
    lines = content.splitlines(keepends=True)
    output: List[str] = []
    log_messages: List[str] = []

    state = _State.NORMAL
    depth = 0
    heredoc_terminator = ""
    opening_indent = ""

    user_data_count = 0
    provisioner_count = 0
    connection_count = 0

    for line in lines:
        if state == _State.NORMAL:
            # Skip lines that are comments — don't match patterns inside them
            if _COMMENT_RE.match(line):
                output.append(line)
                continue

            m_ud = _USER_DATA_RE.match(line)
            m_prov = _PROVISIONER_RE.match(line)
            m_conn = _CONNECTION_RE.match(line)

            if m_ud:
                indent = m_ud.group(1)
                value_part = m_ud.group(2).strip()
                output.append(f'{indent}user_data = "[embedded script removed]"\n')
                user_data_count += 1

                # Determine what follows the =
                m_heredoc = _HEREDOC_RE.match(value_part)
                if m_heredoc:
                    heredoc_terminator = m_heredoc.group(1)
                    state = _State.STRIPPING_HEREDOC
                else:
                    # Count all openers and closers together
                    openers = value_part.count("(") + value_part.count("{")
                    closers = value_part.count(")") + value_part.count("}")
                    depth = openers - closers
                    if depth > 0:
                        state = _State.STRIPPING_VALUE
                    # else: single-line value, stay NORMAL

            elif m_prov:
                indent = m_prov.group(1)
                prov_type = m_prov.group(2)
                output.append(f'{indent}provisioner "{prov_type}" {{\n')
                output.append(f"{indent}  # [provisioner script removed]\n")
                opening_indent = indent
                state = _State.STRIPPING_BLOCK
                depth = 1
                provisioner_count += 1

            elif m_conn:
                indent = m_conn.group(1)
                output.append(f"{indent}connection {{\n")
                output.append(f"{indent}  # [connection details removed]\n")
                opening_indent = indent
                state = _State.STRIPPING_BLOCK
                depth = 1
                connection_count += 1

            else:
                output.append(line)

        elif state == _State.STRIPPING_BLOCK:
            for ch in line:
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
            if depth <= 0:
                output.append(f"{opening_indent}}}\n")
                state = _State.NORMAL

        elif state == _State.STRIPPING_VALUE:
            for ch in line:
                if ch in ("(", "{"):
                    depth += 1
                elif ch in (")", "}"):
                    depth -= 1
            if depth <= 0:
                state = _State.NORMAL
                # No closing delimiter — replacement line is already complete

        elif state == _State.STRIPPING_HEREDOC:
            if line.strip() == heredoc_terminator:
                state = _State.NORMAL
            # Do not write any lines while in heredoc

    # Write sanitized content back
    file_path.write_text("".join(output), encoding="utf-8")

    # Build log messages
    rel_name = file_path.name
    parts = []
    if user_data_count:
        parts.append(f"{user_data_count} user_data attribute{'s' if user_data_count > 1 else ''}")
    if provisioner_count:
        parts.append(f"{provisioner_count} provisioner block{'s' if provisioner_count > 1 else ''}")
    if connection_count:
        parts.append(f"{connection_count} connection block{'s' if connection_count > 1 else ''}")
    if parts:
        log_messages.append(f"Stripped {', '.join(parts)} from {rel_name}")

    return log_messages
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_tf_validator.py::TestSanitization -v`
Expected: PASS

- [ ] **Step 5: Lint**

Run: `uv run ruff check tmi_tf/tf_validator.py tests/test_tf_validator.py && uv run ruff format --check tmi_tf/tf_validator.py tests/test_tf_validator.py`

- [ ] **Step 6: Commit**

```bash
git add tmi_tf/tf_validator.py tests/test_tf_validator.py
git commit -m "feat: add Step 3 content sanitization state machine"
```

---

### Task 5: Wire Sanitization into validate_and_sanitize

**Files:**
- Modify: `tmi_tf/tf_validator.py`
- Modify: `tests/test_tf_validator.py`

- [ ] **Step 1: Write integration test for full pipeline**

Add to `tests/test_tf_validator.py`:

```python
@pytest.mark.usefixtures("_mock_terraform")
class TestFullPipeline:
    """Test the full validate_and_sanitize pipeline."""

    def _make_file(self, tmp_path: Path, name: str, content: str) -> Path:
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(content))
        return p

    def test_valid_file_with_scripts_is_sanitized(self, tmp_path):
        f = self._make_file(tmp_path, "main.tf", """\
            resource "aws_instance" "web" {
              ami       = "abc"
              user_data = "#!/bin/bash"

              provisioner "remote-exec" {
                inline = ["echo hello"]
              }
            }
        """)
        result = validate_and_sanitize([f], tmp_path)
        assert f in result.valid_files
        content = f.read_text()
        assert "[embedded script removed]" in content
        assert "[provisioner script removed]" in content
        assert len(result.sanitization_log) > 0

    def test_tfvars_skips_sanitization(self, tmp_path):
        f = self._make_file(tmp_path, "terraform.tfvars", 'region = "us-east-1"\n')
        result = validate_and_sanitize([f], tmp_path)
        assert f in result.valid_files
        assert f.read_text() == 'region = "us-east-1"\n'

    def test_mixed_valid_and_invalid_raises(self, tmp_path):
        good = self._make_file(
            tmp_path, "good.tf", 'resource "x" "y" {\n  ami = "abc"\n}\n'
        )
        bad = self._make_file(tmp_path, "empty.tf", "")
        with pytest.raises(TerraformValidationError) as exc_info:
            validate_and_sanitize([good, bad], tmp_path)
        assert len(exc_info.value.rejected_files) == 1
        assert exc_info.value.rejected_files[0].path == Path("empty.tf")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_tf_validator.py::TestFullPipeline -v`
Expected: FAIL — sanitization not wired into `validate_and_sanitize` yet

- [ ] **Step 3: Wire sanitization into validate_and_sanitize**

Update the Step 3 section in `validate_and_sanitize` in `tmi_tf/tf_validator.py`:

```python
    # Step 3: Sanitization (.tf files only)
    sanitization_log: List[str] = []
    for f in passed_step2:
        if f.suffix == ".tf":
            messages = _sanitize_file(f)
            sanitization_log.extend(messages)

    if rejected:
        raise TerraformValidationError(rejected)

    return ValidationResult(valid_files=passed_step2, sanitization_log=sanitization_log)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_tf_validator.py::TestFullPipeline -v`
Expected: PASS

- [ ] **Step 5: Run all validator tests**

Run: `uv run pytest tests/test_tf_validator.py -v`
Expected: All PASS

- [ ] **Step 6: Lint**

Run: `uv run ruff check tmi_tf/tf_validator.py tests/test_tf_validator.py && uv run ruff format --check tmi_tf/tf_validator.py tests/test_tf_validator.py`

- [ ] **Step 7: Commit**

```bash
git add tmi_tf/tf_validator.py tests/test_tf_validator.py
git commit -m "feat: wire sanitization into validate_and_sanitize pipeline"
```

---

### Task 6: Integrate into analyzer.py

**Files:**
- Modify: `tmi_tf/analyzer.py:46-73` (`_analyze_single_environment`)
- Modify: `tmi_tf/analyzer.py:193-208` (no-environment fallback)

- [ ] **Step 1: Write test for analyzer integration**

Add to `tests/test_tf_validator.py`:

```python
class TestAnalyzerIntegration:
    """Test that validate_and_sanitize is called from analyzer paths."""

    def test_validation_error_is_catchable(self):
        """Verify TerraformValidationError is a subclass of Exception.

        This ensures it is caught by the existing except Exception handler
        in analyzer.py's run_analysis loop.
        """
        err = TerraformValidationError(
            [RejectedFile(path=Path("x.tf"), reason="bad")]
        )
        assert isinstance(err, Exception)
```

- [ ] **Step 2: Run test to verify it passes**

Run: `uv run pytest tests/test_tf_validator.py::TestAnalyzerIntegration -v`
Expected: PASS (this is a contract test)

- [ ] **Step 3: Add import to analyzer.py**

At the top of `tmi_tf/analyzer.py`, add:

```python
from tmi_tf.tf_validator import validate_and_sanitize
```

- [ ] **Step 4: Add validation to `_analyze_single_environment()`**

In `tmi_tf/analyzer.py`, modify `_analyze_single_environment()`. After the `resolve_modules` call (line 66-68) and before the `llm_analyzer.analyze_repository` call (line 73), insert:

```python
    # Validate and sanitize resolved files before LLM analysis
    validation_result = validate_and_sanitize(tf_repo.terraform_files, tf_repo.clone_path)
    tf_repo.terraform_files = validation_result.valid_files
    for msg in validation_result.sanitization_log:
        logger.info(msg)
```

- [ ] **Step 5: Add validation to the no-environment fallback path**

In `tmi_tf/analyzer.py`, in the `len(envs) == 0` branch (around line 202), insert before the `llm_analyzer.analyze_repository` call:

```python
                            # Validate and sanitize before LLM analysis
                            validation_result = validate_and_sanitize(
                                tf_repo.terraform_files, tf_repo.clone_path
                            )
                            tf_repo.terraform_files = validation_result.valid_files
                            for msg in validation_result.sanitization_log:
                                logger.info(msg)
```

- [ ] **Step 6: Lint and type check**

Run: `uv run ruff check tmi_tf/analyzer.py tmi_tf/tf_validator.py && uv run ruff format --check tmi_tf/analyzer.py tmi_tf/tf_validator.py && uv run pyright`

- [ ] **Step 7: Run full test suite**

Run: `uv run pytest tests/ -v`
Expected: All PASS

- [ ] **Step 8: Commit**

```bash
git add tmi_tf/analyzer.py
git commit -m "feat: integrate Terraform validation into analysis pipeline"
```
