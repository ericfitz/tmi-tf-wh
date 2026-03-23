"""Terraform file validation and sanitization.

Validates .tf and .tfvars files after git clone, before LLM analysis.
Three-step pipeline:
  Step 1: File-level filtering (empty, auto-generated, oversized, no constructs)
  Step 2: Syntax validation (terraform fmt)
  Step 3: Content sanitization (strip user_data, provisioner, connection)
"""

import enum
import logging
import re
import shutil
import subprocess
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
    if file_path.stat().st_size == 0:
        return "empty file"
    if _is_auto_generated(file_path, clone_path):
        return "auto-generated file"
    if file_path.stat().st_size > _MAX_FILE_SIZE:
        return f"exceeds size limit ({_MAX_FILE_SIZE} bytes)"
    if file_path.suffix == ".tf" and not _has_terraform_constructs(file_path):
        return "no Terraform constructs found"
    return None


def _validate_syntax(file_path: Path) -> Optional[str]:
    """Run Step 2 syntax validation on a single file via terraform fmt.

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
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode(errors="replace").strip() if exc.stderr else ""
        return f"terraform fmt failed: {stderr}" if stderr else "terraform fmt failed"
    except subprocess.TimeoutExpired:
        return "terraform fmt timed out"


class _State(enum.Enum):
    NORMAL = "normal"
    STRIPPING_BLOCK = "stripping_block"
    STRIPPING_VALUE = "stripping_value"
    STRIPPING_HEREDOC = "stripping_heredoc"


# Patterns for sanitization (anchored to first non-whitespace token)
_USER_DATA_RE = re.compile(r"^(\s*)user_data\s*=\s*(.*)")
_PROVISIONER_RE = re.compile(r'^(\s*)provisioner\s+"([^"]+)"\s*\{')
_CONNECTION_RE = re.compile(r"^(\s*)connection\s*\{")
_HEREDOC_TERMINATOR_RE = re.compile(r"""^<<-?\s*['"]?(\w+)['"]?""")
_COMMENT_RE = re.compile(r"^\s*(#|//)")


def _sanitize_file(file_path: Path) -> List[str]:
    """Step 3: Sanitize a .tf file by stripping embedded scripts and secrets.

    Reads the file, processes line by line using a state machine, writes
    sanitized content back to disk.

    Returns a list of log messages describing what was stripped.
    """
    with open(file_path, encoding="utf-8") as f:
        lines = f.readlines()

    output: List[str] = []
    state = _State.NORMAL
    depth = 0
    heredoc_terminator = ""
    provisioner_count = 0
    connection_count = 0
    user_data_count = 0

    for line in lines:
        if state == _State.NORMAL:
            # Comments are always passed through unchanged
            if _COMMENT_RE.match(line):
                output.append(line)
                continue

            # Check for user_data assignment (whole word, first token)
            m_ud = _USER_DATA_RE.match(line)
            if m_ud:
                indent = m_ud.group(1)
                value_part = m_ud.group(2)
                output.append(f'{indent}user_data = "[embedded script removed]"\n')
                user_data_count += 1

                # Determine if multi-line
                heredoc_match = _HEREDOC_TERMINATOR_RE.match(value_part)
                if heredoc_match:
                    # Heredoc: enter STRIPPING_HEREDOC
                    heredoc_terminator = heredoc_match.group(1)
                    state = _State.STRIPPING_HEREDOC
                elif "(" in value_part or "{" in value_part:
                    # Count all openers and closers together
                    # Known limitation: braces/parens inside string literals or
                    # comments within stripped blocks could throw off depth counting.
                    depth = (
                        value_part.count("(")
                        + value_part.count("{")
                        - value_part.count(")")
                        - value_part.count("}")
                    )
                    if depth > 0:
                        state = _State.STRIPPING_VALUE
                    # else: balanced on one line, stay NORMAL
                else:
                    # Single-line value, stay NORMAL
                    pass
                continue

            # Check for provisioner block
            m_prov = _PROVISIONER_RE.match(line)
            if m_prov:
                indent = m_prov.group(1)
                prov_type = m_prov.group(2)
                output.append(f'{indent}provisioner "{prov_type}" {{\n')
                output.append(f"{indent}  # [provisioner script removed]\n")
                provisioner_count += 1
                depth = 1
                state = _State.STRIPPING_BLOCK
                continue

            # Check for connection block (standalone, first token)
            m_conn = _CONNECTION_RE.match(line)
            if m_conn:
                indent = m_conn.group(1)
                output.append(f"{indent}connection {{\n")
                output.append(f"{indent}  # [connection details removed]\n")
                connection_count += 1
                depth = 1
                state = _State.STRIPPING_BLOCK
                continue

            # No match — pass through
            output.append(line)

        elif state == _State.STRIPPING_BLOCK:
            # Track brace depth to find end of block
            # Known limitation: braces inside string literals or comments
            # within stripped blocks could throw off depth counting.

            # Detect nested connection blocks and emit their header
            m_conn_nested = _CONNECTION_RE.match(line)
            if m_conn_nested:
                indent = m_conn_nested.group(1)
                output.append(f"{indent}connection {{\n")
                output.append(f"{indent}  # [connection details removed]\n")
                connection_count += 1

            depth += line.count("{") - line.count("}")
            if depth <= 0:
                output.append(line)
                state = _State.NORMAL
                depth = 0

        elif state == _State.STRIPPING_VALUE:
            # Track combined brace+paren depth
            # Known limitation: braces/parens inside string literals or
            # comments within stripped blocks could throw off depth counting.
            depth += (
                line.count("(") + line.count("{") - line.count(")") - line.count("}")
            )
            if depth <= 0:
                # Do NOT write closing delimiter line
                state = _State.NORMAL
                depth = 0

        elif state == _State.STRIPPING_HEREDOC:
            # Wait for terminator line
            stripped = line.strip()
            if stripped == heredoc_terminator:
                state = _State.NORMAL
                heredoc_terminator = ""

    # Write sanitized content back
    with open(file_path, "w", encoding="utf-8") as f:
        f.writelines(output)

    # Build log messages
    log_messages: List[str] = []
    name = file_path.name
    if user_data_count:
        s = "" if user_data_count == 1 else "s"
        log_messages.append(
            f"Stripped {user_data_count} user_data value{s} from {name}"
        )
    if provisioner_count:
        s = "" if provisioner_count == 1 else "s"
        log_messages.append(
            f"Stripped {provisioner_count} provisioner block{s} from {name}"
        )
    if connection_count:
        s = "" if connection_count == 1 else "s"
        log_messages.append(
            f"Stripped {connection_count} connection block{s} from {name}"
        )
    return log_messages


def validate_and_sanitize(
    terraform_files: List[Path], clone_path: Path
) -> ValidationResult:
    """Validate and sanitize Terraform files.

    Runs the three-step pipeline: filtering, syntax validation, sanitization.
    Sanitized content is written back to files on disk.

    Raises TerraformValidationError if any file fails Steps 1 or 2.
    Raises RuntimeError if terraform binary is not found on PATH.
    """
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
            try:
                rel = f.relative_to(clone_path)
            except ValueError:
                rel = f
            rejected.append(RejectedFile(path=rel, reason=reason))
            logger.warning(f"Rejected {rel}: {reason}")
        else:
            passed_step1.append(f)

    # Step 2: Syntax validation
    passed_step2: List[Path] = []
    for f in passed_step1:
        reason = _validate_syntax(f)
        if reason:
            try:
                rel = f.relative_to(clone_path)
            except ValueError:
                rel = f
            rejected.append(RejectedFile(path=rel, reason=reason))
            logger.warning(f"Rejected {rel}: {reason}")
        else:
            passed_step2.append(f)

    # Step 3: Sanitization (.tf files only)
    sanitization_log: List[str] = []
    for f in passed_step2:
        if f.suffix == ".tf":
            messages = _sanitize_file(f)
            sanitization_log.extend(messages)

    if rejected:
        raise TerraformValidationError(rejected)

    return ValidationResult(valid_files=passed_step2, sanitization_log=sanitization_log)
