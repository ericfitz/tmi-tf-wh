"""Terraform file validation and sanitization.

Validates .tf and .tfvars files after git clone, before LLM analysis.
Three-step pipeline:
  Step 1: File-level filtering (empty, auto-generated, oversized, no constructs)
  Step 2: Syntax validation (terraform fmt)
  Step 3: Content sanitization (strip user_data, provisioner, connection)
"""

import logging
import re
import shutil
import subprocess  # noqa: F401 — used in Steps 2/3 (Task 3/4) and patched in tests
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

    # Step 2: Syntax validation (placeholder — implemented in Task 3)

    # Step 3: Sanitization (placeholder — implemented in Task 4)

    if rejected:
        raise TerraformValidationError(rejected)

    return ValidationResult(valid_files=passed_step1)
