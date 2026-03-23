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
from typing import List

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
