"""Tests for Terraform file validation and sanitization."""

from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from tmi_tf.tf_validator import RejectedFile, TerraformValidationError, ValidationResult


@pytest.fixture()
def _mock_terraform():
    """Mock terraform binary check and subprocess for unit tests."""
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
