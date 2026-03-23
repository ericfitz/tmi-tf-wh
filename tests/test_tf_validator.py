"""Tests for Terraform file validation and sanitization."""

from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from tmi_tf.tf_validator import (
    RejectedFile,
    TerraformValidationError,
    ValidationResult,
    validate_and_sanitize,
)


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
        f = self._make_file(
            tmp_path,
            "variables.tf",
            'variable "region" {\n  default = "us-east-1"\n}\n',
        )
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
