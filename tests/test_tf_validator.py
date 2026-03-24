"""Tests for Terraform file validation and sanitization."""

import shutil
import textwrap
from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired
from unittest.mock import patch

import pytest  # type: ignore

from tmi_tf.tf_validator import (
    RejectedFile,
    TerraformValidationError,
    ValidationResult,
    _sanitize_file,
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
        f = self._make_file(
            tmp_path, "bad.tf", 'resource "aws_instance" "web" {\n  ami = \n}\n'
        )
        with pytest.raises(TerraformValidationError):
            validate_and_sanitize([f], tmp_path)

    @terraform_installed
    def test_accepts_valid_hcl(self, tmp_path):
        f = self._make_file(
            tmp_path,
            "good.tf",
            'resource "aws_instance" "web" {\n  ami = "abc-123"\n}\n',
        )
        result = validate_and_sanitize([f], tmp_path)
        assert f in result.valid_files

    def test_terraform_binary_not_found(self, tmp_path):
        f = self._make_file(tmp_path, "main.tf", 'resource "x" "y" {}\n')
        with (
            patch("tmi_tf.tf_validator.shutil.which", return_value=None),
            pytest.raises(RuntimeError, match="terraform binary not found"),
        ):
            validate_and_sanitize([f], tmp_path)

    def test_terraform_fmt_timeout(self, tmp_path):
        f = self._make_file(tmp_path, "slow.tf", 'resource "x" "y" {}\n')
        with (
            patch(
                "tmi_tf.tf_validator.subprocess.run",
                side_effect=TimeoutExpired("terraform", 30),
            ),
            pytest.raises(TerraformValidationError, match="timed out"),
        ):
            validate_and_sanitize([f], tmp_path)


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
        result = self._sanitized(
            tmp_path,
            "main.tf",
            """\
            resource "aws_instance" "web" {
              ami       = "abc"
              user_data = "#!/bin/bash\\napt-get update"
            }
        """,
        )
        assert 'user_data = "[embedded script removed]"' in result
        assert "#!/bin/bash" not in result
        assert 'ami       = "abc"' in result

    def test_user_data_heredoc(self, tmp_path):
        result = self._sanitized(
            tmp_path,
            "main.tf",
            """\
            resource "aws_instance" "web" {
              user_data = <<-EOF
                #!/bin/bash
                apt-get update
                apt-get install -y nginx
              EOF
            }
        """,
        )
        assert 'user_data = "[embedded script removed]"' in result
        assert "#!/bin/bash" not in result
        assert "apt-get" not in result

    def test_user_data_function_call(self, tmp_path):
        result = self._sanitized(
            tmp_path,
            "main.tf",
            """\
            resource "aws_instance" "web" {
              user_data = base64encode(templatefile("${path.module}/init.sh", {
                env = var.environment
              }))
              tags = { Name = "web" }
            }
        """,
        )
        assert 'user_data = "[embedded script removed]"' in result
        assert "base64encode" not in result
        assert "templatefile" not in result
        assert 'tags = { Name = "web" }' in result

    def test_provisioner_block(self, tmp_path):
        result = self._sanitized(
            tmp_path,
            "main.tf",
            """\
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
        """,
        )
        assert 'provisioner "remote-exec" {' in result
        assert "# [provisioner script removed]" in result
        assert "apt-get" not in result
        assert 'tags = { Name = "web" }' in result

    def test_connection_block(self, tmp_path):
        result = self._sanitized(
            tmp_path,
            "main.tf",
            """\
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
        """,
        )
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
        """Known limitation: unmatched braces in comments may affect depth tracking."""
        result = self._sanitized(
            tmp_path,
            "main.tf",
            """\
            resource "aws_instance" "web" {
              provisioner "local-exec" {
                # Note: this } brace is unmatched
                command = "echo hello"
              }
            }
        """,
        )
        assert 'provisioner "local-exec" {' in result
        assert "# [provisioner script removed]" in result

    def test_multiple_constructs_in_one_file(self, tmp_path):
        result = self._sanitized(
            tmp_path,
            "main.tf",
            """\
            resource "aws_instance" "web" {
              ami       = "abc"
              user_data = "#!/bin/bash"
              provisioner "local-exec" {
                command = "echo done"
              }
            }
        """,
        )
        assert 'user_data = "[embedded script removed]"' in result
        assert "# [provisioner script removed]" in result
        assert "#!/bin/bash" not in result
        assert "echo done" not in result

    def test_preserves_indentation(self, tmp_path):
        result = self._sanitized(
            tmp_path,
            "main.tf",
            """\
            resource "aws_instance" "web" {
                user_data = "#!/bin/bash"
            }
        """,
        )
        for line in result.splitlines():
            if "user_data" in line:
                assert line.startswith("    ")
                break

    def test_heredoc_with_indented_marker(self, tmp_path):
        result = self._sanitized(
            tmp_path,
            "main.tf",
            """\
            resource "aws_instance" "web" {
              user_data = <<-"SCRIPT"
                #!/bin/bash
                echo hello
              SCRIPT
            }
        """,
        )
        assert 'user_data = "[embedded script removed]"' in result
        assert "#!/bin/bash" not in result


@pytest.mark.usefixtures("_mock_terraform")
class TestFullPipeline:
    """Test the full validate_and_sanitize pipeline."""

    def _make_file(self, tmp_path: Path, name: str, content: str) -> Path:
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(content))
        return p

    def test_valid_file_with_scripts_is_sanitized(self, tmp_path):
        f = self._make_file(
            tmp_path,
            "main.tf",
            """\
            resource "aws_instance" "web" {
              ami       = "abc"
              user_data = "#!/bin/bash"

              provisioner "remote-exec" {
                inline = ["echo hello"]
              }
            }
        """,
        )
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
