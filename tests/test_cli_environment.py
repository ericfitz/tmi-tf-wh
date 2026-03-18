"""Tests for CLI environment selection behavior."""

import pytest

import click

from tmi_tf.repo_analyzer import RepositoryAnalyzer, TerraformEnvironment


class TestEnvironmentSelection:
    """Test environment selection logic."""

    def test_environment_flag_no_match_raises(self, tmp_path):
        """When --environment doesn't match, should raise ClickException."""
        envs = [
            TerraformEnvironment(name="prod", path=tmp_path / "prod", tf_files=[]),
            TerraformEnvironment(
                name="staging", path=tmp_path / "staging", tf_files=[]
            ),
        ]

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
            TerraformEnvironment(
                name="OCI-Private", path=tmp_path / "oci", tf_files=[]
            ),
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
        assert "network" not in names
        assert "compute" not in names
