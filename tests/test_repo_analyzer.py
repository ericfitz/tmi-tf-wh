"""Tests for environment detection and module resolution in repo_analyzer."""

from pathlib import Path

from tmi_tf.repo_analyzer import (
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
        clone = self._make_tree(
            tmp_path,
            {
                "terraform/environments/prod/main.tf": 'resource "aws_instance" "web" {}',
                "terraform/environments/prod/variables.tf": 'variable "region" {}',
            },
        )
        envs = RepositoryAnalyzer.detect_environments(clone)
        assert len(envs) == 1
        assert envs[0].name == "prod"
        assert len(envs[0].tf_files) == 2

    def test_finds_multiple_environments(self, tmp_path):
        clone = self._make_tree(
            tmp_path,
            {
                "terraform/environments/prod/main.tf": "",
                "terraform/environments/staging/main.tf": "",
                "terraform/environments/dev/backend.tf": "",
            },
        )
        envs = RepositoryAnalyzer.detect_environments(clone)
        assert len(envs) == 3
        names = [e.name for e in envs]
        assert sorted(names) == ["dev", "prod", "staging"]

    def test_excludes_modules_directories(self, tmp_path):
        clone = self._make_tree(
            tmp_path,
            {
                "terraform/environments/prod/main.tf": "",
                "terraform/modules/network/main.tf": "",
                "modules/compute/main.tf": "",
            },
        )
        envs = RepositoryAnalyzer.detect_environments(clone)
        assert len(envs) == 1
        assert envs[0].name == "prod"

    def test_no_environments_returns_empty(self, tmp_path):
        clone = self._make_tree(
            tmp_path,
            {
                "some_dir/file.tf": "",
            },
        )
        envs = RepositoryAnalyzer.detect_environments(clone)
        assert len(envs) == 0

    def test_disambiguates_duplicate_names(self, tmp_path):
        clone = self._make_tree(
            tmp_path,
            {
                "aws/prod/main.tf": "",
                "gcp/prod/main.tf": "",
            },
        )
        envs = RepositoryAnalyzer.detect_environments(clone)
        assert len(envs) == 2
        names = [e.name for e in envs]
        # Should use relative paths to disambiguate
        assert len(set(names)) == 2  # All names unique

    def test_collects_tf_and_tfvars_files(self, tmp_path):
        clone = self._make_tree(
            tmp_path,
            {
                "env/prod/main.tf": "",
                "env/prod/variables.tf": "",
                "env/prod/terraform.tfvars": "",
                "env/prod/subdir/nested.tf": "",  # Should NOT be included (non-recursive)
            },
        )
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
        clone = self._make_tree(
            tmp_path,
            {
                "z-env/main.tf": "",
                "a-env/main.tf": "",
                "m-env/main.tf": "",
            },
        )
        envs = RepositoryAnalyzer.detect_environments(clone)
        names = [e.name for e in envs]
        assert names == sorted(names)
