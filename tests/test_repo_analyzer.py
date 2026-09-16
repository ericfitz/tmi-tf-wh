"""Tests for environment detection and module resolution in repo_analyzer."""

import os
import subprocess
import textwrap
from pathlib import Path
from unittest.mock import patch

from tmi_tf.config import Config
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


class TestResolveModules:
    """Test resolve_modules method."""

    def _make_tree(self, tmp_path: Path, files: dict[str, str]) -> Path:
        for rel, content in files.items():
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        return tmp_path

    def test_resolves_relative_module_sources(self, tmp_path):
        clone = self._make_tree(
            tmp_path,
            {
                "envs/prod/main.tf": textwrap.dedent("""\
                module "network" {
                  source = "../../modules/network"
                }
            """),
                "envs/prod/variables.tf": 'variable "region" {}',
                "modules/network/main.tf": 'resource "aws_vpc" "main" {}',
                "modules/network/outputs.tf": 'output "vpc_id" {}',
            },
        )
        envs = RepositoryAnalyzer.detect_environments(clone)
        assert len(envs) == 1

        all_files = RepositoryAnalyzer.resolve_modules(envs[0], clone)
        filenames = {f.name for f in all_files}
        # Should include env files + module files
        assert "main.tf" in filenames
        assert "variables.tf" in filenames
        assert "outputs.tf" in filenames

    def test_ignores_registry_sources(self, tmp_path):
        clone = self._make_tree(
            tmp_path,
            {
                "env/prod/main.tf": textwrap.dedent("""\
                module "vpc" {
                  source = "terraform-aws-modules/vpc/aws"
                }
                module "local_mod" {
                  source = "../../modules/local"
                }
            """),
                "modules/local/main.tf": "",
            },
        )
        envs = RepositoryAnalyzer.detect_environments(clone)
        all_files = RepositoryAnalyzer.resolve_modules(envs[0], clone)
        # Should include env file + local module, but not fail on registry source
        assert len(all_files) >= 2

    def test_deduplicates_files(self, tmp_path):
        clone = self._make_tree(
            tmp_path,
            {
                "env/prod/main.tf": textwrap.dedent("""\
                module "a" {
                  source = "../modules/shared"
                }
                module "b" {
                  source = "../modules/shared"
                }
            """),
                "modules/shared/main.tf": "",
            },
        )
        envs = RepositoryAnalyzer.detect_environments(clone)
        all_files = RepositoryAnalyzer.resolve_modules(envs[0], clone)
        # No duplicates
        assert len(all_files) == len(set(all_files))

    def test_no_modules_returns_env_files_only(self, tmp_path):
        clone = self._make_tree(
            tmp_path,
            {
                "env/prod/main.tf": 'resource "aws_instance" "web" {}',
                "env/prod/variables.tf": 'variable "x" {}',
            },
        )
        envs = RepositoryAnalyzer.detect_environments(clone)
        all_files = RepositoryAnalyzer.resolve_modules(envs[0], clone)
        assert len(all_files) == 2

    def test_nonexistent_module_path_skipped(self, tmp_path):
        clone = self._make_tree(
            tmp_path,
            {
                "env/prod/main.tf": textwrap.dedent("""\
                module "ghost" {
                  source = "../modules/nonexistent"
                }
            """),
            },
        )
        envs = RepositoryAnalyzer.detect_environments(clone)
        all_files = RepositoryAnalyzer.resolve_modules(envs[0], clone)
        # Should just return the env file, not crash
        assert len(all_files) == 1


def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def _commit(cwd, relpath, content, when):
    p = cwd / relpath
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    _git(cwd, "add", relpath)
    env_date = f"@{when} +0000"
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@x",
            "commit",
            "-q",
            "-m",
            relpath,
        ],
        cwd=cwd,
        check=True,
        capture_output=True,
        env={**os.environ, "GIT_AUTHOR_DATE": env_date, "GIT_COMMITTER_DATE": env_date},
    )


class TestLatestEnvironment:
    def _repo(self, tmp_path):
        _git(tmp_path, "init", "-q")
        _commit(
            tmp_path,
            "envs/a/main.tf",
            'module "m" { source = "../../modules/m" }',
            1000,
        )
        _commit(tmp_path, "envs/b/main.tf", "# b", 2000)
        _commit(tmp_path, "modules/m/main.tf", "# m", 3000)
        return tmp_path

    def test_last_commit_timestamp(self, tmp_path):
        repo = self._repo(tmp_path)
        assert RepositoryAnalyzer.last_commit_timestamp(repo, [Path("envs/b")]) == 2000
        assert RepositoryAnalyzer.last_commit_timestamp(repo, [Path("nope")]) is None

    def test_last_commit_timestamp_empty_paths(self, tmp_path):
        repo = self._repo(tmp_path)
        assert RepositoryAnalyzer.last_commit_timestamp(repo, []) is None

    def test_last_commit_timestamp_path_outside_clone_returns_none(self, tmp_path):
        repo = self._repo(tmp_path)
        assert RepositoryAnalyzer.last_commit_timestamp(repo, [tmp_path.parent]) is None

    def test_module_commit_counts_for_environment(self, tmp_path):
        repo = self._repo(tmp_path)
        envs = RepositoryAnalyzer.detect_environments(repo)
        chosen, ts = RepositoryAnalyzer.select_latest_environment(repo, envs)
        assert chosen.name == "a"  # a's module changed at 3000 > b at 2000
        assert ts == 3000

    def test_no_history_falls_back_to_first(self, tmp_path):
        (tmp_path / "x").mkdir()
        (tmp_path / "x" / "main.tf").write_text("# x")
        (tmp_path / "y").mkdir()
        (tmp_path / "y" / "main.tf").write_text("# y")
        _git(tmp_path, "init", "-q")
        envs = RepositoryAnalyzer.detect_environments(tmp_path)
        chosen, ts = RepositoryAnalyzer.select_latest_environment(tmp_path, envs)
        assert chosen.name == "x" and ts is None


class TestCloneDepth:
    def test_pull_uses_configured_depth(self, tmp_path):
        config = Config()
        config.latest_commit_depth = 7
        analyzer = RepositoryAnalyzer(config)
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)

            class R:
                stdout = b""
                stderr = b""
                returncode = 0

            return R()

        with patch("tmi_tf.repo_analyzer.subprocess.run", side_effect=fake_run):
            (tmp_path / ".git" / "info").mkdir(parents=True)
            (tmp_path / "main.tf").write_text("# keep rglob non-empty")
            analyzer._sparse_clone("https://github.com/o/r", tmp_path, "r")
        pull = next(c for c in calls if c[:2] == ["git", "pull"])
        assert "--depth=7" in pull


class TestExtractRepositoryName:
    """#65: rstrip(".git") stripped trailing characters, turning tmi into tm."""

    def test_trailing_git_chars_kept(self):
        analyzer = RepositoryAnalyzer(Config())
        assert (
            analyzer.extract_repository_name("https://github.com/ericfitz/tmi.git")
            == "ericfitz_tmi"
        )
        assert (
            analyzer.extract_repository_name("https://github.com/ericfitz/tmi")
            == "ericfitz_tmi"
        )
        assert (
            analyzer.extract_repository_name("https://github.com/o/digit.git/")
            == "o_digit"
        )
