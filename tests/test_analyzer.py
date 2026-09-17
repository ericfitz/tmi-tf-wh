"""Tests for tmi_tf.analyzer module."""

from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

from tmi_tf.analyzer import (
    AnalysisResult,
    FanoutTarget,
    resolve_fanout_targets,
    run_analysis,
)
from tmi_tf.config import Config


class TestAnalysisResult:
    """Smoke tests for the AnalysisResult dataclass."""

    def test_returns_analysis_result(self):
        result = AnalysisResult(success=True, analyses=[], errors=[])
        assert result.success is True
        assert result.analyses == []
        assert result.errors == []

    def test_defaults(self):
        result = AnalysisResult(success=False)
        assert result.success is False
        assert result.analyses == []
        assert result.errors == []
        assert result.inventory_content == ""
        assert result.analysis_content == ""

    def test_with_content(self):
        result = AnalysisResult(
            success=True,
            analyses=[],
            errors=[],
            inventory_content="<h1>Inventory</h1>",
            analysis_content="<h1>Analysis</h1>",
        )
        assert result.inventory_content == "<h1>Inventory</h1>"
        assert result.analysis_content == "<h1>Analysis</h1>"

    def test_with_errors(self):
        result = AnalysisResult(
            success=False,
            errors=["repo not found", "auth failed"],
        )
        assert len(result.errors) == 2
        assert "repo not found" in result.errors


def _tree(tmp_path: Path, envs: list[str]) -> Path:
    for e in envs:
        (tmp_path / "envs" / e).mkdir(parents=True)
        (tmp_path / "envs" / e / "main.tf").write_text(f"# {e}")
    return tmp_path


def _fake_clone(tree: Path):
    @contextmanager
    def _cm(self, repo_url, repo_name, base_temp_dir=None):
        repo = MagicMock()
        repo.clone_path = tree
        repo.terraform_files = list(tree.rglob("*.tf"))
        yield repo

    return _cm


def _tmi_with_repo(repo_id="r1", url="https://github.com/o/r"):
    tmi = MagicMock()
    repo = MagicMock(id=repo_id, uri=url)
    repo.name = "r"
    tmi.get_threat_model_repositories.return_value = [repo]
    return tmi


class TestResolveFanoutTargets:
    def _run(self, tmp_path, envs, scope, latest=("b", 100)):
        tree = _tree(tmp_path, envs)
        tmi = _tmi_with_repo()
        with (
            patch(
                "tmi_tf.analyzer.RepositoryAnalyzer.clone_repository_sparse",
                _fake_clone(tree),
            ),
            patch("tmi_tf.analyzer.GitHubClient.is_github_url", return_value=True),
            patch(
                "tmi_tf.analyzer.RepositoryAnalyzer.select_latest_environment",
                side_effect=lambda cp, es: (
                    next(e for e in es if e.name == latest[0]),
                    latest[1],
                ),
            ),
        ):
            targets = resolve_fanout_targets(Config(), "tm1", tmi, scope)
        return targets, tmi

    def test_default_latest(self, tmp_path):
        targets, tmi = self._run(tmp_path, ["a", "b", "c"], None)
        assert targets == [FanoutTarget("r1", "https://github.com/o/r", "b")]
        note = " ".join(str(c) for c in tmi.update_status_note.call_args_list)
        assert "latest" in note and "b" in note

    def test_all(self, tmp_path):
        targets, _ = self._run(tmp_path, ["a", "b"], "all")
        assert [t.environment for t in targets] == ["a", "b"]

    def test_glob_reports_skipped(self, tmp_path):
        targets, tmi = self._run(tmp_path, ["aws-a", "gcp-b"], "aws-*")
        assert [t.environment for t in targets] == ["aws-a"]
        note = " ".join(str(c) for c in tmi.update_status_note.call_args_list)
        assert "gcp-b" in note and "not in scope" in note

    def test_single_environment_ignores_scope(self, tmp_path):
        targets, _ = self._run(tmp_path, ["only"], "zzz-*")
        assert [t.environment for t in targets] == ["only"]

    def test_repo_id_filters(self, tmp_path):
        tree = _tree(tmp_path, ["a"])
        tmi = _tmi_with_repo()
        with (
            patch(
                "tmi_tf.analyzer.RepositoryAnalyzer.clone_repository_sparse",
                _fake_clone(tree),
            ),
            patch("tmi_tf.analyzer.GitHubClient.is_github_url", return_value=True),
        ):
            assert (
                resolve_fanout_targets(Config(), "tm1", tmi, "all", repo_id="other")
                == []
            )

    def test_no_repositories_writes_status_note(self, tmp_path):
        tmi = MagicMock()
        tmi.get_threat_model_repositories.return_value = []
        assert resolve_fanout_targets(Config(), "tm1", tmi, "all") == []
        note = " ".join(str(c) for c in tmi.update_status_note.call_args_list)
        assert "No GitHub repositories" in note

    def test_repo_id_not_found_writes_status_note(self, tmp_path):
        tmi = _tmi_with_repo()
        with patch("tmi_tf.analyzer.GitHubClient.is_github_url", return_value=True):
            targets = resolve_fanout_targets(
                Config(), "tm1", tmi, "all", repo_id="nope"
            )
        assert targets == []
        note = " ".join(str(c) for c in tmi.update_status_note.call_args_list)
        assert "nope" in note

    def test_no_environments_yields_whole_repo_target(self, tmp_path):
        (tmp_path / "loose.tf").write_text("# loose")
        tmi = _tmi_with_repo()
        with (
            patch(
                "tmi_tf.analyzer.RepositoryAnalyzer.clone_repository_sparse",
                _fake_clone(tmp_path),
            ),
            patch("tmi_tf.analyzer.GitHubClient.is_github_url", return_value=True),
        ):
            targets = resolve_fanout_targets(Config(), "tm1", tmi, "all")
        assert targets == [FanoutTarget("r1", "https://github.com/o/r", "")]


class TestRunAnalysisEnvironmentSelection:
    def _patches(self, tree):
        return (
            patch(
                "tmi_tf.analyzer.RepositoryAnalyzer.clone_repository_sparse",
                _fake_clone(tree),
            ),
            patch("tmi_tf.analyzer.GitHubClient.is_github_url", return_value=True),
            patch("tmi_tf.analyzer.get_llm_provider"),
            patch("tmi_tf.analyzer.LLMAnalyzer"),
            patch("tmi_tf.analyzer.MarkdownGenerator"),
            patch(
                "tmi_tf.analyzer.validate_and_sanitize",
                side_effect=lambda files, root: MagicMock(
                    valid_files=files, sanitization_log=[]
                ),
            ),
        )

    def test_none_on_multi_env_selects_latest(self, tmp_path):
        tree = _tree(tmp_path, ["a", "b"])
        tmi = _tmi_with_repo()
        analyze = MagicMock(return_value=MagicMock(success=False, errors=["stub"]))
        clone, gh, prov, llm_cls, md, val = self._patches(tree)
        with (
            clone,
            gh,
            prov,
            llm_cls as llm,
            md,
            val,
            patch(
                "tmi_tf.analyzer.RepositoryAnalyzer.select_latest_environment",
                side_effect=lambda cp, es: (es[1], 5),
            ),
        ):
            llm.return_value.analyze_repository = analyze
            run_analysis(Config(), "tm1", tmi, skip_diagram=True, skip_threats=True)
        assert analyze.call_args.args[0].environment_name == "b"
        assert analyze.call_count == 1

    def test_empty_environment_string_behaves_as_none(self, tmp_path):
        tree = _tree(tmp_path, ["a", "b"])
        tmi = _tmi_with_repo()
        analyze = MagicMock(return_value=MagicMock(success=False, errors=["stub"]))
        clone, gh, prov, llm_cls, md, val = self._patches(tree)
        with (
            clone,
            gh,
            prov,
            llm_cls as llm,
            md,
            val,
            patch(
                "tmi_tf.analyzer.RepositoryAnalyzer.select_latest_environment",
                side_effect=lambda cp, es: (es[1], 5),
            ),
        ):
            llm.return_value.analyze_repository = analyze
            run_analysis(
                Config(),
                "tm1",
                tmi,
                skip_diagram=True,
                skip_threats=True,
                environment="",
            )
        assert analyze.call_args.args[0].environment_name == "b"

    def test_named_environment_missing_is_success_no_retry(self, tmp_path):
        tree = _tree(tmp_path, ["a", "b"])
        tmi = _tmi_with_repo()
        clone, gh, prov, llm_cls, md, val = self._patches(tree)
        with clone, gh, prov, llm_cls, md, val:
            result = run_analysis(Config(), "tm1", tmi, environment="gone")
        assert result.success is True
        assert any("gone" in e for e in result.errors)
        assert result.analyses == []

    def test_nothing_analyzed_for_other_reasons_is_failure(self, tmp_path):
        tmi = _tmi_with_repo()
        with (
            patch("tmi_tf.analyzer.GitHubClient.is_github_url", return_value=False),
            patch("tmi_tf.analyzer.get_llm_provider"),
            patch("tmi_tf.analyzer.LLMAnalyzer"),
        ):
            result = run_analysis(Config(), "tm1", tmi)
        assert result.success is False


class TestAllAnalysesFailed:
    def test_job_fails_when_every_analysis_failed(self, tmp_path):
        tree = _tree(tmp_path, ["a"])
        tmi = _tmi_with_repo()
        analysis = MagicMock(success=False, error_message="**Analysis Failed**: boom")
        analysis.security_findings = []
        analysis.repo_name = "r"
        analysis.repo_url = "https://github.com/o/r"
        clone, gh, prov, llm_cls, md, val = (
            TestRunAnalysisEnvironmentSelection()._patches(tree)
        )
        with clone, gh, prov, llm_cls as llm, md, val:
            llm.return_value.analyze_repository = MagicMock(return_value=analysis)
            result = run_analysis(
                Config(), "tm1", tmi, skip_diagram=True, skip_threats=True
            )
        assert result.success is False
        assert any("boom" in e for e in result.errors)
        last_note = tmi.update_status_note.call_args.args[1]
        assert "failed" in last_note.lower()
