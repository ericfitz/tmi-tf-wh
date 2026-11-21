"""Tests for tmi_tf.analyzer module."""

import time
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from llm_errors import FakeClock

from tmi_tf.analyzer import (
    AnalysisResult,
    FanoutTarget,
    _dfd_timeout,
    _retry_budgets,
    resolve_fanout_targets,
    run_analysis,
    threats_not_created_text,
)
from tmi_tf.config import Config
from tmi_tf.llm_analyzer import ThreatGaps
from tmi_tf.llm_profiles import LLMProfile
from tmi_tf.retry import RetryBudget

PROFILE = LLMProfile("t", "oci", "m", "oci")


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
            run_analysis(
                Config(), "tm1", tmi, PROFILE, skip_diagram=True, skip_threats=True
            )
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
                PROFILE,
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
            result = run_analysis(Config(), "tm1", tmi, PROFILE, environment="gone")
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
            result = run_analysis(Config(), "tm1", tmi, PROFILE)
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
                Config(), "tm1", tmi, PROFILE, skip_diagram=True, skip_threats=True
            )
        assert result.success is False
        assert any("boom" in e for e in result.errors)
        last_note = tmi.update_status_note.call_args.args[1]
        assert "failed" in last_note.lower()


class TestRunAnalysisProfile:
    def test_provider_built_from_profile_and_named_in_status(self):
        tmi = _tmi_with_repo()
        with (
            patch("tmi_tf.analyzer.GitHubClient.is_github_url", return_value=False),
            patch("tmi_tf.analyzer.get_llm_provider") as get_provider,
            patch("tmi_tf.analyzer.LLMAnalyzer"),
        ):
            get_provider.return_value.model = "oci/m"
            run_analysis(Config(), "tm1", tmi, PROFILE)
        get_provider.assert_called_once_with(PROFILE)
        first_note = tmi.update_status_note.call_args_list[0].args[1]
        assert first_note == "Analysis started (profile t, oci/m)"


class TestDFDRefusal:
    def test_dfd_refusal_reported_in_status_and_analysis_note(self, tmp_path):
        from tmi_tf.llm_analyzer import LLMRefusalError
        from tmi_tf.providers import LLMResponse

        tree = _tree(tmp_path, ["a"])
        tmi = _tmi_with_repo()
        analysis = MagicMock(success=True, refusals="", threat_gaps=ThreatGaps())
        analysis.repo_name = "r"
        analysis.repo_url = "https://github.com/o/r"
        analysis.inventory = {"components": [], "services": []}
        analysis.infrastructure = {}
        refused = LLMResponse(
            text=None,
            input_tokens=1,
            output_tokens=0,
            cost=0.0,
            finish_reason="content_filter",
        )
        clone, gh, prov, llm_cls, md, val = (
            TestRunAnalysisEnvironmentSelection()._patches(tree)
        )
        with (
            clone,
            gh,
            prov,
            llm_cls as llm,
            md as md_cls,
            val,
            patch("tmi_tf.analyzer.aggregate_analysis_metadata"),
            patch("tmi_tf.analyzer.DFDLLMGenerator") as dfd_cls,
        ):
            llm.return_value.analyze_repository = MagicMock(return_value=analysis)
            dfd_cls.return_value.generate_structured_components.side_effect = (
                LLMRefusalError("DFD generation: model refused", refused)
            )
            md_cls.return_value.generate_analysis_report.side_effect = lambda **kw: (
                "REFUSED" if kw.get("dfd_refused") else "CLEAN"
            )
            run_analysis(Config(), "tm1", tmi, PROFILE, skip_threats=True)

        notes = [c.args[1] for c in tmi.update_status_note.call_args_list]
        assert "Model refusals (content_filter): DFD generation" in notes
        tmi.create_or_update_diagram.assert_not_called()
        analysis_writes = [
            c.kwargs["content"]
            for c in tmi.create_or_update_note.call_args_list
            if c.kwargs["name"].startswith("Terraform Analysis")
        ]
        assert analysis_writes[-1] == "REFUSED"


class TestRetryBudgets:
    def test_no_deadline_means_no_budgets(self):
        assert _retry_budgets(None, 0.0) == (None, None)

    def test_default_job_timeout(self):
        analysis, dfd = _retry_budgets(3600.0, 0.0)
        assert analysis is not None and dfd is not None
        assert (analysis.deadline, dfd.deadline) == (3000.0, 3480.0)

    def test_small_job_timeout_keeps_a_positive_window(self):
        analysis, dfd = _retry_budgets(10.0, 0.0)
        assert analysis is not None and dfd is not None
        assert (analysis.deadline, dfd.deadline) == (8.0, 9.5)

    def test_deadline_already_passed(self):
        analysis, dfd = _retry_budgets(5.0, 9.0)
        assert analysis is not None and dfd is not None
        assert analysis.deadline == dfd.deadline == 5.0


class TestDfdTimeout:
    def test_no_budget_keeps_the_full_timeout(self):
        assert _dfd_timeout(None) == 1200.0

    @pytest.mark.parametrize(
        ("remaining", "expected"),
        [
            (5000.0, 1200.0),
            (400.0, 400.0),
            (60.0, 60.0),
            (59.9, None),
            (0.0, None),
            (-30.0, None),
        ],
    )
    def test_timeout_is_capped_and_a_short_window_skips(self, remaining, expected):
        clock = FakeClock()
        assert _dfd_timeout(RetryBudget(remaining, clock)) == expected

    def test_exhausted_budget_skips(self):
        budget = RetryBudget(5000.0, FakeClock())
        budget.exhausted = True
        assert _dfd_timeout(budget) is None


class TestRunAnalysisDeadline:
    def _run(self, tmp_path, deadline):
        tree = _tree(tmp_path, ["a"])
        tmi = _tmi_with_repo()
        analysis = MagicMock(success=True, refusals="", threat_gaps=ThreatGaps())
        analysis.repo_name = "r"
        analysis.repo_url = "https://github.com/o/r"
        analysis.inventory = {"components": [], "services": []}
        analysis.infrastructure = {}
        clone, gh, prov, llm_cls, md, val = (
            TestRunAnalysisEnvironmentSelection()._patches(tree)
        )
        with (
            clone,
            gh,
            prov,
            llm_cls as llm,
            md,
            val,
            patch("tmi_tf.analyzer.aggregate_analysis_metadata"),
            patch("tmi_tf.analyzer.DFDLLMGenerator") as dfd_cls,
        ):
            llm.return_value.analyze_repository = MagicMock(return_value=analysis)
            dfd_cls.return_value.generate_structured_components.return_value = None
            kwargs = {} if deadline is None else {"deadline": deadline}
            run_analysis(Config(), "tm1", tmi, PROFILE, skip_threats=True, **kwargs)
        return tmi, llm, dfd_cls

    def test_dfd_gets_a_bounded_timeout_and_a_per_attempt_timeout_fn(self, tmp_path):
        _, _, dfd_cls = self._run(tmp_path, time.monotonic() + 3600)
        gen = dfd_cls.return_value.generate_structured_components
        kw = gen.call_args.kwargs
        assert 60 <= kw["timeout"] <= 1200
        fn = kw["timeout_fn"]
        assert fn is not None and 60 <= fn() <= 1200
        assert isinstance(dfd_cls.call_args.kwargs["retry_budget"], RetryBudget)

    def test_short_dfd_window_skips_the_dfd(self, tmp_path):
        tmi, _, dfd_cls = self._run(tmp_path, time.monotonic() + 1)
        dfd_cls.return_value.generate_structured_components.assert_not_called()
        tmi.create_or_update_diagram.assert_not_called()

    def test_analyzer_gets_a_retry_budget_only_with_a_deadline(self, tmp_path):
        _, llm, _ = self._run(tmp_path, time.monotonic() + 3600)
        assert isinstance(llm.call_args.kwargs["retry_budget"], RetryBudget)
        (tmp_path / "second").mkdir()
        _, llm, _ = self._run(tmp_path / "second", None)
        assert llm.call_args.kwargs["retry_budget"] is None


class _Http503(Exception):
    status_code = 503


class TestStepRows:
    def _run(self, tmp_path, *, skip_threats=True, deadline=None, setup=None):
        tree = _tree(tmp_path, ["a"])
        tmi = _tmi_with_repo()
        analysis = MagicMock(success=True, refusals="", threat_gaps=ThreatGaps())
        analysis.repo_name = "r"
        analysis.repo_url = "https://github.com/o/r"
        analysis.inventory = {"components": [], "services": []}
        analysis.infrastructure = {}
        analysis.security_findings = []
        clone, gh, prov, llm_cls, md, val = (
            TestRunAnalysisEnvironmentSelection()._patches(tree)
        )
        kwargs = {} if deadline is None else {"deadline": deadline}
        with (
            clone,
            gh,
            prov,
            llm_cls as llm,
            md as md_cls,
            val,
            patch("tmi_tf.analyzer.aggregate_analysis_metadata"),
            patch("tmi_tf.analyzer.DFDLLMGenerator") as dfd_cls,
            patch("tmi_tf.analyzer.DFDBuilder") as builder_cls,
            patch("tmi_tf.analyzer.ThreatProcessor") as tp_cls,
        ):
            llm.return_value.analyze_repository = MagicMock(return_value=analysis)
            dfd_cls.return_value.generate_structured_components.return_value = None
            dfd_cls.return_value.last_error = ""
            builder_cls.return_value.build_cells.return_value = [{}] * 12
            if setup:
                setup(llm=llm, md=md_cls, dfd=dfd_cls, tp=tp_cls, analysis=analysis)
            result = run_analysis(
                Config(), "tm1", tmi, PROFILE, skip_threats=skip_threats, **kwargs
            )
        notes = [c.args[1] for c in tmi.update_status_note.call_args_list]
        return result, notes, tmi, dfd_cls

    def test_dfd_failure_row_carries_the_generator_reason(self, tmp_path):
        def setup(dfd, **_):
            dfd.return_value.last_error = "HTTP 429 rate_limit_error"

        _, notes, _, _ = self._run(tmp_path, setup=setup)
        assert "DFD diagram: failed: HTTP 429 rate_limit_error" in notes

    def test_dfd_failure_without_a_reason_says_unknown(self, tmp_path):
        def setup(dfd, **_):
            dfd.return_value.last_error = ""

        _, notes, _, _ = self._run(tmp_path, setup=setup)
        assert "DFD diagram: failed: unknown error" in notes

    def test_dfd_exception_row_uses_the_hint_not_the_message(self, tmp_path):
        def setup(dfd, **_):
            dfd.return_value.generate_structured_components.side_effect = _Http503(
                "secret-body"
            )

        _, notes, _, _ = self._run(tmp_path, setup=setup)
        assert "DFD diagram: failed: HTTP 503 service_unavailable" in notes
        assert not any("secret-body" in n for n in notes)

    def test_dfd_refusal_keeps_its_row_and_gets_an_outcome_row(self, tmp_path):
        from tmi_tf.llm_analyzer import LLMRefusalError
        from tmi_tf.providers import LLMResponse

        refused = LLMResponse(
            text=None,
            input_tokens=1,
            output_tokens=0,
            cost=0.0,
            finish_reason="content_filter",
        )

        def setup(dfd, **_):
            dfd.return_value.generate_structured_components.side_effect = (
                LLMRefusalError("DFD generation: model refused", refused)
            )

        _, notes, _, _ = self._run(tmp_path, setup=setup)
        assert "Model refusals (content_filter): DFD generation" in notes
        assert "DFD diagram: failed: refused (content_filter)" in notes

    def test_dfd_skipped_at_the_deadline_row(self, tmp_path):
        _, notes, tmi, dfd_cls = self._run(tmp_path, deadline=time.monotonic() + 1)
        assert "DFD diagram: failed: deadline reached" in notes
        assert "Generating DFD diagram" not in notes
        dfd_cls.return_value.generate_structured_components.assert_not_called()
        tmi.create_or_update_diagram.assert_not_called()

    def test_dfd_success_row(self, tmp_path):
        def setup(dfd, **_):
            dfd.return_value.generate_structured_components.return_value = {
                "components": [],
                "flows": [],
            }

        _, notes, _, _ = self._run(tmp_path, setup=setup)
        assert "DFD diagram: succeeded (12 cells)" in notes
        assert not any(n.startswith("DFD diagram: failed") for n in notes)

    def test_no_dfd_row_when_skip_diagram(self, tmp_path):
        tree = _tree(tmp_path, ["a"])
        tmi = _tmi_with_repo()
        analysis = MagicMock(success=True, refusals="", threat_gaps=ThreatGaps())
        analysis.repo_name = "r"
        analysis.repo_url = "https://github.com/o/r"
        clone, gh, prov, llm_cls, md, val = (
            TestRunAnalysisEnvironmentSelection()._patches(tree)
        )
        with clone, gh, prov, llm_cls as llm, md, val:
            llm.return_value.analyze_repository = MagicMock(return_value=analysis)
            run_analysis(
                Config(), "tm1", tmi, PROFILE, skip_diagram=True, skip_threats=True
            )
        notes = [c.args[1] for c in tmi.update_status_note.call_args_list]
        assert not any(n.startswith("DFD diagram") for n in notes)

    def test_report_and_clone_rows(self, tmp_path):
        _, notes, _, _ = self._run(tmp_path)
        for row in (
            "Clone o_r: succeeded",
            "Inventory report: succeeded",
            "Analysis report: succeeded",
        ):
            assert row in notes
        assert "Clone complete: o_r" not in notes

    def test_no_terraform_files_row(self, tmp_path):
        tmi = _tmi_with_repo()

        @contextmanager
        def _no_repo(self, repo_url, repo_name, base_temp_dir=None):
            yield None

        with (
            patch(
                "tmi_tf.analyzer.RepositoryAnalyzer.clone_repository_sparse", _no_repo
            ),
            patch("tmi_tf.analyzer.GitHubClient.is_github_url", return_value=True),
            patch("tmi_tf.analyzer.get_llm_provider"),
            patch("tmi_tf.analyzer.LLMAnalyzer"),
        ):
            run_analysis(Config(), "tm1", tmi, PROFILE)
        notes = [c.args[1] for c in tmi.update_status_note.call_args_list]
        assert "Clone o_r: failed: no Terraform files found" in notes

    def test_repository_failure_row(self, tmp_path):
        tmi = _tmi_with_repo()

        @contextmanager
        def _boom(self, repo_url, repo_name, base_temp_dir=None):
            raise _Http503("secret-body")
            yield  # pragma: no cover

        with (
            patch("tmi_tf.analyzer.RepositoryAnalyzer.clone_repository_sparse", _boom),
            patch("tmi_tf.analyzer.GitHubClient.is_github_url", return_value=True),
            patch("tmi_tf.analyzer.get_llm_provider"),
            patch("tmi_tf.analyzer.LLMAnalyzer"),
        ):
            run_analysis(Config(), "tm1", tmi, PROFILE)
        notes = [c.args[1] for c in tmi.update_status_note.call_args_list]
        assert "Repository r: failed: HTTP 503 service_unavailable" in notes
        assert not any("secret-body" in n for n in notes)

    def test_fatal_error_row_names_the_step(self, tmp_path):
        def setup(md, **_):
            md.return_value.generate_inventory_report.side_effect = _Http503("x")

        result, notes, _, _ = self._run(tmp_path, setup=setup)
        assert "Inventory report: failed: HTTP 503 service_unavailable" in notes
        assert result.success is False

    def test_failed_inventory_note_write_is_labeled_inventory_report(self, tmp_path):
        tree = _tree(tmp_path, ["a"])
        tmi = _tmi_with_repo()
        tmi.create_or_update_note.side_effect = _Http503("x")
        analysis = MagicMock(success=True, refusals="", threat_gaps=ThreatGaps())
        analysis.repo_name = "r"
        analysis.repo_url = "https://github.com/o/r"
        clone, gh, prov, llm_cls, md, val = (
            TestRunAnalysisEnvironmentSelection()._patches(tree)
        )
        with (
            clone,
            gh,
            prov,
            llm_cls as llm,
            md,
            val,
            patch("tmi_tf.analyzer.aggregate_analysis_metadata"),
        ):
            llm.return_value.analyze_repository = MagicMock(return_value=analysis)
            result = run_analysis(Config(), "tm1", tmi, PROFILE)
        notes = [c.args[1] for c in tmi.update_status_note.call_args_list]
        assert "Inventory report: failed: HTTP 503 service_unavailable" in notes
        assert "Analysis report: succeeded" not in notes
        assert result.success is False

    def test_fatal_row_write_failure_does_not_mask_the_result(self, tmp_path):
        def setup(md, **_):
            md.return_value.generate_inventory_report.side_effect = _Http503("x")

        tree = _tree(tmp_path, ["a"])
        tmi = _tmi_with_repo()

        def flaky(_tm, msg):
            if "failed" in msg:
                raise RuntimeError("note write failed")

        tmi.update_status_note.side_effect = flaky
        analysis = MagicMock(success=True, refusals="", threat_gaps=ThreatGaps())
        analysis.repo_name = "r"
        analysis.repo_url = "https://github.com/o/r"
        clone, gh, prov, llm_cls, md, val = (
            TestRunAnalysisEnvironmentSelection()._patches(tree)
        )
        with clone, gh, prov, llm_cls as llm, md as md_cls, val:
            llm.return_value.analyze_repository = MagicMock(return_value=analysis)
            setup(md=md_cls)
            result = run_analysis(Config(), "tm1", tmi, PROFILE)
        assert result.success is False
        assert any("Fatal error" in e for e in result.errors)

    def _threat_setup(self, hints):
        def setup(tp, analysis, **_):
            analysis.security_findings = [{"name": "x"}]
            analysis.security_input_tokens = 0
            analysis.security_output_tokens = 0
            analysis.security_cost = 0.0
            inst = tp.return_value
            inst.threats_from_findings.return_value = [MagicMock()] * 3
            inst.create_threats_in_tmi.return_value = [{}, {}]
            inst.create_error_hints = hints

        return setup

    def test_threat_creation_rows(self, tmp_path):
        from tmi_tf import analyzer as mod

        real = mod.threats_not_created_text
        gap_calls: list[str] = []

        def spy(*a, **kw):
            text = real(*a, **kw)
            if kw.get("phrase"):
                gap_calls.append(text)
            return text

        with patch("tmi_tf.analyzer.threats_not_created_text", spy):
            _, notes, _, _ = self._run(
                tmp_path,
                skip_threats=False,
                setup=self._threat_setup(["HTTP 500 internal_server_error"]),
            )
        assert (
            "Threat creation: failed: 1 of 3 threats not created "
            "(HTTP 500 internal_server_error)" in notes
        )
        assert gap_calls == [
            ("1 of 3 threats not created in TMI (HTTP 500 internal_server_error)")
        ]

    def test_threat_creation_success_row(self, tmp_path):
        def setup(tp, analysis, **kw):
            self._threat_setup([])(tp=tp, analysis=analysis)
            tp.return_value.create_threats_in_tmi.return_value = [{}] * 3

        _, notes, _, _ = self._run(tmp_path, skip_threats=False, setup=setup)
        assert "Threat creation: succeeded (3 created)" in notes

    def test_threat_creation_with_nothing_extracted_row(self, tmp_path):
        _, notes, _, _ = self._run(tmp_path, skip_threats=False)
        assert "Threat creation: succeeded (0 created)" in notes

    def test_threat_creation_unknown_error_text(self, tmp_path):
        from tmi_tf import analyzer as mod

        real = mod.threats_not_created_text
        gap_calls: list[str] = []

        def spy(*a, **kw):
            text = real(*a, **kw)
            if kw.get("phrase"):
                gap_calls.append(text)
            return text

        with patch("tmi_tf.analyzer.threats_not_created_text", spy):
            _, notes, _, _ = self._run(
                tmp_path, skip_threats=False, setup=self._threat_setup([])
            )
        assert (
            "Threat creation: failed: 1 of 3 threats not created (unknown error)"
            in notes
        )
        assert gap_calls == ["1 of 3 threats not created in TMI (unknown error)"]

    def test_threat_creation_exception_row(self, tmp_path):
        def setup(tp, analysis, **_):
            analysis.security_findings = [{"name": "x"}]
            tp.return_value.threats_from_findings.side_effect = _Http503("secret-body")

        from tmi_tf import analyzer as mod

        real = mod.threats_not_created_text
        gap_calls: list[str] = []

        def spy(*a, **kw):
            text = real(*a, **kw)
            if kw.get("phrase"):
                gap_calls.append(text)
            return text

        with patch("tmi_tf.analyzer.threats_not_created_text", spy):
            _, notes, _, _ = self._run(tmp_path, skip_threats=False, setup=setup)
        assert gap_calls == [
            "threats not created in TMI (HTTP 503 service_unavailable)"
        ]
        assert "Threat creation: failed: HTTP 503 service_unavailable" in notes
        assert not any("secret-body" in n for n in notes)


class TestThreatsNotCreatedText:
    def test_counts_and_hints(self):
        assert (
            threats_not_created_text(["a", "b"], missing=1, total=3)
            == "1 of 3 threats not created (a, b)"
        )

    def test_gap_phrase(self):
        assert (
            threats_not_created_text(
                ["a"], missing=2, total=5, phrase="threats not created in TMI"
            )
            == "2 of 5 threats not created in TMI (a)"
        )

    def test_without_counts_and_without_hints(self):
        assert threats_not_created_text(["a"]) == "threats not created (a)"
        assert threats_not_created_text([]) == "threats not created (unknown error)"


def _mock_analysis(name="r", url="https://github.com/o/r", gaps=None):
    analysis = MagicMock(success=True, refusals="", threat_gaps=gaps or ThreatGaps())
    analysis.repo_name = name
    analysis.repo_url = url
    analysis.inventory = {"components": [], "services": []}
    analysis.infrastructure = {}
    analysis.security_findings = []
    return analysis


class TestRunGaps:
    def _run(
        self,
        tmp_path,
        *,
        analyses=None,
        skip_threats=True,
        deadline=None,
        setup=None,
        all_failed=False,
    ):
        tree = _tree(tmp_path, ["a"])
        analyses = analyses or [_mock_analysis()]
        if all_failed:
            bad = MagicMock(success=False, error_message="boom")
            bad.repo_name = "r"
            bad.repo_url = "https://github.com/o/r"
            analyses = [bad]
        tmi = _tmi_with_repo()
        if len(analyses) > 1:
            repos = []
            for a in analyses:
                repo = MagicMock(id=a.repo_name, uri=a.repo_url)
                repo.name = a.repo_name
                repos.append(repo)
            tmi.get_threat_model_repositories.return_value = repos
        clone, gh, prov, llm_cls, md, val = (
            TestRunAnalysisEnvironmentSelection()._patches(tree)
        )
        kwargs = {} if deadline is None else {"deadline": deadline}
        with (
            clone,
            gh,
            prov,
            llm_cls as llm,
            md as md_cls,
            val,
            patch("tmi_tf.analyzer.aggregate_analysis_metadata"),
            patch("tmi_tf.analyzer.DFDLLMGenerator") as dfd_cls,
            patch("tmi_tf.analyzer.DFDBuilder") as builder_cls,
            patch("tmi_tf.analyzer.ThreatProcessor") as tp_cls,
        ):
            llm.return_value.analyze_repository = MagicMock(side_effect=analyses)
            dfd_cls.return_value.generate_structured_components.return_value = {
                "components": [],
                "flows": [],
            }
            dfd_cls.return_value.last_error = ""
            builder_cls.return_value.build_cells.return_value = [{}] * 12
            if setup:
                setup(md=md_cls, dfd=dfd_cls, tp=tp_cls, analysis=analyses[0])
            result = run_analysis(
                Config(), "tm1", tmi, PROFILE, skip_threats=skip_threats, **kwargs
            )
        return result, tmi, md_cls

    @staticmethod
    def _dfd_returns_none(reason):
        def setup(dfd, **_):
            dfd.return_value.generate_structured_components.return_value = None
            dfd.return_value.last_error = reason

        return setup

    def test_clean_run_reports_no_gaps(self, tmp_path):
        result, tmi, _ = self._run(tmp_path)
        assert result.gaps == []
        assert tmi.update_status_note.call_args.args[1] == "Analysis complete"

    def test_threat_and_dfd_gaps_reach_the_result_and_the_final_row(self, tmp_path):
        analysis = _mock_analysis(
            gaps=ThreatGaps(28, failed=25, hints=("HTTP 429 rate_limit_error",))
        )
        result, tmi, _ = self._run(
            tmp_path,
            analyses=[analysis],
            setup=self._dfd_returns_none("HTTP 429 rate_limit_error"),
        )
        assert result.success is True
        assert result.gaps == [
            "25 of 28 threats not analyzed (HTTP 429 rate_limit_error)",
            "DFD not generated (HTTP 429 rate_limit_error)",
        ]
        assert tmi.update_status_note.call_args.args[1] == (
            "Analysis completed with gaps: 25 of 28 threats not analyzed "
            "(HTTP 429 rate_limit_error); DFD not generated (HTTP 429 rate_limit_error)"
        )

    def test_gapped_run_logs_a_warning_not_a_clean_finish(self, tmp_path, caplog):
        analysis = _mock_analysis(gaps=ThreatGaps(3, failed=2, hints=("x",)))
        with caplog.at_level("INFO", logger="tmi_tf.analyzer"):
            self._run(tmp_path, analyses=[analysis])
        msgs = [(r.levelname, r.getMessage()) for r in caplog.records]
        assert (
            "WARNING",
            "Analysis completed with gaps: 2 of 3 threats not analyzed (x)",
        ) in msgs
        assert not any("Analysis complete!" in m for _, m in msgs)

    def test_clean_run_still_logs_complete(self, tmp_path, caplog):
        with caplog.at_level("INFO", logger="tmi_tf.analyzer"):
            self._run(tmp_path)
        assert any("Analysis complete!" in r.getMessage() for r in caplog.records)
        assert not any("with gaps" in r.getMessage() for r in caplog.records)

    def test_dfd_refusal_is_a_gap(self, tmp_path):
        from tmi_tf.llm_analyzer import LLMRefusalError
        from tmi_tf.providers import LLMResponse

        refused = LLMResponse(
            text=None,
            input_tokens=1,
            output_tokens=0,
            cost=0.0,
            finish_reason="content_filter",
        )

        def setup(dfd, **_):
            dfd.return_value.generate_structured_components.side_effect = (
                LLMRefusalError("DFD generation: model refused", refused)
            )

        result, _, _ = self._run(tmp_path, setup=setup)
        assert result.gaps == ["DFD not generated (refused)"]

    def test_dfd_skipped_at_the_deadline_is_a_gap(self, tmp_path):
        result, _, _ = self._run(tmp_path, deadline=time.monotonic() + 1)
        assert result.gaps == ["DFD not generated (deadline reached)"]

    def test_threat_creation_shortfall_is_a_gap(self, tmp_path):
        setup = TestStepRows()._threat_setup(["HTTP 500 internal_server_error"])
        result, _, _ = self._run(tmp_path, skip_threats=False, setup=setup)
        assert result.gaps == [
            "1 of 3 threats not created in TMI (HTTP 500 internal_server_error)"
        ]

    def test_repo_name_prefix_only_with_several_analyses(self, tmp_path):
        a1 = _mock_analysis("r1", "https://github.com/o/r1")
        a2 = _mock_analysis(
            "r2",
            "https://github.com/o/r2",
            gaps=ThreatGaps(2, failed=1, hints=("RuntimeError",)),
        )
        result, _, _ = self._run(tmp_path, analyses=[a1, a2])
        assert result.gaps == ["r2: 1 of 2 threats not analyzed (RuntimeError)"]

    def test_dfd_failure_rewrites_the_analysis_note(self, tmp_path):
        result, _, md_cls = self._run(
            tmp_path, setup=self._dfd_returns_none("HTTP 429 rate_limit_error")
        )
        calls = md_cls.return_value.generate_analysis_report.call_args_list
        assert len(calls) == 2
        assert calls[-1].kwargs["dfd_error"] == "HTTP 429 rate_limit_error"
        assert not calls[-1].kwargs.get("dfd_refused", False)
        assert result.gaps == ["DFD not generated (HTTP 429 rate_limit_error)"]

    def test_dfd_refusal_rewrite_passes_refused_only(self, tmp_path):
        from tmi_tf.llm_analyzer import LLMRefusalError
        from tmi_tf.providers import LLMResponse

        refused = LLMResponse(None, 1, 0, 0.0, finish_reason="content_filter")

        def setup(dfd, **_):
            dfd.return_value.generate_structured_components.side_effect = (
                LLMRefusalError("DFD generation: model refused", refused)
            )

        _, _, md_cls = self._run(tmp_path, setup=setup)
        last = md_cls.return_value.generate_analysis_report.call_args_list[-1]
        assert last.kwargs["dfd_refused"] is True
        assert not last.kwargs.get("dfd_error")

    def test_all_failed_path_is_unchanged(self, tmp_path):
        result, tmi, _ = self._run(tmp_path, all_failed=True)
        assert result.success is False and result.gaps == []
        assert tmi.update_status_note.call_args.args[1].startswith("Analysis failed: ")
