"""Tests for the grype gate in scripts/push-aws.sh (--check-report mode)."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "push-aws.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("jq") is None or shutil.which("bash") is None,
    reason="push-aws.sh --check-report needs bash and jq",
)


def _match(severity, vuln_id="CVE-2026-0001", name="pkg", fixed=True, fix="2.0"):
    vulnerability = {
        "id": vuln_id,
        "fix": {
            "state": "fixed" if fixed else "not-fixed",
            "versions": [fix] if fixed else [],
        },
    }
    if severity is not None:
        vulnerability["severity"] = severity
    return {
        "vulnerability": vulnerability,
        "artifact": {"name": name, "version": "1.0"},
    }


def _run(tmp_path, report, *args):
    path = tmp_path / "report.json"
    path.write_text(report if isinstance(report, str) else json.dumps(report))
    return subprocess.run(
        ["bash", str(SCRIPT), "--check-report", str(path), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_clean_report_passes(tmp_path):
    result = _run(tmp_path, {"matches": []})
    assert result.returncode == 0, result.stderr
    assert "No fixable vulnerabilities at or above high" in result.stderr


def test_fixable_high_fails_and_names_it(tmp_path):
    report = {"matches": [_match("High", "GHSA-xxxx", "filelock", fix="4.2.1")]}
    result = _run(tmp_path, report)
    assert result.returncode == 3
    assert "GHSA-xxxx\tfilelock\t1.0\t4.2.1" in result.stderr


def test_critical_fails_at_default_threshold(tmp_path):
    result = _run(tmp_path, {"matches": [_match("Critical")]})
    assert result.returncode == 3


def test_below_threshold_passes(tmp_path):
    report = {"matches": [_match("Medium"), _match("Low"), _match("Negligible")]}
    assert _run(tmp_path, report).returncode == 0


def test_unfixed_high_passes(tmp_path):
    result = _run(tmp_path, {"matches": [_match("Critical", fixed=False)]})
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("severity", ["Unknown", "Bogus", None])
def test_unknown_or_missing_severity_fails(tmp_path, severity):
    result = _run(tmp_path, {"matches": [_match(severity)]})
    assert result.returncode == 3


def test_fail_on_lowers_threshold(tmp_path):
    result = _run(tmp_path, {"matches": [_match("Medium")]}, "--fail-on", "medium")
    assert result.returncode == 3


def test_duplicate_matches_listed_once(tmp_path):
    result = _run(tmp_path, {"matches": [_match("High"), _match("High")]})
    assert result.returncode == 3
    assert "Fixable vulnerabilities at or above high (1):" in result.stderr


def test_invalid_fail_on_rejected(tmp_path):
    result = _run(tmp_path, {"matches": []}, "--fail-on", "severe")
    assert result.returncode == 1
    assert "--fail-on must be one of" in result.stderr


@pytest.mark.parametrize("report", ["not json", "[]", '{"foo": 1}'])
def test_malformed_report_is_an_error(tmp_path, report):
    result = _run(tmp_path, report)
    assert result.returncode == 1
    assert "could not read grype report" in result.stderr


def test_missing_report_is_an_error(tmp_path):
    result = subprocess.run(
        ["bash", str(SCRIPT), "--check-report", str(tmp_path / "nope.json")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "grype report not found" in result.stderr
