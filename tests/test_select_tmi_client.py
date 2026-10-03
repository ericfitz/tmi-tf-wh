"""Build-time TMI client selection: newest client at or above the minimum API version."""

import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "select_tmi_client",
    Path(__file__).parent.parent / "scripts" / "select_tmi_client.py",
)
sel = importlib.util.module_from_spec(spec)  # pyright: ignore[reportArgumentType]
spec.loader.exec_module(sel)  # type: ignore[union-attr]


def _clients(tmp_path: Path, *versions: str) -> Path:
    root = tmp_path / "python-client-generated"
    for v in versions:
        (root / v).mkdir(parents=True)
        (root / v / "marker").write_text(v)
    (root / "scripts").mkdir(parents=True, exist_ok=True)  # non-version dir is ignored
    return root


def test_picks_newest_at_or_above_minimum(tmp_path):
    root = _clients(tmp_path, "v1.14.9", "v1.15.0", "v1.15.4", "v1.16.0")
    assert sel.select(root, "1.15.0").name == "v1.16.0"


def test_exact_minimum_accepted(tmp_path):
    root = _clients(tmp_path, "v1.14.9", "v1.15.0")
    assert sel.select(root, "1.15.0").name == "v1.15.0"


def test_numeric_not_lexical_ordering(tmp_path):
    root = _clients(tmp_path, "v1.15.2", "v1.15.10")
    assert sel.select(root, "1.15.0").name == "v1.15.10"


def test_nothing_at_or_above_minimum_fails(tmp_path):
    root = _clients(tmp_path, "v1.14.9", "v1.15.0")
    with pytest.raises(SystemExit, match="no python client at or above TMI API 1.15.1"):
        sel.select(root, "1.15.1")


def test_parse_version_tolerates_v_prefix_and_whitespace():
    assert sel.parse_version(" v1.15.0\n") == (1, 15, 0)


def test_main_copies_selected_client(tmp_path):
    root = _clients(tmp_path, "v1.14.9", "v1.15.0")
    floor = tmp_path / "tmi-api-min-version"
    floor.write_text("1.15.0\n")
    out = tmp_path / "out"
    sel.main(
        ["--min-version-file", str(floor), "--clients", str(root), "--out", str(out)]
    )
    assert (out / "marker").read_text() == "v1.15.0"


def test_repo_minimum_file_is_a_version():
    floor = Path(__file__).parent.parent / "deploy" / "docker" / "tmi-api-min-version"
    sel.parse_version(floor.read_text())
