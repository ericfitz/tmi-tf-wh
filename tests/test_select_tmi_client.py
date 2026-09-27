"""Build-time TMI client selection: newest same major.minor patch <= schema version."""

import importlib.util
import json
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


def test_picks_newest_patch_not_above_schema(tmp_path):
    root = _clients(tmp_path, "v1.14.9", "v1.15.0", "v1.15.4", "v1.15.7", "v1.16.0")
    assert sel.select(root, "1.15.6").name == "v1.15.4"


def test_exact_match_wins(tmp_path):
    root = _clients(tmp_path, "v1.15.0", "v1.15.6")
    assert sel.select(root, "1.15.6").name == "v1.15.6"


def test_numeric_not_lexical_ordering(tmp_path):
    root = _clients(tmp_path, "v1.15.2", "v1.15.10")
    assert sel.select(root, "1.15.12").name == "v1.15.10"


def test_no_same_minor_fails(tmp_path):
    root = _clients(tmp_path, "v1.14.9", "v1.16.0")
    with pytest.raises(SystemExit, match="no python client for TMI API 1.15"):
        sel.select(root, "1.15.6")


def test_schema_version_parsed_from_info(tmp_path):
    schema = tmp_path / "tmi-openapi.json"
    schema.write_text(json.dumps({"info": {"version": "1.15.6"}}))
    assert sel.schema_version(str(schema)) == "1.15.6"


def test_main_copies_selected_client(tmp_path):
    root = _clients(tmp_path, "v1.15.0")
    schema = tmp_path / "tmi-openapi.json"
    schema.write_text(json.dumps({"info": {"version": "1.15.6"}}))
    out = tmp_path / "out"
    sel.main(["--schema", str(schema), "--clients", str(root), "--out", str(out)])
    assert (out / "marker").read_text() == "v1.15.0"
