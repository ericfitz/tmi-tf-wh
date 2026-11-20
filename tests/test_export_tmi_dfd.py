"""Offline tests for scripts/export_tmi_dfd.py (anonymized DFD fixture export)."""

import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tmi_tf.diagram_builder import DFDBuilder

ROOT = Path(__file__).parent.parent
spec = importlib.util.spec_from_file_location(
    "export_tmi_dfd", ROOT / "scripts" / "export_tmi_dfd.py"
)
export_tmi_dfd = importlib.util.module_from_spec(spec)  # pyright: ignore[reportArgumentType]
spec.loader.exec_module(export_tmi_dfd)  # type: ignore[union-attr]
ExportError = export_tmi_dfd.ExportError

CELLS = json.loads(
    (ROOT / "tests" / "fixtures" / "dfd_export" / "synthetic_cells.json").read_text(
        encoding="utf-8"
    )
)


def _cell(cells, n):
    cid = f"00000000-0000-4000-8000-{n:012d}"
    return next(c for c in cells if c["id"] == cid)


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


def test_placeholder_keeps_length():
    assert export_tmi_dfd.placeholder("c", 1, 10) == "c0001xxxxx"
    assert export_tmi_dfd.placeholder("f", 12, 3) == "f00"
    assert export_tmi_dfd.placeholder("c", 1, 0) == ""


def test_cells_to_dfd_maps_nodes_and_edges():
    dfd = export_tmi_dfd.cells_to_dfd(CELLS)
    assert [c["type"] for c in dfd["components"]] == [
        "tenant",
        "network",
        "container",
        "gateway",
        "service",
        "storage",
        "actor",
        "compute",
    ]
    assert dfd["components"][3]["parent_id"] == dfd["components"][2]["id"]
    assert "parent_id" not in dfd["components"][0]
    assert "parent_id" not in dfd["components"][6]
    assert len(dfd["flows"]) == 6
    assert all(f["bidirectional"] is False for f in dfd["flows"])
    assert dfd["flows"][4]["name"] == ""


def test_anonymize_replaces_names_ids_and_drops_metadata():
    out = export_tmi_dfd.export_cells(CELLS)
    assert [c["id"] for c in out["components"]] == [f"c{n:04d}" for n in range(1, 9)]
    assert out["components"][0]["name"] == "c0001" + "x" * (
        len("acme-prod-account-123456789012") - 5
    )
    assert out["flows"][0] == {
        "id": "f0001",
        "name": "f0001xxxx",
        "source_id": "c0007",
        "target_id": "c0004",
        "bidirectional": False,
    }
    assert all(set(c) <= {"id", "name", "type", "parent_id"} for c in out["components"])


def test_unknown_shape_is_error_naming_cell():
    cells = copy.deepcopy(CELLS)
    _cell(cells, 5)["shape"] = "text-box"
    with pytest.raises(ExportError, match="0000000005"):
        export_tmi_dfd.cells_to_dfd(cells)


def test_unknown_metadata_type_is_error():
    cells = copy.deepcopy(CELLS)
    for item in _cell(cells, 4)["data"]["_metadata"]:
        if item["key"] == "component_type":
            item["value"] = "network_access_control"
    with pytest.raises(ExportError, match="0000000004"):
        export_tmi_dfd.cells_to_dfd(cells)


def test_edge_to_missing_node_is_error():
    cells = copy.deepcopy(CELLS)
    _cell(cells, 12)["target"]["cell"] = "00000000-0000-4000-8000-0000000000ff"
    with pytest.raises(ExportError, match="0000000012"):
        export_tmi_dfd.cells_to_dfd(cells)
    cells = copy.deepcopy(CELLS)
    _cell(cells, 13)["source"]["cell"] = "00000000-0000-4000-8000-0000000000ff"
    with pytest.raises(ExportError, match="0000000013"):
        export_tmi_dfd.cells_to_dfd(cells)


def test_missing_parent_is_error():
    cells = copy.deepcopy(CELLS)
    _cell(cells, 5)["parent"] = "00000000-0000-4000-8000-0000000000ff"
    with pytest.raises(ExportError, match="0000000005"):
        export_tmi_dfd.cells_to_dfd(cells)


def test_find_leaks_clean_export_is_empty():
    assert export_tmi_dfd.find_leaks(CELLS, export_tmi_dfd.export_cells(CELLS)) == []


def test_find_leaks_flags_original_name_and_ip():
    out = export_tmi_dfd.export_cells(CELLS)
    out["components"][0]["name"] = "api.internal.example.com"
    out["components"][1]["name"] = "host 10.20.0.5"
    leaks = export_tmi_dfd.find_leaks(CELLS, out)
    assert any("c0001" in m and "api.internal.example.com" in m for m in leaks)
    assert any("c0002" in m and "10.20.0.5" in m for m in leaks)


def test_find_leaks_flags_flow_name_and_digit_run():
    out = export_tmi_dfd.export_cells(CELLS)
    out["flows"][1]["name"] = "acct 999988887777"
    leaks = export_tmi_dfd.find_leaks(CELLS, out)
    assert any("f0002" in m for m in leaks)


def test_export_cells_raises_on_leak():
    cells = copy.deepcopy(CELLS)
    # Input strings equal to the placeholder make the output echo the input.
    _cell(cells, 7)["attrs"]["text"]["text"] = "c0007"
    with pytest.raises(ExportError, match="c0007"):
        export_tmi_dfd.export_cells(cells)


def test_export_contains_no_original_strings():
    out = export_tmi_dfd.export_cells(CELLS)
    originals = {s for s in _strings(CELLS) if len(s) >= 4}
    for section in out.values():
        for item in section:
            for key, value in item.items():
                if key == "type":
                    continue
                for s in _strings(value):
                    assert not any(o.lower() in s.lower() for o in originals), (key, s)


def test_main_cells_file_writes_fixture(tmp_path, capsys):
    cells_path = tmp_path / "cells.json"
    cells_path.write_text(json.dumps(CELLS), encoding="utf-8")
    out_path = tmp_path / "out.json"
    rc = export_tmi_dfd.main(["--cells-file", str(cells_path), "--out", str(out_path)])
    assert rc == 0
    assert capsys.readouterr().out.strip() == (
        f"exported 8 components, 6 flows -> {out_path}"
    )
    assert json.loads(out_path.read_text(encoding="utf-8")) == (
        export_tmi_dfd.export_cells(CELLS)
    )


def test_main_refuses_overwrite_without_force(tmp_path, capsys):
    cells_path = tmp_path / "cells.json"
    cells_path.write_text(json.dumps(CELLS), encoding="utf-8")
    out_path = tmp_path / "out.json"
    args = ["--cells-file", str(cells_path), "--out", str(out_path)]
    assert export_tmi_dfd.main(args) == 0
    before = out_path.read_bytes()
    assert export_tmi_dfd.main(args) == 2
    assert out_path.read_bytes() == before
    assert "--force" in capsys.readouterr().err
    assert export_tmi_dfd.main([*args, "--force"]) == 0


def test_main_error_leaves_no_file(tmp_path, capsys):
    cells = copy.deepcopy(CELLS)
    _cell(cells, 5)["shape"] = "text-box"
    cells_path = tmp_path / "cells.json"
    cells_path.write_text(json.dumps(cells), encoding="utf-8")
    out_path = tmp_path / "out.json"
    rc = export_tmi_dfd.main(["--cells-file", str(cells_path), "--out", str(out_path)])
    assert rc == 2
    assert "0000000005" in capsys.readouterr().err
    assert not out_path.exists()


def test_main_missing_or_invalid_input_file(tmp_path, capsys):
    out_path = tmp_path / "out.json"
    missing = tmp_path / "nope.json"
    assert (
        export_tmi_dfd.main(["--cells-file", str(missing), "--out", str(out_path)]) == 2
    )
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert export_tmi_dfd.main(["--cells-file", str(bad), "--out", str(out_path)]) == 2
    notlist = tmp_path / "obj.json"
    notlist.write_text("{}", encoding="utf-8")
    assert (
        export_tmi_dfd.main(["--cells-file", str(notlist), "--out", str(out_path)]) == 2
    )
    assert not out_path.exists()
    assert capsys.readouterr().err


def test_main_requires_out(tmp_path, capsys):
    cells_path = tmp_path / "cells.json"
    cells_path.write_text(json.dumps(CELLS), encoding="utf-8")
    assert export_tmi_dfd.main(["--cells-file", str(cells_path)]) == 2
    assert "--out" in capsys.readouterr().err


def _fake_tmi(monkeypatch):
    calls = []

    class FakeClient:
        def get_threat_model_diagrams(self, tm_id):
            calls.append(("list", tm_id))
            return [
                SimpleNamespace(id="d-1", name="First"),
                SimpleNamespace(id="d-2", name="Second"),
            ]

        def get_diagram_cells(self, tm_id, diagram_id):
            calls.append(("cells", tm_id, diagram_id))
            return CELLS

    monkeypatch.setattr(export_tmi_dfd, "Config", lambda *a, **k: object())
    monkeypatch.setattr(
        export_tmi_dfd.TMIClient,
        "create_authenticated",
        classmethod(lambda cls, config, **k: FakeClient()),
    )
    return calls


def test_main_lists_diagrams(monkeypatch, tmp_path, capsys):
    calls = _fake_tmi(monkeypatch)
    out_path = tmp_path / "out.json"
    rc = export_tmi_dfd.main(["--threat-model-id", "tm-1", "--out", str(out_path)])
    assert rc == 0
    assert capsys.readouterr().out.splitlines() == ["d-1\tFirst", "d-2\tSecond"]
    assert calls == [("list", "tm-1")]
    assert not out_path.exists()


def test_main_fetches_from_tmi(monkeypatch, tmp_path, capsys):
    calls = _fake_tmi(monkeypatch)
    out_path = tmp_path / "out.json"
    rc = export_tmi_dfd.main(
        [
            "--threat-model-id",
            "tm-1",
            "--diagram-id",
            "d-2",
            "--out",
            str(out_path),
        ]
    )
    assert rc == 0
    assert calls == [("cells", "tm-1", "d-2")]
    assert json.loads(out_path.read_text(encoding="utf-8")) == (
        export_tmi_dfd.export_cells(CELLS)
    )
    assert "exported 8 components, 6 flows" in capsys.readouterr().out


def test_export_builds_with_dfd_builder():
    out = export_tmi_dfd.export_cells(CELLS)
    cells = DFDBuilder(out["components"], out["flows"]).build_cells()
    edges = [c for c in cells if c.get("shape") == "flow"]
    assert len(edges) == 6
    assert len(cells) - len(edges) == 8
