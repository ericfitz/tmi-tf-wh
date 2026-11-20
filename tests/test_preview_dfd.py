"""SVG preview script: structure, escaping, determinism, CLI contract."""

import importlib.util
import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from tests.dfd_cases import fixture_files, load_fixture
from tmi_tf.diagram_builder import DFDBuilder
from tmi_tf.layout import compound

ROOT = Path(__file__).parent.parent
SMALL = ROOT / "tests" / "fixtures" / "dfd_preview" / "small.json"
spec = importlib.util.spec_from_file_location(
    "preview_dfd", ROOT / "scripts" / "preview_dfd.py"
)
preview_dfd = importlib.util.module_from_spec(spec)  # pyright: ignore[reportArgumentType]
spec.loader.exec_module(preview_dfd)  # type: ignore[union-attr]


def cells_for(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    return DFDBuilder(data["components"], data["flows"]).build_cells()


def test_render_has_one_rect_per_node_and_one_polyline_per_edge():
    svg = preview_dfd.render_svg(cells_for(SMALL))
    assert svg.startswith("<svg")
    assert svg.count("<rect") == 6 and svg.count("<polyline") == 5


def test_text_is_escaped():
    svg = preview_dfd.render_svg(cells_for(SMALL))
    assert "User &lt;admin&gt; &amp; &quot;ops&quot;" in svg and "<admin>" not in svg


def test_render_is_deterministic():
    assert preview_dfd.render_svg(cells_for(SMALL)) == preview_dfd.render_svg(
        cells_for(SMALL)
    )


def test_main_writes_svg_and_direction_changes_it(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(compound, "LAYOUT_DIRECTION", "LR")  # restored after the test
    monkeypatch.setattr(compound, "EMIT_BORDER_VERTICES", False)
    lr, tb = tmp_path / "lr.svg", tmp_path / "tb.svg"
    assert preview_dfd.main([str(SMALL), str(lr)]) == 0
    assert capsys.readouterr().out.strip() == f"wrote {lr}: 6 nodes, 5 edges"
    assert preview_dfd.main([str(SMALL), str(tb), "--direction", "TB"]) == 0
    assert lr.read_text() != tb.read_text()


def test_main_rejects_bad_input(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text('{"components": []}')
    assert preview_dfd.main([str(bad), str(tmp_path / "o.svg")]) == 2
    assert "flows" in capsys.readouterr().err and not (tmp_path / "o.svg").exists()
    assert (
        preview_dfd.main([str(tmp_path / "missing.json"), str(tmp_path / "o.svg")]) == 2
    )
    notjson = tmp_path / "x.json"
    notjson.write_text("nope")
    assert preview_dfd.main([str(notjson), str(tmp_path / "o.svg")]) == 2


@pytest.mark.parametrize("path", fixture_files(), ids=lambda p: p.stem)
def test_exported_fixtures_render(path):
    comps, flows = load_fixture(path)
    svg = preview_dfd.render_svg(DFDBuilder(comps, flows).build_cells())
    assert svg.count("<rect") == len(comps)


def test_svg_is_well_formed_xml_and_labels_are_placed():
    svg = preview_dfd.render_svg(cells_for(SMALL))
    root = ET.fromstring(svg)
    ns = "{http://www.w3.org/2000/svg}"
    texts = {t.text: t for t in root.iter(f"{ns}text")}
    assert 'User <admin> & "ops"' in texts
    reply = texts["reply"]
    assert float(reply.get("x", "nan")) == float(reply.get("x", "nan"))  # numeric
    assert float(reply.get("y", "nan")) == float(reply.get("y", "nan"))
    # the reply label lies on the a->b polyline's bounding box
    poly_boxes = []
    for pl in root.iter(f"{ns}polyline"):
        pts = [tuple(map(float, p.split(","))) for p in pl.get("points", "").split()]
        xs, ys = [p[0] for p in pts], [p[1] for p in pts]
        poly_boxes.append((min(xs), max(xs), min(ys), max(ys)))
    x, y = float(reply.get("x", 0)), float(reply.get("y", 0))
    assert any(a - 1 <= x <= b + 1 and c - 1 <= y <= d + 1 for a, b, c, d in poly_boxes)


def test_main_border_vertices_flag_runs_and_restores_globals(tmp_path, monkeypatch):
    monkeypatch.setattr(compound, "LAYOUT_DIRECTION", "LR")
    monkeypatch.setattr(compound, "EMIT_BORDER_VERTICES", False)
    out = tmp_path / "bv.svg"
    assert preview_dfd.main([str(SMALL), str(out), "--border-vertices"]) == 0
    ET.fromstring(out.read_text())
    assert compound.EMIT_BORDER_VERTICES is False
    assert compound.LAYOUT_DIRECTION == "LR"


def test_main_reports_malformed_components_and_unwritable_output(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text(
        json.dumps({"components": [{"id": "a", "type": "compute"}], "flows": []})
    )
    assert preview_dfd.main([str(bad), str(tmp_path / "o.svg")]) == 2
    assert "malformed" in capsys.readouterr().err
    assert not (tmp_path / "o.svg").exists()
    assert preview_dfd.main([str(SMALL), str(tmp_path / "nodir" / "o.svg")]) == 2
    assert "cannot write" in capsys.readouterr().err
