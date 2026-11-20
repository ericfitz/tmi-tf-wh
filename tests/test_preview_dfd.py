"""SVG preview script: structure, escaping, determinism, CLI contract."""

import importlib.util
import json
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
