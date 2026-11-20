"""Property tests for the DFD layout: hand cases, seeded random trees, real exports."""

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest  # pyright: ignore[reportMissingImports] # ty:ignore[unresolved-import]
from dfd_cases import all_cases, digest_all, fixture_files

from tmi_tf.diagram_builder import DFDBuilder
from tmi_tf.layout import compound

CASES = all_cases()

INSET_SIDE = 30
INSET_TOP = 60
MIN_GAP = 40
MAX_VERTICES = 1000


def _node_cells(cells: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [c for c in cells if c.get("shape") != "flow"]


def _gap(a: dict[str, Any], b: dict[str, Any]) -> int:
    gap_x = max(a["x"] - (b["x"] + b["width"]), b["x"] - (a["x"] + a["width"]))
    gap_y = max(a["y"] - (b["y"] + b["height"]), b["y"] - (a["y"] + a["height"]))
    return max(gap_x, gap_y)


def check_invariants(builder: DFDBuilder, cells: list[dict[str, Any]]) -> None:
    nodes = _node_cells(cells)
    by_id = {c["id"]: c for c in nodes}
    groups: dict[str | None, list[dict[str, Any]]] = {}
    for c in nodes:
        groups.setdefault(c.get("parent"), []).append(c)
        for k in ("x", "y", "width", "height"):
            assert type(c[k]) is int, (c["id"], k, c[k])
        assert c["width"] >= 40 and c["height"] >= 30
    for parent_id, siblings in groups.items():
        if parent_id is not None:
            p = by_id[parent_id]
            for c in siblings:
                assert c["x"] - p["x"] >= INSET_SIDE
                assert (p["x"] + p["width"]) - (c["x"] + c["width"]) >= INSET_SIDE
                assert (p["y"] + p["height"]) - (c["y"] + c["height"]) >= INSET_SIDE
                assert c["y"] - p["y"] >= INSET_TOP
        for i, a in enumerate(siblings):
            for b in siblings[i + 1 :]:
                assert _gap(a, b) >= MIN_GAP, (a["id"], b["id"])

    layout = builder._layout
    if layout is not None:
        for rt in layout.routes.values():
            if not rt.lifted:
                continue
            if rt.reversed:
                assert rt.rank_b < rt.rank_a
            else:
                assert rt.rank_b > rt.rank_a

    def ancestors(cell_id: str) -> list[str]:
        out = []
        cur = by_id[cell_id].get("parent")
        while cur is not None:
            out.append(cur)
            cur = by_id[cur].get("parent")
        return out

    for e in cells:
        if e.get("shape") != "flow":
            continue
        verts = e.get("vertices", [])
        assert len(verts) <= MAX_VERTICES
        exempt = set(ancestors(e["source"]["cell"])) | set(
            ancestors(e["target"]["cell"])
        )
        for v in verts:
            for n in nodes:
                if n["id"] in exempt:
                    continue
                inside = (
                    n["x"] < v["x"] < n["x"] + n["width"]
                    and n["y"] < v["y"] < n["y"] + n["height"]
                )
                assert not inside, (e["id"], n["id"], v)


@pytest.mark.parametrize("name,components,flows", CASES, ids=[c[0] for c in CASES])
@pytest.mark.parametrize("direction", ["LR", "TB"])
def test_layout_invariants(name, components, flows, direction, monkeypatch):
    monkeypatch.setattr(compound, "LAYOUT_DIRECTION", direction)
    builder = DFDBuilder(components, flows)
    check_invariants(builder, builder.build_cells())


def test_fixture_files_are_picked_up():
    assert [n for n, _, _ in CASES if n.startswith("fixture:")] == [
        f"fixture:{p.stem}" for p in fixture_files()
    ]


def test_output_is_byte_identical_across_processes():
    script = Path(__file__).parent / "dfd_cases.py"

    def run(seed: str) -> str:
        return subprocess.run(
            [sys.executable, str(script)],
            env={**os.environ, "PYTHONHASHSEED": seed},
            capture_output=True,
            text=True,
            check=True,
        ).stdout

    assert run("0") == run("1") == digest_all() + "\n"
