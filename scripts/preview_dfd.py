"""Render a DFD layout to SVG so layouts can be judged without pushing to TMI.

Usage: uv run python scripts/preview_dfd.py INPUT.json OUT.svg [--direction LR|TB] [--border-vertices | --no-border-vertices]

INPUT.json holds {"components": [...], "flows": [...]}. OUT.svg is a derived file and is
overwritten on every run. Standard library plus the project's own modules only.
"""

import argparse
import html
import json
import math
import sys
from itertools import pairwise
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tmi_tf.diagram_builder import DFDBuilder
from tmi_tf.layout import compound
from tmi_tf.layout.compound import Box
from tmi_tf.layout.routes import side_point

MARGIN = 20
Point = tuple[float, float]


def _box(cell: dict[str, Any]) -> Box:
    return Box(cell["x"], cell["y"], cell["width"], cell["height"])


def _text(cell: dict[str, Any]) -> str:
    return str(cell.get("attrs", {}).get("text", {}).get("text", ""))


def _polyline_point(points: list[Point], fraction: float) -> Point:
    """Point at `fraction` of the polyline's total length."""
    lengths = [math.dist(a, b) for a, b in pairwise(points)]
    total = sum(lengths)
    if total == 0:
        return points[0]
    target = total * fraction
    for (a, b), length in zip(pairwise(points), lengths, strict=True):
        if length and target <= length:
            t = target / length
            return (a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t)
        target -= length
    return points[-1]


def _num(v: float) -> str:
    return f"{v:g}"


def render_svg(cells: list[dict[str, Any]]) -> str:
    """SVG for the cells of `DFDBuilder.build_cells()`; no cell ids reach the output."""
    nodes = {c["id"]: c for c in cells if "source" not in c}
    edges = [c for c in cells if "source" in c]
    xs: list[float] = []
    ys: list[float] = []
    for c in nodes.values():
        xs += [c["x"], c["x"] + c["width"]]
        ys += [c["y"], c["y"] + c["height"]]
    for e in edges:
        for v in e.get("vertices", []):
            xs.append(v["x"])
            ys.append(v["y"])
    min_x, min_y = (min(xs), min(ys)) if xs else (0, 0)
    max_x, max_y = (max(xs), max(ys)) if xs else (0, 0)
    vx, vy = min_x - MARGIN, min_y - MARGIN
    vw, vh = max_x - min_x + 2 * MARGIN, max_y - min_y + 2 * MARGIN

    out = [
        (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{_num(vx)} {_num(vy)}'
            f' {_num(vw)} {_num(vh)}" font-family="sans-serif" font-size="12">'
        ),
        (
            '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5"'
            ' markerWidth="8" markerHeight="8" orient="auto-start-reverse">'
            '<path d="M 0 0 L 10 5 L 0 10 z" fill="#333"/></marker></defs>'
        ),
    ]
    boundaries = sorted(
        (c for c in nodes.values() if "ports" not in c),
        key=lambda c: c.get("zIndex", 0),
    )
    for c in boundaries:
        out.append(
            f'<rect x="{c["x"]}" y="{c["y"]}" width="{c["width"]}" height="{c["height"]}"'
            ' fill="none" stroke="#888" stroke-dasharray="6 4"/>'
        )
        out.append(
            f'<text x="{c["x"] + 6}" y="{c["y"] + 16}">{html.escape(_text(c))}</text>'
        )
    for c in nodes.values():
        if "ports" not in c:
            continue
        out.append(
            f'<rect x="{c["x"]}" y="{c["y"]}" width="{c["width"]}" height="{c["height"]}"'
            ' fill="#e8f0fe" stroke="#335"/>'
        )
        out.append(
            f'<text x="{_num(c["x"] + c["width"] / 2)}" y="{_num(c["y"] + c["height"] / 2)}"'
            f' text-anchor="middle" dominant-baseline="middle">{html.escape(_text(c))}</text>'
        )
    labels: list[str] = []
    for e in edges:
        src, tgt = nodes[e["source"]["cell"]], nodes[e["target"]["cell"]]
        pts: list[Point] = [
            side_point(_box(src), e["source"].get("port")),
            *[(v["x"], v["y"]) for v in e.get("vertices", [])],
            side_point(_box(tgt), e["target"].get("port")),
        ]
        coords = " ".join(f"{_num(x)},{_num(y)}" for x, y in pts)
        out.append(
            f'<polyline points="{coords}" fill="none" stroke="#333" stroke-width="2"'
            ' marker-end="url(#arrow)"/>'
        )
        for label in e.get("labels", []):
            text = label.get("attrs", {}).get("text", {}).get("text", "")
            if not text:
                continue
            x, y = _polyline_point(pts, label.get("position", 0.5))
            labels.append(
                f'<text x="{_num(x)}" y="{_num(y)}" text-anchor="middle" fill="#a00">'
                f"{html.escape(str(text))}</text>"
            )
    out.extend(labels)
    out.append("</svg>")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render a DFD layout to SVG.")
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--direction", choices=["LR", "TB"], default="LR")
    parser.add_argument(
        "--border-vertices",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="emit border-crossing vertices (default: compound.EMIT_BORDER_VERTICES)",
    )
    args = parser.parse_args(argv)

    try:
        data = json.loads(args.input.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"cannot read {args.input}: {exc}", file=sys.stderr)
        return 2
    if not isinstance(data, dict):
        print(f"{args.input}: top level must be an object", file=sys.stderr)
        return 2
    for key in ("components", "flows"):
        if not isinstance(data.get(key), list):
            print(f"{args.input}: missing list key '{key}'", file=sys.stderr)
            return 2

    saved = (compound.LAYOUT_DIRECTION, compound.EMIT_BORDER_VERTICES)
    compound.LAYOUT_DIRECTION = args.direction
    if args.border_vertices is not None:
        compound.EMIT_BORDER_VERTICES = args.border_vertices
    try:
        cells = DFDBuilder(data["components"], data["flows"]).build_cells()
        svg = render_svg(cells)
    except (KeyError, TypeError, AttributeError) as exc:
        print(
            f"{args.input}: malformed components/flows ({type(exc).__name__}: {exc})",
            file=sys.stderr,
        )
        return 2
    finally:
        compound.LAYOUT_DIRECTION, compound.EMIT_BORDER_VERTICES = saved
    try:
        args.output.write_text(svg, encoding="utf-8")
    except OSError as exc:
        print(f"cannot write {args.output}: {exc}", file=sys.stderr)
        return 2
    n_edges = sum(1 for c in cells if "source" in c)
    print(f"wrote {args.output}: {len(cells) - n_edges} nodes, {n_edges} edges")
    return 0


if __name__ == "__main__":
    sys.exit(main())
