# Portions of this file are a Python port of Pele (https://github.com/obsidianmd/pele),
# src/layout/compound.ts, commit 3a2f075, used under the MIT License:
#
# Copyright (c) 2026 kepano
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,

"""Compound layout: nested security boundaries laid out level by level on the flat layered core.

Each level (the virtual root, then every group) is laid out with one `layered()` call over its
children. A flow between different subtrees is lifted to the lowest common level and merged with
the other flows between the same two children there.
"""

from dataclasses import dataclass, field
from math import floor
from typing import Literal

from tmi_tf.layout.layered import LayeredOptions, LEdge, LNode, layered

Direction = Literal["LR", "TB"]
Side = Literal["top", "right", "bottom", "left"]

LAYOUT_DIRECTION: Direction = "LR"
EMIT_BORDER_VERTICES: bool = False
LABEL_CHAR_W = 7
LABEL_PAD = 16
LABEL_MAX_W = 240

MIN_GROUP_W = 40
MIN_GROUP_H = 30


@dataclass(frozen=True)
class LayoutOptions:
    node_sep: int = 40
    edge_sep: int = 20
    rank_sep: int = 60
    pad: int = 30  # group padding left, right, bottom
    pad_top: int = 60  # group padding top: pad plus 30 for the boundary's own label
    label_margin: int = 24
    origin: int = 50  # absolute x and y of the diagram's top-left corner


@dataclass(frozen=True)
class LayoutNode:
    id: str
    parent: str | None
    w: int  # leaf: fixed width; group: minimum width
    h: int  # leaf: fixed height; group: minimum height
    is_group: bool = False


@dataclass(frozen=True)
class LayoutEdge:
    id: str
    source: str
    target: str
    label_w: int = 0


@dataclass
class Box:
    x: int  # absolute top-left
    y: int
    w: int
    h: int


@dataclass
class EdgeRoute:
    lifted: bool = False  # False: the flow took no part in layout
    level: str | None = (
        None  # group whose level holds the lifted edge; None is the virtual root
    )
    a: str = ""  # child of `level` containing the source
    b: str = ""  # child of `level` containing the target
    reversed: bool = False  # cycle breaking reversed a -> b
    rank_a: int = 0
    rank_b: int = 0
    points: list[tuple[int, int]] = field(
        default_factory=list
    )  # absolute, source to target
    border_out: list[tuple[int, int]] = field(default_factory=list)  # Task 7
    border_in: list[tuple[int, int]] = field(default_factory=list)  # Task 7


@dataclass
class LayoutResult:
    boxes: dict[str, Box]  # keyed by node id, in input order
    routes: dict[str, EdgeRoute]  # keyed by edge id, in input order
    width: int
    height: int


def label_width(text: str) -> int:
    if not text:
        return 0
    return min(len(text) * LABEL_CHAR_W + LABEL_PAD, LABEL_MAX_W)


def edge_sides(
    direction: Direction, rank_delta: int, cross_delta: float
) -> tuple[Side, Side]:
    if direction == "TB":
        if rank_delta > 0:
            return ("bottom", "top")
        if rank_delta < 0:
            return ("top", "bottom")
        return ("right", "left") if cross_delta >= 0 else ("left", "right")
    if rank_delta > 0:
        return ("right", "left")
    if rank_delta < 0:
        return ("left", "right")
    return ("bottom", "top") if cross_delta >= 0 else ("top", "bottom")


def _round(v: float) -> int:
    return floor(v + 0.5)


@dataclass
class _Merged:
    """One lifted edge of a level: all flows between the same two children."""

    a: int  # index into the level's children
    b: int
    count: int = 0
    label_w: int = 0


@dataclass
class _LevelLayout:
    offsets: list[tuple[int, int]]  # child top-left, relative to the content box
    content_w: int
    content_h: int
    ranks: list[int]
    reversed: list[bool]  # per merged edge
    points: list[list[tuple[int, int]]]  # per merged edge, relative, a -> b


def _layout_level(
    sizes: list[tuple[int, int]],
    merged: list[_Merged],
    direction: Direction,
    opt: LayoutOptions,
) -> _LevelLayout:
    """Lay out one level: children sizes and merged edges in, offsets, content size and routes out."""
    lr = direction == "LR"
    rank_sep = opt.rank_sep
    if lr and merged:
        rank_sep = max(rank_sep, max(m.label_w for m in merged) + opt.label_margin)
    lnodes = [LNode(h, w) if lr else LNode(w, h) for w, h in sizes]
    ledges = [
        LEdge(m.a, m.b, weight=m.count, label_w=0 if lr else m.label_w) for m in merged
    ]
    layered(lnodes, ledges, LayeredOptions(opt.node_sep, opt.edge_sep, rank_sep))

    def screen(lx: float, ly: float) -> tuple[float, float]:
        return (ly, lx) if lr else (lx, ly)

    tops: list[tuple[int, int]] = []
    for ln, (w, h) in zip(lnodes, sizes, strict=True):
        sx, sy = screen(ln.x, ln.y)
        tops.append((_round(sx - w / 2), _round(sy - h / 2)))
    pts = [
        [(_round(p[0]), _round(p[1])) for p in (screen(*q) for q in e.points)]
        for e in ledges
    ]

    xs = [t[0] for t in tops] + [p[0] for row in pts for p in row]
    ys = [t[1] for t in tops] + [p[1] for row in pts for p in row]
    x_hi = [t[0] + s[0] for t, s in zip(tops, sizes, strict=True)] + xs[len(tops) :]
    y_hi = [t[1] + s[1] for t, s in zip(tops, sizes, strict=True)] + ys[len(tops) :]
    if not xs:
        return _LevelLayout([], 0, 0, [], [], [])
    x0, y0 = min(xs), min(ys)
    return _LevelLayout(
        offsets=[(x - x0, y - y0) for x, y in tops],
        content_w=max(x_hi) - x0,
        content_h=max(y_hi) - y0,
        ranks=[ln.rank for ln in lnodes],
        reversed=[e.reversed for e in ledges],
        points=[[(x - x0, y - y0) for x, y in row] for row in pts],
    )


def _validate(
    nodes: list[LayoutNode], edges: list[LayoutEdge], direction: str
) -> dict[str, LayoutNode]:
    if direction not in ("LR", "TB"):
        raise ValueError(f"direction must be 'LR' or 'TB', got {direction!r}")
    by_id: dict[str, LayoutNode] = {}
    for n in nodes:
        if n.id in by_id:
            raise ValueError(f"duplicate node id {n.id!r}")
        by_id[n.id] = n
    for n in nodes:
        if n.parent is None:
            continue
        p = by_id.get(n.parent)
        if p is None:
            raise ValueError(f"node {n.id!r} has unknown parent {n.parent!r}")
        if not p.is_group:
            raise ValueError(
                f"node {n.id!r} has parent {n.parent!r}, which is not a group"
            )
    for n in nodes:
        seen = {n.id}
        cur = n.parent
        while cur is not None:
            if cur in seen:
                raise ValueError(f"parent cycle through node {cur!r}")
            seen.add(cur)
            cur = by_id[cur].parent
    seen_edges: set[str] = set()
    for e in edges:
        if e.id in seen_edges:
            raise ValueError(f"duplicate edge id {e.id!r}")
        seen_edges.add(e.id)
        for end in (e.source, e.target):
            if end not in by_id:
                raise ValueError(f"edge {e.id!r} endpoint {end!r} is not a node")
    return by_id


def compound_layout(
    nodes: list[LayoutNode],
    edges: list[LayoutEdge],
    direction: Direction,
    opt: LayoutOptions | None = None,
) -> LayoutResult:
    opt = opt or LayoutOptions()
    by_id = _validate(nodes, edges, direction)

    children: dict[str | None, list[str]] = {None: []}
    for n in nodes:
        if n.is_group:
            children[n.id] = []
    for n in nodes:
        children[n.parent].append(n.id)

    def chain(nid: str) -> list[str | None]:
        out: list[str | None] = [nid]
        cur = by_id[nid].parent
        while cur is not None:
            out.append(cur)
            cur = by_id[cur].parent
        out.append(None)
        out.reverse()
        return out

    # Lifting: merge flows by (level, a, b) in first-appearance order.
    routes: dict[str, EdgeRoute] = {}
    level_merged: dict[str | None, dict[tuple[str, str], _Merged]] = {}
    edge_key: dict[str, tuple[str | None, str, str]] = {}
    child_index = {
        lvl: {c: i for i, c in enumerate(cs)} for lvl, cs in children.items()
    }
    for e in edges:
        routes[e.id] = EdgeRoute()
        cs, ct = chain(e.source), chain(e.target)
        i = 0
        while i < len(cs) and i < len(ct) and cs[i] == ct[i]:
            i += 1
        if i >= len(cs) or i >= len(ct):
            continue  # one end is an ancestor of the other, or a self-flow
        level, a, b = cs[i - 1], cs[i], ct[i]
        assert a is not None and b is not None
        m = level_merged.setdefault(level, {}).get((a, b))
        if m is None:
            m = _Merged(child_index[level][a], child_index[level][b])
            level_merged[level][(a, b)] = m
        m.count += 1
        m.label_w = max(m.label_w, e.label_w)
        edge_key[e.id] = (level, a, b)

    # Bottom-up: deepest groups first, so child sizes are known.
    depth = {n.id: len(chain(n.id)) - 2 for n in nodes}
    group_ids = [n.id for n in nodes if n.is_group]
    order = sorted(
        group_ids, key=lambda g: (-depth[g], [n.id for n in nodes].index(g))
    ) + [None]
    size: dict[str, tuple[int, int]] = {
        n.id: (n.w, n.h) for n in nodes if not n.is_group
    }
    layouts: dict[str | None, _LevelLayout] = {}
    group_w: dict[str, int] = {}
    for lvl in order:
        cs = children[lvl]
        merged = list(level_merged.get(lvl, {}).values())
        lay = _layout_level([size[c] for c in cs], merged, direction, opt)
        layouts[lvl] = lay
        if lvl is not None:
            g = by_id[lvl]
            w = max(g.w, lay.content_w + 2 * opt.pad, MIN_GROUP_W)
            h = max(g.h, lay.content_h + opt.pad + opt.pad_top, MIN_GROUP_H)
            size[lvl] = (w, h)
            group_w[lvl] = w

    # Top-down absolute positions.
    boxes: dict[str, Box] = {}
    level_origin: dict[str | None, tuple[int, int]] = {None: (opt.origin, opt.origin)}
    for lvl in [None] + sorted(
        group_ids, key=lambda g: (depth[g], [n.id for n in nodes].index(g))
    ):
        lay = layouts[lvl]
        ox, oy = level_origin[lvl]
        for c, (dx, dy) in zip(children[lvl], lay.offsets, strict=True):
            w, h = size[c]
            boxes[c] = Box(ox + dx, oy + dy, w, h)
            if c in layouts:
                level_origin[c] = (
                    boxes[c].x + (w - layouts[c].content_w) // 2,
                    boxes[c].y + opt.pad_top,
                )
    boxes = {n.id: boxes[n.id] for n in nodes}

    merged_pos = {
        lvl: {k: i for i, k in enumerate(d)} for lvl, d in level_merged.items()
    }
    for eid, (lvl, a, b) in edge_key.items():
        lay = layouts[lvl]
        mi = merged_pos[lvl][(a, b)]
        ox, oy = level_origin[lvl]
        routes[eid] = EdgeRoute(
            lifted=True,
            level=lvl,
            a=a,
            b=b,
            reversed=lay.reversed[mi],
            rank_a=lay.ranks[child_index[lvl][a]],
            rank_b=lay.ranks[child_index[lvl][b]],
            points=[(ox + x, oy + y) for x, y in lay.points[mi]],
        )
    root = layouts[None]
    return LayoutResult(boxes, routes, root.content_w, root.content_h)
