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
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Compound layout: nested security boundaries laid out level by level on the flat layered core.

Each level (the virtual root, then every group) is laid out with one `layered()` call over its
children. A flow between different subtrees is lifted to the lowest common level and merged with
the other flows between the same two children there.
"""

from dataclasses import dataclass, field
from math import floor
from typing import Literal

from tmi_tf.layout.layered import (
    Kind,
    LayeredOptions,
    LEdge,
    LNode,
    layered,
    orient,
    rank,
)
from tmi_tf.layout.pack import connected_parts, grid_block, shelf_pack

Direction = Literal["LR", "TB"]
Side = Literal["top", "right", "bottom", "left"]

LAYOUT_DIRECTION: Direction = "LR"
EMIT_BORDER_VERTICES: bool = True
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
    # False: the flow took no part in layout
    lifted: bool = False
    # group whose level holds the lifted edge; None is the virtual root
    level: str | None = None
    # child of `level` containing the source
    a: str = ""
    # child of `level` containing the target
    b: str = ""
    # cycle breaking reversed a -> b
    reversed: bool = False
    rank_a: int = 0
    rank_b: int = 0
    # absolute bend points, source to target
    points: list[tuple[int, int]] = field(default_factory=list)
    # port points (with the port edge's bend points), innermost group first
    border_out: list[tuple[int, int]] = field(default_factory=list)
    # port points (with the port edge's bend points), outermost group first
    border_in: list[tuple[int, int]] = field(default_factory=list)


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
    # per port: its point on the cross axis (the rank axis is snapped later), relative
    port_at: list[tuple[int, int]] = field(default_factory=list)
    # per port: bend points of its port edge, relative, in the order the route runs
    port_pts: list[list[tuple[int, int]]] = field(default_factory=list)


@dataclass
class _Port:
    """One flow crossing the border of group `group`, attached to child `inner` of that group."""

    flow: int  # index into the edge list
    group: str
    inner: int  # index into the group's children
    out: bool  # the flow leaves through the border (else enters)
    start: bool  # on the start side (left in LR, top in TB)


def _layered_part(
    sizes: list[tuple[int, int]],
    merged: list[_Merged],
    direction: Direction,
    opt: LayoutOptions,
    rank_sep: int,
    ports: list[_Port] | None = None,
) -> _LevelLayout:
    """One connected part as one layered graph; offsets are relative to the part's bounding box.

    `ports` (inner indices local to `sizes`) become zero-size port nodes after the children, with a
    weight-1 edge each. They stay out of the bounding box; their edges' bend points count.
    """
    lr = direction == "LR"
    ports = ports or []
    n = len(sizes)
    lnodes = [LNode(h, w) if lr else LNode(w, h) for w, h in sizes]
    ledges = [
        LEdge(m.a, m.b, weight=m.count, label_w=0 if lr else m.label_w) for m in merged
    ]
    for p in ports:
        lnodes.append(LNode(0, 0, Kind.START_PORT if p.start else Kind.END_PORT))
        pn = len(lnodes) - 1
        ledges.append(LEdge(p.inner, pn) if p.out else LEdge(pn, p.inner))
    layered(lnodes, ledges, LayeredOptions(opt.node_sep, opt.edge_sep, rank_sep))

    def screen(lx: float, ly: float) -> tuple[float, float]:
        return (ly, lx) if lr else (lx, ly)

    tops: list[tuple[int, int]] = []
    for ln, (w, h) in zip(lnodes[:n], sizes, strict=True):
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
    m = len(merged)
    port_at = []
    for ln in lnodes[n:]:
        sx, sy = screen(ln.x, ln.y)
        port_at.append((_round(sx) - x0, _round(sy) - y0))
    return _LevelLayout(
        offsets=[(x - x0, y - y0) for x, y in tops],
        content_w=max(x_hi) - x0,
        content_h=max(y_hi) - y0,
        ranks=[ln.rank for ln in lnodes[:n]],
        reversed=[e.reversed for e in ledges[:m]],
        points=[[(x - x0, y - y0) for x, y in row] for row in pts[:m]],
        port_at=port_at,
        port_pts=[[(x - x0, y - y0) for x, y in row] for row in pts[m:]],
    )


@dataclass
class _Piece:
    """A laid-out part (or the grid block of lone children) awaiting its place in the level."""

    members: list[int]  # child indices
    lay: _LevelLayout
    merged_ids: list[int]  # indices into the level's merged list, in lay.points order
    port_ids: list[int] = field(default_factory=list)  # indices into the level's ports


def _layout_level(
    sizes: list[tuple[int, int]],
    merged: list[_Merged],
    direction: Direction,
    opt: LayoutOptions,
    border: list[int] | None = None,
    ports: list[_Port] | None = None,
) -> _LevelLayout:
    """Lay out one level: children sizes and merged edges in, offsets, content size and routes out.

    The children split into connected parts. Each part of two or more children is its own layered
    graph; lone children share one grid block. `border` (child indices) designates one part that is
    kept whole, laid out first and placed apart from the packed block, on the cross axis. Every
    child that is the inner child of a port joins that part, and `ports` become its port nodes (in
    the order given); their results come back in `port_at` / `port_pts`, in the same order.
    """
    lr = direction == "LR"
    rank_sep = opt.rank_sep
    if lr and merged:
        rank_sep = max(rank_sep, max(m.label_w for m in merged) + opt.label_margin)
    n = len(sizes)
    ports = ports or []
    for i in [*(border or []), *(p.inner for p in ports)]:
        if not 0 <= i < n:
            raise ValueError(f"border index {i} is out of range ({n} children)")
    pairs = [(m.a, m.b) for m in merged]
    border = sorted(set(border or []) | {p.inner for p in ports})
    pairs += [(border[0], c) for c in border[1:]]
    parts = connected_parts(n, pairs)
    if len(parts) <= 1:
        return _layered_part(sizes, merged, direction, opt, rank_sep, ports)

    part_of = {c: pi for pi, part in enumerate(parts) for c in part}
    border_part = part_of[border[0]] if border else -1
    pieces: list[_Piece] = []  # packed block, in position-list order
    border_piece: _Piece | None = None
    singles: list[int] = []
    single_at = -1  # position in `pieces` of the grid block

    def layered_piece(pi: int) -> _Piece:
        members = parts[pi]
        local = {c: i for i, c in enumerate(members)}
        ids = [i for i, m in enumerate(merged) if part_of[m.a] == pi]
        sub = [_Merged(local[merged[i].a], local[merged[i].b]) for i in ids]
        for s_, i in zip(sub, ids, strict=True):
            s_.count, s_.label_w = merged[i].count, merged[i].label_w
        mine = [
            _Port(p.flow, p.group, local[p.inner], p.out, p.start)
            for p in ports
            if part_of[p.inner] == pi
        ]
        lay = _layered_part(
            [sizes[c] for c in members], sub, direction, opt, rank_sep, mine
        )
        port_ids = [i for i, p in enumerate(ports) if part_of[p.inner] == pi]
        return _Piece(members, lay, ids, port_ids)

    for pi, part in enumerate(parts):
        if pi == border_part:
            border_piece = layered_piece(pi)
        elif len(part) >= 2:
            pieces.append(layered_piece(pi))
        else:
            if not singles:
                single_at = len(pieces)
                pieces.append(_Piece([], _LevelLayout([], 0, 0, [], [], []), []))
            singles.append(part[0])
    if singles:
        pos, w, h = grid_block([sizes[c] for c in singles], opt.node_sep)
        pieces[single_at] = _Piece(
            singles,
            _LevelLayout(pos, w, h, [0] * len(singles), [], []),
            [],
        )

    placed, block_w, block_h = shelf_pack(
        [(p.lay.content_w, p.lay.content_h) for p in pieces], opt.node_sep
    )
    shifts = list(placed)
    all_pieces = list(pieces)
    total_w, total_h = block_w, block_h
    if border_piece is not None:
        bw, bh = border_piece.lay.content_w, border_piece.lay.content_h
        if not pieces:
            total_w, total_h = bw, bh
            shifts = [(0, 0)]
            all_pieces = [border_piece]
        else:
            # the border part first, the packed block beside it on the cross axis
            dx, dy = (0, bh + opt.node_sep) if lr else (bw + opt.node_sep, 0)
            shifts = [(x + dx, y + dy) for x, y in placed] + [(0, 0)]
            all_pieces = pieces + [border_piece]
            total_w = max(bw, block_w + dx)
            total_h = max(bh, block_h + dy)

    offsets: list[tuple[int, int]] = [(0, 0)] * n
    ranks = [0] * n
    rev = [False] * len(merged)
    points: list[list[tuple[int, int]]] = [[] for _ in merged]
    port_at: list[tuple[int, int]] = [(0, 0)] * len(ports)
    port_pts: list[list[tuple[int, int]]] = [[] for _ in ports]
    for piece, (sx, sy) in zip(all_pieces, shifts, strict=True):
        for c, (x, y) in zip(piece.members, piece.lay.offsets, strict=True):
            offsets[c] = (x + sx, y + sy)
        for c, r in zip(piece.members, piece.lay.ranks, strict=True):
            ranks[c] = r
        for i, rv, row in zip(
            piece.merged_ids, piece.lay.reversed, piece.lay.points, strict=True
        ):
            rev[i] = rv
            points[i] = [(x + sx, y + sy) for x, y in row]
        for i, (x, y), row in zip(
            piece.port_ids, piece.lay.port_at, piece.lay.port_pts, strict=True
        ):
            port_at[i] = (x + sx, y + sy)
            port_pts[i] = [(px + sx, py + sy) for px, py in row]
    return _LevelLayout(
        offsets, total_w, total_h, ranks, rev, points, port_at, port_pts
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
    # per lifted flow: chain from `a` / `b` down to the source / target itself
    flow_paths: dict[str, tuple[list[str | None], list[str | None]]] = {}
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
        flow_paths[e.id] = (cs[i:], ct[i:])

    # Sides (top-down in Pele; each flow's side depends only on its own level, so order is free):
    # rank each level's children and merged edges without ports.
    above: dict[tuple[str | None, str, str], bool] = {}
    for lvl, ms in level_merged.items():
        keys = list(ms)
        lnodes = [LNode(0, 0) for _ in children[lvl]]
        ledges = [LEdge(m.a, m.b, weight=m.count) for m in ms.values()]
        orient(lnodes, ledges)
        rank(lnodes, ledges)
        for (a, b), le in zip(keys, ledges, strict=True):
            above[(lvl, a, b)] = not le.reversed

    # Ports: one per flow for every group strictly between an end and the lifted level.
    level_ports: dict[str | None, list[_Port]] = {}
    flow_index = {e.id: k for k, e in enumerate(edges)}
    for eid, (lvl, a, b) in edge_key.items():
        a_above = above[(lvl, a, b)]
        src_path, dst_path = flow_paths[eid]
        for path, out in ((src_path, True), (dst_path, False)):
            for k, g in enumerate(path[:-1]):
                assert g is not None
                inner = path[k + 1]
                assert inner is not None
                level_ports.setdefault(g, []).append(
                    _Port(
                        flow_index[eid],
                        g,
                        child_index[g][inner],
                        out,
                        start=(not a_above) if out else a_above,
                    )
                )
    for lst in level_ports.values():
        lst.sort(key=lambda p: (p.inner, p.flow, p.out))

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
        lay = _layout_level(
            [size[c] for c in cs], merged, direction, opt, ports=level_ports.get(lvl)
        )
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

    # Port points: cross coordinate from the layout clamped to the group, rank coordinate on its
    # border. Keyed by (flow index, group, out).
    lr = direction == "LR"
    port_route: dict[tuple[int, str, bool], list[tuple[int, int]]] = {}
    port_point: dict[tuple[int, str, bool], tuple[int, int]] = {}
    for g, plist in level_ports.items():
        assert g is not None
        box, lay = boxes[g], layouts[g]
        ox, oy = level_origin[g]
        for p, (rx, ry), rel in zip(plist, lay.port_at, lay.port_pts, strict=True):
            if lr:
                px = box.x if p.start else box.x + box.w
                py = min(max(oy + ry, box.y), box.y + box.h)
            else:
                py = box.y if p.start else box.y + box.h
                px = min(max(ox + rx, box.x), box.x + box.w)
            key = (p.flow, g, p.out)
            port_point[key] = (px, py)
            port_route[key] = [(ox + x, oy + y) for x, y in rel]
    for eid, (lvl, a, b) in edge_key.items():
        src_path, dst_path = flow_paths[eid]
        fi = flow_index[eid]
        route = routes[eid]
        for g in reversed(src_path[:-1]):
            assert g is not None
            route.border_out += port_route[(fi, g, True)] + [port_point[(fi, g, True)]]
        for g in dst_path[:-1]:
            assert g is not None
            route.border_in += [port_point[(fi, g, False)]] + port_route[(fi, g, False)]
    root = layouts[None]
    return LayoutResult(boxes, routes, root.content_w, root.content_h)
