"""Pure helpers that turn layout routes into X6 edge vertices, fans and label positions."""

import math

from tmi_tf.layout.compound import Box, Direction, Side

Point = tuple[int, int]
MAX_VERTICES = 1000


def _round(v: float) -> int:
    return math.floor(v + 0.5)


def side_point(box: Box, side: Side | None) -> Point:
    """Middle of the given side of `box`; the center when `side` is None."""
    cx = _round(box.x + box.w / 2)
    cy = _round(box.y + box.h / 2)
    if side == "top":
        return (cx, box.y)
    if side == "bottom":
        return (cx, box.y + box.h)
    if side == "left":
        return (box.x, cy)
    if side == "right":
        return (box.x + box.w, cy)
    return (cx, cy)


def _distance_to_line(p: Point, a: Point, b: Point) -> float:
    dx, dy = b[0] - a[0], b[1] - a[1]
    length = math.hypot(dx, dy)
    if length == 0:
        return math.hypot(p[0] - a[0], p[1] - a[1])
    return abs(dx * (p[1] - a[1]) - dy * (p[0] - a[0])) / length


def straighten(
    points: list[Point], start: Point, end: Point, tol: float = 0.5
) -> list[Point]:
    """Drop each point closer than `tol` to the line through its kept predecessor and its successor."""
    kept: list[Point] = []
    prev = start
    for i, p in enumerate(points):
        nxt = points[i + 1] if i + 1 < len(points) else end
        if _distance_to_line(p, prev, nxt) < tol:
            continue
        kept.append(p)
        prev = p
    return kept


def fan_offsets(k: int, edge_sep: int) -> list[float]:
    return [(i - (k - 1) / 2) * edge_sep for i in range(k)]


def label_positions(k: int) -> list[float]:
    if k <= 1:
        return [0.5]
    return [round(0.35 + 0.3 * i / (k - 1), 4) for i in range(k)]


def gap_midpoint(
    a: Box, b: Box, source: Box, target: Box, direction: Direction
) -> Point:
    """Middle of the gap between the lifted children `a` and `b`, centerd between the end boxes."""
    if direction == "LR":
        lo, hi = ((a.x + a.w, b.x), (b.x + b.w, a.x))[a.x > b.x]
        if hi < lo:  # overlapping on the rank axis: fall back to the centers
            lo = hi = (a.x + a.w / 2 + b.x + b.w / 2) / 2
        rank = (lo + hi) / 2
        cross = (source.y + source.h / 2 + target.y + target.h / 2) / 2
        return (_round(rank), _round(cross))
    lo, hi = ((a.y + a.h, b.y), (b.y + b.h, a.y))[a.y > b.y]
    if hi < lo:
        lo = hi = (a.y + a.h / 2 + b.y + b.h / 2) / 2
    rank = (lo + hi) / 2
    cross = (source.x + source.w / 2 + target.x + target.w / 2) / 2
    return (_round(cross), _round(rank))


def shift_cross(
    points: list[Point], offset: float, direction: Direction
) -> list[Point]:
    """Move points along the cross axis (y in LR, x in TB) in screen coordinates."""
    if direction == "LR":
        return [(x, _round(y + offset)) for x, y in points]
    return [(_round(x + offset), y) for x, y in points]


def drop_blocked(points: list[Point], blockers: list[Box]) -> list[Point]:
    """Remove points strictly inside any blocker."""
    return [
        p
        for p in points
        if not any(
            bx.x < p[0] < bx.x + bx.w and bx.y < p[1] < bx.y + bx.h for bx in blockers
        )
    ]
