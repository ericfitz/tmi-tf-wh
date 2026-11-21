# Portions of this file are a Python port of Pele (https://github.com/obsidianmd/pele),
# src/layout/layered.ts, commit 3a2f075, used under the MIT License:
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

"""Layered (Sugiyama) layout core: cycle breaking, ranking, layers, crossing reduction, coordinates.

Ranks run along the "rank axis" (y in the layout's own frame); vertices within a rank are
ordered along the "cross axis" (x). Direction handling belongs to the caller.
"""

from dataclasses import dataclass, field
from enum import IntEnum
from math import inf

MAX_SWEEPS = 24
STALE_SWEEPS = 4
SWAP_PASSES = 8
BALANCE_PASSES = 8


class Kind(IntEnum):
    NODE = 0
    DUMMY = 1
    START_PORT = 2
    END_PORT = 3


@dataclass
class LNode:
    w: float  # cross-axis extent
    h: float  # rank-axis extent
    kind: Kind = Kind.NODE
    x: float = 0.0  # output: center on the cross axis
    y: float = 0.0  # output: center on the rank axis
    rank: int = 0  # output


@dataclass
class LEdge:
    tail: int
    head: int
    weight: int = 1  # number of merged parallel flows
    label_w: float = 0.0  # cross-axis width given to each dummy of this edge
    reversed: bool = False  # output of orient()
    points: list[tuple[float, float]] = field(
        default_factory=list
    )  # output of layered(), tail-to-head


@dataclass(frozen=True)
class LayeredOptions:
    node_sep: float
    edge_sep: float
    rank_sep: float


@dataclass
class Layers:
    kinds: list[
        Kind
    ]  # per vertex; real nodes first (same indices as `nodes`), then dummies
    widths: list[float]
    heights: list[float]
    ranks: list[int]
    segs: list[
        tuple[int, int, int]
    ]  # (upper vertex, lower vertex, weight), one per rank-to-rank segment
    order: list[list[int]]  # order[r]: vertices of rank r, in cross-axis order
    chains: list[
        list[int]
    ]  # chains[ei]: dummy vertices of edge ei from its upper end down; [] if one rank


def _validate(nodes: list[LNode], edges: list[LEdge]) -> None:
    n = len(nodes)
    for i, e in enumerate(edges):
        if not (0 <= e.tail < n and 0 <= e.head < n):
            raise ValueError(
                f"edge {i} has an endpoint out of range: {e.tail} -> {e.head} ({n} nodes)"
            )
        if e.tail == e.head:
            raise ValueError(f"edge {i} is a self-edge on node {e.tail}")


def orient(nodes: list[LNode], edges: list[LEdge]) -> None:
    """Reverse the edges that close a cycle, found by depth-first search in declaration order.

    An edge into a start port or out of an end port is reversed up front and left out of the search.
    """
    _validate(nodes, edges)
    n = len(nodes)
    out: list[list[int]] = [[] for _ in range(n)]
    for i, e in enumerate(edges):
        e.reversed = (
            nodes[e.head].kind == Kind.START_PORT or nodes[e.tail].kind == Kind.END_PORT
        )
        if not e.reversed:
            out[e.tail].append(i)
    state = [0] * n  # 0 unseen, 1 on the stack, 2 done
    cursor = [0] * n
    for root in range(n):
        if state[root] != 0:
            continue
        stack = [root]
        state[root] = 1
        while stack:
            v = stack[-1]
            if cursor[v] < len(out[v]):
                e = edges[out[v][cursor[v]]]
                cursor[v] += 1
                w = e.head
                if state[w] == 1:
                    e.reversed = True
                elif state[w] == 0:
                    state[w] = 1
                    stack.append(w)
            else:
                state[v] = 2
                stack.pop()


def rank(nodes: list[LNode], edges: list[LEdge]) -> None:
    """Longest-path ranking with loose nodes pulled toward the side with more edge weight."""
    _validate(nodes, edges)
    n = len(nodes)
    frm = [e.head if e.reversed else e.tail for e in edges]
    to = [e.tail if e.reversed else e.head for e in edges]
    out_e: list[list[int]] = [[] for _ in range(n)]
    in_e: list[list[int]] = [[] for _ in range(n)]
    for i in range(len(edges)):
        out_e[frm[i]].append(i)
        in_e[to[i]].append(i)

    r = [0] * n
    # Start ports go above every node later, so they don't push their targets down a rank.
    for i in range(n):
        if nodes[i].kind == Kind.START_PORT:
            r[i] = -1
    indeg = [len(in_e[i]) for i in range(n)]
    topo = [i for i in range(n) if indeg[i] == 0]
    q = 0
    while q < len(topo):
        v = topo[q]
        q += 1
        for ei in out_e[v]:
            w = to[ei]
            r[w] = max(r[w], r[v] + 1)
            indeg[w] -= 1
            if indeg[w] == 0:
                topo.append(w)
    if len(topo) < n:
        raise ValueError("graph still has a cycle after orient(); call orient() first")

    for _ in range(BALANCE_PASSES):
        changed = False
        for v in reversed(topo):
            if not in_e[v] and not out_e[v]:
                continue
            ins = sum(edges[ei].weight for ei in in_e[v])
            outs = sum(edges[ei].weight for ei in out_e[v])
            lo = max((r[frm[ei]] + 1 for ei in in_e[v]), default=None)
            hi = min((r[to[ei]] - 1 for ei in out_e[v]), default=None)
            nxt = r[v]
            if outs > ins and hi is not None:
                nxt = hi
            elif ins > outs and lo is not None:
                nxt = lo
            if nxt != r[v]:
                r[v] = nxt
                changed = True
        if not changed:
            break

    lowest: int | None = None
    highest: int | None = None
    start_ports = False
    for i in range(n):
        kind = nodes[i].kind
        if kind == Kind.START_PORT:
            start_ports = True
        if kind in (Kind.START_PORT, Kind.END_PORT):
            continue
        lowest = r[i] if lowest is None else min(lowest, r[i])
        highest = r[i] if highest is None else max(highest, r[i])
    lo_r = 0 if lowest is None else lowest
    hi_r = 0 if highest is None else highest
    for i in range(n):
        if nodes[i].kind == Kind.START_PORT:
            r[i] = lo_r - 1
        elif nodes[i].kind == Kind.END_PORT:
            r[i] = hi_r + 1
    if start_ports:
        lo_r -= 1
    for i in range(n):
        nodes[i].rank = r[i] - lo_r


def _fixed_rank(kinds: list[Kind], row: list[int]) -> bool:
    """A rank made only of start ports, or only of end ports, keeps its order."""
    if not row:
        return False
    first = kinds[row[0]]
    return first in (Kind.START_PORT, Kind.END_PORT) and all(
        kinds[v] == first for v in row
    )


def build_layers(nodes: list[LNode], edges: list[LEdge]) -> Layers:
    """Split long edges into one dummy vertex per skipped rank and give each rank a starting order."""
    _validate(nodes, edges)
    kinds = [v.kind for v in nodes]
    widths = [float(v.w) for v in nodes]
    heights = [float(v.h) for v in nodes]
    ranks = [v.rank for v in nodes]
    for i, v in enumerate(nodes):
        if v.rank < 0:
            raise ValueError(f"node {i} has negative rank {v.rank}")
    segs: list[tuple[int, int, int]] = []
    chains: list[list[int]] = []
    for ei, e in enumerate(edges):
        if e.weight < 1:
            raise ValueError(f"edge {ei} has weight {e.weight}; must be at least 1")
        a = e.head if e.reversed else e.tail
        b = e.tail if e.reversed else e.head
        ra, rb = ranks[a], ranks[b]
        if kinds[a] == kinds[b] and kinds[a] in (Kind.START_PORT, Kind.END_PORT):
            raise ValueError(
                f"edge {ei} connects two {kinds[a].name} nodes ({e.tail} -> {e.head}); "
                "ports cannot be joined to ports of the same kind"
            )
        if rb <= ra:
            raise ValueError(
                f"edge {ei} runs from rank {ra} to rank {rb}; run rank() first"
            )
        # Pele's MAX_DUMMIES / `direct` fallback is intentionally not ported (DFD-sized inputs).
        chain: list[int] = []
        prev = a
        for rk in range(ra + 1, rb):
            d = len(kinds)
            kinds.append(Kind.DUMMY)
            widths.append(float(e.label_w))
            heights.append(0.0)
            ranks.append(rk)
            segs.append((prev, d, e.weight))
            chain.append(d)
            prev = d
        segs.append((prev, b, e.weight))
        chains.append(chain)
    total = len(kinds)
    max_rank = max(ranks, default=-1)

    succ: list[list[int]] = [[] for _ in range(total)]
    for upper, lower, _ in segs:
        succ[upper].append(lower)

    # Initial order: depth-first from the top so that subtrees start out contiguous.
    by_rank = sorted(range(total), key=lambda v: (ranks[v], v))
    order: list[list[int]] = [[] for _ in range(max_rank + 1)]
    visited = [False] * total
    for first in by_rank:
        if visited[first]:
            continue
        stack = [first]
        while stack:
            v = stack.pop()
            if visited[v]:
                continue
            visited[v] = True
            order[ranks[v]].append(v)
            for w in reversed(succ[v]):
                if not visited[w]:
                    stack.append(w)
    for row in order:
        if _fixed_rank(kinds, row):
            row.sort()
    return Layers(kinds, widths, heights, ranks, segs, order, chains)


class _Net:
    """Adjacency and fixed-rank flags derived once from a Layers value."""

    def __init__(self, layers: Layers) -> None:
        total = len(layers.kinds)
        self.segs = layers.segs
        self.succ: list[list[int]] = [[] for _ in range(total)]
        self.pred: list[list[int]] = [[] for _ in range(total)]
        for k, (upper, lower, _) in enumerate(layers.segs):
            self.succ[upper].append(k)
            self.pred[lower].append(k)
        self.total = total
        self.fixed = [_fixed_rank(layers.kinds, row) for row in layers.order]


def _positions(net: _Net, order: list[list[int]]) -> list[int]:
    pos = [0] * net.total
    for row in order:
        for i, v in enumerate(row):
            pos[v] = i
    return pos


def _count(net: _Net, order: list[list[int]], pos: list[int]) -> int:
    """Weighted crossings: two crossing segments count weight_1 * weight_2."""
    total = 0
    for r in range(len(order) - 1):
        south = len(order[r + 1])
        if south < 2:
            continue
        targets: list[tuple[int, int]] = []
        for v in order[r]:
            targets.extend(
                sorted((pos[net.segs[k][1]], net.segs[k][2]) for k in net.succ[v])
            )
        if len(targets) < 2:
            continue
        tree = [0] * (south + 1)
        inserted = 0
        for p, w in targets:
            # weight already inserted with a larger target position
            prefix = 0
            i = p + 1
            while i > 0:
                prefix += tree[i]
                i -= i & -i
            total += w * (inserted - prefix)
            i = p + 1
            while i <= south:
                tree[i] += w
                i += i & -i
            inserted += w
    return total


def count_crossings(layers: Layers) -> int:
    net = _Net(layers)
    return _count(net, layers.order, _positions(net, layers.order))


def _sweep(
    net: _Net, order: list[list[int]], pos: list[int], down: bool, bias_right: bool
) -> None:
    ranks_n = len(order)
    for step in range(1, ranks_n):
        r = step if down else ranks_n - 1 - step
        if net.fixed[r]:
            continue
        row = order[r]
        bary: dict[int, float] = {}
        for v in row:
            adj = net.pred[v] if down else net.succ[v]
            if not adj:
                continue  # no neighbor in the adjacent rank: keeps its slot
            acc = 0
            weight = 0
            for k in adj:
                upper, lower, w = net.segs[k]
                acc += pos[upper if down else lower] * w
                weight += w
            bary[v] = acc / weight
        moving = sorted(
            bary, key=lambda v: (bary[v], -pos[v] if bias_right else pos[v])
        )
        if len(moving) < 2:
            continue
        slots = [i for i, v in enumerate(row) if v in bary]
        for i, v in zip(slots, moving):
            row[i] = v
        for i, v in enumerate(row):
            pos[v] = i


def _between(net: _Net, pos: list[int], a: int, b: int) -> int:
    """Crossings between a and b, assuming a is left of b."""
    c = 0
    for lists, end in ((net.pred, 0), (net.succ, 1)):
        for ka in lists[a]:
            sa = net.segs[ka]
            xa = pos[sa[end]]
            for kb in lists[b]:
                sb = net.segs[kb]
                if xa > pos[sb[end]]:
                    c += sa[2] * sb[2]
    return c


def _transpose(net: _Net, order: list[list[int]], pos: list[int]) -> None:
    for _ in range(SWAP_PASSES):
        improved = False
        for r, row in enumerate(order):
            if net.fixed[r]:
                continue
            for i in range(len(row) - 1):
                a, b = row[i], row[i + 1]
                if _between(net, pos, b, a) >= _between(net, pos, a, b):
                    continue
                row[i], row[i + 1] = b, a
                pos[b] = i
                pos[a] = i + 1
                improved = True
        if not improved:
            break


def reduce_crossings(layers: Layers) -> int:
    """Barycenter sweeps then adjacent swaps, in place on `layers.order`; returns the crossings left."""
    net = _Net(layers)
    order = layers.order
    pos = _positions(net, order)
    found = _count(net, order, pos)
    if found == 0:
        return 0
    found_order = [row[:] for row in order]
    stale = 0
    for i in range(MAX_SWEEPS):
        if stale >= STALE_SWEEPS:
            break
        _sweep(net, order, pos, i % 2 == 0, i % 4 >= 2)
        c = _count(net, order, pos)
        if c < found:
            found = c
            found_order = [row[:] for row in order]
            stale = 0
            if c == 0:
                break
        else:
            stale += 1
    for r, row in enumerate(found_order):
        order[r][:] = row
    pos = _positions(net, order)
    if found > 0:
        _transpose(net, order, pos)
        found = _count(net, order, pos)
    return found


@dataclass(frozen=True)
class LayeredResult:
    width: float
    height: float


def _half_room(layers: Layers, opt: LayeredOptions, v: int) -> float:
    gap = opt.node_sep if layers.kinds[v] == Kind.NODE else opt.edge_sep
    return layers.widths[v] / 2 + gap / 2


def _mark_conflicts(net: _Net, layers: Layers, pos: list[int]) -> list[bool]:
    """Mark segments between real nodes that would cross a dummy-to-dummy segment."""
    order, kinds = layers.order, layers.kinds
    conflict = [False] * len(net.segs)
    for r in range(1, len(order)):
        row = order[r]
        prev_len = len(order[r - 1])
        k0 = 0
        scan = 0
        for i, v in enumerate(row):
            inner = -1
            if kinds[v] == Kind.DUMMY and net.pred[v]:
                u = net.segs[net.pred[v][0]][0]
                if kinds[u] == Kind.DUMMY:
                    inner = u
            k1 = pos[inner] if inner >= 0 else prev_len
            if inner >= 0 or i == len(row) - 1:
                for j in range(scan, i + 1):
                    w = row[j]
                    w_dummy = kinds[w] == Kind.DUMMY
                    for k in net.pred[w]:
                        up = pos[net.segs[k][0]]
                        if (up < k0 or k1 < up) and not (
                            w_dummy and kinds[net.segs[k][0]] == Kind.DUMMY
                        ):
                            conflict[k] = True
                scan = i + 1
                k0 = k1
    return conflict


def _align_variant(
    net: _Net,
    layers: Layers,
    gap: list[float],
    pos: list[int],
    conflict: list[bool],
    nbrs_up: list[list[int]],
    nbrs_down: list[list[int]],
    up: bool,
    right: bool,
) -> list[float]:
    order = layers.order
    total = net.total
    max_rank = len(order) - 1
    root = list(range(total))
    align = list(range(total))
    lists = nbrs_up if up else nbrs_down
    for step in range(max_rank + 1):
        r = step if up else max_rank - step
        adjacent = r - 1 if up else r + 1
        adjacent_last = len(order[adjacent]) - 1 if 0 <= adjacent <= max_rank else 0
        prev_idx = -1
        row = order[r]
        for v in reversed(row) if right else row:
            d = len(lists[v])
            if d == 0:
                continue
            lo = (d - 1) >> 1
            hi = d >> 1
            for pass_no in range(2):
                if pass_no == 1 and lo == hi:
                    break
                k = lists[v][lo if (pass_no == 0) != right else hi]
                w = net.segs[k][0] if up else net.segs[k][1]
                idx = adjacent_last - pos[w] if right else pos[w]
                if align[v] == v and prev_idx < idx and not conflict[k]:
                    align[w] = v
                    root[v] = root[w]
                    align[v] = root[w]
                    prev_idx = idx

    # Horizontal compaction over the blocks, as a longest-path problem on their roots.
    out_e: list[list[tuple[int, float]]] = [[] for _ in range(total)]
    indeg = [0] * total
    for row in order:
        for i in range(1, len(row)):
            a = row[i] if right else row[i - 1]
            b = row[i - 1] if right else row[i]
            out_e[root[a]].append((root[b], gap[a] + gap[b]))
            indeg[root[b]] += 1
    x = [0.0] * total
    topo = [v for v in range(total) if root[v] == v and indeg[v] == 0]
    q = 0
    while q < len(topo):
        v = topo[q]
        q += 1
        for w, sep in out_e[v]:
            x[w] = max(x[w], x[v] + sep)
            indeg[w] -= 1
            if indeg[w] == 0:
                topo.append(w)
    n_roots = sum(1 for v in range(total) if root[v] == v)
    if len(topo) != n_roots:
        raise ValueError(
            "block graph is not acyclic: "
            f"{n_roots - len(topo)} of {n_roots} alignment blocks never became ready"
        )
    for v in reversed(topo):
        cand = min((x[w] - sep for w, sep in out_e[v]), default=inf)
        if cand != inf and cand > x[v]:
            x[v] = cand
    return [-x[root[i]] if right else x[root[i]] for i in range(total)]


def position(layers: Layers, opt: LayeredOptions) -> list[float]:
    """Brandes-Koepf coordinates: cross-axis center per vertex."""
    net = _Net(layers)
    total = net.total
    if total == 0:
        return []
    order = layers.order
    pos = _positions(net, order)
    gap = [_half_room(layers, opt, v) for v in range(total)]
    # Neighbor segments in left-to-right order, so the medians can be read off directly.
    nbrs_up = [
        sorted(net.pred[v], key=lambda k: (pos[net.segs[k][0]], k))
        for v in range(total)
    ]
    nbrs_down = [
        sorted(net.succ[v], key=lambda k: (pos[net.segs[k][1]], k))
        for v in range(total)
    ]
    conflict = _mark_conflicts(net, layers, pos)
    results = [
        _align_variant(
            net,
            layers,
            gap,
            pos,
            conflict,
            nbrs_up,
            nbrs_down,
            variant < 2,
            bool(variant & 1),
        )
        for variant in range(4)
    ]
    half = [w / 2 for w in layers.widths]
    mins = [min(xs[i] - half[i] for i in range(total)) for xs in results]
    maxs = [max(xs[i] + half[i] for i in range(total)) for xs in results]
    narrowest = min(range(4), key=lambda k: (maxs[k] - mins[k], k))
    for k in range(4):
        delta = mins[narrowest] - mins[k] if k & 1 == 0 else maxs[narrowest] - maxs[k]
        if delta != 0:
            results[k] = [v + delta for v in results[k]]
    out: list[float] = []
    for i in range(total):
        vals = sorted(results[k][i] for k in range(4))
        out.append((vals[1] + vals[2]) / 2)
    return out


def layered(
    nodes: list[LNode], edges: list[LEdge], opt: LayeredOptions
) -> LayeredResult:
    """Lay out a flat graph: writes x, y, rank on each node and points on each edge."""
    if not nodes:
        return LayeredResult(0, 0)
    orient(nodes, edges)
    rank(nodes, edges)
    layers = build_layers(nodes, edges)
    reduce_crossings(layers)
    xs = position(layers, opt)
    total = len(layers.kinds)
    half = [w / 2 for w in layers.widths]
    shift = -min(xs[i] - half[i] for i in range(total))
    xs = [v + shift for v in xs]

    band_h = [
        max((layers.heights[v] for v in row), default=0.0) for row in layers.order
    ]
    top: list[float] = []
    y = 0.0
    for h in band_h:
        top.append(y)
        y += h + opt.rank_sep
    for i, node in enumerate(nodes):
        r = layers.ranks[i]
        node.x = xs[i]
        node.y = top[r] + band_h[r] / 2
        node.rank = r

    for ei, e in enumerate(edges):
        pts: list[tuple[float, float]] = []
        for d in layers.chains[ei]:
            r = layers.ranks[d]
            pts.append((xs[d], top[r]))
            if band_h[r] > 0:
                pts.append((xs[d], top[r] + band_h[r]))
        if e.reversed:
            pts.reverse()
        e.points = pts

    width = max(xs[i] + half[i] for i in range(total))
    height = max(
        top[layers.ranks[i]] + band_h[layers.ranks[i]] / 2 + layers.heights[i] / 2
        for i in range(total)
    ) - min(
        top[layers.ranks[i]] + band_h[layers.ranks[i]] / 2 - layers.heights[i] / 2
        for i in range(total)
    )
    return LayeredResult(width, height)
