"""Tests for the flat-graph core of the layered layout."""

import itertools
import random

import pytest

from tmi_tf.layout import layered as layered_mod
from tmi_tf.layout.layered import (
    Kind,
    LayeredOptions,
    LayeredResult,
    Layers,
    LEdge,
    LNode,
    build_layers,
    count_crossings,
    layered,
    orient,
    rank,
    reduce_crossings,
)


def graph(n, pairs, kinds=None):
    nodes = [LNode(100, 40, (kinds or {}).get(i, Kind.NODE)) for i in range(n)]
    return nodes, [LEdge(a, b) for a, b in pairs]


def ranks(n, pairs, kinds=None):
    nodes, edges = graph(n, pairs, kinds)
    orient(nodes, edges)
    rank(nodes, edges)
    return [v.rank for v in nodes], edges


def test_orient_reverses_one_edge_of_cycle():
    nodes, edges = graph(3, [(0, 1), (1, 2), (2, 0)])
    orient(nodes, edges)
    assert [e.reversed for e in edges] == [False, False, True]


def test_rank_chain_and_diamond():
    assert ranks(3, [(0, 1), (1, 2)])[0] == [0, 1, 2]
    assert ranks(4, [(0, 1), (0, 2), (1, 3), (2, 3)])[0] == [0, 1, 1, 2]


def test_rank_moves_loose_source_next_to_its_target():
    assert ranks(4, [(0, 1), (1, 2), (3, 2)])[0] == [0, 1, 2, 1]


def test_rank_puts_ports_outside_real_nodes():
    # 0 -> 1 real; 2 is a start port feeding 0; 3 is an end port fed by 1
    r, edges = ranks(
        4, [(0, 1), (2, 0), (1, 3)], {2: Kind.START_PORT, 3: Kind.END_PORT}
    )
    assert r == [1, 2, 0, 3] and not any(e.reversed for e in edges)


def test_orient_prereverses_edges_against_ports():
    # an edge leaving through the start side, and one entering from the end side
    _, edges = ranks(
        4, [(0, 1), (0, 2), (3, 1)], {2: Kind.START_PORT, 3: Kind.END_PORT}
    )
    assert [e.reversed for e in edges] == [False, True, True]


def test_build_layers_long_edge_gets_one_dummy_per_skipped_rank():
    nodes, edges = graph(3, [(0, 1), (1, 2), (0, 2)])
    orient(nodes, edges)
    rank(nodes, edges)
    layers = build_layers(nodes, edges)
    assert len(layers.chains[2]) == 1 and layers.chains[0] == []
    assert layers.kinds[layers.chains[2][0]] == Kind.DUMMY and len(layers.segs) == 4
    assert sorted(layers.order[1]) == sorted([1, layers.chains[2][0]])


def test_build_layers_dummy_carries_label_width_and_weight():
    nodes, edges = graph(3, [(0, 1), (1, 2), (0, 2)])
    edges[2].label_w = 30.0
    edges[2].weight = 4
    orient(nodes, edges)
    rank(nodes, edges)
    layers = build_layers(nodes, edges)
    d = layers.chains[2][0]
    assert layers.widths[d] == 30.0 and layers.heights[d] == 0 and layers.ranks[d] == 1
    assert (0, d, 4) in layers.segs and (d, 2, 4) in layers.segs


def test_build_layers_reversed_edge_chain_runs_top_down():
    nodes, edges = graph(3, [(0, 1), (1, 2), (2, 0)])
    orient(nodes, edges)
    rank(nodes, edges)
    layers = build_layers(nodes, edges)
    d = layers.chains[2][0]
    assert (
        (0, d, 1) in layers.segs
        and (d, 2, 1) in layers.segs
        and (2, d, 1) not in layers.segs
    )


def test_reduce_crossings_untangles_a_scrambled_rank():
    nodes, edges = graph(6, [(0, 3), (1, 4), (2, 5)])
    orient(nodes, edges)
    rank(nodes, edges)
    layers = build_layers(nodes, edges)
    layers.order[1].reverse()
    assert count_crossings(layers) == 3
    assert reduce_crossings(layers) == 0 and count_crossings(layers) == 0


def test_port_ranks_are_fixed_in_list_order():
    # start ports 2, 3 feed 1, 0; end ports 4, 5 are fed by 0, 1: one crossing is unavoidable
    kinds = {2: Kind.START_PORT, 3: Kind.START_PORT, 4: Kind.END_PORT, 5: Kind.END_PORT}
    nodes, edges = graph(6, [(2, 1), (3, 0), (0, 4), (1, 5)], kinds)
    orient(nodes, edges)
    rank(nodes, edges)
    layers = build_layers(nodes, edges)
    assert reduce_crossings(layers) == 1
    assert layers.order[0] == [2, 3] and layers.order[2] == [4, 5]


def test_weighted_crossings_count_products():
    nodes, edges = graph(4, [(0, 3), (1, 2)])
    edges[0].weight = 2
    edges[1].weight = 3
    orient(nodes, edges)
    rank(nodes, edges)
    layers = build_layers(nodes, edges)
    assert layers.order == [[0, 1], [3, 2]]
    assert count_crossings(layers) == 0
    layers.order[1].reverse()
    assert count_crossings(layers) == 6


def test_reduce_result_matches_recount():
    nodes, edges = graph(5, [(0, 2), (1, 3), (1, 4), (0, 4), (0, 3)])
    orient(nodes, edges)
    rank(nodes, edges)
    layers = build_layers(nodes, edges)
    result = reduce_crossings(layers)
    assert result == count_crossings(layers)


@pytest.mark.parametrize("bad", [[(0, 0)], [(0, 5)], [(-1, 1)]])
def test_self_edge_and_bad_index_raise(bad):
    nodes, edges = graph(2, bad)
    with pytest.raises(ValueError):
        orient(nodes, edges)
    with pytest.raises(ValueError):
        rank(nodes, edges)
    with pytest.raises(ValueError):
        build_layers(nodes, edges)


def test_build_layers_rejects_unranked_edge_and_bad_weight():
    nodes, edges = graph(2, [(0, 1)])  # both rank 0: rank() was never run
    with pytest.raises(ValueError):
        build_layers(nodes, edges)
    nodes, edges = graph(2, [(0, 1)])
    orient(nodes, edges)
    rank(nodes, edges)
    edges[0].weight = 0
    with pytest.raises(ValueError):
        build_layers(nodes, edges)


def test_rank_rejects_cycle_left_by_two_port_edges():
    kinds = {0: Kind.START_PORT, 1: Kind.START_PORT}
    nodes, edges = graph(2, [(0, 1), (1, 0)], kinds)
    orient(nodes, edges)
    with pytest.raises(ValueError):
        rank(nodes, edges)


def test_empty_graph():
    layers = build_layers([], [])
    assert isinstance(layers, Layers) and layers.order == []
    assert count_crossings(layers) == 0 and reduce_crossings(layers) == 0


def _random_dag(seed):
    rng = random.Random(seed)
    pairs = set()
    while len(pairs) < 20:
        a, b = rng.sample(range(12), 2)
        pairs.add((min(a, b), max(a, b)))
    nodes, edges = graph(12, sorted(pairs))
    orient(nodes, edges)
    rank(nodes, edges)
    layers = build_layers(nodes, edges)
    reduce_crossings(layers)
    return [n.rank for n in nodes], layers.order


def test_same_input_same_order():
    assert _random_dag(7) == _random_dag(7)


def test_reduce_never_increases_crossings():
    for seed in range(10):
        rng = random.Random(seed)
        pairs = {tuple(sorted(rng.sample(range(10), 2))) for _ in range(18)}
        nodes, edges = graph(10, sorted(pairs))
        orient(nodes, edges)
        rank(nodes, edges)
        layers = build_layers(nodes, edges)
        before = count_crossings(layers)
        after = reduce_crossings(layers)
        assert after <= before and after == count_crossings(layers)
        for r, row in enumerate(layers.order):
            assert all(layers.ranks[v] == r for v in row)


OPT = LayeredOptions(40, 20, 60)


def run(n, pairs):
    nodes, edges = graph(n, pairs)
    return nodes, edges, layered(nodes, edges, OPT)


def test_empty_and_single():
    assert layered([], [], OPT) == LayeredResult(0, 0)
    nodes, _, size = run(1, [])
    assert (nodes[0].x, nodes[0].y, size) == (50, 20, LayeredResult(100, 40))


def test_chain_is_straight():
    nodes, _, size = run(3, [(0, 1), (1, 2)])
    assert [v.x for v in nodes] == [50, 50, 50]
    assert [v.y for v in nodes] == [20, 120, 220] and size == LayeredResult(100, 240)


def test_diamond_is_symmetric():
    nodes, _, _ = run(4, [(0, 1), (0, 2), (1, 3), (2, 3)])
    assert nodes[1].y == nodes[2].y and abs(nodes[1].x - nodes[2].x) >= 140
    assert nodes[0].x == nodes[3].x == (nodes[1].x + nodes[2].x) / 2


def test_cycle_completes_with_one_reversed_edge():
    nodes, edges, _ = run(3, [(0, 1), (1, 2), (2, 0)])
    assert sum(e.reversed for e in edges) == 1
    assert sorted(v.rank for v in nodes) == [0, 1, 2]


def test_long_edge_points_run_beside_the_skipped_node():
    nodes, edges, _ = run(3, [(0, 1), (1, 2), (0, 2)])
    (x1, y1), (x2, y2) = edges[2].points
    assert x1 == x2 and (y1, y2) == (100, 140)  # band of rank 1
    assert abs(x1 - nodes[1].x) >= 50 + 30  # half width + (node_sep + edge_sep) / 2
    assert edges[0].points == []


def test_disconnected_parts_do_not_overlap():
    nodes, _, _ = run(4, [(0, 1), (2, 3)])
    assert abs(nodes[0].x - nodes[2].x) >= 140


def test_reversed_edge_points_run_tail_to_head():
    # 0->1->2->3 chain plus 3->0 reversed, spanning three ranks: three dummies' worth of points
    _nodes, edges, _ = run(4, [(0, 1), (1, 2), (2, 3), (3, 0)])
    assert edges[3].reversed
    ys = [y for _, y in edges[3].points]
    assert ys == sorted(ys, reverse=True) and len(ys) == 4


def test_random_graphs_keep_invariants():
    def build(seed):
        rnd = random.Random(seed)
        n = rnd.randint(3, 25)
        pairs = []
        for _ in range(rnd.randint(0, 2 * n)):
            a, b = rnd.randrange(n), rnd.randrange(n)
            if a != b:
                pairs.append((a, b))
        return graph(n, pairs)

    for seed in range(20):
        nodes, edges = build(seed)
        size = layered(nodes, edges, OPT)
        for e in edges:
            lo, hi = (e.head, e.tail) if e.reversed else (e.tail, e.head)
            assert nodes[hi].rank > nodes[lo].rank
        by_rank: dict[int, list[LNode]] = {}
        for v in nodes:
            by_rank.setdefault(v.rank, []).append(v)
            assert 0 <= v.x - 50 and v.x + 50 <= size.width
            assert 0 <= v.y - 20 and v.y + 20 <= size.height
        for row in by_rank.values():
            xs = sorted(v.x for v in row)
            assert all(b - a >= 140 for a, b in itertools.pairwise(xs))
        again_nodes, again_edges = build(seed)
        layered(again_nodes, again_edges, OPT)
        assert [(v.x, v.y, v.rank) for v in nodes] == [
            (v.x, v.y, v.rank) for v in again_nodes
        ]
        assert [e.points for e in edges] == [e.points for e in again_edges]


def _hand_layers(order, segs):
    n = sum(len(r) for r in order)
    return Layers([Kind.NODE] * n, [1.0] * n, [1.0] * n, [0] * n, segs, order, [])


def test_only_the_adjacent_swap_pass_removes_this_crossing(monkeypatch):
    order = [[0, 1, 2, 3], [4, 5, 6, 7]]
    segs = [(0, 5, 1), (1, 4, 1), (2, 4, 2), (3, 5, 1), (3, 6, 1)]
    with_swaps = _hand_layers([r[:] for r in order], segs)
    assert reduce_crossings(with_swaps) == 0 == count_crossings(with_swaps)
    monkeypatch.setattr(layered_mod, "_transpose", lambda *a: None)
    sweeps_only = _hand_layers([r[:] for r in order], segs)
    assert reduce_crossings(sweeps_only) > 0


def test_sweep_keeps_the_slot_of_a_vertex_without_neighbors():
    # vertex 3 has no segment; 2 and 4 must swap around it
    layers = _hand_layers([[0, 1], [2, 3, 4]], [(0, 4, 1), (1, 2, 1)])
    assert count_crossings(layers) == 1
    assert reduce_crossings(layers) == 0
    assert layers.order[1] == [4, 3, 2]


@pytest.mark.parametrize(
    ("kind", "pair"),
    [(Kind.START_PORT, (0, 1)), (Kind.END_PORT, (0, 1))],
)
def test_build_layers_rejects_edge_between_same_kind_ports(kind, pair):
    nodes, edges = graph(2, [pair], {0: kind, 1: kind})
    orient(nodes, edges)
    rank(nodes, edges)
    with pytest.raises(ValueError, match=r"connects two .*_PORT nodes"):
        build_layers(nodes, edges)


def test_position_rejects_cyclic_block_graph():
    # Not reachable from build_layers; two rows that order the same pair oppositely make
    # the two blocks wait on each other.
    nodes, edges = graph(2, [(0, 1)])
    orient(nodes, edges)
    rank(nodes, edges)
    layers = build_layers(nodes, edges)
    layers.order = [[0, 1], [1, 0]]  # vertex 1 listed in both rows, in opposite order
    layers.ranks = [0, 0]
    with pytest.raises(ValueError, match="not acyclic"):
        layered_mod.position(layers, LayeredOptions(40, 20, 60))


@pytest.mark.parametrize("seed", range(6))
def test_every_adjacent_pair_in_a_rank_is_separated_dummies_included(seed):
    rng = random.Random(seed)
    n = rng.randint(6, 14)
    nodes = [LNode(rng.choice([40, 80, 120, 200]), 40) for _ in range(n)]
    pairs = []
    for _ in range(n * 2):
        a, b = rng.sample(range(n), 2)
        pairs.append((min(a, b), max(a, b)))
    edges = [LEdge(a, b, label_w=rng.choice([0, 0, 30, 90])) for a, b in pairs]
    opt = LayeredOptions(40, 20, 60)
    orient(nodes, edges)
    rank(nodes, edges)
    layers = build_layers(nodes, edges)
    reduce_crossings(layers)
    xs = layered_mod.position(layers, opt)
    for row in layers.order:
        for u, v in itertools.pairwise(row):
            need = layered_mod._half_room(layers, opt, u) + layered_mod._half_room(
                layers, opt, v
            )
            assert xs[v] - xs[u] >= need - 1e-6
