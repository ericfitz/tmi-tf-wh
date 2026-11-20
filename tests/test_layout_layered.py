"""Tests for the flat-graph core of the layered layout."""

import random

import pytest

from tmi_tf.layout.layered import (
    Kind,
    Layers,
    LEdge,
    LNode,
    build_layers,
    count_crossings,
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
