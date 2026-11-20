"""Tests for the compound (nested boundary) layout."""

import random

import pytest

from tmi_tf.layout import compound
from tmi_tf.layout.compound import (
    LayoutEdge,
    LayoutNode,
    compound_layout,
    edge_sides,
    label_width,
)


def leaf(id, parent=None):
    return LayoutNode(id, parent, 120, 60)


def group(id, parent=None, w=40, h=30):
    return LayoutNode(id, parent, w, h, True)


def edge(i, s, t, label_w=0):
    return LayoutEdge(str(i), s, t, label_w)


def xywh(b):
    return (b.x, b.y, b.w, b.h)


def test_lr_chain_runs_left_to_right():
    r = compound_layout(
        [leaf("a"), leaf("b"), leaf("c")], [edge(0, "a", "b"), edge(1, "b", "c")], "LR"
    )
    assert [xywh(r.boxes[i]) for i in "abc"] == [
        (50, 50, 120, 60),
        (230, 50, 120, 60),
        (410, 50, 120, 60),
    ]
    assert (r.width, r.height) == (480, 60)


def test_tb_chain_runs_top_to_bottom():
    r = compound_layout(
        [leaf("a"), leaf("b"), leaf("c")], [edge(0, "a", "b"), edge(1, "b", "c")], "TB"
    )
    assert [(r.boxes[i].x, r.boxes[i].y) for i in "abc"] == [
        (50, 50),
        (50, 170),
        (50, 290),
    ]


def test_lr_label_widens_rank_gap():
    r = compound_layout([leaf("a"), leaf("b")], [edge(0, "a", "b", label_w=200)], "LR")
    assert r.boxes["b"].x - (r.boxes["a"].x + 120) == 224


def test_tb_label_widens_cross_gap_not_rank_gap():
    r = compound_layout([leaf("a"), leaf("b")], [edge(0, "a", "b", label_w=200)], "TB")
    assert r.boxes["b"].y - (r.boxes["a"].y + 60) == 60


def test_group_wraps_children_with_padding():
    r = compound_layout(
        [group("g"), leaf("a", "g"), leaf("b", "g")], [edge(0, "a", "b")], "LR"
    )
    assert xywh(r.boxes["g"]) == (50, 50, 360, 150)
    assert (r.boxes["a"].x, r.boxes["a"].y) == (80, 110) and r.boxes["b"].x == 260


def test_empty_group_and_minimum_width():
    r = compound_layout([group("g"), group("wide", w=200), leaf("a", "wide")], [], "LR")
    assert (r.boxes["g"].w, r.boxes["g"].h) == (60, 90)
    assert r.boxes["wide"].w == 200 and r.boxes["a"].x == r.boxes["wide"].x + 40


def test_edge_between_nested_leaves_is_lifted_to_the_common_level():
    nodes = [group("g1"), leaf("a", "g1"), group("g2"), leaf("b", "g2")]
    r = compound_layout(nodes, [edge(0, "a", "b")], "LR")
    rt = r.routes["0"]
    assert (rt.lifted, rt.level, rt.a, rt.b, rt.reversed, rt.rank_a, rt.rank_b) == (
        True,
        None,
        "g1",
        "g2",
        False,
        0,
        1,
    )
    assert r.boxes["g2"].x >= r.boxes["g1"].x + r.boxes["g1"].w + 60


def test_lifted_inside_a_group_names_that_level():
    nodes = [group("g"), group("h", "g"), leaf("a", "h"), leaf("b", "g")]
    r = compound_layout(nodes, [edge(0, "a", "b")], "LR")
    rt = r.routes["0"]
    assert (rt.level, rt.a, rt.b) == ("g", "h", "b")


def test_ancestor_and_self_flows_take_no_part():
    nodes = [group("g"), leaf("a", "g"), leaf("b", "g")]
    base = compound_layout(nodes, [edge(0, "a", "b")], "LR")
    r = compound_layout(
        nodes,
        [edge(0, "a", "b"), edge(1, "g", "a"), edge(2, "b", "g"), edge(3, "a", "a")],
        "LR",
    )
    assert r.boxes == base.boxes
    assert [r.routes[k].lifted for k in "0123"] == [True, False, False, False]


def test_long_label_is_capped():
    assert label_width("") == 0
    assert label_width("HTTPS") == 51
    assert label_width("x" * 200) == 240


def test_long_edge_points_pass_beside_the_middle_node():
    r = compound_layout(
        [leaf("a"), leaf("b"), leaf("c")],
        [edge(0, "a", "b"), edge(1, "b", "c"), edge(2, "a", "c")],
        "LR",
    )
    b = r.boxes["b"]
    (x1, y1), (x2, y2) = r.routes["2"].points
    assert (x1, x2) == (b.x, b.x + b.w) and y1 == y2
    assert y1 <= b.y - 10 or y1 >= b.y + b.h + 10


def test_duplicate_flows_merge():
    nodes = [leaf("a"), leaf("b")]
    one = compound_layout(nodes, [edge(0, "a", "b")], "LR")
    two = compound_layout(nodes, [edge(0, "a", "b"), edge(1, "a", "b")], "LR")
    assert two.boxes == one.boxes
    assert two.routes["0"] == two.routes["1"]
    assert two.routes["0"].lifted


def test_two_cycle_reverses_one():
    r = compound_layout(
        [leaf("a"), leaf("b")], [edge(0, "a", "b"), edge(1, "b", "a")], "LR"
    )
    rev = [k for k in "01" if r.routes[k].reversed]
    assert len(rev) == 1
    rt = r.routes[rev[0]]
    assert rt.rank_b < rt.rank_a


@pytest.mark.parametrize(
    ("direction", "delta", "cross", "expected"),
    [
        ("TB", 1, 0, ("bottom", "top")),
        ("TB", -1, 0, ("top", "bottom")),
        ("TB", 0, 5, ("right", "left")),
        ("TB", 0, -5, ("left", "right")),
        ("LR", 1, 0, ("right", "left")),
        ("LR", -1, 0, ("left", "right")),
        ("LR", 0, 0, ("bottom", "top")),
        ("LR", 0, -1, ("top", "bottom")),
    ],
)
def test_edge_sides_table(direction, delta, cross, expected):
    assert edge_sides(direction, delta, cross) == expected


@pytest.mark.parametrize(
    ("nodes", "edges", "direction", "offender"),
    [
        ([leaf("a"), leaf("a")], [], "LR", "a"),
        ([leaf("a", "nope")], [], "LR", "nope"),
        ([leaf("p"), leaf("c", "p")], [], "LR", "p"),
        ([group("x", "y"), group("y", "x")], [], "LR", "x"),
        ([group("s", "s")], [], "LR", "s"),
        ([leaf("a")], [edge(0, "a", "ghost")], "LR", "ghost"),
        ([leaf("a")], [edge(0, "ghost", "a")], "LR", "ghost"),
        ([leaf("a")], [], "BT", "BT"),
    ],
)
def test_validation_rejects_bad_input(nodes, edges, direction, offender):
    with pytest.raises(ValueError, match=offender):
        compound_layout(nodes, edges, direction)  # type: ignore[arg-type]


def test_duplicate_edge_id_is_rejected():
    with pytest.raises(ValueError, match="dup"):
        compound_layout(
            [leaf("a"), leaf("b")],
            [LayoutEdge("dup", "a", "b"), LayoutEdge("dup", "b", "a")],
            "LR",
        )


def _tree(seed):
    rng = random.Random(seed)
    nodes = [group("g0")]
    groups = ["g0"]
    for i in range(1, 4):
        parent = rng.choice(groups)
        nodes.append(group(f"g{i}", parent))
        groups.append(f"g{i}")
    leaves = []
    for i in range(10):
        nodes.append(leaf(f"l{i}", rng.choice(groups + [None])))
        leaves.append(f"l{i}")
    edges = [
        edge(i, *rng.sample(leaves, 2), label_w=rng.choice([0, 51, 100]))
        for i in range(14)
    ]
    return nodes, edges


@pytest.mark.parametrize("direction", ["LR", "TB"])
def test_all_outputs_are_ints(direction):
    nodes, edges = _tree(1)
    r = compound_layout(nodes, edges, direction)
    assert isinstance(r.width, int) and isinstance(r.height, int)
    for b in r.boxes.values():
        assert all(type(v) is int for v in (b.x, b.y, b.w, b.h))
    for rt in r.routes.values():
        assert all(type(v) is int for p in rt.points for v in p)


@pytest.mark.parametrize("direction", ["LR", "TB"])
def test_same_input_same_result(direction):
    nodes, edges = _tree(2)
    a = compound_layout(nodes, edges, direction)
    b = compound_layout(nodes, edges, direction)
    assert a == b
    assert list(a.boxes) == [n.id for n in nodes]
    assert list(a.routes) == [e.id for e in edges]


@pytest.mark.parametrize("direction", ["LR", "TB"])
def test_children_stay_inside_their_group(direction):
    nodes, edges = _tree(3)
    r = compound_layout(nodes, edges, direction)
    for n in nodes:
        if n.parent is None:
            continue
        c, p = r.boxes[n.id], r.boxes[n.parent]
        assert p.x <= c.x and c.x + c.w <= p.x + p.w
        assert p.y + 60 <= c.y and c.y + c.h <= p.y + p.h


def test_layout_options_default_matches_explicit():
    nodes, edges = _tree(4)
    assert compound_layout(nodes, edges, "LR") == compound_layout(
        nodes, edges, "LR", compound.LayoutOptions()
    )
