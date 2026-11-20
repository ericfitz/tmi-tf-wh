"""Tests for the compound (nested boundary) layout."""

import random
import re
from pathlib import Path

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
        ([leaf("dupnode"), leaf("dupnode")], [], "LR", "dupnode"),
        ([leaf("orphan", "nope")], [], "LR", "nope"),
        ([leaf("plainparent"), leaf("kid", "plainparent")], [], "LR", "plainparent"),
        ([group("cyc1", "cyc2"), group("cyc2", "cyc1")], [], "LR", "cyc"),
        ([group("selfloop", "selfloop")], [], "LR", "selfloop"),
        ([leaf("a")], [edge(0, "a", "ghost")], "LR", "ghost"),
        ([leaf("a")], [edge(0, "ghost", "a")], "LR", "ghost"),
        ([leaf("a")], [], "BT", "BT"),
    ],
)
def test_validation_rejects_bad_input(nodes, edges, direction, offender):
    with pytest.raises(ValueError, match=re.escape(offender)):
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


LICENSE_TAIL = """\
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
"""


@pytest.mark.parametrize(
    ("name", "source"),
    [("layered", "layered"), ("compound", "compound"), ("pack", "components")],
)
def test_pele_mit_header_is_complete(name, source):
    path = Path(compound.__file__).with_name(f"{name}.py")
    text = path.read_text()
    assert text.startswith(
        "# Portions of this file are a Python port of Pele "
        "(https://github.com/obsidianmd/pele),\n"
        f"# src/layout/{source}.ts, commit 3a2f075, used under the MIT License:\n"
        "#\n# Copyright (c) 2026 kepano\n"
    )
    assert LICENSE_TAIL in text


def test_edgeless_children_form_a_grid_block():
    nodes = [group("g")] + [leaf(f"l{i}", "g") for i in range(9)]
    for d in ("LR", "TB"):
        g = compound_layout(nodes, [], d).boxes["g"]
        assert (g.w, g.h) == (500, 350)  # 3x3 grid 440x260 plus padding


def test_disconnected_parts_are_shelf_packed():
    nodes = [leaf(i) for i in "abcdxyz"]
    r = compound_layout(nodes, [edge(0, "a", "b"), edge(1, "c", "d")], "LR")
    assert (r.width, r.height) == (300, 360)
    assert r.boxes["c"].y == r.boxes["a"].y + 100
    assert r.boxes["x"].y == r.boxes["a"].y + 200
    assert r.boxes["y"].x == r.boxes["x"].x + 160
    assert r.boxes["z"].y == r.boxes["x"].y + 100


def test_level_border_part_is_first_and_apart_from_packed_block():
    from tmi_tf.layout.compound import LayoutOptions, _layout_level, _Merged

    sizes = [(120, 60)] * 5
    merged = [
        _Merged(0, 1, count=1)
    ]  # children 2 and 4 form the border part; 3 is alone
    opt = LayoutOptions()
    lay = _layout_level(sizes, merged, "LR", opt, border=[2, 4])
    # border part at the origin: two nodes on one rank stacked on the cross axis
    assert lay.offsets[2][0] == lay.offsets[4][0] == 0
    assert lay.offsets[2][1] == 0 and lay.offsets[4][1] == 100
    # packed block (edge part 0-1 and lone child 3) sits below it, after the gap
    for c in (0, 1, 3):
        assert lay.offsets[c][1] >= 160 + opt.node_sep
    tb = _layout_level(sizes, merged, "TB", opt, border=[2, 4])
    assert tb.offsets[2] == (0, 0) and tb.offsets[4][0] == 160
    for c in (0, 1, 3):
        assert tb.offsets[c][0] >= 280 + opt.node_sep
    none = _layout_level(sizes, merged, "LR", opt)
    assert none.offsets[2] != (0, 0) or none.offsets[3] != (0, 0)


def test_packed_part_away_from_origin_shifts_its_bent_edge_points():
    from tmi_tf.layout.compound import LayoutOptions, _layout_level, _Merged

    opt = LayoutOptions()
    sizes = [(120, 60)] * 5
    # part 0-1 first; part 2-3-4 has the bent edge 2->4 and is packed away from the origin
    merged = [
        _Merged(0, 1, count=1),
        _Merged(2, 3, count=1),
        _Merged(3, 4, count=1),
        _Merged(2, 4, count=1),
    ]
    lay = _layout_level(sizes, merged, "LR", opt)
    alone = _layout_level(
        sizes[2:], [_Merged(0, 1, 1), _Merged(1, 2, 1), _Merged(0, 2, 1)], "LR", opt
    )
    assert lay.offsets[2] != (0, 0)
    dx = lay.offsets[2][0] - alone.offsets[0][0]
    dy = lay.offsets[2][1] - alone.offsets[0][1]
    assert alone.points[2]
    assert lay.points[3] == [(x + dx, y + dy) for x, y in alone.points[2]]


def test_border_indices_are_validated():
    from tmi_tf.layout.compound import LayoutOptions, _layout_level

    for bad in ([5], [-1], [0, 3]):
        with pytest.raises(ValueError, match=rf"border index {bad[-1]}"):
            _layout_level([(120, 60)] * 3, [], "LR", LayoutOptions(), border=bad)


def test_ports_sit_on_the_facing_borders():
    nodes = [leaf("src"), group("g"), leaf("a", "g"), leaf("b", "g"), leaf("dst")]
    r = compound_layout(nodes, [edge(0, "src", "a"), edge(1, "b", "dst")], "LR")
    g = r.boxes["g"]
    [(x_in, y_in)] = r.routes["0"].border_in
    [(x_out, y_out)] = r.routes["1"].border_out
    assert x_in == g.x and x_out == g.x + g.w
    assert g.y <= y_in <= g.y + g.h and g.y <= y_out <= g.y + g.h
    assert r.routes["0"].border_out == [] and r.routes["1"].border_in == []


def test_tb_ports_sit_on_top_and_bottom():
    nodes = [leaf("src"), group("g"), leaf("a", "g")]
    r = compound_layout(nodes, [edge(0, "src", "a")], "TB")
    assert r.routes["0"].border_in[0][1] == r.boxes["g"].y


def test_nested_groups_get_one_port_per_border():
    nodes = [group("o"), group("i", "o"), leaf("a", "i"), leaf("dst")]
    r = compound_layout(nodes, [edge(0, "a", "dst")], "LR")
    out = r.routes["0"].border_out
    assert [p[0] for p in out] == [
        r.boxes["i"].x + r.boxes["i"].w,
        r.boxes["o"].x + r.boxes["o"].w,
    ]


def test_reversed_lifted_edge_uses_the_start_side():
    nodes = [group("g1"), leaf("a", "g1"), group("g2"), leaf("b", "g2")]
    r = compound_layout(nodes, [edge(0, "a", "b"), edge(1, "b", "a")], "LR")
    back = r.routes["1"]
    assert back.reversed and back.border_out[0][0] == r.boxes["g2"].x
    assert back.border_in[0][0] == r.boxes["g1"].x + r.boxes["g1"].w


def test_ports_keep_inner_child_order():
    nodes = [leaf("s1"), leaf("s2"), group("g"), leaf("a1", "g"), leaf("a2", "g")]
    r = compound_layout(nodes, [edge(0, "s2", "a2"), edge(1, "s1", "a1")], "LR")
    assert r.routes["1"].border_in[0][1] < r.routes["0"].border_in[0][1]


def test_only_untouched_children_go_to_the_grid_block():
    nodes = [
        leaf("src"),
        group("g"),
        leaf("a", "g"),
        leaf("p", "g"),
        leaf("q", "g"),
        leaf("u", "g"),
    ]
    r = compound_layout(nodes, [edge(0, "src", "a"), edge(1, "p", "q")], "LR")
    a, p, u = (r.boxes[k] for k in "apu")
    assert p.y >= a.y + a.h + 40 and u.y >= a.y + a.h + 40


def test_port_edge_bends_pass_beside_siblings():
    nodes = [group("g"), leaf("a", "g"), leaf("b", "g"), leaf("dst")]
    r = compound_layout(nodes, [edge(0, "a", "b"), edge(1, "a", "dst")], "LR")
    g, b, out = r.boxes["g"], r.boxes["b"], r.routes["1"].border_out
    assert len(out) == 3 and out[-1][0] == g.x + g.w
    assert all(not (b.x < x < b.x + b.w and b.y < y < b.y + b.h) for x, y in out)
    assert all(g.x <= x <= g.x + g.w and g.y <= y <= g.y + g.h for x, y in out)


def test_boundary_endpoint_gets_no_port_of_its_own():
    nodes = [leaf("src"), group("o"), group("g", "o")]
    r = compound_layout(nodes, [edge(0, "src", "g")], "LR")
    assert len(r.routes["0"].border_in) == 1


def test_untouched_flows_have_no_border_points():
    r = compound_layout([leaf("a"), leaf("b")], [edge(0, "a", "b")], "LR")
    assert r.routes["0"].border_in == [] and r.routes["0"].border_out == []
