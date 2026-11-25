"""Tests for the DFD diagram builder."""

import itertools
import logging

import pytest  # pyright: ignore[reportMissingImports] # ty:ignore[unresolved-import]
from dfd_cases import HAND_CASES

from tmi_tf.cell_schema import CellSchemaError
from tmi_tf.diagram_builder import DFDBuilder
from tmi_tf.layout import compound, routes
from tmi_tf.layout.compound import EdgeRoute

# --- Helpers ---


def make_component(
    id: str,
    name: str,
    type: str,
    parent_id: str | None = None,
    subtype: str = "",
) -> dict:
    comp: dict = {"id": id, "name": name, "type": type, "subtype": subtype}
    if parent_id is not None:
        comp["parent_id"] = parent_id
    return comp


def make_flow(
    id: str,
    source_id: str,
    target_id: str,
    name: str = "flow",
    protocol: str | None = None,
    port: int | None = None,
    bidirectional: bool = False,
    forward_label: str | None = None,
    reverse_label: str | None = None,
) -> dict:
    flow: dict = {
        "id": id,
        "name": name,
        "source_id": source_id,
        "target_id": target_id,
        "bidirectional": bidirectional,
    }
    if protocol:
        flow["protocol"] = protocol
    if port is not None:
        flow["port"] = port
    if forward_label is not None:
        flow["forward_label"] = forward_label
    if reverse_label is not None:
        flow["reverse_label"] = reverse_label
    return flow


def find_cell_by_component_id(cells: list[dict], component_id: str) -> dict | None:
    for cell in cells:
        metadata = cell.get("data", {}).get("_metadata", [])
        for m in metadata:
            if m["key"] == "component_id" and m["value"] == component_id:
                return cell
    return None


def get_cell(cells: list[dict], component_id: str) -> dict:
    """Find cell by component ID, asserting it exists."""
    cell = find_cell_by_component_id(cells, component_id)
    assert cell is not None, f"Cell for component '{component_id}' not found"
    return cell


def get_node_cells(cells: list[dict]) -> list[dict]:
    return [c for c in cells if c.get("shape") != "flow"]


def get_edge_cells(cells: list[dict]) -> list[dict]:
    return [c for c in cells if c.get("shape") == "flow"]


def cell_bbox(cell: dict) -> tuple[int, int, int, int]:
    """Return (x, y, x+width, y+height) for a cell."""
    return (cell["x"], cell["y"], cell["x"] + cell["width"], cell["y"] + cell["height"])


def bboxes_overlap(a: dict, b: dict) -> bool:
    """Check if two cells' bounding boxes overlap (touching edges don't count)."""
    ax1, ay1, ax2, ay2 = cell_bbox(a)
    bx1, by1, bx2, by2 = cell_bbox(b)
    return ax1 < bx2 and ax2 > bx1 and ay1 < by2 and ay2 > by1


def is_inside(child: dict, parent: dict) -> bool:
    """Check if child bounding box is fully inside parent bounding box."""
    cx1, cy1, cx2, cy2 = cell_bbox(child)
    px1, py1, px2, py2 = cell_bbox(parent)
    return cx1 >= px1 and cy1 >= py1 and cx2 <= px2 and cy2 <= py2


# --- Tests: Component type support ---


class TestComponentTypes:
    """Test that each component type produces correct cell properties."""

    @pytest.mark.parametrize(
        "comp_type,expected_shape,expected_z",
        [
            ("tenant", "security-boundary", None),  # z is depth-based
            ("container", "security-boundary", None),
            ("network", "security-boundary", None),
            ("gateway", "process", 10),
            ("compute", "process", 11),
            ("service", "process", 11),
            ("storage", "store", 11),
            ("actor", "actor", 11),
        ],
    )
    def test_shape_and_zindex(
        self, comp_type: str, expected_shape: str, expected_z: int | None
    ):
        components = [make_component("c1", "Test", comp_type)]
        builder = DFDBuilder(components, [])
        cells = builder.build_cells()

        cell = get_cell(cells, "c1")
        assert cell["shape"] == expected_shape
        if expected_z is not None:
            assert cell["zIndex"] == expected_z

    @pytest.mark.parametrize(
        "comp_type",
        ["gateway", "compute", "service", "storage", "actor"],
    )
    def test_leaf_nodes_have_ports(self, comp_type: str):
        components = [make_component("c1", "Test", comp_type)]
        builder = DFDBuilder(components, [])
        cells = builder.build_cells()

        cell = get_cell(cells, "c1")
        assert "ports" in cell
        port_groups = {item["group"] for item in cell["ports"]["items"]}
        assert port_groups == {"top", "bottom", "left", "right"}

    @pytest.mark.parametrize("comp_type", ["tenant", "container", "network"])
    def test_boundary_nodes_have_no_ports(self, comp_type: str):
        components = [make_component("c1", "Test", comp_type)]
        builder = DFDBuilder(components, [])
        cells = builder.build_cells()

        cell = get_cell(cells, "c1")
        assert "ports" not in cell

    def test_no_body_attrs(self):
        """Cells should not have body color attributes (server ignores them)."""
        components = [
            make_component("c1", "Tenant", "tenant"),
            make_component("c2", "Compute", "compute", parent_id="c1"),
        ]
        builder = DFDBuilder(components, [])
        cells = builder.build_cells()

        for cell in get_node_cells(cells):
            assert "body" not in cell.get("attrs", {}), (
                f"Cell {cell['id']} should not have body attrs"
            )
            assert "text" in cell.get("attrs", {})

    def test_service_metadata(self):
        """Components in a service should have service metadata."""
        components = [
            make_component("c1", "Web Server", "compute"),
            make_component("c2", "Worker", "compute"),
            make_component("c3", "Database", "storage"),
        ]
        services = [
            {
                "name": "web-frontend",
                "compute_units": ["c1"],
                "associated_resources": ["c3"],
            }
        ]
        builder = DFDBuilder(components, [], services=services)
        cells = builder.build_cells()

        # c1 should have service metadata
        c1_cell = get_cell(cells, "c1")
        c1_meta = {m["key"]: m["value"] for m in c1_cell["data"]["_metadata"]}
        assert c1_meta["service"] == "web-frontend"

        # c3 (associated_resources) should also have service metadata
        c3_cell = get_cell(cells, "c3")
        c3_meta = {m["key"]: m["value"] for m in c3_cell["data"]["_metadata"]}
        assert c3_meta["service"] == "web-frontend"

        # c2 is not in any service, should not have service metadata
        c2_cell = get_cell(cells, "c2")
        c2_meta = {m["key"]: m["value"] for m in c2_cell["data"]["_metadata"]}
        assert "service" not in c2_meta


# --- Tests: Parent-child embedding ---


class TestParentChild:
    def test_parent_cell_reference(self):
        components = [
            make_component("t1", "Tenant", "tenant"),
            make_component("n1", "Network", "network", parent_id="t1"),
            make_component("c1", "Server", "compute", parent_id="n1"),
        ]
        builder = DFDBuilder(components, [])
        cells = builder.build_cells()

        t_cell = get_cell(cells, "t1")
        n_cell = get_cell(cells, "n1")
        c_cell = get_cell(cells, "c1")

        # Network's parent should be tenant's cell UUID
        assert n_cell.get("parent") == t_cell["id"]
        # Compute's parent should be network's cell UUID
        assert c_cell.get("parent") == n_cell["id"]
        # Tenant has no parent
        assert "parent" not in t_cell

    def test_boundary_z_index_increases_with_depth(self):
        components = [
            make_component("t1", "Tenant", "tenant"),
            make_component("n1", "VPC", "network", parent_id="t1"),
            make_component("n2", "Subnet", "network", parent_id="n1"),
        ]
        builder = DFDBuilder(components, [])
        cells = builder.build_cells()

        t_cell = get_cell(cells, "t1")
        n1_cell = get_cell(cells, "n1")
        n2_cell = get_cell(cells, "n2")

        assert t_cell["zIndex"] < n1_cell["zIndex"] < n2_cell["zIndex"]


# --- Tests: Edge creation ---


class TestEdges:
    def test_unidirectional_flow(self):
        components = [
            make_component("c1", "Server", "compute"),
            make_component("c2", "DB", "storage"),
        ]
        flows = [make_flow("f1", "c1", "c2", name="Query", protocol="TCP", port=5432)]
        builder = DFDBuilder(components, flows)
        cells = builder.build_cells()

        edges = get_edge_cells(cells)
        assert len(edges) == 1
        # Label should contain only the descriptive name
        assert edges[0]["labels"][0]["attrs"]["text"]["text"] == "Query"
        # Protocol and port should be in edge metadata
        metadata = edges[0]["data"]["_metadata"]
        meta_dict = {m["key"]: m["value"] for m in metadata}
        assert meta_dict["protocol"] == "TCP"
        assert meta_dict["port"] == "5432"

    def test_bidirectional_flow_creates_two_edges(self):
        components = [
            make_component("c1", "Client", "compute"),
            make_component("c2", "Server", "compute"),
        ]
        flows = [
            make_flow(
                "f1",
                "c1",
                "c2",
                name="API",
                bidirectional=True,
                forward_label="API Call",
                reverse_label="API Response",
            )
        ]
        builder = DFDBuilder(components, flows)
        cells = builder.build_cells()

        edges = get_edge_cells(cells)
        assert len(edges) == 2
        labels = {e["labels"][0]["attrs"]["text"]["text"] for e in edges}
        assert labels == {"API Call", "API Response"}

    def test_bidirectional_flow_falls_back_to_name(self):
        """Bidirectional flow without forward/reverse labels falls back to name."""
        components = [
            make_component("c1", "Client", "compute"),
            make_component("c2", "Server", "compute"),
        ]
        flows = [make_flow("f1", "c1", "c2", name="API", bidirectional=True)]
        builder = DFDBuilder(components, flows)
        cells = builder.build_cells()

        edges = get_edge_cells(cells)
        assert len(edges) == 2
        labels = [e["labels"][0]["attrs"]["text"]["text"] for e in edges]
        assert all(label == "API" for label in labels)

    def test_missing_endpoint_skips_edge(self):
        components = [make_component("c1", "Server", "compute")]
        flows = [make_flow("f1", "c1", "missing", name="Bad")]
        builder = DFDBuilder(components, flows)
        cells = builder.build_cells()

        edges = get_edge_cells(cells)
        assert len(edges) == 0


# --- Tests: Layout ---


class TestLayout:
    def test_leaf_only_parent_children_inside(self):
        """Boundary with leaf children: all children positioned within parent."""
        components = [
            make_component("t1", "Tenant", "tenant"),
            make_component("c1", "Server 1", "compute", parent_id="t1"),
            make_component("c2", "Server 2", "compute", parent_id="t1"),
            make_component("c3", "DB", "storage", parent_id="t1"),
        ]
        builder = DFDBuilder(components, [])
        cells = builder.build_cells()

        t_cell = get_cell(cells, "t1")
        for cid in ["c1", "c2", "c3"]:
            child_cell = get_cell(cells, cid)
            assert is_inside(child_cell, t_cell), f"Child {cid} should be inside parent"

    def test_no_sibling_overlap(self):
        """Sibling nodes should not overlap each other."""
        components = [
            make_component("t1", "Tenant", "tenant"),
            make_component("c1", "S1", "compute", parent_id="t1"),
            make_component("c2", "S2", "compute", parent_id="t1"),
            make_component("c3", "S3", "compute", parent_id="t1"),
            make_component("c4", "S4", "compute", parent_id="t1"),
            make_component("c5", "DB", "storage", parent_id="t1"),
        ]
        builder = DFDBuilder(components, [])
        cells = builder.build_cells()

        siblings = [get_cell(cells, f"c{i}") for i in range(1, 6)]
        for i, a in enumerate(siblings):
            for b in siblings[i + 1 :]:
                assert not bboxes_overlap(a, b), "Siblings should not overlap"

    def test_mixed_children_all_inside_parent(self):
        """Boundary with both leaf and boundary children: all fit inside parent."""
        components = [
            make_component("t1", "Tenant", "tenant"),
            make_component("c1", "Server", "compute", parent_id="t1"),
            make_component("c2", "GW", "gateway", parent_id="t1"),
            make_component("n1", "Subnet", "network", parent_id="t1"),
            make_component("c3", "Inner Server", "compute", parent_id="n1"),
            make_component("c4", "Inner DB", "storage", parent_id="n1"),
        ]
        builder = DFDBuilder(components, [])
        cells = builder.build_cells()

        t_cell = get_cell(cells, "t1")
        for cid in ["c1", "c2", "n1"]:
            child_cell = get_cell(cells, cid)
            assert is_inside(child_cell, t_cell), f"Child {cid} should be inside tenant"

        # Inner children should be inside network
        n_cell = get_cell(cells, "n1")
        for cid in ["c3", "c4"]:
            child_cell = get_cell(cells, cid)
            assert is_inside(child_cell, n_cell), (
                f"Child {cid} should be inside network"
            )

    def test_deep_nesting_sizes_correctly(self):
        """3-level hierarchy: sizes grow from inside out."""
        components = [
            make_component("t1", "Tenant", "tenant"),
            make_component("n1", "VPC", "network", parent_id="t1"),
            make_component("c1", "Server", "compute", parent_id="n1"),
        ]
        builder = DFDBuilder(components, [])
        cells = builder.build_cells()

        t_cell = get_cell(cells, "t1")
        n_cell = get_cell(cells, "n1")
        c_cell = get_cell(cells, "c1")

        # Compute is smallest
        assert c_cell["width"] == DFDBuilder.DEFAULT_NODE_WIDTH
        assert c_cell["height"] == DFDBuilder.DEFAULT_NODE_HEIGHT

        # Network contains compute, so must be larger
        assert n_cell["width"] > c_cell["width"]
        assert n_cell["height"] > c_cell["height"]

        # Tenant contains network, so must be largest
        assert t_cell["width"] > n_cell["width"]
        assert t_cell["height"] > n_cell["height"]

    def test_multiple_roots_no_overlap(self):
        """Two root-level boundaries should not overlap."""
        components = [
            make_component("t1", "Tenant 1", "tenant"),
            make_component("c1", "S1", "compute", parent_id="t1"),
            make_component("t2", "Tenant 2", "tenant"),
            make_component("c2", "S2", "compute", parent_id="t2"),
        ]
        builder = DFDBuilder(components, [])
        cells = builder.build_cells()

        t1_cell = get_cell(cells, "t1")
        t2_cell = get_cell(cells, "t2")

        assert not bboxes_overlap(t1_cell, t2_cell), (
            "Root boundaries should not overlap"
        )

    def test_service_in_layout(self):
        """Service components participate in layout as leaf nodes."""
        components = [
            make_component("t1", "Tenant", "tenant"),
            make_component("s1", "API Service", "service", parent_id="t1"),
            make_component("c1", "Worker", "compute", parent_id="t1"),
        ]
        builder = DFDBuilder(components, [])
        cells = builder.build_cells()

        t_cell = get_cell(cells, "t1")
        s_cell = get_cell(cells, "s1")
        c_cell = get_cell(cells, "c1")

        # Service should be a leaf node with standard size
        assert s_cell["width"] == DFDBuilder.DEFAULT_NODE_WIDTH
        assert s_cell["height"] == DFDBuilder.DEFAULT_NODE_HEIGHT

        # Both should be inside tenant
        assert is_inside(s_cell, t_cell)
        assert is_inside(c_cell, t_cell)

        # Should not overlap
        assert not bboxes_overlap(s_cell, c_cell)

    def test_childless_boundary_has_minimum_size(self):
        """A boundary with no children should still have a valid size."""
        components = [make_component("t1", "Empty Tenant", "tenant")]
        builder = DFDBuilder(components, [])
        cells = builder.build_cells()

        t_cell = get_cell(cells, "t1")
        assert t_cell["width"] >= DFDBuilder.MIN_WIDTH
        assert t_cell["height"] >= DFDBuilder.MIN_HEIGHT


class TestNetworkAccessControlRemoval:
    """network_access_control components should be skipped with a warning."""

    def test_nac_component_skipped(self):
        """A network_access_control component should not produce a cell."""
        components = [
            make_component("t1", "Tenant", "tenant"),
            make_component("nac1", "Web SG", "network_access_control", parent_id="t1"),
            make_component("c1", "Server", "compute", parent_id="t1"),
        ]
        builder = DFDBuilder(components, [])
        cells = builder.build_cells()

        # NAC should not have a cell
        assert find_cell_by_component_id(cells, "nac1") is None
        # Other components should still have cells
        assert find_cell_by_component_id(cells, "t1") is not None
        assert find_cell_by_component_id(cells, "c1") is not None

    def test_nac_component_skipped_no_edge_created(self):
        """Flows referencing a skipped NAC component should be dropped."""
        components = [
            make_component("t1", "Tenant", "tenant"),
            make_component("nac1", "Web SG", "network_access_control", parent_id="t1"),
            make_component("c1", "Server", "compute", parent_id="t1"),
            make_component("c2", "DB", "storage", parent_id="t1"),
        ]
        flows = [
            make_flow("f1", "c1", "nac1", name="To SG"),
            make_flow("f2", "nac1", "c2", name="From SG"),
            make_flow("f3", "c1", "c2", name="Direct"),
        ]
        builder = DFDBuilder(components, flows)
        cells = builder.build_cells()

        edges = get_edge_cells(cells)
        # Only the direct flow should produce an edge
        assert len(edges) == 1
        assert edges[0]["labels"][0]["attrs"]["text"]["text"] == "Direct"


def ports(edge: dict) -> tuple:
    return (edge["source"].get("port"), edge["target"].get("port"))


class TestLayeredLayout:
    def test_flow_runs_left_to_right_by_default(self):
        comps = [
            make_component("t1", "T", "tenant"),
            make_component("c1", "A", "compute", "t1"),
            make_component("c2", "B", "storage", "t1"),
            make_component("c3", "C", "compute", "t1"),
        ]
        cells = DFDBuilder(comps, [make_flow("f1", "c1", "c2")]).build_cells()
        c1, c2 = get_cell(cells, "c1"), get_cell(cells, "c2")
        assert c2["x"] >= c1["x"] + c1["width"] + 60
        assert ports(get_edge_cells(cells)[0]) == ("right", "left")

    def test_top_to_bottom_when_direction_is_tb(self, monkeypatch):
        monkeypatch.setattr(compound, "LAYOUT_DIRECTION", "TB")
        comps = [
            make_component("c1", "A", "compute"),
            make_component("c2", "B", "storage"),
        ]
        cells = DFDBuilder(comps, [make_flow("f1", "c1", "c2")]).build_cells()
        assert get_cell(cells, "c2")["y"] >= get_cell(cells, "c1")["y"] + 60 + 60
        assert ports(get_edge_cells(cells)[0]) == ("bottom", "top")

    def test_back_edge_and_reverse_cell_swap_sides(self):
        comps = [
            make_component("c1", "A", "compute"),
            make_component("c2", "B", "compute"),
        ]
        cells = DFDBuilder(
            comps, [make_flow("f1", "c1", "c2"), make_flow("f2", "c2", "c1")]
        ).build_cells()
        assert [ports(e) for e in get_edge_cells(cells)] == [
            ("right", "left"),
            ("left", "right"),
        ]
        cells = DFDBuilder(
            comps, [make_flow("f1", "c1", "c2", bidirectional=True)]
        ).build_cells()
        assert [ports(e) for e in get_edge_cells(cells)] == [
            ("right", "left"),
            ("left", "right"),
        ]

    def test_inner_boundary_wraps_its_children(self):
        comps = [
            make_component("t1", "Outer", "tenant"),
            make_component("c1", "L1", "compute", "t1"),
            make_component("n1", "Inner", "network", "t1"),
        ]
        comps += [make_component(c, c, "compute", "n1") for c in ("c3", "c4", "c5")]
        cells = DFDBuilder(comps, []).build_cells()
        n = get_cell(cells, "n1")
        assert all(is_inside(get_cell(cells, c), n) for c in ["c3", "c4", "c5"])
        assert n["width"] > 120 and n["height"] > 60

    def test_sibling_order_sets_cross_axis_order(self):
        a = {**make_component("a", "A", "compute"), "sibling_order": 1}
        b = {**make_component("b", "B", "compute"), "sibling_order": 0}
        cells = DFDBuilder([a, b], []).build_cells()
        assert (
            get_cell(cells, "b")["y"] < get_cell(cells, "a")["y"]
            or get_cell(cells, "b")["x"] < get_cell(cells, "a")["x"]
        )


def build_edges(specs):
    """Edge cells for two root computes c1, c2 and flows given as (source, target[, bidirectional])."""
    comps = [
        make_component("c1", "A", "compute"),
        make_component("c2", "B", "compute"),
    ]
    flows = [
        make_flow(f"f{i}", s[0], s[1], bidirectional=len(s) > 2 and s[2])
        for i, s in enumerate(specs)
    ]
    return get_edge_cells(DFDBuilder(comps, flows).build_cells())


class TestEdgeGeometry:
    def test_single_short_edge_is_smooth_without_vertices(self):
        e = build_edges([("c1", "c2")])[0]
        assert "vertices" not in e and e["connector"] == {"name": "smooth"}
        assert "position" not in e["labels"][0] and e["router"] == {"name": "normal"}

    def test_bidirectional_pair_is_fanned(self):
        fwd, rev = build_edges([("c1", "c2", True)])
        (v1,), (v2,) = fwd["vertices"], rev["vertices"]
        assert v1["x"] == v2["x"] and v2["y"] - v1["y"] == 20
        assert [e["labels"][0]["position"] for e in (fwd, rev)] == [0.35, 0.35]
        assert fwd["connector"] == rev["connector"] == {"name": "rounded"}

    def test_bidirectional_halves_get_different_label_points(self):
        fwd, rev = build_edges([("c1", "c2", True)])
        # rev runs c2 -> c1, so its position is measured from c2; convert to c1.
        absolute_fwd = fwd["labels"][0]["position"]
        absolute_rev = 1 - rev["labels"][0]["position"]
        assert absolute_fwd != absolute_rev

    def test_opposite_direction_cells_use_complement_position(self):
        edges = build_edges([("c1", "c2"), ("c2", "c1")])
        assert [e["labels"][0]["position"] for e in edges] == [0.35, 0.35]

    def test_three_cells_on_one_pair_share_a_fan(self):
        edges = build_edges([("c1", "c2"), ("c2", "c1"), ("c1", "c2")])
        ys = [e["vertices"][0]["y"] for e in edges]
        assert ys[1] - ys[0] == 20 and ys[2] - ys[1] == 20
        assert [e["labels"][0]["position"] for e in edges] == [0.35, 0.5, 0.65]

    def test_long_edge_does_not_cross_the_node_it_skips(self):
        comps = [make_component(c, c, "compute") for c in ("a", "b", "c")]
        flows = [
            make_flow("f1", "a", "b"),
            make_flow("f2", "b", "c"),
            make_flow("f3", "a", "c"),
        ]
        cells = DFDBuilder(comps, flows).build_cells()
        a, b, c = (get_cell(cells, k) for k in "abc")
        skip = get_edge_cells(cells)[2]
        pts = [(a["x"] + a["width"], a["y"] + a["height"] / 2)]  # port "right"
        pts += [(v["x"], v["y"]) for v in skip.get("vertices", [])]
        pts.append((c["x"], c["y"] + c["height"] / 2))  # port "left"
        for (x1, y1), (x2, y2) in itertools.pairwise(pts):
            for t in range(101):
                x, y = x1 + (x2 - x1) * t / 100, y1 + (y2 - y1) * t / 100
                assert not (
                    b["x"] < x < b["x"] + b["width"]
                    and b["y"] < y < b["y"] + b["height"]
                )

    @pytest.mark.parametrize("name", list(HAND_CASES))
    def test_connector_matches_vertices(self, name):
        comps, flows = HAND_CASES[name]
        for e in get_edge_cells(DFDBuilder(comps, flows).build_cells()):
            expected = "rounded" if "vertices" in e else "smooth"
            assert e["connector"] == {"name": expected}

    def test_route_points_respects_border_flag(self, monkeypatch):
        builder = DFDBuilder([], [])
        route = EdgeRoute(
            lifted=True, points=[(5, 5)], border_out=[(1, 1)], border_in=[(9, 9)]
        )
        monkeypatch.setattr(compound, "EMIT_BORDER_VERTICES", False)
        assert builder._route_points(route, True) == [(5, 5)]
        monkeypatch.setattr(compound, "EMIT_BORDER_VERTICES", True)
        assert builder._route_points(route, True) == [(1, 1), (5, 5), (9, 9)]
        assert builder._route_points(route, False) == [(9, 9), (5, 5), (1, 1)]
        assert builder._route_points(EdgeRoute(), True) == []

    def test_self_and_ancestor_flows_get_no_vertices(self):
        comps = [make_component("c1", "A", "compute")]
        flows = [make_flow("f1", "c1", "c1"), make_flow("f2", "c1", "c1")]
        edges = get_edge_cells(DFDBuilder(comps, flows).build_cells())
        assert len(edges) == 2 and all("vertices" not in e for e in edges)
        assert [e["labels"][0]["position"] for e in edges] == [0.35, 0.65]

    def test_too_many_vertices_are_dropped_with_warning(self, monkeypatch, caplog):
        monkeypatch.setattr(routes, "MAX_VERTICES", 0)
        with caplog.at_level(logging.WARNING):
            edges = build_edges([("c1", "c2", True)])
        assert all("vertices" not in e for e in edges)
        assert all(e["connector"] == {"name": "smooth"} for e in edges)
        msgs = [r.getMessage() for r in caplog.records if "vertices" in r.getMessage()]
        assert len(msgs) == 2
        assert all("f0" in m and "c1" in m and "c2" in m for m in msgs)

    def test_fan_shifts_along_y_in_lr_and_x_in_tb(self, monkeypatch):
        monkeypatch.setattr(compound, "LAYOUT_DIRECTION", "TB")
        fwd, rev = build_edges([("c1", "c2", True)])
        (v1,), (v2,) = fwd["vertices"], rev["vertices"]
        assert v1["y"] == v2["y"] and v2["x"] - v1["x"] == 20


class TestRejection:
    def test_unknown_type_skipped_with_warning(self, caplog):
        caplog.set_level(logging.WARNING)
        comps = [
            make_component("x1", "X", "lambda"),
            make_component("c1", "A", "compute"),
        ]
        cells = DFDBuilder(comps, []).build_cells()
        assert find_cell_by_component_id(cells, "x1") is None
        assert find_cell_by_component_id(cells, "c1") is not None
        assert "x1" in caplog.text

    def test_duplicate_id_skipped_with_warning(self, caplog):
        caplog.set_level(logging.WARNING)
        comps = [
            make_component("c1", "First", "compute"),
            make_component("c1", "Second", "storage"),
        ]
        cells = DFDBuilder(comps, []).build_cells()
        assert len(get_node_cells(cells)) == 1
        assert get_cell(cells, "c1")["attrs"]["text"]["text"] == "First"
        assert "c1" in caplog.text

    def test_empty_input_returns_no_cells(self):
        assert DFDBuilder([], []).build_cells() == []
        assert DFDBuilder([], [make_flow("f1", "a", "b")]).build_cells() == []

    def test_missing_parent_becomes_root(self, caplog):
        caplog.set_level(logging.WARNING)
        cells = DFDBuilder(
            [make_component("c1", "A", "compute", "nope")], []
        ).build_cells()
        assert "parent" not in get_cell(cells, "c1")
        assert "c1" in caplog.text

    def test_leaf_or_skipped_parent_becomes_root(self):
        comps = [
            make_component("p1", "P", "compute"),
            make_component("nac", "N", "network_access_control"),
            make_component("a", "A", "compute", "p1"),
            make_component("b", "B", "compute", "nac"),
        ]
        cells = DFDBuilder(comps, []).build_cells()
        assert "parent" not in get_cell(cells, "a")
        assert "parent" not in get_cell(cells, "b")

    def test_self_parent_becomes_root(self):
        cells = DFDBuilder(
            [make_component("n1", "N", "network", "n1")], []
        ).build_cells()
        assert "parent" not in get_cell(cells, "n1")

    def test_parent_cycle_becomes_root(self, caplog):
        caplog.set_level(logging.WARNING)
        comps = [
            make_component("n1", "N1", "network", "n2"),
            make_component("n2", "N2", "network", "n1"),
        ]
        cells = DFDBuilder(comps, []).build_cells()
        n1, n2 = get_cell(cells, "n1"), get_cell(cells, "n2")
        assert "parent" not in n1
        assert n2["parent"] == n1["id"]
        assert len([r for r in caplog.records if r.levelno == logging.WARNING]) == 1

    def test_bad_sibling_order_falls_back_to_input_order(self):
        orders = ["2", None, True, 1, 1]
        comps = [
            {**make_component(f"c{i}", f"C{i}", "compute"), "sibling_order": o}
            for i, o in enumerate(orders)
        ]
        cells = DFDBuilder(comps, []).build_cells()
        assert len(get_node_cells(cells)) == 5

    def test_ancestor_and_self_flows_still_get_cells(self):
        comps = [
            make_component("t1", "T", "tenant"),
            make_component("c1", "A", "compute", "t1"),
        ]
        flows = [
            make_flow("f1", "t1", "c1"),
            make_flow("f2", "c1", "t1"),
            make_flow("f3", "c1", "c1"),
        ]
        edges = get_edge_cells(DFDBuilder(comps, flows).build_cells())
        assert len(edges) == 3
        assert ports(edges[0]) == (None, "left")
        assert ports(edges[1]) == ("right", None)
        assert ports(edges[2]) == ("right", "left")


class TestMalformedFlows:
    @staticmethod
    def edges(flows, caplog=None):
        comps = [
            make_component("c1", "A", "compute"),
            make_component("c2", "B", "compute"),
        ]
        return get_edge_cells(DFDBuilder(comps, flows).build_cells())

    @pytest.mark.parametrize(
        "bad",
        [
            {"id": "x", "name": "n", "target_id": "c2"},
            {"id": "x", "name": "n", "source_id": "c1"},
            {"id": "x", "name": "n", "source_id": None, "target_id": "c2"},
            {"id": "x", "name": "n", "source_id": "c1", "target_id": 7},
            {"id": "x", "name": "n", "source_id": ["c1"], "target_id": "c2"},
            "not a dict",
        ],
    )
    def test_flow_without_str_endpoints_is_skipped(self, bad, caplog):
        good = make_flow("ok", "c1", "c2")
        with caplog.at_level(logging.WARNING):
            edges = self.edges([bad, good])
        assert len(edges) == 1
        assert any("Skipping flow" in r.getMessage() for r in caplog.records)

    def test_missing_name_uses_empty_label(self):
        flow = {"id": "f", "source_id": "c1", "target_id": "c2"}
        (edge,) = self.edges([flow])
        assert edge["labels"][0]["attrs"]["text"]["text"] == ""

    def test_non_str_name_uses_empty_label(self):
        flow = {"id": "f", "name": 5, "source_id": "c1", "target_id": "c2"}
        (edge,) = self.edges([flow])
        assert edge["labels"][0]["attrs"]["text"]["text"] == ""

    @pytest.mark.parametrize("value", ["yes", 1, None, "true"])
    def test_non_bool_bidirectional_is_false(self, value, caplog):
        flow = make_flow("f", "c1", "c2")
        flow["bidirectional"] = value
        with caplog.at_level(logging.WARNING):
            edges = self.edges([flow])
        assert len(edges) == 1
        assert any("bidirectional" in r.getMessage() for r in caplog.records)

    def test_caller_flows_are_not_mutated(self):
        flow = make_flow("f", "c1", "c2")
        flow["bidirectional"] = "yes"
        self.edges([flow])
        assert flow["bidirectional"] == "yes"


class TestTmiMetadataConformance:
    """Generated cells must satisfy TMI's Metadata schema (#107): TMI accepts
    an empty value on create but rejects the same cells on a later PATCH."""

    @staticmethod
    def _metadata(cell: dict) -> dict[str, str]:
        return {m["key"]: m["value"] for m in cell["data"]["_metadata"]}

    def _edge_metadata(self, **flow_fields) -> dict[str, str]:
        components = [
            make_component("a", "A", "compute"),
            make_component("b", "B", "storage"),
        ]
        flow = make_flow("f1", "a", "b", protocol="internal")
        flow.update(flow_fields)
        [edge] = get_edge_cells(DFDBuilder(components, [flow]).build_cells())
        return self._metadata(edge)

    @pytest.mark.parametrize("port", ["", "   ", None])
    def test_unknown_port_is_omitted(self, port):
        md = self._edge_metadata(port=port)
        assert "port" not in md
        assert md["protocol"] == "internal"

    def test_known_port_is_kept(self):
        assert self._edge_metadata(port=443)["port"] == "443"

    def test_empty_data_type_is_omitted(self):
        assert "data_type" not in self._edge_metadata(data_type="")

    def _node_metadata(self, **component_fields) -> dict[str, str]:
        component = make_component("a", "A", "compute")
        component.update(component_fields)
        cells = DFDBuilder([component], []).build_cells()
        return self._metadata(get_cell(cells, "a"))

    def test_empty_subtype_is_omitted(self):
        md = self._node_metadata(subtype="")
        assert "component_subtype" not in md
        assert md["component_type"] == "compute"

    def test_llm_metadata_is_cleaned(self):
        md = self._node_metadata(
            metadata={
                "region": "us-east-1",
                "cidr": "",
                "bad key": "x",
                "notes": "n" * 3000,
                "count": 0,
            }
        )
        assert md["region"] == "us-east-1"
        assert md["count"] == "0"
        assert "cidr" not in md
        assert "bad key" not in md
        assert len(md["notes"]) == 1024

    def test_every_metadata_value_is_non_empty(self):
        for name, (components, flows) in HAND_CASES.items():
            for cell in DFDBuilder(components, flows).build_cells():
                for entry in cell.get("data", {}).get("_metadata", []):
                    assert entry["value"].strip(), (name, entry["key"])

    def test_target_marker_uses_schema_keys(self):
        components = [
            make_component("a", "A", "compute"),
            make_component("b", "B", "storage"),
        ]
        [edge] = get_edge_cells(
            DFDBuilder(components, [make_flow("f1", "a", "b")]).build_cells()
        )
        assert edge["attrs"]["line"]["targetMarker"] == {"name": "classic", "size": 8}

    def test_hostile_label_text_is_normalized(self):
        """Names and labels are LLM text: control characters and length must
        fit TMI's label schema, or the whole DFD would now be rejected."""
        nasty = "Ünï\tname\nline2 " * 30 + "\x07"
        components = [
            make_component("a", nasty, "compute"),
            make_component("b", "B", "storage"),
        ]
        flows = [
            make_flow("f1", "a", "b", name=nasty),
            make_flow(
                "f2",
                "b",
                "a",
                bidirectional=True,
                forward_label=nasty,
                reverse_label="",
            ),
        ]
        cells = DFDBuilder(components, flows).build_cells()
        texts = [get_cell(cells, "a")["attrs"]["text"]["text"]] + [
            label["attrs"]["text"]["text"]
            for edge in get_edge_cells(cells)
            for label in edge["labels"]
        ]
        for text in texts:
            assert len(text) <= 256
            assert not any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text)
        assert texts[0].startswith("Ünï name line2")
        # An empty explicit label falls back to the flow name.
        assert "flow" in texts

    def test_build_cells_rejects_non_conforming_output(self, monkeypatch):
        """build_cells is the gate: a builder regression that emits an empty
        metadata value raises instead of reaching TMI."""
        monkeypatch.setattr(
            DFDBuilder,
            "_build_edge_metadata",
            lambda self, flow: [{"key": "port", "value": ""}],
        )
        components = [
            make_component("a", "A", "compute"),
            make_component("b", "B", "storage"),
        ]
        with pytest.raises(CellSchemaError):
            DFDBuilder(components, [make_flow("f1", "a", "b")]).build_cells()
