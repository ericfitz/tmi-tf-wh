"""Tests for the DFD diagram builder."""

import pytest  # pyright: ignore[reportMissingImports] # ty:ignore[unresolved-import]

from tmi_tf.diagram_builder import DFDBuilder


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
    return [c for c in cells if c.get("shape") != "edge"]


def get_edge_cells(cells: list[dict]) -> list[dict]:
    return [c for c in cells if c.get("shape") == "edge"]


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

    def test_flow_connected_peers_have_gap(self):
        """Two flow-connected leaf siblings should have at least 1 grid cell gap."""
        components = [
            make_component("t1", "Tenant", "tenant"),
            make_component("c1", "Server", "compute", parent_id="t1"),
            make_component("c2", "DB", "storage", parent_id="t1"),
            make_component("c3", "Other", "compute", parent_id="t1"),
        ]
        flows = [make_flow("f1", "c1", "c2", name="Query")]
        builder = DFDBuilder(components, flows)
        cells = builder.build_cells()

        c1_cell = get_cell(cells, "c1")
        c2_cell = get_cell(cells, "c2")

        # Calculate distance between flow-connected nodes
        gap_x = abs(c1_cell["x"] - c2_cell["x"]) - c1_cell["width"]
        gap_y = abs(c1_cell["y"] - c2_cell["y"]) - c1_cell["height"]
        max_gap = max(gap_x, gap_y)

        # Should have at least one node-size gap in one direction
        node_size = min(DFDBuilder.DEFAULT_NODE_WIDTH, DFDBuilder.DEFAULT_NODE_HEIGHT)
        assert max_gap >= node_size, (
            f"Flow-connected peers should have at least 1 grid cell gap, got {max_gap}px"
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

    def test_boundary_child_occupies_multiple_grid_cells(self):
        """An inner boundary should be larger than a leaf node peer."""
        components = [
            make_component("t1", "Outer", "tenant"),
            make_component("c1", "Leaf 1", "compute", parent_id="t1"),
            make_component("c2", "Leaf 2", "compute", parent_id="t1"),
            make_component("n1", "Inner Net", "network", parent_id="t1"),
            make_component("c3", "Inner S1", "compute", parent_id="n1"),
            make_component("c4", "Inner S2", "compute", parent_id="n1"),
            make_component("c5", "Inner DB", "storage", parent_id="n1"),
        ]
        builder = DFDBuilder(components, [])
        cells = builder.build_cells()

        n_cell = get_cell(cells, "n1")
        c1_cell = get_cell(cells, "c1")

        # Inner boundary should be significantly larger than a leaf node
        assert n_cell["width"] > c1_cell["width"]
        assert n_cell["height"] > c1_cell["height"]


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
