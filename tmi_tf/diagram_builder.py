"""
Data Flow Diagram Builder for TMI.

This module converts structured component and flow data into AntV X6 v2 format
cells for creating diagrams in TMI.
"""

import uuid
from math import ceil, sqrt
from typing import Any, Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class DFDBuilder:
    """Builds Data Flow Diagram cells from structured component and flow data."""

    # Component type categories for layout
    BOUNDARY_TYPES = {"tenant", "container", "network"}
    LEAF_TYPES = {
        "gateway",
        "compute",
        "service",
        "storage",
        "actor",
        "network_access_control",
    }

    # Shape mapping from component types to X6 shapes
    SHAPE_MAP = {
        "tenant": "security-boundary",
        "container": "security-boundary",
        "network": "security-boundary",
        "gateway": "process",
        "compute": "process",
        "service": "process",
        "network_access_control": "process",
        "storage": "store",
        "actor": "actor",
    }

    # Z-index ranges for different element types
    Z_INDEX = {
        "boundary_base": 1,
        "boundary_increment": 1,
        "gateway": 10,
        "compute": 11,
        "service": 11,
        "network_access_control": 11,
        "storage": 11,
        "actor": 11,
        "edge": 20,
    }

    # Minimum dimensions per OpenAPI spec
    MIN_WIDTH = 40
    MIN_HEIGHT = 30

    # Layout constants
    BOUNDARY_PADDING = 50
    NODE_SPACING = 30
    DEFAULT_NODE_WIDTH = 120
    DEFAULT_NODE_HEIGHT = 60
    DEFAULT_BOUNDARY_WIDTH = 800
    DEFAULT_BOUNDARY_HEIGHT = 600

    def __init__(
        self,
        components: List[Dict[str, Any]],
        flows: List[Dict[str, Any]],
        services: Optional[List[Dict[str, Any]]] = None,
    ):
        """
        Initialize the DFD builder.

        Args:
            components: List of component dictionaries with id, name, type, parent_id, etc.
            flows: List of flow dictionaries with source_id, target_id, protocol, etc.
            services: Optional list of service dicts from inventory (with name,
                      compute_units, associated_resources). Used to tag component
                      cells with their service membership.
        """
        self.components = components
        self.flows = flows
        self.cells: List[Dict[str, Any]] = []
        self.component_cells: Dict[str, Dict[str, Any]] = {}  # id -> cell mapping
        # Build component_id -> service_name lookup from inventory services
        self._service_lookup: Dict[str, str] = {}
        if services:
            for svc in services:
                svc_name = svc.get("name", "")
                if not svc_name:
                    continue
                for comp_id in svc.get("compute_units", []):
                    self._service_lookup[comp_id] = svc_name
                for comp_id in svc.get("associated_resources", []):
                    self._service_lookup[comp_id] = svc_name

    def build_cells(self) -> List[Dict[str, Any]]:
        """
        Build all diagram cells.

        Returns:
            List of AntV X6 v2 format cell objects
        """
        logger.info(
            "Building DFD cells from %d components and %d flows",
            len(self.components),
            len(self.flows),
        )

        # Step 1: Create all node cells
        self._create_boundary_cells()
        self._create_node_cells()

        # Step 2: Layout nodes
        self._auto_layout()

        # Step 3: Create edge cells for flows
        self._create_edge_cells()

        logger.info("Generated %d total cells", len(self.cells))
        return self.cells

    def _create_boundary_cells(self):
        """Create security boundary cells for tenant, container, and network components."""
        boundaries = [c for c in self.components if c["type"] in self.BOUNDARY_TYPES]

        # Sort by hierarchy depth (tenant first, then container, then network)
        boundaries.sort(key=lambda c: self._get_depth(c["id"]))

        for component in boundaries:
            z_index = self._calculate_boundary_z_index(component)
            cell = self._create_node_cell(component, z_index)
            self.cells.append(cell)
            self.component_cells[component["id"]] = cell

    def _create_node_cells(self):
        """Create node cells for gateway, compute, service, storage, and actor components."""
        nodes = [c for c in self.components if c["type"] in self.LEAF_TYPES]

        for component in nodes:
            z_index = self.Z_INDEX.get(component["type"], 11)
            cell = self._create_node_cell(component, z_index)

            # Add ports for all connectable leaf nodes
            cell["ports"] = self._create_ports()

            self.cells.append(cell)
            self.component_cells[component["id"]] = cell

    def _create_node_cell(
        self, component: Dict[str, Any], z_index: int
    ) -> Dict[str, Any]:
        """
        Create a single node cell.

        Args:
            component: Component data dictionary
            z_index: Z-index for rendering order

        Returns:
            Node cell in X6 format
        """
        cell_id = str(uuid.uuid4())
        shape = self.SHAPE_MAP.get(component["type"], "process")

        # Determine if this is a boundary (needs larger default size)
        is_boundary = component["type"] in self.BOUNDARY_TYPES
        width = self.DEFAULT_BOUNDARY_WIDTH if is_boundary else self.DEFAULT_NODE_WIDTH
        height = (
            self.DEFAULT_BOUNDARY_HEIGHT if is_boundary else self.DEFAULT_NODE_HEIGHT
        )

        cell = {
            "id": cell_id,
            "shape": shape,
            "x": 0,  # Will be set by layout algorithm
            "y": 0,  # Will be set by layout algorithm
            "width": width,
            "height": height,
            "zIndex": z_index,
            "attrs": {
                "text": {"text": component["name"]},
            },
            "data": {
                "_metadata": self._build_node_metadata(component),
            },
        }

        # Set parent relationship for nested components
        if component.get("parent_id"):
            parent_cell = self.component_cells.get(component["parent_id"])
            if parent_cell:
                cell["parent"] = parent_cell["id"]

        return cell

    def _build_node_metadata(self, component: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Build metadata list for a node cell from component data.

        Includes core fields (id, type, subtype, description) plus any
        additional properties from the LLM-generated metadata dict.

        Args:
            component: Component data dictionary

        Returns:
            List of metadata key-value dicts
        """
        metadata = [
            {"key": "component_id", "value": component["id"]},
            {"key": "component_type", "value": component["type"]},
            {"key": "component_subtype", "value": component.get("subtype", "")},
        ]

        if component.get("description"):
            metadata.append({"key": "description", "value": component["description"]})

        # Tag with service membership if component belongs to a service
        service_name = self._service_lookup.get(component["id"])
        if service_name:
            metadata.append({"key": "service", "value": service_name})

        # Include LLM-generated metadata properties (region, cidr, etc.)
        llm_metadata = component.get("metadata")
        if isinstance(llm_metadata, dict):
            for key, value in llm_metadata.items():
                if value is not None:
                    metadata.append({"key": key, "value": str(value)})

        return metadata

    def _build_edge_metadata(self, flow: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Build metadata list for an edge cell from flow data.

        Args:
            flow: Flow data dictionary

        Returns:
            List of metadata key-value dicts
        """
        metadata = []
        if flow.get("protocol"):
            metadata.append({"key": "protocol", "value": flow["protocol"]})
        if flow.get("port") is not None:
            metadata.append({"key": "port", "value": str(flow["port"])})
        if flow.get("data_type"):
            metadata.append({"key": "data_type", "value": flow["data_type"]})
        return metadata

    def _create_edge_cells(self):
        """Create edge cells for data flows."""
        for flow in self.flows:
            # Create edges (two if bidirectional)
            edges_to_create = []

            if flow.get("bidirectional", False):
                # Create two edges for bidirectional flow using directional labels
                forward_label = flow.get("forward_label", flow["name"])
                reverse_label = flow.get("reverse_label", flow["name"])
                edges_to_create.append(
                    {
                        "source_id": flow["source_id"],
                        "target_id": flow["target_id"],
                        "label": forward_label,
                    }
                )
                edges_to_create.append(
                    {
                        "source_id": flow["target_id"],
                        "target_id": flow["source_id"],
                        "label": reverse_label,
                    }
                )
            else:
                # Single unidirectional edge
                edges_to_create.append(
                    {
                        "source_id": flow["source_id"],
                        "target_id": flow["target_id"],
                        "label": flow["name"],
                    }
                )

            for edge_data in edges_to_create:
                edge = self._create_edge_cell(edge_data, flow)
                if edge:
                    self.cells.append(edge)

    def _create_edge_cell(
        self, edge_data: Dict[str, str], flow: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Create a single edge cell.

        Args:
            edge_data: Dictionary with source_id, target_id, label
            flow: Original flow data with protocol, port, etc.

        Returns:
            Edge cell in X6 format, or None if source/target not found
        """
        source_cell = self.component_cells.get(edge_data["source_id"])
        target_cell = self.component_cells.get(edge_data["target_id"])

        if not source_cell or not target_cell:
            logger.warning(
                "Skipping flow %s: source or target component not found",
                flow.get("id", "unknown"),
            )
            return None

        cell_id = str(uuid.uuid4())

        # Determine source and target ports based on node positions
        source_port = self._get_optimal_port(source_cell, target_cell, is_source=True)
        target_port = self._get_optimal_port(target_cell, source_cell, is_source=False)

        # Use descriptive name only as label; details go in metadata
        label_text = edge_data["label"]

        # Build source and target dicts with optional port
        source_dict: dict[str, str] = {"cell": source_cell["id"]}
        target_dict: dict[str, str] = {"cell": target_cell["id"]}

        if source_port:
            source_dict["port"] = source_port
        if target_port:
            target_dict["port"] = target_port

        edge: Dict[str, Any] = {
            "id": cell_id,
            "shape": "edge",
            "source": source_dict,
            "target": target_dict,
            "zIndex": self.Z_INDEX["edge"],
            "attrs": {
                "line": {
                    "stroke": "#333333",
                    "strokeWidth": 2,
                    "targetMarker": {"name": "block", "width": 12, "height": 8},
                }
            },
            "labels": [{"attrs": {"text": {"text": label_text}}}],
            "router": {"name": "normal"},
            "connector": {"name": "smooth"},
        }

        # Add protocol, port, data_type as edge metadata
        edge_metadata = self._build_edge_metadata(flow)
        if edge_metadata:
            edge["data"] = {"_metadata": edge_metadata}

        return edge

    def _create_ports(self) -> Dict[str, Any]:
        """
        Create port configuration for a node.

        Returns:
            Port configuration object with 4 ports (top, bottom, left, right)
        """
        return {
            "groups": {
                "top": {"position": "top"},
                "bottom": {"position": "bottom"},
                "left": {"position": "left"},
                "right": {"position": "right"},
            },
            "items": [
                {"id": "top", "group": "top"},
                {"id": "bottom", "group": "bottom"},
                {"id": "left", "group": "left"},
                {"id": "right", "group": "right"},
            ],
        }

    def _get_optimal_port(
        self, cell: Dict[str, Any], other_cell: Dict[str, Any], is_source: bool
    ) -> Optional[str]:
        """
        Get optimal port ID for a cell based on the position of another cell.

        Args:
            cell: Cell to get port for
            other_cell: Other cell to connect to
            is_source: True if cell is the source, False if it's the target

        Returns:
            Port ID or None if no ports defined
        """
        if "ports" not in cell:
            return None

        # Calculate center positions of both cells
        cell_center_x = cell["x"] + cell["width"] / 2
        cell_center_y = cell["y"] + cell["height"] / 2
        other_center_x = other_cell["x"] + other_cell["width"] / 2
        other_center_y = other_cell["y"] + other_cell["height"] / 2

        # Calculate angle from cell to other_cell
        dx = other_center_x - cell_center_x
        dy = other_center_y - cell_center_y

        # Determine which port to use based on angle
        if abs(dx) > abs(dy):
            port_group = "right" if dx > 0 else "left"
        else:
            port_group = "bottom" if dy > 0 else "top"

        # Find the port with the selected group
        items = cell.get("ports", {}).get("items", [])
        for item in items:
            if item.get("group") == port_group:
                return item.get("id")

        return None

    def _calculate_boundary_z_index(self, component: Dict[str, Any]) -> int:
        """
        Calculate z-index for a boundary component based on nesting depth.

        Args:
            component: Component dictionary

        Returns:
            Z-index value
        """
        depth = self._get_depth(component["id"])
        return self.Z_INDEX["boundary_base"] + (
            depth * self.Z_INDEX["boundary_increment"]
        )

    def _get_depth(self, component_id: str) -> int:
        """
        Get the nesting depth of a component.

        Args:
            component_id: Component ID

        Returns:
            Depth (0 for root, 1 for first level children, etc.)
        """
        component = next((c for c in self.components if c["id"] == component_id), None)
        if not component or not component.get("parent_id"):
            return 0

        return 1 + self._get_depth(component["parent_id"])

    # ---- Layout algorithm ----

    def _build_flow_adjacency(self) -> Dict[str, set]:
        """Build a peer-flow adjacency map from self.flows.

        Returns:
            Dict mapping component_id to set of component_ids it has flows with.
        """
        adjacency: Dict[str, set] = {}
        for flow in self.flows:
            src = flow["source_id"]
            tgt = flow["target_id"]
            adjacency.setdefault(src, set()).add(tgt)
            adjacency.setdefault(tgt, set()).add(src)
        return adjacency

    def _get_children(self, component_id: str) -> List[Dict[str, Any]]:
        """Get direct children of a component."""
        return [c for c in self.components if c.get("parent_id") == component_id]

    def _auto_layout(self):
        """
        Bottom-up sizing then top-down positioning.

        Phase 1: Recursively compute sizes for all components (leaves up to roots).
        Phase 2: Assign absolute x,y positions top-down.
        """
        adjacency = self._build_flow_adjacency()
        placements_map: Dict[str, List[Tuple[int, int, int, int, Dict[str, Any]]]] = {}

        roots = [c for c in self.components if not c.get("parent_id")]

        # Phase 1: Bottom-up sizing
        for root in roots:
            self._compute_component_size(root["id"], adjacency, placements_map)

        # Phase 2: Top-down positioning
        x_offset = 50
        y_offset = 50

        for root in roots:
            cell = self.component_cells.get(root["id"])
            if not cell:
                continue

            self._assign_positions(root["id"], x_offset, y_offset, placements_map)

            # Stack root components
            if root["type"] in self.BOUNDARY_TYPES:
                y_offset += cell["height"] + self.BOUNDARY_PADDING
            else:
                x_offset += cell["width"] + self.NODE_SPACING

    def _compute_component_size(
        self,
        component_id: str,
        adjacency: Dict[str, set],
        placements_map: Dict[str, List[Tuple[int, int, int, int, Dict[str, Any]]]],
    ) -> Tuple[int, int]:
        """
        Recursively compute the size of a component based on its children.

        Leaf nodes keep their default size. Boundary nodes are sized to fit
        their children arranged in a grid.

        Args:
            component_id: Component to size
            adjacency: Flow adjacency map
            placements_map: Populated with grid placements for each parent

        Returns:
            (width, height) of the component
        """
        cell = self.component_cells.get(component_id)
        if not cell:
            return (self.DEFAULT_NODE_WIDTH, self.DEFAULT_NODE_HEIGHT)

        children = self._get_children(component_id)

        if not children:
            return (cell["width"], cell["height"])

        # Recursively size all children first (bottom-up)
        for child in children:
            self._compute_component_size(child["id"], adjacency, placements_map)

        # Classify children
        leaf_children = [c for c in children if c["type"] in self.LEAF_TYPES]
        boundary_children = [c for c in children if c["type"] in self.BOUNDARY_TYPES]

        # Grid cell unit size (one leaf node + spacing)
        grid_cell_w = self.DEFAULT_NODE_WIDTH + self.NODE_SPACING
        grid_cell_h = self.DEFAULT_NODE_HEIGHT + self.NODE_SPACING

        # Build items list: (span_cols, span_rows, component, is_boundary)
        items: List[Tuple[int, int, Dict[str, Any], bool]] = []

        for bc in boundary_children:
            bc_cell = self.component_cells[bc["id"]]
            span_cols = max(1, ceil(bc_cell["width"] / grid_cell_w))
            span_rows = max(1, ceil(bc_cell["height"] / grid_cell_h))
            items.append((span_cols, span_rows, bc, True))

        for lc in leaf_children:
            items.append((1, 1, lc, False))

        # Place items into grid
        placements, grid_cols, grid_rows = self._place_items_in_grid(
            items, adjacency, component_id
        )
        placements_map[component_id] = placements

        # Compute parent size from grid dimensions
        content_w = grid_cols * grid_cell_w - self.NODE_SPACING
        content_h = grid_rows * grid_cell_h - self.NODE_SPACING

        cell["width"] = max(content_w + 2 * self.BOUNDARY_PADDING, self.MIN_WIDTH)
        cell["height"] = max(content_h + 2 * self.BOUNDARY_PADDING, self.MIN_HEIGHT)

        return (cell["width"], cell["height"])

    def _place_items_in_grid(
        self,
        items: List[Tuple[int, int, Dict[str, Any], bool]],
        adjacency: Dict[str, set],
        parent_id: str,
    ) -> Tuple[
        List[Tuple[int, int, int, int, Dict[str, Any]]],
        int,
        int,
    ]:
        """
        Place items into a 2D grid with flow-aware ordering.

        Boundary children are placed first (largest area first) using first-fit.
        Leaf children are placed with flow-aware ordering: connected peers are
        placed near each other with one empty grid cell gap between them.

        Args:
            items: List of (span_cols, span_rows, component, is_boundary) tuples
            adjacency: Flow adjacency map
            parent_id: ID of the parent component

        Returns:
            (placements, grid_cols, grid_rows) where placements is
            list of (col, row, span_cols, span_rows, component)
        """
        if not items:
            return ([], 0, 0)

        # Separate boundary and leaf items
        boundary_items = [(sc, sr, c) for sc, sr, c, is_b in items if is_b]
        leaf_items = [(sc, sr, c) for sc, sr, c, is_b in items if not is_b]

        # Calculate total grid units needed
        total_units = sum(sc * sr for sc, sr, _, _ in items)
        # Account for flow gaps: each pair of flow-connected leaves needs 1 extra cell
        sibling_ids = {c["id"] for _, _, c, _ in items}
        flow_pairs_count = 0
        seen_pairs: set[Tuple[str, str]] = set()
        for _, _, c, is_b in items:
            if is_b:
                continue
            for neighbor_id in adjacency.get(c["id"], set()):
                if neighbor_id in sibling_ids:
                    pair = tuple(sorted((c["id"], neighbor_id)))
                    if pair not in seen_pairs:
                        seen_pairs.add(pair)
                        flow_pairs_count += 1
        total_units += flow_pairs_count

        # Determine grid dimensions (as square as possible)
        grid_cols = max(1, ceil(sqrt(total_units)))
        grid_rows = max(1, ceil(total_units / grid_cols))

        # Flow gaps require at least 3 columns so the +2 offset placement works
        if flow_pairs_count > 0:
            grid_cols = max(grid_cols, 3)
            grid_rows = max(1, ceil(total_units / grid_cols))

        # Ensure grid is large enough for the widest/tallest boundary item
        for sc, sr, _ in boundary_items:
            grid_cols = max(grid_cols, sc)
            grid_rows = max(grid_rows, sr)

        # 2D occupancy grid (True = occupied)
        occupancy = [[False] * grid_cols for _ in range(grid_rows)]

        placements: List[Tuple[int, int, int, int, Dict[str, Any]]] = []
        placed_positions: Dict[str, Tuple[int, int]] = {}  # component_id -> (col, row)

        def try_place(
            sc: int, sr: int, start_col: int = 0, start_row: int = 0
        ) -> Optional[Tuple[int, int]]:
            """Find first available position for a span_cols x span_rows block."""
            for r in range(start_row, grid_rows):
                for c_start in range(start_col if r == start_row else 0, grid_cols):
                    if c_start + sc > grid_cols or r + sr > grid_rows:
                        continue
                    if all(
                        not occupancy[r + dr][c_start + dc]
                        for dr in range(sr)
                        for dc in range(sc)
                    ):
                        return (c_start, r)
            return None

        def mark_occupied(col: int, row: int, sc: int, sr: int):
            for dr in range(sr):
                for dc in range(sc):
                    occupancy[row + dr][col + dc] = True

        def expand_grid(needed_cols: int, needed_rows: int):
            nonlocal grid_cols, grid_rows, occupancy
            new_cols = max(grid_cols, needed_cols)
            new_rows = max(grid_rows, needed_rows)
            if new_cols > grid_cols or new_rows > grid_rows:
                new_occupancy = [[False] * new_cols for _ in range(new_rows)]
                for r in range(grid_rows):
                    for c in range(grid_cols):
                        new_occupancy[r][c] = occupancy[r][c]
                occupancy = new_occupancy
                grid_cols = new_cols
                grid_rows = new_rows

        # Place boundary items first (largest area first)
        boundary_items.sort(key=lambda x: x[0] * x[1], reverse=True)
        for sc, sr, component in boundary_items:
            pos = try_place(sc, sr)
            if pos is None:
                # Expand grid to accommodate
                expand_grid(grid_cols, grid_rows + sr)
                pos = try_place(sc, sr)
            if pos is None:
                # Fallback: place at end
                pos = (0, grid_rows)
                expand_grid(max(grid_cols, sc), grid_rows + sr)
            col, row = pos
            mark_occupied(col, row, sc, sr)
            placements.append((col, row, sc, sr, component))
            placed_positions[component["id"]] = (col, row)

        # Order leaf items for flow-aware placement
        ordered_leaves = self._order_leaves_by_flow(leaf_items, adjacency, sibling_ids)

        # Place leaf items with flow gap awareness
        for _, _, component in ordered_leaves:
            # Find preferred position: near flow-connected already-placed peers
            connected_placed = [
                placed_positions[nid]
                for nid in adjacency.get(component["id"], set())
                if nid in placed_positions and nid in sibling_ids
            ]

            best_pos: Optional[Tuple[int, int]] = None

            if connected_placed:
                # Try to place near a connected peer with 1 cell gap
                for peer_col, peer_row in connected_placed:
                    # Try positions around the peer with 1 cell gap
                    candidates = [
                        (peer_col + 2, peer_row),  # 1 cell gap to the right
                        (peer_col, peer_row + 2),  # 1 cell gap below
                        (peer_col - 2, peer_row),  # 1 cell gap to the left
                        (peer_col, peer_row - 2),  # 1 cell gap above
                        (peer_col + 1, peer_row + 1),  # diagonal
                        (peer_col + 1, peer_row),  # adjacent right (fallback)
                        (peer_col, peer_row + 1),  # adjacent below (fallback)
                    ]
                    for cc, cr in candidates:
                        if (
                            0 <= cc < grid_cols
                            and 0 <= cr < grid_rows
                            and not occupancy[cr][cc]
                        ):
                            best_pos = (cc, cr)
                            break
                    if best_pos:
                        break

            if best_pos is None:
                best_pos = try_place(1, 1)

            if best_pos is None:
                # Expand grid
                expand_grid(grid_cols, grid_rows + 1)
                best_pos = try_place(1, 1)

            if best_pos is None:
                best_pos = (0, grid_rows - 1)

            col, row = best_pos
            mark_occupied(col, row, 1, 1)
            placements.append((col, row, 1, 1, component))
            placed_positions[component["id"]] = (col, row)

        return (placements, grid_cols, grid_rows)

    def _order_leaves_by_flow(
        self,
        leaf_items: List[Tuple[int, int, Dict[str, Any]]],
        adjacency: Dict[str, set],
        sibling_ids: set,
    ) -> List[Tuple[int, int, Dict[str, Any]]]:
        """
        Order leaf items so that flow-connected nodes are placed consecutively.

        Uses a greedy walk: start with any leaf, then prefer a flow-connected
        sibling as the next item.

        Args:
            leaf_items: List of (span_cols, span_rows, component)
            adjacency: Flow adjacency map
            sibling_ids: Set of all sibling component IDs

        Returns:
            Reordered leaf_items list
        """
        if len(leaf_items) <= 1:
            return list(leaf_items)

        remaining = {c["id"]: (sc, sr, c) for sc, sr, c in leaf_items}
        ordered: List[Tuple[int, int, Dict[str, Any]]] = []

        # Start with the leaf that has the most flow connections to siblings
        def sibling_flow_count(cid: str) -> int:
            return len(adjacency.get(cid, set()) & sibling_ids)

        current_id = max(remaining.keys(), key=sibling_flow_count)

        while remaining:
            item = remaining.pop(current_id)
            ordered.append(item)

            # Find next: prefer a flow-connected sibling that hasn't been placed
            neighbors = adjacency.get(current_id, set()) & sibling_ids
            unplaced_neighbors = [n for n in neighbors if n in remaining]

            if unplaced_neighbors:
                # Pick the neighbor with most connections (hub preference)
                current_id = max(unplaced_neighbors, key=sibling_flow_count)
            elif remaining:
                # No connected neighbor left, pick any remaining
                current_id = next(iter(remaining))
            else:
                break

        return ordered

    def _assign_positions(
        self,
        component_id: str,
        x: int,
        y: int,
        placements_map: Dict[str, List[Tuple[int, int, int, int, Dict[str, Any]]]],
    ):
        """
        Recursively assign x,y positions to a component and its children.

        Args:
            component_id: The component to position
            x: Absolute X coordinate
            y: Absolute Y coordinate
            placements_map: Grid placements for each parent's children
        """
        cell = self.component_cells.get(component_id)
        if not cell:
            return

        cell["x"] = x
        cell["y"] = y

        if component_id not in placements_map:
            return  # leaf, no children

        grid_cell_w = self.DEFAULT_NODE_WIDTH + self.NODE_SPACING
        grid_cell_h = self.DEFAULT_NODE_HEIGHT + self.NODE_SPACING

        for col, row, span_c, span_r, child in placements_map[component_id]:
            child_x = x + self.BOUNDARY_PADDING + col * grid_cell_w
            child_y = y + self.BOUNDARY_PADDING + row * grid_cell_h
            self._assign_positions(child["id"], child_x, child_y, placements_map)
