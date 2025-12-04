"""
Data Flow Diagram Builder for TMI.

This module converts structured component and flow data into AntV X6 v2 format
cells for creating diagrams in TMI.
"""

import uuid
from typing import Any, Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class DFDBuilder:
    """Builds Data Flow Diagram cells from structured component and flow data."""

    # Shape mapping from component types to X6 shapes
    SHAPE_MAP = {
        "tenancy": "security-boundary",
        "container": "security-boundary",
        "network": "security-boundary",
        "gateway": "process",
        "compute": "process",
        "storage": "store",
        "actor": "actor",
    }

    # Z-index ranges for different element types
    Z_INDEX = {
        "boundary_base": 1,
        "boundary_increment": 1,
        "gateway": 10,
        "compute": 11,
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

    def __init__(self, components: List[Dict[str, Any]], flows: List[Dict[str, Any]]):
        """
        Initialize the DFD builder.

        Args:
            components: List of component dictionaries with id, name, type, parent_id, etc.
            flows: List of flow dictionaries with source_id, target_id, protocol, etc.
        """
        self.components = components
        self.flows = flows
        self.cells: List[Dict[str, Any]] = []
        self.component_cells: Dict[str, Dict[str, Any]] = {}  # id -> cell mapping

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
        """Create security boundary cells for tenancy, container, and network components."""
        # Get boundary components (tenancy, container, network)
        boundaries = [
            c
            for c in self.components
            if c["type"] in ["tenancy", "container", "network"]
        ]

        # Sort by hierarchy depth (tenancy first, then container, then network)
        boundaries.sort(key=lambda c: self._get_depth(c["id"]))

        for component in boundaries:
            z_index = self._calculate_boundary_z_index(component)
            cell = self._create_node_cell(component, z_index)
            self.cells.append(cell)
            self.component_cells[component["id"]] = cell

    def _create_node_cells(self):
        """Create node cells for gateway, compute, storage, and actor components."""
        nodes = [
            c
            for c in self.components
            if c["type"] in ["gateway", "compute", "storage", "actor"]
        ]

        for component in nodes:
            z_index = self.Z_INDEX.get(component["type"], 11)
            cell = self._create_node_cell(component, z_index)

            # Add ports for compute and gateway nodes
            if component["type"] in ["compute", "gateway"]:
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
        is_boundary = component["type"] in ["tenancy", "container", "network"]
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
                "body": self._get_body_attrs(component["type"]),
                "text": {"text": component["name"]},
            },
            "data": {
                "_metadata": [
                    {"key": "component_id", "value": component["id"]},
                    {"key": "component_type", "value": component["type"]},
                    {"key": "component_subtype", "value": component.get("subtype", "")},
                ]
            },
        }

        # Set parent relationship for nested components
        if component.get("parent_id"):
            parent_cell = self.component_cells.get(component["parent_id"])
            if parent_cell:
                cell["parent"] = parent_cell["id"]

        return cell

    def _create_edge_cells(self):
        """Create edge cells for data flows."""
        for flow in self.flows:
            # Create edges (two if bidirectional)
            edges_to_create = []

            if flow.get("bidirectional", False):
                # Create two edges for bidirectional flow
                edges_to_create.append(
                    {
                        "source_id": flow["source_id"],
                        "target_id": flow["target_id"],
                        "label": f"{flow['name']} →",
                    }
                )
                edges_to_create.append(
                    {
                        "source_id": flow["target_id"],
                        "target_id": flow["source_id"],
                        "label": f"{flow['name']} ←",
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

        # Determine source and target ports
        source_port = self._get_port(source_cell, "out")
        target_port = self._get_port(target_cell, "in")

        # Build label text with protocol and port if available
        label_parts = [edge_data["label"]]
        if flow.get("protocol"):
            label_parts.append(f"({flow['protocol']}")
            if flow.get("port"):
                label_parts[-1] += f":{flow['port']}"
            label_parts[-1] += ")"

        label_text = " ".join(label_parts)

        edge = {
            "id": cell_id,
            "shape": "edge",
            "source": {"cell": source_cell["id"]},
            "target": {"cell": target_cell["id"]},
            "zIndex": self.Z_INDEX["edge"],
            "attrs": {
                "line": {
                    "stroke": "#333333",
                    "strokeWidth": 2,
                    "targetMarker": {"name": "block", "width": 12, "height": 8},
                }
            },
            "labels": [{"attrs": {"text": {"text": label_text}}}],
            "router": {"name": "manhattan"},
            "connector": {"name": "rounded"},
        }

        # Add ports if available
        if source_port:
            edge["source"]["port"] = source_port
        if target_port:
            edge["target"]["port"] = target_port

        return edge

    def _create_ports(self) -> Dict[str, Any]:
        """
        Create port configuration for a node.

        Returns:
            Port configuration object
        """
        return {
            "groups": {"in": {"position": "left"}, "out": {"position": "right"}},
            "items": [
                {"id": "port-in", "group": "in"},
                {"id": "port-out", "group": "out"},
            ],
        }

    def _get_port(self, cell: Dict[str, Any], direction: str) -> Optional[str]:
        """
        Get port ID for a cell in a given direction.

        Args:
            cell: Cell dictionary
            direction: "in" or "out"

        Returns:
            Port ID or None if no ports defined
        """
        if "ports" not in cell:
            return None

        items = cell.get("ports", {}).get("items", [])
        for item in items:
            if item.get("group") == direction:
                return item.get("id")

        return None

    def _get_body_attrs(self, component_type: str) -> Dict[str, Any]:
        """
        Get body styling attributes for a component type.

        Args:
            component_type: Component type (tenancy, compute, etc.)

        Returns:
            Attrs object for body styling
        """
        # Color scheme for different component types
        colors = {
            "tenancy": {"fill": "#FFF3E0", "stroke": "#FF9800"},
            "container": {"fill": "#E3F2FD", "stroke": "#2196F3"},
            "network": {"fill": "#F3E5F5", "stroke": "#9C27B0"},
            "gateway": {"fill": "#E8F5E9", "stroke": "#4CAF50"},
            "compute": {"fill": "#E1F5FE", "stroke": "#03A9F4"},
            "storage": {"fill": "#FFF9C4", "stroke": "#FBC02D"},
            "actor": {"fill": "#FFEBEE", "stroke": "#F44336"},
        }

        return colors.get(component_type, {"fill": "#FFFFFF", "stroke": "#333333"})

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

    def _auto_layout(self):
        """
        Automatically layout all nodes using hierarchical algorithm.

        This implements a simple hierarchical layout where:
        1. Boundaries are sized to fit their children
        2. Children are positioned within parents using grid layout
        3. Root-level components are positioned first
        """
        # Get components organized by hierarchy
        roots = [c for c in self.components if not c.get("parent_id")]

        # Layout root components first
        x_offset = 50
        y_offset = 50

        for component in roots:
            cell = self.component_cells.get(component["id"])
            if cell:
                self._layout_component(component, x_offset, y_offset)

                # Move to next position for next root component
                if component["type"] in ["tenancy", "container"]:
                    # Stack boundaries vertically with spacing
                    y_offset += cell["height"] + self.BOUNDARY_PADDING
                else:
                    # Stack other root nodes horizontally
                    x_offset += cell["width"] + self.NODE_SPACING

    def _layout_component(self, component: Dict[str, Any], x: int, y: int):
        """
        Recursively layout a component and its children.

        Args:
            component: Component dictionary
            x: X position
            y: Y position
        """
        cell = self.component_cells.get(component["id"])
        if not cell:
            return

        # Set position for this component
        cell["x"] = x
        cell["y"] = y

        # Get children
        children = [c for c in self.components if c.get("parent_id") == component["id"]]

        if not children:
            return

        # Layout children within this component
        is_boundary = component["type"] in ["tenancy", "container", "network"]

        if is_boundary:
            # Calculate grid layout for children
            child_positions = self._calculate_grid_layout(
                children, x, y, cell["width"], cell["height"]
            )

            # Position each child
            for child, (child_x, child_y) in zip(children, child_positions):
                self._layout_component(child, child_x, child_y)

            # Adjust boundary size to fit all children
            self._resize_boundary_to_fit_children(cell, children)

    def _calculate_grid_layout(
        self,
        children: List[Dict[str, Any]],
        parent_x: int,
        parent_y: int,
        parent_width: int,
        parent_height: int,
    ) -> List[Tuple[int, int]]:
        """
        Calculate grid layout positions for children within a parent.

        Args:
            children: List of child components
            parent_x: Parent X position
            parent_y: Parent Y position
            parent_width: Parent width
            parent_height: Parent height

        Returns:
            List of (x, y) positions for each child
        """
        if not children:
            return []

        # Calculate grid dimensions
        num_children = len(children)
        cols = max(1, int((num_children**0.5) + 0.5))  # Square root rounded up
        rows = (num_children + cols - 1) // cols  # Ceiling division

        # Calculate available space
        available_width = parent_width - (2 * self.BOUNDARY_PADDING)
        available_height = parent_height - (2 * self.BOUNDARY_PADDING)

        # Calculate cell size
        cell_width = (available_width - (cols - 1) * self.NODE_SPACING) // cols
        cell_height = (available_height - (rows - 1) * self.NODE_SPACING) // rows

        positions = []
        for i, child in enumerate(children):
            row = i // cols
            col = i % cols

            x = (
                parent_x
                + self.BOUNDARY_PADDING
                + col * (cell_width + self.NODE_SPACING)
            )
            y = (
                parent_y
                + self.BOUNDARY_PADDING
                + row * (cell_height + self.NODE_SPACING)
            )

            positions.append((x, y))

        return positions

    def _resize_boundary_to_fit_children(
        self, boundary_cell: Dict[str, Any], children: List[Dict[str, Any]]
    ):
        """
        Resize a boundary to fit all its children with padding.

        Args:
            boundary_cell: Boundary cell to resize
            children: List of child components
        """
        if not children:
            return

        # Find bounding box of all children
        min_x = float("inf")
        min_y = float("inf")
        max_x = float("-inf")
        max_y = float("-inf")

        for child in children:
            child_cell = self.component_cells.get(child["id"])
            if not child_cell:
                continue

            min_x = min(min_x, child_cell["x"])
            min_y = min(min_y, child_cell["y"])
            max_x = max(max_x, child_cell["x"] + child_cell["width"])
            max_y = max(max_y, child_cell["y"] + child_cell["height"])

        # Calculate required boundary size with padding
        required_width = max_x - boundary_cell["x"] + self.BOUNDARY_PADDING
        required_height = max_y - boundary_cell["y"] + self.BOUNDARY_PADDING

        # Ensure minimum size
        boundary_cell["width"] = max(required_width, self.DEFAULT_BOUNDARY_WIDTH // 2)
        boundary_cell["height"] = max(
            required_height, self.DEFAULT_BOUNDARY_HEIGHT // 2
        )
