"""
Data Flow Diagram Builder for TMI.

This module converts structured component and flow data into AntV X6 v2 format
cells for creating diagrams in TMI.
"""

import logging
import uuid
from typing import Any, ClassVar

from tmi_tf.layout import compound, routes
from tmi_tf.layout.compound import (
    Box,
    EdgeRoute,
    LayoutEdge,
    LayoutNode,
    LayoutResult,
    Side,
    edge_sides,
    label_width,
)

logger = logging.getLogger(__name__)


class DFDBuilder:
    """Builds Data Flow Diagram cells from structured component and flow data."""

    # Component type categories for layout
    BOUNDARY_TYPES: ClassVar[set[str]] = {"tenant", "container", "network"}
    LEAF_TYPES: ClassVar[set[str]] = {
        "gateway",
        "compute",
        "service",
        "storage",
        "actor",
    }

    # Shape mapping from component types to X6 shapes
    SHAPE_MAP: ClassVar[dict[str, str]] = {
        "tenant": "security-boundary",
        "container": "security-boundary",
        "network": "security-boundary",
        "gateway": "process",
        "compute": "process",
        "service": "process",
        "storage": "store",
        "actor": "actor",
    }

    # Z-index ranges for different element types
    Z_INDEX: ClassVar[dict[str, int]] = {
        "boundary_base": 1,
        "boundary_increment": 1,
        "gateway": 10,
        "compute": 11,
        "service": 11,
        "storage": 11,
        "actor": 11,
        "edge": 20,
    }

    # Minimum dimensions per OpenAPI spec
    MIN_WIDTH = 40
    MIN_HEIGHT = 30

    # Layout constants
    DEFAULT_NODE_WIDTH = 120
    DEFAULT_NODE_HEIGHT = 60

    def __init__(
        self,
        components: list[dict[str, Any]],
        flows: list[dict[str, Any]],
        services: list[dict[str, Any]] | None = None,
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
        self.cells: list[dict[str, Any]] = []
        self.component_cells: dict[str, dict[str, Any]] = {}  # id -> cell mapping
        self._components: list[dict[str, Any]] = []  # accepted, input order
        self._parent: dict[str, str | None] = {}  # effective parent per accepted id
        self._layout: LayoutResult | None = None
        self._direction: compound.Direction = "LR"
        # Build component_id -> service_name lookup from inventory services
        self._service_lookup: dict[str, str] = {}
        if services:
            for svc in services:
                svc_name = svc.get("name", "")
                if not svc_name:
                    continue
                for comp_id in svc.get("compute_units", []):
                    self._service_lookup[comp_id] = svc_name
                for comp_id in svc.get("associated_resources", []):
                    self._service_lookup[comp_id] = svc_name

    def build_cells(self) -> list[dict[str, Any]]:
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

        self.cells = []
        self.component_cells = {}
        self._layout = None
        self._normalize_components()
        if not self._components:
            return self.cells

        # Step 1: Create all node cells
        self._create_boundary_cells()
        self._create_node_cells()

        # Step 2: Layout nodes
        self._auto_layout()

        # Step 3: Create edge cells for flows
        self._create_edge_cells()

        logger.info("Generated %d total cells", len(self.cells))
        return self.cells

    def _normalize_components(self) -> None:
        """Accept valid components and settle each one's effective parent.

        Rejected items (unknown type, duplicate id, bad parent) are logged, one
        warning each; a bad parent makes the component a root.
        """
        accepted: list[dict[str, Any]] = []
        by_id: dict[str, dict[str, Any]] = {}
        for component in self.components:
            cid = component.get("id")
            ctype = component.get("type")
            if ctype == "network_access_control":
                # Safety filter: the LLM may still emit these despite prompt changes
                logger.warning(
                    "Skipping network_access_control component '%s' (%s) — "
                    "security controls should be in parent boundary metadata",
                    component.get("name", "unknown"),
                    cid,
                )
                continue
            if ctype not in self.BOUNDARY_TYPES | self.LEAF_TYPES:
                logger.warning("Skipping component %r: unknown type %r", cid, ctype)
                continue
            if not isinstance(cid, str):
                logger.warning("Skipping component with invalid id %r", cid)
                continue
            if cid in by_id:
                logger.warning("Skipping component %r: duplicate id", cid)
                continue
            accepted.append(component)
            by_id[cid] = component

        parent: dict[str, str | None] = {}
        for component in accepted:
            cid = component["id"]
            pid = component.get("parent_id")
            if not pid:
                parent[cid] = None
                continue
            target = by_id.get(pid) if isinstance(pid, str) else None
            if pid == cid:
                reason = "is its own parent"
            elif target is None:
                reason = f"has unknown parent {pid!r}"
            elif target["type"] not in self.BOUNDARY_TYPES:
                reason = f"has non-boundary parent {pid!r}"
            else:
                parent[cid] = pid
                continue
            logger.warning("Component %r %s; placing it at the root", cid, reason)
            parent[cid] = None

        # Break parent cycles: whatever is unreachable from a root becomes a root.
        children: dict[str, list[str]] = {}
        for cid, pid in parent.items():
            if pid is not None:
                children.setdefault(pid, []).append(cid)
        reachable: dict[str, bool] = {}

        def mark(start: str) -> None:
            stack = [start]
            while stack:
                cur = stack.pop()
                if cur in reachable:
                    continue
                reachable[cur] = True
                stack.extend(children.get(cur, []))

        for cid, pid in parent.items():
            if pid is None:
                mark(cid)
        for component in accepted:
            cid = component["id"]
            if cid in reachable:
                continue
            logger.warning(
                "Component %r is in a parent cycle; placing it at the root", cid
            )
            old = parent[cid]
            assert old is not None
            children[old].remove(cid)
            parent[cid] = None
            mark(cid)

        self._components = accepted
        self._parent = parent

    def _create_boundary_cells(self):
        """Create security boundary cells for tenant, container, and network components."""
        boundaries = [c for c in self._components if c["type"] in self.BOUNDARY_TYPES]

        # Sort by hierarchy depth (tenant first, then container, then network)
        boundaries.sort(key=lambda c: self._get_depth(c["id"]))

        for component in boundaries:
            z_index = self._calculate_boundary_z_index(component)
            cell = self._create_node_cell(component, z_index)
            self.cells.append(cell)
            self.component_cells[component["id"]] = cell

    def _create_node_cells(self):
        """Create node cells for gateway, compute, service, storage, and actor components."""
        nodes = [c for c in self._components if c["type"] in self.LEAF_TYPES]

        for component in nodes:
            z_index = self.Z_INDEX.get(component["type"], 11)
            cell = self._create_node_cell(component, z_index)

            # Add ports for all connectable leaf nodes
            cell["ports"] = self._create_ports()

            self.cells.append(cell)
            self.component_cells[component["id"]] = cell

    def _create_node_cell(
        self, component: dict[str, Any], z_index: int
    ) -> dict[str, Any]:
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

        # Provisional size; the layout sets the real position and size
        is_boundary = component["type"] in self.BOUNDARY_TYPES
        width = self.MIN_WIDTH if is_boundary else self.DEFAULT_NODE_WIDTH
        height = self.MIN_HEIGHT if is_boundary else self.DEFAULT_NODE_HEIGHT

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
        parent_id = self._parent.get(component["id"])
        if parent_id is not None:
            parent_cell = self.component_cells.get(parent_id)
            if parent_cell:
                cell["parent"] = parent_cell["id"]

        return cell

    def _build_node_metadata(self, component: dict[str, Any]) -> list[dict[str, str]]:
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

    def _build_edge_metadata(self, flow: dict[str, Any]) -> list[dict[str, str]]:
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

    @staticmethod
    def _flow_labels(flow: dict[str, Any]) -> tuple[str, str | None]:
        """Forward label and, for a bidirectional flow, the reverse label."""
        if flow.get("bidirectional", False):
            return (
                flow.get("forward_label", flow["name"]),
                flow.get("reverse_label", flow["name"]),
            )
        return flow["name"], None

    def _create_edge_cells(self):
        """Create edge cells for data flows."""
        direction = self._direction
        # (flow index, source cell, target cell, label, sides, forward)
        specs: list[tuple[int, dict, dict, str, tuple[Side, Side], bool]] = []
        for index, flow in enumerate(self.flows):
            src_id, tgt_id = flow["source_id"], flow["target_id"]
            src_cell = self.component_cells.get(src_id)
            tgt_cell = self.component_cells.get(tgt_id)
            if not src_cell or not tgt_cell:
                logger.warning(
                    "Skipping flow %s: source or target component not found",
                    flow.get("id", "unknown"),
                )
                continue

            route = self._layout.routes.get(str(index)) if self._layout else None
            rank_delta = self._rank_delta(route)
            cross_delta = self._cross_delta(src_cell, tgt_cell, direction)
            forward, reverse = self._flow_labels(flow)

            sides = edge_sides(direction, rank_delta, cross_delta)
            specs.append((index, src_cell, tgt_cell, forward, sides, True))
            if reverse is not None:
                rev_sides = edge_sides(direction, -rank_delta, -cross_delta)
                specs.append((index, tgt_cell, src_cell, reverse, rev_sides, False))

        groups: dict[tuple[str, str], list[int]] = {}
        for pos, spec in enumerate(specs):
            flow = self.flows[spec[0]]
            ids = sorted((flow["source_id"], flow["target_id"]))
            groups.setdefault((ids[0], ids[1]), []).append(pos)
        slot: dict[int, tuple[int, int]] = {}
        for members in groups.values():
            for i, pos in enumerate(members):
                slot[pos] = (i, len(members))

        for pos, (index, source, target, label, sides, forward) in enumerate(specs):
            i, k = slot[pos]
            vertices = self._edge_vertices(index, source, target, sides, forward, i, k)
            position = routes.label_positions(k)[i] if k > 1 else None
            edge = self._create_edge_cell(
                source,
                target,
                label,
                sides,
                self.flows[index],
                vertices=vertices,
                label_position=position,
            )
            self.cells.append(edge)

    def _route_points(self, route: EdgeRoute, forward: bool) -> list[tuple[int, int]]:
        """Route bend points in the cell's direction; `[]` for a route that is not lifted."""
        if not route.lifted:
            return []
        points = list(route.points)
        if compound.EMIT_BORDER_VERTICES:
            points = list(route.border_out) + points + list(route.border_in)
        return points if forward else points[::-1]

    def _box(self, cell: dict[str, Any]) -> Box:
        return Box(cell["x"], cell["y"], cell["width"], cell["height"])

    def _edge_vertices(
        self,
        index: int,
        source: dict[str, Any],
        target: dict[str, Any],
        sides: tuple[Side, Side],
        forward: bool,
        i: int,
        k: int,
    ) -> list[tuple[int, int]]:
        """Vertices for one edge cell: route, straighten, fan, drop blocked, cap."""
        route = self._layout.routes.get(str(index)) if self._layout else None
        if route is None or not route.lifted or self._layout is None:
            return []
        flow = self.flows[index]
        src_id, tgt_id = (
            (flow["source_id"], flow["target_id"])
            if forward
            else (flow["target_id"], flow["source_id"])
        )
        direction = self._direction
        src_box, tgt_box = self._box(source), self._box(target)
        start = routes.side_point(
            src_box,
            sides[0] if "ports" in source else None,
        )
        end = routes.side_point(
            tgt_box,
            sides[1] if "ports" in target else None,
        )
        points = routes.straighten(self._route_points(route, forward), start, end)
        if k > 1:
            offset = routes.fan_offsets(k, compound.LayoutOptions().edge_sep)[i]
            if points:
                points = routes.shift_cross(points, offset, direction)
            else:
                box_a = self._layout.boxes.get(route.a)
                box_b = self._layout.boxes.get(route.b)
                if box_a is not None and box_b is not None:
                    mid = routes.gap_midpoint(box_a, box_b, src_box, tgt_box, direction)
                    points = routes.shift_cross([mid], offset, direction)
        if not points:
            return []
        excluded = set(self._proper_ancestors(src_id)) | set(
            self._proper_ancestors(tgt_id)
        )
        blockers = [
            self._box(c)
            for cid, c in self.component_cells.items()
            if cid not in excluded
        ]
        points = routes.drop_blocked(points, blockers)
        if len(points) > routes.MAX_VERTICES:
            logger.warning(
                "Flow %s (%s -> %s) has %d vertices; dropping them",
                flow.get("id", "unknown"),
                src_id,
                tgt_id,
                len(points),
            )
            return []
        return points

    def _proper_ancestors(self, comp_id: str) -> list[str]:
        """Component ids of the proper ancestors of a component."""
        out: list[str] = []
        cur = self._parent.get(comp_id)
        while cur is not None:
            out.append(cur)
            cur = self._parent.get(cur)
        return out

    @staticmethod
    def _rank_delta(route: EdgeRoute | None) -> int:
        if route is not None and route.lifted:
            return route.rank_b - route.rank_a
        return 1

    @staticmethod
    def _cross_delta(
        source: dict[str, Any], target: dict[str, Any], direction: str
    ) -> float:
        """Target centre minus source centre on the cross axis."""
        if direction == "TB":
            return (target["x"] + target["width"] / 2) - (
                source["x"] + source["width"] / 2
            )
        return (target["y"] + target["height"] / 2) - (
            source["y"] + source["height"] / 2
        )

    def _create_edge_cell(
        self,
        source_cell: dict[str, Any],
        target_cell: dict[str, Any],
        label_text: str,
        sides: tuple[Side, Side],
        flow: dict[str, Any],
        vertices: list[tuple[int, int]] | None = None,
        label_position: float | None = None,
    ) -> dict[str, Any]:
        """
        Create a single edge cell.

        Args:
            source_cell: Source node cell
            target_cell: Target node cell
            label_text: Edge label
            sides: (source port, target port) names; ignored for a boundary end
            flow: Original flow data with protocol, port, etc.
            vertices: Absolute bend points; the key is omitted when empty
            label_position: 0-1 label position along the edge; omitted when None

        Returns:
            Edge cell in X6 format
        """
        cell_id = str(uuid.uuid4())
        source_port = sides[0] if "ports" in source_cell else None
        target_port = sides[1] if "ports" in target_cell else None

        # Build source and target dicts with optional port
        source_dict: dict[str, str] = {"cell": source_cell["id"]}
        target_dict: dict[str, str] = {"cell": target_cell["id"]}

        if source_port:
            source_dict["port"] = source_port
        if target_port:
            target_dict["port"] = target_port

        edge: dict[str, Any] = {
            "id": cell_id,
            "shape": "flow",
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
            "connector": {"name": "rounded" if vertices else "smooth"},
        }
        if label_position is not None:
            edge["labels"][0]["position"] = label_position
        if vertices:
            edge["vertices"] = [{"x": x, "y": y} for x, y in vertices]

        # Add protocol, port, data_type as edge metadata
        edge_metadata = self._build_edge_metadata(flow)
        if edge_metadata:
            edge["data"] = {"_metadata": edge_metadata}

        return edge

    def _create_ports(self) -> dict[str, Any]:
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

    def _calculate_boundary_z_index(self, component: dict[str, Any]) -> int:
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
        depth = 0
        cur = self._parent.get(component_id)
        while cur is not None:
            depth += 1
            cur = self._parent.get(cur)
        return depth

    # ---- Layout ----

    def _auto_layout(self):
        """Lay out all node cells with the layered compound layout."""
        self._direction = compound.LAYOUT_DIRECTION
        order = sorted(
            enumerate(self._components),
            key=lambda ic: (
                (0, ic[1]["sibling_order"], ic[0])
                if type(ic[1].get("sibling_order")) is int
                else (1, 0, ic[0])
            ),
        )
        nodes: list[LayoutNode] = []
        for _, component in order:
            cid = component["id"]
            parent = self._parent[cid]
            if component["type"] in self.BOUNDARY_TYPES:
                nodes.append(
                    LayoutNode(
                        cid,
                        parent,
                        max(self.MIN_WIDTH, label_width(str(component["name"]))),
                        self.MIN_HEIGHT,
                        is_group=True,
                    )
                )
            else:
                nodes.append(
                    LayoutNode(
                        cid,
                        parent,
                        self.DEFAULT_NODE_WIDTH,
                        self.DEFAULT_NODE_HEIGHT,
                    )
                )

        edges: list[LayoutEdge] = []
        for index, flow in enumerate(self.flows):
            if (
                flow["source_id"] not in self.component_cells
                or flow["target_id"] not in self.component_cells
            ):
                continue
            forward, reverse = self._flow_labels(flow)
            label_w = max(
                label_width(str(forward)),
                label_width(str(reverse)) if reverse is not None else 0,
            )
            edges.append(
                LayoutEdge(str(index), flow["source_id"], flow["target_id"], label_w)
            )

        result = compound.compound_layout(nodes, edges, self._direction)
        self._layout = result
        for cid, box in result.boxes.items():
            cell = self.component_cells[cid]
            cell["x"], cell["y"] = box.x, box.y
            cell["width"], cell["height"] = box.w, box.h
