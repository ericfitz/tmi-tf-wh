# Remove Security Control Diagram Nodes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop rendering security controls as standalone nodes in Mermaid and DFD diagrams; fold their info into parent object labels (Mermaid) or metadata (DFD).

**Architecture:** Prompt-level changes tell the LLM to stop generating `network_access_control` components and instead attach security control info to parent objects. A safety filter in `diagram_builder.py` drops any stray NAC nodes the LLM might still emit. No post-processing flow-collapsing logic.

**Tech Stack:** Python 3.13, pytest, ruff, pyright, LLM prompt templates (plain text)

---

### Task 1: Update DFD generation system prompt

Remove `network_access_control` as a component type and instruct the LLM to put security control info in parent boundary metadata instead.

**Files:**
- Modify: `prompts/dfd_generation_system.txt`

- [ ] **Step 1: Edit the Component Categories section**

In `prompts/dfd_generation_system.txt`, replace the line for item 4 in the Component Categories list:

```
4. **network_access_control** - Network access control mechanisms (AWS Security Group, Network ACL, firewall rules/policies, firewalls, web application firewalls/cloud armor, GCP VPC service controls)
```

With:

```
4. **[REMOVED — see Security Controls Handling below]**
```

And renumber items 5-9 to 4-8:

```
4. **gateway** - Network gateways (Internet Gateway, NAT Gateway, VPN Gateway, Load Balancers, peering connections, VPC endpoints, private endpoints/privatelink/service connect, direct connect)
5. **compute** - Compute resources (EC2, VM, Container Instance, Function)
6. **service** - Logical groupings of compute units
7. **storage** - Data stores (RDS, S3, Blob Storage, Object Storage, Database)
8. **actor** - External entities (Users, External Systems, Internet, Third-party APIs)
```

- [ ] **Step 2: Add Security Controls Handling section**

After the Component Categories section (before Flow Direction Convention), add:

```
# Security Controls Handling

Do NOT create components for network access controls (AWS Security Groups, Network ACLs, firewall rules/policies, firewalls, WAFs, GCP VPC service controls). Instead:

1. Identify security controls from the inventory (components with type "security_control")
2. For each security control, determine its parent/containing object (the VPC, subnet, or boundary it protects)
3. Add the security control as metadata on that parent boundary component using key-value pairs:
   - {"key": "security_control", "value": "<control-name-or-id>"}
   - {"key": "security_control_type", "value": "<subtype, e.g. security_group, nacl, waf>"}
   - If the control has specific rules worth noting, add: {"key": "security_control_rules", "value": "<brief summary>"}
4. If multiple security controls apply to the same parent, use numbered keys: "security_control_01", "security_control_02", etc.
5. Generate flows directly between source and target components — do NOT route flows through security control intermediaries
```

- [ ] **Step 3: Update the Hierarchy and Nesting section**

Replace this line (around line 48):

```
- **network.security_group** applies to (but doesn't contain) compute/storage resources; it can be modeled as a process node that intermediates flows between source and destination
```

With:

```
- **Security controls** (security groups, NACLs, WAFs) are NOT modeled as components. Their information is stored in the metadata of the parent boundary they protect.
```

- [ ] **Step 4: Remove NAC-specific layout rules**

Remove the entire "Network Access Control Placement" subsection (lines 147-153):

```
### Network Access Control Placement

When a NAC intermediates a flow, place it spatially BETWEEN its source and target in the primary flow direction:

- The NAC's rank must be between the ranks of the components it mediates
- The NAC's sibling_order should align with the components it connects to, not be placed arbitrarily
- Example: If load-balancer (rank 1) → security-group-web → web-server (rank 5), then security-group-web should be rank 2, positioned between them
```

- [ ] **Step 5: Update the rank table**

In the Flow Direction Convention section, remove the NAC-specific rows from the rank table:

Remove these rows:
```
| 2 | Ingress NACs protecting public tier | Security groups on LBs |
| 4 | Internal NACs protecting app tier | Security groups on app servers |
| 6 | Data-tier NACs protecting data tier | Security groups on databases |
```

And renumber the remaining rows to close the gaps:

```
| Rank | Component Role | Examples |
|------|---------------|----------|
| 0 | External actors, ingress sources | Internet, Users, External APIs |
| 1 | Ingress gateways | Internet Gateway, Load Balancer |
| 2 | Public-facing compute | Bastion hosts, web frontends |
| 3 | Internal compute | Application servers, middleware |
| 4 | Data stores | RDS, object storage, caches |
| 5 | Egress gateways | NAT Gateway, VPN Gateway |
| 6 | Egress targets | External services reached outbound |
```

- [ ] **Step 6: Update Special Considerations item 3**

Replace item 3 in the Special Considerations section:

```
3. **Network Access Controls**: Create process objects for network access controls, and use the network access control node as a separate hop in flows that are subject to that control.  For example, if a process protected by a network access control communicates with a process that is not protected by the same NAC object, then flows should be created from the first process to the NAC object, and from the NAC object to the second process, and the same pattern applies in flows in the other direction.
```

With:

```
3. **Network Access Controls**: Do NOT create components for network access controls. Instead, add security control information as metadata on the parent boundary component that the control protects. Generate flows directly between source and target components without routing through security control intermediaries.
```

- [ ] **Step 7: Update the Output Format component type list**

In the Components subsection of Output Format, replace the `type` field description:

```
- **type** - One of: tenant, container, network, network_access_control, gateway, compute, service, storage, actor
```

With:

```
- **type** - One of: tenant, container, network, gateway, compute, service, storage, actor
```

- [ ] **Step 8: Update Pre-Output Validation**

Remove item 5 from the Pre-Output Validation section:

```
5. **NAC positioning**: Verify every NAC component has a rank strictly between the ranks of the components it mediates. If not, adjust.
```

- [ ] **Step 9: Update Critical Instructions**

In the Critical Instructions section, remove this line:

```
- Model network access controls as processes that intermediate flows, ranked between the components they mediate
```

And add:

```
- Do NOT create components for network access controls — add their info as metadata on the parent boundary
```

- [ ] **Step 10: Commit**

```bash
git add prompts/dfd_generation_system.txt
git commit -m "refactor(prompts): remove NAC components from DFD generation prompt

Security controls are no longer rendered as standalone diagram nodes.
The LLM now adds security control info as metadata on parent boundary
components and generates direct flows without NAC intermediaries.

Refs #6"
```

---

### Task 2: Update DFD generation user prompt

Remove any NAC references from the user prompt template.

**Files:**
- Modify: `prompts/dfd_generation_user.txt`

- [ ] **Step 1: Review and update**

Read `prompts/dfd_generation_user.txt`. The current content is a simple template that passes `inventory_json` and `infrastructure_json`. It does not contain explicit NAC references, so no changes are needed to this file.

Note: The inventory data passed via `{inventory_json}` will still contain `security_control` components — this is correct. The DFD system prompt now instructs the LLM to read those but emit metadata instead of components.

- [ ] **Step 2: Commit (skip if no changes)**

No commit needed — file is unchanged.

---

### Task 3: Update infrastructure analysis system prompt

Stop generating security control nodes in Mermaid diagrams; append their info to parent labels instead.

**Files:**
- Modify: `prompts/infrastructure_analysis_system.txt`

- [ ] **Step 1: Update the mermaid_diagram field specification**

In `prompts/infrastructure_analysis_system.txt`, find the `mermaid_diagram` field specification (around line 30). Replace:

```
## mermaid_diagram
A Mermaid diagram string (using graph TD or graph LR) visualizing:
- Major infrastructure components (use services instead of individual compute units where services were identified)
- Network boundaries and security zones as subgraphs
- Data flows with arrows and labels
- External interfaces (users, external services, internet)
- Key security controls represented as intermediate nodes in flows
```

With:

```
## mermaid_diagram
A Mermaid diagram string (using graph TD or graph LR) visualizing:
- Major infrastructure components (use services instead of individual compute units where services were identified)
- Network boundaries and security zones as subgraphs
- Data flows with arrows and labels
- External interfaces (users, external services, internet)

Do NOT create separate nodes for security controls (security groups, NACLs, WAFs, firewalls). Instead, append security control information to the label of the parent/containing node that the control protects. For example, a subnet with a security group should be labeled: "Web Subnet\nsecurity group: sg-web-rules". Flows should go directly between source and target components without routing through security control intermediaries.
```

- [ ] **Step 2: Commit**

```bash
git add prompts/infrastructure_analysis_system.txt
git commit -m "refactor(prompts): remove NAC nodes from Mermaid diagram instructions

Security controls are now appended to parent node labels instead of
being rendered as separate intermediate nodes. Flows go directly
between source and target.

Refs #6"
```

---

### Task 4: Add safety filter tests to diagram_builder

Write failing tests for the safety filter that drops `network_access_control` components.

**Files:**
- Modify: `tests/test_diagram_builder.py`

- [ ] **Step 1: Write the test for NAC component being skipped**

Add a new test class at the end of `tests/test_diagram_builder.py`:

```python
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
        # Only the direct flow should produce an edge; the NAC flows are dropped
        # because the NAC endpoint won't be found (existing behavior for missing endpoints)
        assert len(edges) == 1
        assert edges[0]["labels"][0]["attrs"]["text"]["text"] == "Direct"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_diagram_builder.py::TestNetworkAccessControlRemoval -v`

Expected: FAIL — `test_nac_component_skipped` fails because a cell IS currently created for the NAC component. `test_nac_component_skipped_no_edge_created` may pass or fail depending on whether NAC cells exist (the edge skip logic already handles missing endpoints, but with NAC cells present the flows TO/FROM NAC would succeed).

- [ ] **Step 3: Commit failing tests**

```bash
git add tests/test_diagram_builder.py
git commit -m "test: add failing tests for NAC component safety filter

Tests verify that network_access_control components are skipped
during diagram building and that flows to/from them are dropped.

Refs #6"
```

---

### Task 5: Update existing tests that reference network_access_control

Update tests that assert on `network_access_control` behavior.

**Files:**
- Modify: `tests/test_diagram_builder.py`

- [ ] **Step 1: Update TestComponentTypes.test_shape_and_zindex**

In the `@pytest.mark.parametrize` block of `test_shape_and_zindex`, remove this line from the parameters:

```python
            ("network_access_control", "process", 11),
```

- [ ] **Step 2: Update TestComponentTypes.test_leaf_nodes_have_ports**

In the `@pytest.mark.parametrize` block of `test_leaf_nodes_have_ports`, remove `"network_access_control"` from the list:

Change:
```python
    @pytest.mark.parametrize(
        "comp_type",
        ["gateway", "compute", "service", "network_access_control", "storage", "actor"],
    )
```

To:
```python
    @pytest.mark.parametrize(
        "comp_type",
        ["gateway", "compute", "service", "storage", "actor"],
    )
```

- [ ] **Step 3: Run updated tests to confirm they pass (before implementation)**

Run: `uv run pytest tests/test_diagram_builder.py::TestComponentTypes -v`

Expected: PASS (these tests no longer reference NAC, so they test only the remaining types which are unchanged).

- [ ] **Step 4: Commit**

```bash
git add tests/test_diagram_builder.py
git commit -m "test: remove network_access_control from component type tests

These parametrized tests no longer cover NAC since it's being removed
as a valid diagram component type. NAC filtering is tested separately
in TestNetworkAccessControlRemoval.

Refs #6"
```

---

### Task 6: Implement safety filter in diagram_builder.py

Remove `network_access_control` from type sets and add the safety filter.

**Files:**
- Modify: `tmi_tf/diagram_builder.py`

- [ ] **Step 1: Remove network_access_control from LEAF_TYPES**

In `tmi_tf/diagram_builder.py`, change `LEAF_TYPES` (line 21-28):

```python
    LEAF_TYPES = {
        "gateway",
        "compute",
        "service",
        "storage",
        "actor",
    }
```

- [ ] **Step 2: Remove network_access_control from SHAPE_MAP**

Remove this line from `SHAPE_MAP` (line 38):

```python
        "network_access_control": "process",
```

- [ ] **Step 3: Remove network_access_control from Z_INDEX**

Remove this line from `Z_INDEX` (line 50):

```python
        "network_access_control": 11,
```

- [ ] **Step 4: Add safety filter in _create_node_cells**

In `_create_node_cells` (line 139), add a filter at the start of the method to skip and warn on NAC components:

```python
    def _create_node_cells(self):
        """Create node cells for gateway, compute, service, storage, and actor components."""
        nodes = [c for c in self.components if c["type"] in self.LEAF_TYPES]

        # Safety filter: warn and skip any network_access_control components
        # that the LLM may still emit despite prompt changes
        skipped = [c for c in self.components if c["type"] == "network_access_control"]
        for component in skipped:
            logger.warning(
                "Skipping network_access_control component '%s' (%s) — "
                "security controls should be in parent boundary metadata",
                component.get("name", "unknown"),
                component["id"],
            )

        for component in nodes:
            z_index = self.Z_INDEX.get(component["type"], 11)
            cell = self._create_node_cell(component, z_index)

            # Add ports for all connectable leaf nodes
            cell["ports"] = self._create_ports()

            self.cells.append(cell)
            self.component_cells[component["id"]] = cell
```

- [ ] **Step 5: Run all tests**

Run: `uv run pytest tests/test_diagram_builder.py -v`

Expected: ALL PASS, including the new `TestNetworkAccessControlRemoval` tests.

- [ ] **Step 6: Run linter and type checker**

Run: `uv run ruff check tmi_tf/diagram_builder.py tests/test_diagram_builder.py`
Run: `uv run ruff format --check tmi_tf/diagram_builder.py tests/test_diagram_builder.py`
Run: `uv run pyright`

Expected: No errors.

- [ ] **Step 7: Commit**

```bash
git add tmi_tf/diagram_builder.py
git commit -m "refactor: remove network_access_control from DFD diagram builder

Remove NAC from LEAF_TYPES, SHAPE_MAP, and Z_INDEX. Add safety filter
that logs a warning and skips any NAC components the LLM may still emit.

Refs #6"
```

---

### Task 7: Full test suite and final verification

Run the complete test suite and verify everything passes.

**Files:**
- None (verification only)

- [ ] **Step 1: Run full test suite**

Run: `uv run pytest tests/ -v`

Expected: ALL PASS.

- [ ] **Step 2: Run full lint and type check**

Run: `uv run ruff check tmi_tf/ tests/`
Run: `uv run ruff format --check tmi_tf/ tests/`
Run: `uv run pyright`

Expected: No errors.

- [ ] **Step 3: Review all changes**

Run: `git diff main --stat` to verify only expected files were changed:
- `prompts/dfd_generation_system.txt` — NAC removal, security controls handling section
- `prompts/infrastructure_analysis_system.txt` — Mermaid label changes
- `tmi_tf/diagram_builder.py` — NAC removal from type sets, safety filter
- `tests/test_diagram_builder.py` — Updated and new tests
- `docs/superpowers/specs/2026-04-04-remove-security-control-nodes-design.md` — Design doc
- `docs/superpowers/plans/2026-04-04-remove-security-control-nodes.md` — This plan
