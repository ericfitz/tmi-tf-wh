# Design: Remove Non-Inline Security Controls from Diagrams

**Date**: 2026-04-04
**Issue**: [#6](https://github.com/ericfitz/tmi-tf-wh/issues/6)

## Goal

Stop rendering security controls (security groups, NACLs, WAFs, firewall rules, etc.) as standalone nodes in Mermaid and DFD diagrams. Instead, fold their information into the parent/containing object — as label text in Mermaid diagrams, and as metadata in DFD diagrams. Security controls remain in the Phase 1 inventory as `security_control` components (no inventory changes).

## Approach

Prompt-level changes (Approach A). Modify the LLM prompts so the model stops generating security controls as diagram nodes from the start. A lightweight safety filter in `diagram_builder.py` drops any stray `network_access_control` nodes the LLM might still emit. No post-processing flow-collapsing logic.

## Decisions

- **Inventory**: Unchanged. `security_control` remains a valid Phase 1 component type. The inventory table still lists all security controls.
- **Mermaid diagrams**: Security control info appended to the label of the parent/containing node (e.g., `"Web Subnet\nsecurity group: sg-web-rules"`). No standalone security control nodes.
- **DFD diagrams**: Security control info added as metadata on the parent boundary component (e.g., `{"key": "security_control", "value": "sg-web-rules"}`). No standalone `network_access_control` nodes. No label changes.
- **Flows**: Go directly between source and target. No intermediary security control nodes. The LLM is instructed to generate direct flows.
- **Multiple protected objects**: Security control metadata goes on the parent/containing object, not on each individual protected child.

## Changes

### Prompt Changes

#### `prompts/infrastructure_analysis_system.txt`

- Modify Mermaid diagram instructions: security controls are not drawn as nodes.
- Instruct the LLM to append security control info to the label of the parent/containing node.
- Remove instructions about routing flows through security control nodes — flows go directly between source and target.

#### `prompts/dfd_generation_system.txt`

- Remove `network_access_control` from the valid component types list.
- Add instructions to: (a) identify security controls from the inventory, (b) add their info as metadata key-value pairs on the parent boundary component, (c) generate flows directly between source and target with no NAC intermediaries.
- Remove NAC-specific ranking and placement rules.

#### `prompts/dfd_generation_user.txt`

- Remove any references to `network_access_control` type if present.

### Python Code Changes

#### `tmi_tf/diagram_builder.py`

- Remove `network_access_control` from `LEAF_TYPES`.
- Remove `network_access_control` from `SHAPE_MAP`.
- Add safety filter: if a component with type `network_access_control` is encountered, log a warning and skip cell creation.

### No Changes To

- `prompts/inventory_system.txt` — security controls remain in inventory
- `tmi_tf/llm_analyzer.py` — pipeline unchanged
- `tmi_tf/dfd_llm_generator.py` — passes data to LLM, no structural change
- `tmi_tf/analyzer.py` — orchestration unchanged
- `tmi_tf/markdown_generator.py` — report generation unchanged
- `tmi_tf/threat_processor.py` — threat processing unchanged
- `tmi_tf/cli.py` — CLI unchanged

## Testing

- Update existing tests that assert on `network_access_control` component generation or NAC node creation in diagram_builder to reflect new behavior.
- Add test: `network_access_control` component in LLM output is skipped with a warning (safety filter).
- Add test: no cells are created for NAC types.
- No new LLM integration tests — prompt changes are validated by LLM output at runtime.
