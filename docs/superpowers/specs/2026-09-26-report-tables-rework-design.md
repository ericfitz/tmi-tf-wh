# Report tables rework (#10 subtasks 2-3) — design

Date: 2026-09-26. Issue: #10 (subtask 2: rework report tables; subtask 3: consolidate inventory tables).

## Human decisions (Eric, 2026-09-26)

- **Two notes per run, split by kind** (not one combined note). The inventory note holds every table; the analysis note holds the narrative and findings.
- **Multi-value cells use `<br>`** inside markdown pipe tables (TMI permits safe inline HTML; `br` and `code` are in our nh3 allow-list).
- **Configuration shown = registry `security_attrs`, re-applied at render time**, so the full-LLM fallback path is filtered too. Registry-unknown types show no configuration.

## Goal

Notes that are readable as plain markdown, show only security-relevant settings, and do not split related tables across two notes.

## Note layout

Note names stay as today (`Terraform Inventory (...)`, `Terraform Analysis (...)`, per-run, see `analyzer.py`).

Inventory note (`generate_inventory_report`), per repository:

1. Components, grouped by category (existing `type_order`)
2. Services
3. Relationships (moved from analysis note)
4. Data flows (moved)
5. Trust boundaries (moved)
6. External dependencies (moved)

then Analysis job info.

Analysis note (`generate_analysis_report`), per repository:

1. Architecture summary
2. Mermaid architecture diagram
3. One line: "Inventory, relationships, data flows, trust boundaries and dependencies: see note *<inventory note name>*." (`analyzer.py` passes the inventory note name in.)
4. Security observations

then Consolidated findings and Analysis job info.

## Tables

- All tables are markdown pipe tables: components, services, relationships, data flows, trust boundaries, dependencies, security observations, consolidated findings, job info.
- `_html_table`, `_html_list`, `_config_nested_table` are removed, replaced by:
  - `_md_cell(value)` — str / list → cell text: HTML-escape, `|` → `\|`, newlines → `<br>`; a list joins its escaped items with `<br>`; empty → `—`.
  - `_md_table(headers, rows)` — header row, `|---|` separator, one line per row. Rows are pre-rendered cell strings.
- Column widths (HTML `colgroup`) are dropped; markdown cannot express them.
- The dead combined report (`generate_report`, `_generate_repository_sections`, `_generate_header`) is removed.

### Configuration cell

- Rendered from the component's `configuration` by re-applying the registry: `tf_filter._select(config, tf_filter._attr_tree(registry.security_attrs(resource_type)))`, imported from `tf_filter` (made public if needed), not reimplemented.
- The `_select` rule that keeps any reference-bearing attribute does not apply here: the report shows registry-listed paths only. References are covered by the Relationships table.
- Registry-unknown resource types (`security_attrs` is `None`) → `—`.
- Nested dicts/lists flatten to dot paths, one `` `path = value` `` line per leaf, joined with `<br>`; list indices are omitted when the list has one element, otherwise `path[i]`.
- No key-count cap. Each value is truncated at 120 characters with `…`.
- `MarkdownGenerator` receives the `Registry` (default: `load_registry()`).

## Testing

- Rewrite `tests/test_markdown_generator.py` helpers tests for `_md_cell` / `_md_table` (escaping, `|`, lists, empty).
- Section placement: inventory note contains the relationships/flows/boundaries/dependencies headings; analysis note does not, and contains the pointer line.
- Configuration filter: registry-known type drops a non-security attribute; unknown type renders `—`; LLM-fallback-shaped configuration (unfiltered dict) is filtered; nested block flattens to dot paths; long value truncates.
- Size sanity: a 150-component fixture renders well under TMI's 262,144-character note cap.

## Out of scope

- #14 script/metadata risk analysis (separate spec).
- Changing note names, note metadata, or the DFD.
