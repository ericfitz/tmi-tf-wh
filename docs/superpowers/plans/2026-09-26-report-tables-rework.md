# Report Tables Rework Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the two TMI notes readable as plain markdown (pipe tables, no HTML tables), show only registry-listed security attributes in the Configuration column, and move every table into the inventory note so related tables are not split across notes.

**Architecture:** `tmi_tf/markdown_generator.py` gets two tiny helpers (`_md_cell`, `_md_table`) that replace `_html_table`/`_html_list`/`_config_nested_table`; a `_config_cell` helper re-applies the resource registry (`tf_filter._select` / `_attr_tree`) to each component's `configuration` at render time and flattens the result to `` `dot.path = value` `` lines. `generate_inventory_report` gains the relationships / data flows / trust boundaries / dependencies sections; `generate_analysis_report` loses them and gets a one-line pointer to the inventory note. The dead combined report (`generate_report`, `_generate_repository_sections`, `_generate_header`) is deleted. `analyzer.py` passes the inventory note name into the analysis report.

**Tech Stack:** Python 3.10+, stdlib `html.escape` / `json`, existing `tmi_tf.tf_filter` registry code, pytest. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-26-report-tables-rework-design.md`

## Global Constraints

- Branch is `feat/10-followups`; do not switch branches. Never touch `HANDOFF.md`.
- Python floor 3.10 (`requires-python = ">=3.10"`).
- Note names stay as today (`Terraform Inventory (...)`, `Terraform Analysis (...)`); note metadata and the DFD are unchanged.
- Multi-value cells use `<br>` (TMI's nh3 allow-list permits `br` and `code`).
- Configuration shown = registry `security_attrs`, re-applied at render time via `tf_filter._select(config, tf_filter._attr_tree(attrs))`, never reimplemented. Registry-unknown types (`security_attrs()` returns `None`) render `—`.
- No key-count cap; each configuration value truncated at 120 characters with `…`.
- The TMI note cap is 262,144 characters; a 150-component fixture must render well under it.
- Every task ends with all four green, then a commit:
  `uv run ruff format tmi_tf/ tests/` (fix), `uv run ruff check tmi_tf/ tests/`, `uv run ruff format --check tmi_tf/ tests/`, `uv run pyright`, `uv run pytest tests/`.
- Commit messages `feat(#10): ...` / `refactor(#10): ...` / `test(#10): ...`, ending with the trailer lines:

```
Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01N62rqqmm3Y4M72NtUMEA9i
```

## Facts implementers need

- `tmi_tf/markdown_generator.py` (664 lines today) renders from `TerraformAnalysis` (`tmi_tf/llm_analyzer.py`): fields `repo_name`, `repo_url`, `inventory: dict`, `infrastructure: dict`, `security_findings: list[dict]`, `success`, `error_message`, `elapsed_time`, `input_tokens`, `output_tokens`, `model`, `provider`, `total_cost`.
- `inventory["components"]` items: `{id, name, type, resource_type, configuration, purpose, ...}`. On the static path `configuration` is already `clean_value`'d: plain `str`/`bool`/`int`/`list`/`dict`, no `${...}` wrappers, no `__is_block__` keys. hcl2 nested blocks arrive as a **list of one dict** (`root_block_device: [{"encrypted": true}]`), which is why single-element lists drop their index. On the full-LLM fallback path `configuration` is whatever dict the LLM emitted (may be missing, may not be a dict).
- `name` can be `None` on a component (pre-built inventory before merge); fall back to `id`.
- `tf_filter._attr_tree(paths: list[str]) -> dict` builds a nested keep-tree (`None` = keep whole subtree); `tf_filter._select(value, tree)` keeps only keys in the tree, recursing through dicts and mapping over lists. It also keeps `dynamic` keys and reference-bearing values, but clean values contain no `${`, so the reference rule is inert here. Import both privately (`from tmi_tf.tf_filter import Registry, _attr_tree, _select, load_registry`); ruff's default rule set does not flag private imports.
- `Registry` (frozen dataclass in `tf_filter.py`): `Registry(providers={}, resources={...}, hash_only_attrs=frozenset(), data_hash_only_attrs=frozenset())`; `security_attrs(rt) -> list[str] | None`. Real registry: `load_registry()`; `aws_instance` lists `ami`, `root_block_device.encrypted`, ... but **not** `instance_type`.
- `MarkdownGenerator()` is constructed with no args in `tmi_tf/analyzer.py:261` and `tmi_tf/cli.py:186`; `tests/test_analyzer.py:179` patches the class. Keep the no-arg constructor working.
- `analyzer.py:451-465` calls `generate_inventory_report(...)` then `generate_analysis_report(...)`; `inventory_note_name` is defined at `analyzer.py:435-445` before both calls.
- The old helpers `_esc`, `_html_list`, `_html_table`, `_config_nested_table` and the old tests in `tests/test_markdown_generator.py` (`TestEsc`, `TestHtmlList`, `TestHtmlTable`, `TestConfigNestedTable`) are deleted in Task 5. Until then, keep them so the suite stays green at every commit.

## Decisions made while planning

1. `_select` / `_attr_tree` are imported as private names, not made public (nothing in the toolchain objects).
2. Configuration lines are markdown code spans (`` `path = value` ``) joined by `<br>` **outside** the spans. Code-span content is not HTML-escaped (a renderer shows entities literally inside code); instead backticks in a value become `'`, `|` becomes `\|`, and whitespace runs/newlines collapse to one space. Non-string leaves render via `json.dumps` (`true`, `null`, `{}`), so Terraform booleans read as Terraform.
3. Empty dict/list leaves render as `{}` / `[]`; a dict with only `__`-prefixed keys yields no lines. A configuration that filters to nothing renders `—`.
4. `_md_cell` treats `None`, `""` and `[]` as empty (`—`); list items that are `None`/`""` are skipped.
5. Resource type, CWE ids and configuration paths render in backticks; all other text goes through `_md_cell`. Headers are literal constants, never escaped.
6. Metrics totals row is bolded with `**...**`; column alignment is dropped along with widths.
7. Trust boundaries become their own `### Trust Boundaries` section (own method) instead of a sub-heading under Data Flows, and no longer depend on data flows existing.
8. `generate_analysis_report(..., inventory_note_name: str | None = None)`: the pointer line is emitted only when a name is given (CLI file output and existing tests pass none).
9. Component `name` falls back to `id`, then `"Unknown"`.
10. Each task rewrites the tests for the sections it converts (old `<table`/`<ul>` assertions would fail), so the suite is green at every commit.

## Review Focus

1. A component with `configuration` that is not a dict (LLM fallback emitted a string or `null`) must render `—`, never raise. Test: Task 2 `test_non_dict_config_is_dash`.
2. A configuration value containing `|`, a backtick or a newline must not break the pipe table or the code span. Test: Task 2 `test_leaf_text_escapes_pipe_backtick_newline`.
3. A cell value (name, purpose, description) containing `|`, `<`, or newlines must stay inside its cell and be inert HTML. Test: Task 1 `test_md_cell_escapes_pipe_html_and_newline`.
4. A component with `name: None` (pre-merge inventory) must show its `id`, not the text `None`. Test: Task 3 `test_name_falls_back_to_id`.
5. Trust boundaries with no data flows must still render in the inventory note. Test: Task 4 `test_trust_boundaries_without_flows`.

## File Structure

- Modify `tmi_tf/markdown_generator.py`: new helpers `_md_cell`, `_md_table`, `_flatten`, `_leaf_text`, `_config_cell`; `MarkdownGenerator.__init__(registry)`; section methods rewritten; dead combined report removed.
- Modify `tmi_tf/analyzer.py:460-465`: pass `inventory_note_name`.
- Rewrite `tests/test_markdown_generator.py` incrementally (one class per section).
- Add one assertion to `tests/test_analyzer.py` (Task 6) only if a test already exercises the analysis-report call; otherwise none (the class is patched there).

---

### Task 1: `_md_cell` and `_md_table` helpers

**Files:**
- Modify: `tmi_tf/markdown_generator.py` (module-level helpers, after `_esc`)
- Test: `tests/test_markdown_generator.py`

**Interfaces:**
- Produces: `_md_cell(value: Any) -> str`, `_md_table(headers: list[str], rows: list[list[str]]) -> str`. Rows are pre-rendered cell strings.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_markdown_generator.py`; add `_md_cell, _md_table` to the existing `from tmi_tf.markdown_generator import (...)`)

```python
class TestMdCell:
    def test_plain_text(self):
        assert _md_cell("hello") == "hello"

    def test_md_cell_escapes_pipe_html_and_newline(self):
        assert _md_cell("a|b") == "a\\|b"
        assert _md_cell("<script>") == "&lt;script&gt;"
        assert _md_cell("line1\nline2") == "line1<br>line2"

    def test_list_joins_with_br(self):
        assert _md_cell(["a", "b|c", "<d>"]) == "a<br>b\\|c<br>&lt;d&gt;"

    def test_empty_is_dash(self):
        assert _md_cell("") == "—"
        assert _md_cell(None) == "—"
        assert _md_cell([]) == "—"
        assert _md_cell(["", None]) == "—"

    def test_non_string_scalars(self):
        assert _md_cell(443) == "443"
        assert _md_cell(5.0) == "5.0"


class TestMdTable:
    def test_basic_table(self):
        assert _md_table(["A", "B"], [["1", "2"], ["3", "4"]]) == (
            "| A | B |\n|---|---|\n| 1 | 2 |\n| 3 | 4 |"
        )

    def test_empty_rows_still_has_header_and_separator(self):
        assert _md_table(["A"], []) == "| A |\n|---|"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_markdown_generator.py -k "TestMdCell or TestMdTable" -v`
Expected: ImportError (`_md_cell` not defined).

- [ ] **Step 3: Implement** (insert after `_esc` in `tmi_tf/markdown_generator.py`)

```python
def _md_cell(value: Any) -> str:
    """One markdown table cell: HTML-escaped, ``|`` escaped, newlines as <br>.

    A list joins its items with <br>; anything empty renders as an em dash.
    """
    items = value if isinstance(value, list) else [value]
    lines = [
        html_escape(str(v), quote=True).replace("|", "\\|").replace("\n", "<br>")
        for v in items
        if v is not None and str(v) != ""
    ]
    return "<br>".join(lines) or "—"


def _md_table(headers: list[str], rows: list[list[str]]) -> str:
    """Markdown pipe table; ``rows`` are pre-rendered cell strings."""
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(lines)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_markdown_generator.py -v`
Expected: all PASS (old tests untouched).

- [ ] **Step 5: Lint, type-check, commit**

```bash
uv run ruff format tmi_tf/ tests/ && uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright && uv run pytest tests/
git add tmi_tf/markdown_generator.py tests/test_markdown_generator.py
git commit -m "feat(#10): markdown pipe-table cell and table helpers"
```

---

### Task 2: Registry-filtered configuration cell

**Files:**
- Modify: `tmi_tf/markdown_generator.py` (imports, helpers after `_md_table`, `MarkdownGenerator.__init__`)
- Test: `tests/test_markdown_generator.py`

**Interfaces:**
- Consumes: `tf_filter._select`, `tf_filter._attr_tree`, `tf_filter.Registry`, `tf_filter.load_registry`.
- Produces: `_config_cell(config: Any, attrs: list[str] | None) -> str`; `_flatten(value, prefix="") -> list[tuple[str, Any]]`; `_leaf_text(value) -> str`; `MarkdownGenerator(registry: Registry | None = None)` with attribute `self._registry`.

- [ ] **Step 1: Write the failing tests** (append; extend the import with `_config_cell, _flatten, _leaf_text`; add `from tmi_tf.tf_filter import Registry`)

```python
def _fake_registry() -> Registry:
    return Registry(
        providers={},
        resources={
            "aws_instance": {
                "category": "compute",
                "security_attrs": ["ami", "root_block_device.encrypted", "metadata_options"],
            }
        },
        hash_only_attrs=frozenset(),
        data_hash_only_attrs=frozenset(),
    )


class TestFlatten:
    def test_scalar(self):
        assert _flatten({"a": 1}) == [("a", 1)]

    def test_nested_dict_dot_path(self):
        assert _flatten({"a": {"b": {"c": "x"}}}) == [("a.b.c", "x")]

    def test_single_element_list_omits_index(self):
        assert _flatten({"blk": [{"enc": True}]}) == [("blk.enc", True)]

    def test_multi_element_list_indexes(self):
        assert _flatten({"ids": ["x", "y"]}) == [("ids[0]", "x"), ("ids[1]", "y")]

    def test_empty_containers_are_leaves(self):
        assert _flatten({"a": {}, "b": []}) == [("a", {}), ("b", [])]

    def test_bookkeeping_keys_skipped(self):
        assert _flatten({"__is_block__": True, "a": 1}) == [("a", 1)]


class TestLeafText:
    def test_bool_and_none_are_json(self):
        assert _leaf_text(True) == "true"
        assert _leaf_text(None) == "null"

    def test_truncates_at_120(self):
        text = _leaf_text("x" * 200)
        assert text == "x" * 120 + "…"

    def test_leaf_text_escapes_pipe_backtick_newline(self):
        assert _leaf_text("a|b") == "a\\|b"
        assert _leaf_text("a`b") == "a'b"
        assert _leaf_text("a\n  b") == "a b"


class TestConfigCell:
    ATTRS = ["ami", "root_block_device.encrypted", "metadata_options"]

    def test_drops_non_security_attr(self):
        cell = _config_cell({"ami": "ami-1", "instance_type": "t3.micro"}, self.ATTRS)
        assert cell == "`ami = ami-1`"

    def test_unknown_type_is_dash(self):
        assert _config_cell({"ami": "ami-1"}, None) == "—"

    def test_non_dict_config_is_dash(self):
        assert _config_cell(None, self.ATTRS) == "—"
        assert _config_cell("t3.micro", self.ATTRS) == "—"

    def test_nothing_kept_is_dash(self):
        assert _config_cell({"instance_type": "t3.micro"}, self.ATTRS) == "—"

    def test_nested_block_flattens_to_dot_path(self):
        cfg = {"root_block_device": [{"encrypted": True, "volume_size": 10}]}
        assert _config_cell(cfg, self.ATTRS) == "`root_block_device.encrypted = true`"

    def test_whole_subtree_kept_and_joined_with_br(self):
        cfg = {"ami": "ami-1", "metadata_options": [{"http_tokens": "required", "hop": 1}]}
        assert _config_cell(cfg, self.ATTRS) == (
            "`ami = ami-1`<br>`metadata_options.http_tokens = required`"
            "<br>`metadata_options.hop = 1`"
        )

    def test_llm_fallback_shaped_config_is_filtered(self):
        # Fallback path: arbitrary LLM dict, no registry filtering upstream.
        cfg = {"instance_type": "t3.micro", "ami": "ami-1", "tags": {"Name": "web"}}
        assert _config_cell(cfg, self.ATTRS) == "`ami = ami-1`"

    def test_long_value_truncates(self):
        cell = _config_cell({"ami": "a" * 200}, self.ATTRS)
        assert cell == "`ami = " + "a" * 120 + "…`"


class TestGeneratorRegistry:
    def test_default_registry_is_loaded(self):
        gen = MarkdownGenerator()
        assert gen._registry.security_attrs("aws_instance") is not None

    def test_injected_registry(self):
        reg = _fake_registry()
        assert MarkdownGenerator(reg)._registry is reg
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_markdown_generator.py -k "Flatten or LeafText or ConfigCell or GeneratorRegistry" -v`
Expected: ImportError.

- [ ] **Step 3: Implement**

Add imports at the top of `tmi_tf/markdown_generator.py`:

```python
import json
from tmi_tf.tf_filter import Registry, _attr_tree, _select, load_registry
```

Insert after `_md_table`:

```python
_VALUE_MAX = 120


def _flatten(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    """(dot.path, leaf) pairs. Single-element lists drop their index (hcl2
    renders nested blocks as one-element lists); longer lists use ``path[i]``."""
    if isinstance(value, dict) and value:
        return [
            leaf
            for k, v in value.items()
            if not k.startswith("__")
            for leaf in _flatten(v, f"{prefix}.{k}" if prefix else k)
        ]
    if isinstance(value, list) and value:
        if len(value) == 1:
            return _flatten(value[0], prefix)
        return [
            leaf
            for i, v in enumerate(value)
            for leaf in _flatten(v, f"{prefix}[{i}]")
        ]
    return [(prefix, value)]


def _leaf_text(value: Any) -> str:
    """Value text for a code span: whitespace collapsed, truncated, and
    ``|``/backtick made safe (code spans are not HTML-escaped)."""
    text = value if isinstance(value, str) else json.dumps(value)
    text = " ".join(text.split())
    if len(text) > _VALUE_MAX:
        text = text[:_VALUE_MAX] + "…"
    return text.replace("`", "'").replace("|", "\\|")


def _config_cell(config: Any, attrs: list[str] | None) -> str:
    """Configuration column: registry security_attrs re-applied at render
    time (so the full-LLM fallback path is filtered too), one
    `` `path = value` `` per leaf, joined with <br>."""
    if attrs is None or not isinstance(config, dict):
        return "—"
    selected = _select(config, _attr_tree(attrs))
    lines = [f"`{path} = {_leaf_text(v)}`" for path, v in _flatten(selected)]
    return "<br>".join(lines) or "—"
```

Add to `MarkdownGenerator` (first method in the class):

```python
    def __init__(self, registry: Registry | None = None) -> None:
        self._registry = registry or load_registry()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_markdown_generator.py -v`
Expected: all PASS.

- [ ] **Step 5: Lint, type-check, commit**

```bash
uv run ruff format tmi_tf/ tests/ && uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright && uv run pytest tests/
git add tmi_tf/markdown_generator.py tests/test_markdown_generator.py
git commit -m "feat(#10): registry-filtered configuration cell for reports"
```

---

### Task 3: Components and services as markdown tables

**Files:**
- Modify: `tmi_tf/markdown_generator.py` (`_format_inventory_section`)
- Test: `tests/test_markdown_generator.py` (`TestMarkdownGeneratorInventory` rewritten)

**Interfaces:**
- Consumes: `_md_cell`, `_md_table`, `_config_cell`, `self._registry` (Task 1-2).
- Produces: `_format_inventory_section(self, inventory: dict) -> str` (unchanged signature; headings `### Infrastructure Inventory`, `#### <Category>`, `#### Services (Logical Groupings)`).

- [ ] **Step 1: Replace `TestMarkdownGeneratorInventory` with the failing tests**

```python
class TestMarkdownGeneratorInventory:
    def test_empty_components(self):
        gen = MarkdownGenerator(_fake_registry())
        result = gen._format_inventory_section({"components": []})
        assert "No infrastructure components identified" in result

    def test_components_table_filters_configuration(self):
        gen = MarkdownGenerator(_fake_registry())
        inventory = {
            "components": [
                {
                    "type": "compute",
                    "name": "Web Server",
                    "resource_type": "aws_instance",
                    "purpose": "Serves web traffic",
                    "configuration": {"instance_type": "t3.micro", "ami": "ami-123"},
                }
            ]
        }
        result = gen._format_inventory_section(inventory)
        assert "#### Compute" in result
        assert "| Name | Resource Type | Purpose | Configuration |" in result
        assert "|---|---|---|---|" in result
        assert "| Web Server | `aws_instance` | Serves web traffic | `ami = ami-123` |" in result
        assert "t3.micro" not in result
        assert "<table" not in result

    def test_unknown_resource_type_config_is_dash(self):
        gen = MarkdownGenerator(_fake_registry())
        inventory = {
            "components": [
                {
                    "type": "other",
                    "name": "thing",
                    "resource_type": "vendor_widget",
                    "purpose": "p",
                    "configuration": {"secret": "x"},
                }
            ]
        }
        result = gen._format_inventory_section(inventory)
        assert "| thing | `vendor_widget` | p | — |" in result
        assert "secret" not in result

    def test_name_falls_back_to_id(self):
        gen = MarkdownGenerator(_fake_registry())
        inventory = {
            "components": [
                {"id": "aws_instance.web", "name": None, "type": "compute",
                 "resource_type": "aws_instance", "purpose": None, "configuration": {}}
            ]
        }
        result = gen._format_inventory_section(inventory)
        assert "| aws_instance.web | `aws_instance` | — | — |" in result
        assert "None" not in result

    def test_services_table(self):
        gen = MarkdownGenerator(_fake_registry())
        inventory = {
            "components": [
                {"type": "compute", "name": "web-1", "resource_type": "aws_instance",
                 "purpose": "Web server"}
            ],
            "services": [
                {
                    "name": "web-frontend",
                    "criteria": ["shared VPC", "naming pattern"],
                    "compute_units": ["web-1", "web-2"],
                    "associated_resources": ["alb-1"],
                }
            ],
        }
        result = gen._format_inventory_section(inventory)
        assert "#### Services (Logical Groupings)" in result
        assert "| web-frontend | shared VPC<br>naming pattern | web-1<br>web-2 | alb-1 |" in result
        assert "<ul>" not in result
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_markdown_generator.py::TestMarkdownGeneratorInventory -v`
Expected: FAIL (HTML table output).

- [ ] **Step 3: Rewrite `_format_inventory_section`** (keep `type_order` and the `by_type` grouping loop exactly as today; replace the row building and table calls)

```python
            rows: list[list[str]] = []
            for comp in group:
                resource_type = comp.get("resource_type") or ""
                rows.append(
                    [
                        _md_cell(comp.get("name") or comp.get("id") or "Unknown"),
                        f"`{resource_type}`" if resource_type else "—",
                        _md_cell(comp.get("purpose")),
                        _config_cell(
                            comp.get("configuration"),
                            self._registry.security_attrs(resource_type),
                        ),
                    ]
                )
            parts.append(
                _md_table(["Name", "Resource Type", "Purpose", "Configuration"], rows)
            )
```

and for services:

```python
            rows = [
                [
                    _md_cell(svc.get("name") or "Unknown"),
                    _md_cell(svc.get("criteria", [])),
                    _md_cell(svc.get("compute_units", [])),
                    _md_cell(svc.get("associated_resources", [])),
                ]
                for svc in services
            ]
            parts.append(
                _md_table(
                    ["Service", "Criteria", "Compute Units", "Associated Resources"], rows
                )
            )
```

`self._registry.security_attrs("")` returns `None` for an empty resource type, so a component without a type renders `—`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_markdown_generator.py -v`
Expected: all PASS. (`TestGenerateInventoryReport` still passes: it only checks headings and names.)

- [ ] **Step 5: Lint, type-check, commit**

```bash
uv run ruff format tmi_tf/ tests/ && uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright && uv run pytest tests/
git add tmi_tf/markdown_generator.py tests/test_markdown_generator.py
git commit -m "feat(#10): components and services as markdown tables"
```

---

### Task 4: Relationships, data flows, trust boundaries, dependencies as markdown tables

**Files:**
- Modify: `tmi_tf/markdown_generator.py` (`_format_relationships_section`, `_format_data_flows_section`, new `_format_trust_boundaries_section`, `_format_dependencies_section`, and the two call sites in `generate_analysis_report` / `_generate_repository_sections`)
- Test: `tests/test_markdown_generator.py` (`TestMarkdownGeneratorDataFlows`, `TestMarkdownGeneratorDependencies` rewritten; new `TestMarkdownGeneratorRelationships`, `TestMarkdownGeneratorTrustBoundaries`)

**Interfaces:**
- Produces: `_format_relationships_section(self, infrastructure) -> str` (`### Component Relationships`, `#### <Relationship Type>` groups); `_format_data_flows_section(self, infrastructure) -> str` (`### Data Flows` only); `_format_trust_boundaries_section(self, infrastructure) -> str` (`### Trust Boundaries`); `_format_dependencies_section(self, inventory) -> str` (`### External Dependencies`). Each returns `""` when its list is empty.

- [ ] **Step 1: Replace `TestMarkdownGeneratorDataFlows` and `TestMarkdownGeneratorDependencies`; add the two new classes**

```python
class TestMarkdownGeneratorRelationships:
    def test_empty(self):
        gen = MarkdownGenerator(_fake_registry())
        assert gen._format_relationships_section({"relationships": []}) == ""

    def test_grouped_table(self):
        gen = MarkdownGenerator(_fake_registry())
        infra = {
            "relationships": [
                {"source_id": "web", "target_id": "db", "relationship_type": "connects_to",
                 "description": "Web | DB"},
            ]
        }
        result = gen._format_relationships_section(infra)
        assert "### Component Relationships" in result
        assert "#### Connects To" in result
        assert "| Source | Target | Description |" in result
        assert "| web | db | Web \\| DB |" in result


class TestMarkdownGeneratorDataFlows:
    def test_empty_flows(self):
        gen = MarkdownGenerator(_fake_registry())
        assert gen._format_data_flows_section({"data_flows": []}) == ""

    def test_flows_table(self):
        gen = MarkdownGenerator(_fake_registry())
        infra = {
            "data_flows": [
                {"name": "Web Traffic", "source_id": "lb-1", "target_id": "web-1",
                 "protocol": "HTTPS", "port": 443, "data_type": "API requests"}
            ]
        }
        result = gen._format_data_flows_section(infra)
        assert "### Data Flows" in result
        assert "| Flow | Source | Target | Protocol | Port | Data Type |" in result
        assert "| Web Traffic | lb-1 | web-1 | HTTPS | 443 | API requests |" in result
        assert "Trust Boundaries" not in result


class TestMarkdownGeneratorTrustBoundaries:
    def test_empty(self):
        gen = MarkdownGenerator(_fake_registry())
        assert gen._format_trust_boundaries_section({}) == ""

    def test_trust_boundaries_without_flows(self):
        gen = MarkdownGenerator(_fake_registry())
        infra = {
            "data_flows": [],
            "trust_boundaries": [
                {"name": "Public Zone", "boundary_type": "network",
                 "component_ids": ["lb-1", "web-1"]}
            ],
        }
        result = gen._format_trust_boundaries_section(infra)
        assert "### Trust Boundaries" in result
        assert "| Boundary | Type | Components |" in result
        assert "| Public Zone | network | lb-1<br>web-1 |" in result


class TestMarkdownGeneratorDependencies:
    def test_empty_dependencies(self):
        gen = MarkdownGenerator(_fake_registry())
        assert gen._format_dependencies_section({"dependencies": []}) == ""
        assert gen._format_dependencies_section({}) == ""

    def test_dependencies_table(self):
        gen = MarkdownGenerator(_fake_registry())
        inventory = {
            "dependencies": [
                {"type": "cloud", "provider": "AWS", "service": "S3",
                 "dependent_components": ["aws_s3_bucket.logs", "aws_s3_bucket.data"]},
                {"type": "saas", "provider": "Google", "service": "Sign-In",
                 "dependent_components": ["aws_lambda.auth"]},
            ]
        }
        result = gen._format_dependencies_section(inventory)
        assert "### External Dependencies" in result
        assert "| Type | Provider | Service | Dependent Components |" in result
        assert "| cloud | AWS | S3 | aws_s3_bucket.logs<br>aws_s3_bucket.data |" in result
        assert "| saas | Google | Sign-In | aws_lambda.auth |" in result
        assert "<ul>" not in result
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_markdown_generator.py -k "Relationships or DataFlows or TrustBoundaries or Dependencies" -v`
Expected: FAIL / AttributeError for `_format_trust_boundaries_section`.

- [ ] **Step 3: Rewrite the four section methods**

```python
    def _format_relationships_section(self, infrastructure: dict[str, Any]) -> str:
        relationships = infrastructure.get("relationships", [])
        if not relationships:
            return ""
        by_type: dict[str, list[dict[str, Any]]] = {}
        for rel in relationships:
            by_type.setdefault(rel.get("relationship_type", "other"), []).append(rel)
        parts = ["### Component Relationships"]
        for rel_type, rels in by_type.items():
            parts.append(f"#### {rel_type.replace('_', ' ').title()}")
            rows = [
                [
                    _md_cell(rel.get("source_id", "?")),
                    _md_cell(rel.get("target_id", "?")),
                    _md_cell(rel.get("description")),
                ]
                for rel in rels
            ]
            parts.append(_md_table(["Source", "Target", "Description"], rows))
        return "\n\n".join(parts)

    def _format_data_flows_section(self, infrastructure: dict[str, Any]) -> str:
        flows = infrastructure.get("data_flows", [])
        if not flows:
            return ""
        keys = ("name", "source_id", "target_id", "protocol", "port", "data_type")
        rows = [[_md_cell(flow.get(k)) for k in keys] for flow in flows]
        return "### Data Flows\n\n" + _md_table(
            ["Flow", "Source", "Target", "Protocol", "Port", "Data Type"], rows
        )

    def _format_trust_boundaries_section(self, infrastructure: dict[str, Any]) -> str:
        boundaries = infrastructure.get("trust_boundaries", [])
        if not boundaries:
            return ""
        rows = [
            [
                _md_cell(b.get("name")),
                _md_cell(b.get("boundary_type")),
                _md_cell(b.get("component_ids", [])),
            ]
            for b in boundaries
        ]
        return "### Trust Boundaries\n\n" + _md_table(
            ["Boundary", "Type", "Components"], rows
        )

    def _format_dependencies_section(self, inventory: dict[str, Any]) -> str:
        dependencies = inventory.get("dependencies", [])
        if not dependencies:
            return ""
        rows = [
            [
                _md_cell(dep.get("type")),
                _md_cell(dep.get("provider")),
                _md_cell(dep.get("service")),
                _md_cell(dep.get("dependent_components", [])),
            ]
            for dep in dependencies
        ]
        return "### External Dependencies\n\n" + _md_table(
            ["Type", "Provider", "Service", "Dependent Components"], rows
        )
```

In `generate_analysis_report` (and `_generate_repository_sections`, until Task 6 deletes it) add `parts.append(self._format_trust_boundaries_section(analysis.infrastructure))` right after the data-flows append, so trust boundaries keep rendering.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_markdown_generator.py -v`
Expected: all PASS.

- [ ] **Step 5: Lint, type-check, commit**

```bash
uv run ruff format tmi_tf/ tests/ && uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright && uv run pytest tests/
git add tmi_tf/markdown_generator.py tests/test_markdown_generator.py
git commit -m "feat(#10): relationship, flow, boundary and dependency markdown tables"
```

---

### Task 5: Security findings and job-info tables; delete the HTML helpers

**Files:**
- Modify: `tmi_tf/markdown_generator.py` (`_format_security_section`, `_generate_analysis_job_info`; delete `_esc`, `_html_list`, `_html_table`, `_config_nested_table`, the `Sequence` import)
- Test: `tests/test_markdown_generator.py` (rewrite `TestMarkdownGeneratorSecurity`, `TestMarkdownGeneratorMetrics`; delete `TestEsc`, `TestHtmlList`, `TestHtmlTable`, `TestConfigNestedTable`; drop the deleted names from the import)

**Interfaces:**
- Produces: `_format_security_section(self, security_findings) -> str` (`### Security Observations`); `_generate_analysis_job_info(self, threat_model_id, analyses) -> str` (unchanged signature).

- [ ] **Step 1: Rewrite the tests**

Delete `TestEsc`, `TestHtmlList`, `TestHtmlTable`, `TestConfigNestedTable` and remove `_config_nested_table, _esc, _html_list, _html_table` from the import. Replace the two classes:

```python
class TestMarkdownGeneratorSecurity:
    def test_no_findings(self):
        gen = MarkdownGenerator(_fake_registry())
        assert "No security findings identified" in gen._format_security_section([])

    def test_findings_table(self):
        gen = MarkdownGenerator(_fake_registry())
        findings = [
            {
                "name": "SQL Injection",
                "severity": "High",
                "score": 8.5,
                "description": "desc",
                "threat_type": "Tampering",
                "category": "Input Validation",
                "mitigation": "Use parameterized queries",
                "cwe_id": ["CWE-89", "CWE-564"],
                "affected_components": ["db-1", "api-1"],
            }
        ]
        result = gen._format_security_section(findings)
        assert "### Security Observations" in result
        assert (
            "| Finding | Severity | STRIDE | Category | Description | Mitigation "
            "| Affected Components |"
        ) in result
        assert (
            "| SQL Injection<br>`CWE-89` `CWE-564` | High (8.5) | Tampering "
            "| Input Validation | desc | Use parameterized queries | db-1<br>api-1 |"
        ) in result
        assert "<table" not in result

    def test_severity_without_score(self):
        gen = MarkdownGenerator(_fake_registry())
        findings = [{"name": "F", "severity": "Low", "cwe_id": [], "affected_components": []}]
        result = gen._format_security_section(findings)
        assert "| F | Low | — | — | — | — | — |" in result


class TestMarkdownGeneratorMetrics:
    def test_metrics_table_structure(self):
        gen = MarkdownGenerator(_fake_registry())
        analysis = TerraformAnalysis(
            repo_name="test-repo",
            repo_url="https://github.com/test/repo",
            success=True,
            elapsed_time=10.5,
            input_tokens=1000,
            output_tokens=500,
            total_cost=0.05,
            model="test-model",
            provider="test-provider",
        )
        result = gen._generate_analysis_job_info("tm-123", [analysis])
        assert "| Repository | Time | Input Tokens | Output Tokens | Cost |" in result
        assert "| test-repo | 10.50s | 1,000 | 500 | $0.0500 |" in result
        assert "| **Total** | **10.50s** | **1,000** | **500** | **$0.0500** |" in result
        assert "<table" not in result
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_markdown_generator.py -k "Security or Metrics" -v`
Expected: FAIL (HTML output).

- [ ] **Step 3: Rewrite the two methods, delete the helpers**

```python
    def _format_security_section(self, security_findings: list[dict[str, Any]]) -> str:
        if not security_findings:
            return "### Security Observations\n\nNo security findings identified."
        rows: list[list[str]] = []
        for finding in security_findings:
            name = _md_cell(finding.get("name", "Unknown"))
            cwe_ids = finding.get("cwe_id", [])
            if cwe_ids:
                name += "<br>" + " ".join(f"`{_md_cell(c)}`" for c in cwe_ids)
            severity = _md_cell(finding.get("severity", "Medium"))
            score = finding.get("score")
            if score is not None:
                severity += f" ({_md_cell(score)})"
            rows.append(
                [
                    name,
                    severity,
                    _md_cell(finding.get("threat_type")),
                    _md_cell(finding.get("category")),
                    _md_cell(finding.get("description")),
                    _md_cell(finding.get("mitigation")),
                    _md_cell(finding.get("affected_components", [])),
                ]
            )
        return "### Security Observations\n\n" + _md_table(
            ["Finding", "Severity", "STRIDE", "Category", "Description", "Mitigation",
             "Affected Components"],
            rows,
        )
```

In `_generate_analysis_job_info`, keep everything up to the per-repository rows; change the repo-name cell to `_md_cell(a.repo_name)`, bold the totals row and use `_md_table`:

```python
            rows.append(
                [
                    f"**{c}**"
                    for c in (
                        "Total",
                        f"{total_time:.2f}s",
                        f"{total_input:,}",
                        f"{total_output:,}",
                        f"${total_cost:.4f}",
                    )
                ]
            )
            parts.append(
                _md_table(
                    ["Repository", "Time", "Input Tokens", "Output Tokens", "Cost"], rows
                )
            )
```

Delete `_esc`, `_html_list`, `_html_table`, `_config_nested_table` and `from collections.abc import Sequence`. Run `rg -n '_esc\(|_html_|_config_nested' tmi_tf/ tests/` and expect no hits.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_markdown_generator.py -v`
Expected: all PASS.

- [ ] **Step 5: Lint, type-check, commit**

```bash
uv run ruff format tmi_tf/ tests/ && uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright && uv run pytest tests/
git add tmi_tf/markdown_generator.py tests/test_markdown_generator.py
git commit -m "refactor(#10): security and metrics as markdown tables; drop HTML helpers"
```

---

### Task 6: Two-note split, pointer line, dead combined report removed

**Files:**
- Modify: `tmi_tf/markdown_generator.py` (`generate_inventory_report`, `generate_analysis_report`; delete `generate_report`, `_generate_header`, `_generate_repository_sections`)
- Modify: `tmi_tf/analyzer.py:460-465` (pass `inventory_note_name`)
- Test: `tests/test_markdown_generator.py` (`TestGenerateInventoryReport`, `TestGenerateAnalysisReport` rewritten)

**Interfaces:**
- Produces: `generate_analysis_report(self, threat_model_name, threat_model_id, analyses, environment_name=None, inventory_note_name: str | None = None) -> str`. `generate_inventory_report` signature unchanged.

- [ ] **Step 1: Replace the two report test classes**

```python
INFRA_HEADINGS = (
    "### Component Relationships",
    "### Data Flows",
    "### Trust Boundaries",
    "### External Dependencies",
)


class TestGenerateInventoryReport:
    def test_contains_all_tables(self):
        gen = MarkdownGenerator(_fake_registry())
        analysis = _make_analysis()
        analysis.infrastructure["trust_boundaries"] = [
            {"name": "Edge", "boundary_type": "network", "component_ids": ["web"]}
        ]
        report = gen.generate_inventory_report("TM", "tm-1", [analysis])
        assert "### Infrastructure Inventory" in report
        assert "web-server" in report
        assert "web-service" in report
        for heading in INFRA_HEADINGS:
            assert heading in report
        assert "Edge" in report
        assert "EC2" in report
        assert "## Analysis Job Information" in report

    def test_section_order(self):
        gen = MarkdownGenerator(_fake_registry())
        analysis = _make_analysis()
        analysis.infrastructure["trust_boundaries"] = [
            {"name": "Edge", "boundary_type": "network", "component_ids": ["web"]}
        ]
        report = gen.generate_inventory_report("TM", "tm-1", [analysis])
        positions = [report.index(h) for h in ("### Infrastructure Inventory", *INFRA_HEADINGS)]
        assert positions == sorted(positions)

    def test_excludes_analysis_sections(self):
        gen = MarkdownGenerator(_fake_registry())
        report = gen.generate_inventory_report("TM", "tm-1", [_make_analysis()])
        assert "Security Observations" not in report
        assert "Open port" not in report
        assert "Architecture Summary" not in report
        assert "Consolidated Findings" not in report

    def test_environment_name_in_title(self):
        gen = MarkdownGenerator(_fake_registry())
        report = gen.generate_inventory_report(
            "TM", "tm-1", [_make_analysis()], environment_name="oci-private"
        )
        assert "# Terraform Infrastructure Inventory - oci-private" in report

    def test_failed_analysis(self):
        gen = MarkdownGenerator(_fake_registry())
        failed = TerraformAnalysis(
            repo_name="bad", repo_url="https://x/bad", success=False, error_message="boom"
        )
        report = gen.generate_inventory_report("TM", "tm-1", [failed])
        assert "*Analysis failed: boom*" in report


class TestGenerateAnalysisReport:
    def test_contains_narrative_and_findings(self):
        gen = MarkdownGenerator(_fake_registry())
        report = gen.generate_analysis_report("TM", "tm-1", [_make_analysis()])
        assert "### Architecture Summary" in report
        assert "simple web app" in report
        assert "```mermaid" in report
        assert "### Security Observations" in report
        assert "Open port" in report
        assert "## Consolidated Findings" in report
        assert "## Analysis Job Information" in report

    def test_excludes_inventory_tables(self):
        gen = MarkdownGenerator(_fake_registry())
        report = gen.generate_analysis_report("TM", "tm-1", [_make_analysis()])
        assert "Infrastructure Inventory" not in report
        for heading in INFRA_HEADINGS:
            assert heading not in report
        assert "EC2" not in report

    def test_pointer_line(self):
        gen = MarkdownGenerator(_fake_registry())
        report = gen.generate_analysis_report(
            "TM", "tm-1", [_make_analysis()],
            inventory_note_name="Terraform Inventory (m, 2026-09-26 00:00:00 UTC)",
        )
        assert (
            "Inventory, relationships, data flows, trust boundaries and dependencies: "
            "see note *Terraform Inventory (m, 2026-09-26 00:00:00 UTC)*."
        ) in report
        assert report.index("see note *") < report.index("### Security Observations")

    def test_no_pointer_without_name(self):
        gen = MarkdownGenerator(_fake_registry())
        report = gen.generate_analysis_report("TM", "tm-1", [_make_analysis()])
        assert "see note *" not in report

    def test_environment_name_in_title(self):
        gen = MarkdownGenerator(_fake_registry())
        report = gen.generate_analysis_report(
            "TM", "tm-1", [_make_analysis()], environment_name="aws-public"
        )
        assert "# Terraform Infrastructure Analysis - aws-public" in report

    def test_combined_report_removed(self):
        assert not hasattr(MarkdownGenerator, "generate_report")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_markdown_generator.py -k "GenerateInventoryReport or GenerateAnalysisReport" -v`
Expected: FAIL (`INFRA_HEADINGS` missing from inventory, unexpected kwarg, `generate_report` present).

- [ ] **Step 3: Implement**

Delete `generate_report`, `_generate_header`, `_generate_repository_sections` from `MarkdownGenerator`. Replace the per-repository body of the two report methods:

```python
    def generate_inventory_report(
        self,
        threat_model_name: str,
        threat_model_id: str,
        analyses: list[TerraformAnalysis],
        environment_name: str | None = None,
    ) -> str:
        """Inventory note: every table (components, services, relationships,
        data flows, trust boundaries, dependencies) plus job info."""
        sections = []
        title = "Terraform Infrastructure Inventory"
        if environment_name:
            title += f" - {environment_name}"
        sections.append(f"# {title}\n\n**Threat Model**: {threat_model_name}")

        for i, analysis in enumerate(analyses, 1):
            header = f"## Repository {i}: {analysis.repo_name}\n\n**URL**: [{analysis.repo_url}]({analysis.repo_url})"
            if not analysis.success:
                sections.append(f"{header}\n\n*Analysis failed: {analysis.error_message}*")
                continue
            parts = [
                header,
                self._format_inventory_section(analysis.inventory),
                self._format_relationships_section(analysis.infrastructure),
                self._format_data_flows_section(analysis.infrastructure),
                self._format_trust_boundaries_section(analysis.infrastructure),
                self._format_dependencies_section(analysis.inventory),
            ]
            sections.append("\n\n".join(part for part in parts if part))

        sections.append(self._generate_analysis_job_info(threat_model_id, analyses))
        return "\n\n---\n\n".join(sections)

    def generate_analysis_report(
        self,
        threat_model_name: str,
        threat_model_id: str,
        analyses: list[TerraformAnalysis],
        environment_name: str | None = None,
        inventory_note_name: str | None = None,
    ) -> str:
        """Analysis note: architecture narrative, diagram, pointer to the
        inventory note, security findings, consolidated findings, job info."""
        sections = []
        title = "Terraform Infrastructure Analysis"
        if environment_name:
            title += f" - {environment_name}"
        sections.append(f"# {title}\n\n**Threat Model**: {threat_model_name}")

        for i, analysis in enumerate(analyses, 1):
            header = f"## Repository {i}: {analysis.repo_name}\n\n**URL**: [{analysis.repo_url}]({analysis.repo_url})"
            if not analysis.success:
                sections.append(f"{header}\n\n*Analysis failed: {analysis.error_message}*")
                continue
            parts = [header]
            arch_summary = analysis.infrastructure.get("architecture_summary", "")
            if arch_summary:
                parts.append(f"### Architecture Summary\n\n{arch_summary}")
            mermaid = analysis.infrastructure.get("mermaid_diagram", "")
            if mermaid:
                if not mermaid.strip().startswith("```"):
                    mermaid = f"```mermaid\n{mermaid}\n```"
                parts.append(f"### Architecture Diagram\n\n{mermaid}")
            if inventory_note_name:
                parts.append(
                    "Inventory, relationships, data flows, trust boundaries and "
                    f"dependencies: see note *{inventory_note_name}*."
                )
            parts.append(self._format_security_section(analysis.security_findings))
            sections.append("\n\n".join(part for part in parts if part))

        sections.append(self._generate_consolidated_findings(analyses))
        sections.append(self._generate_analysis_job_info(threat_model_id, analyses))
        return "\n\n---\n\n".join(sections)
```

In `tmi_tf/analyzer.py` add one kwarg to the `generate_analysis_report` call (around line 460):

```python
        analysis_content = markdown_gen.generate_analysis_report(
            threat_model_name=threat_model.name,
            threat_model_id=threat_model_id,
            analyses=analyses,
            environment_name=selected_env_name,
            inventory_note_name=inventory_note_name,
        )
```

Confirm nothing else references the deleted methods: `rg -n 'generate_report\b|_generate_header|_generate_repository_sections' tmi_tf/ tests/` must return nothing. Update the module docstring of `tests/test_markdown_generator.py` to `"""Tests for markdown report generation."""`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_markdown_generator.py tests/test_analyzer.py -v`
Expected: all PASS.

- [ ] **Step 5: Lint, type-check, commit**

```bash
uv run ruff format tmi_tf/ tests/ && uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright && uv run pytest tests/
git add tmi_tf/markdown_generator.py tmi_tf/analyzer.py tests/test_markdown_generator.py
git commit -m "feat(#10): move all tables to the inventory note; analysis note points to it"
```

---

### Task 7: Size sanity test and final verification

**Files:**
- Test: `tests/test_markdown_generator.py` (append)

- [ ] **Step 1: Write the size test**

```python
class TestNoteSize:
    TMI_NOTE_CAP = 262_144

    def test_150_components_fit_under_note_cap(self):
        gen = MarkdownGenerator()  # real registry
        components = [
            {
                "id": f"aws_instance.web_{i}",
                "name": f"web-{i}",
                "type": "compute",
                "resource_type": "aws_instance",
                "purpose": "Serves web traffic for tenant " + "x" * 40,
                "configuration": {
                    "ami": f"ami-{i:08d}",
                    "instance_type": "t3.micro",
                    "subnet_id": f"aws_subnet.private_{i}.id",
                    "vpc_security_group_ids": [f"aws_security_group.web_{i}.id"],
                    "root_block_device": [{"encrypted": True, "volume_size": 20}],
                    "metadata_options": [{"http_tokens": "required", "http_endpoint": "enabled"}],
                    "user_data": "sha256:" + "ab" * 32,
                    "tags": {"Name": f"web-{i}", "Team": "platform"},
                },
            }
            for i in range(150)
        ]
        analysis = _make_analysis()
        analysis.inventory["components"] = components
        analysis.infrastructure["relationships"] = [
            {"source_id": f"aws_instance.web_{i}", "target_id": "aws_db_instance.main",
             "relationship_type": "connects_to", "description": "app to database"}
            for i in range(150)
        ]
        report = gen.generate_inventory_report("TM", "tm-1", [analysis])
        assert len(report) < self.TMI_NOTE_CAP // 2
        assert "t3.micro" not in report
        assert "`root_block_device.encrypted = true`" in report
```

- [ ] **Step 2: Run it**

Run: `uv run pytest tests/test_markdown_generator.py::TestNoteSize -v`
Expected: PASS (roughly 60-80 KB rendered). If it fails on size, report the length; do not raise the cap.

- [ ] **Step 3: Full verification**

```bash
uv run ruff format tmi_tf/ tests/ && uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright && uv run pytest tests/
rg -n '<table|<ul>|<li>|colgroup' tmi_tf/markdown_generator.py   # expect no hits
```

- [ ] **Step 4: Commit**

```bash
git add tests/test_markdown_generator.py
git commit -m "test(#10): note size sanity for 150-component inventory"
```

---

## Self-review (done while writing)

- Spec coverage: helpers (T1), configuration cell + registry injection (T2), components/services tables (T3), relationships/flows/boundaries/dependencies tables (T4), security/job-info tables + helper deletion (T5), note split + pointer line + dead-report removal + `analyzer.py` (T6), size sanity (T7). Column widths dropped (T3-T5 use `_md_table` only). Note names untouched.
- Type consistency: `_config_cell(config, attrs)` used identically in T2 and T3; `_format_trust_boundaries_section` defined in T4 and called in T6; `inventory_note_name` kwarg matches between T6 test, method and `analyzer.py`.
- Review Focus tests are pinned: T2 `test_non_dict_config_is_dash`, T2 `test_leaf_text_escapes_pipe_backtick_newline`, T1 `test_md_cell_escapes_pipe_html_and_newline`, T3 `test_name_falls_back_to_id`, T4 `test_trust_boundaries_without_flows`.
- Deviation from spec: `_md_cell` HTML-escapes plain cells as the spec says, but configuration code spans are not HTML-escaped (Decision 2) because markdown code spans render entities literally.
