# External Dependency Tracking Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add external service dependency tracking to Phase 1 inventory, DFD metadata, and analysis report.

**Architecture:** Modify Phase 1 inventory prompt to extract per-component dependencies (type/provider/service) and a top-level dependency summary. Update DFD prompt to serialize dependencies into component metadata. Add a new External Dependencies table to the analysis report.

**Tech Stack:** Python 3.13, pytest, ruff, pyright, LLM prompt templates (plain text)

---

### Task 1: Update Phase 1 inventory prompt

Add dependency extraction instructions and output schema to the inventory prompt.

**Files:**
- Modify: `prompts/inventory_system.txt`

- [ ] **Step 1: Add dependencies field to the component schema**

In `prompts/inventory_system.txt`, find the Component Extraction section (line 17). After the `- **purpose**:` line (line 24), add:

```
- **dependencies**: Array of external service dependencies for this component. Most Terraform resources have at least one dependency — the service that Terraform instructs to instantiate the resource. Each dependency is an object with:
  - **type**: One of: "cloud" (AWS, Azure, GCP, OCI services), "saas" (GitHub, Salesforce, Google Sign-In, etc.), "on-prem" (Active Directory, locally-deployed Vault, on-prem databases, etc.)
  - **provider**: The organization providing the service (e.g., "AWS", "Microsoft", "Google", "Hashicorp", "Salesforce")
  - **service**: The specific service name (e.g., "S3", "EC2", "Active Directory", "Vault", "Sales Cloud")
```

- [ ] **Step 2: Update the output JSON structure**

Replace the output structure section (lines 9-13):

```
The JSON must have this structure:
{
  "components": [ ... ],
  "services": [ ... ]
}
```

With:

```
The JSON must have this structure:
{
  "components": [ ... ],
  "services": [ ... ],
  "dependencies": [ ... ]
}
```

- [ ] **Step 3: Add dependency summary section**

Before the `CRITICAL: Return ONLY the JSON object` line at the end of the file (line 45), add:

```
# Dependency Summary

After extracting all components, produce a top-level "dependencies" array that aggregates unique service dependencies across all components. Each entry includes:

- **type**: "cloud", "saas", or "on-prem"
- **provider**: The service provider name
- **service**: The specific service name
- **dependent_components**: Array of component IDs that depend on this service

Deduplicate by (type, provider, service) — if multiple components depend on the same service, list all their IDs in dependent_components.

Example:
{
  "dependencies": [
    {
      "type": "cloud",
      "provider": "AWS",
      "service": "S3",
      "dependent_components": ["aws_s3_bucket.logs", "aws_s3_bucket.data"]
    },
    {
      "type": "cloud",
      "provider": "AWS",
      "service": "EC2",
      "dependent_components": ["aws_instance.web_server"]
    },
    {
      "type": "on-prem",
      "provider": "Hashicorp",
      "service": "Vault",
      "dependent_components": ["aws_instance.app_server"]
    }
  ]
}
```

- [ ] **Step 4: Commit**

```bash
git add prompts/inventory_system.txt
git commit -m "feat(prompts): add dependency extraction to inventory prompt

Phase 1 now extracts per-component service dependencies (type, provider,
service) and produces a top-level dependency summary aggregating unique
dependencies with their dependent component IDs.

Refs #7"
```

---

### Task 2: Update DFD generation prompt

Instruct the LLM to transfer per-component dependencies from inventory into DFD component metadata.

**Files:**
- Modify: `prompts/dfd_generation_system.txt`

- [ ] **Step 1: Add dependency metadata instructions**

In `prompts/dfd_generation_system.txt`, find the `## Components` subsection within `# Output Format` (around line 162). After the `- **metadata**` line (line 174), add:

```
  - If the inventory component has a `dependencies` array, include it in metadata as a JSON-encoded string:
    {"key": "dependencies", "value": "[{\"type\":\"cloud\",\"provider\":\"AWS\",\"service\":\"S3\"}]"}
    Serialize the component's dependencies array as a JSON string. Include all dependency objects from the inventory component.
```

- [ ] **Step 2: Commit**

```bash
git add prompts/dfd_generation_system.txt
git commit -m "feat(prompts): add dependency metadata to DFD generation prompt

DFD components now include a 'dependencies' metadata key with a
JSON-serialized array of service dependencies from the inventory.

Refs #7"
```

---

### Task 3: Write failing test for External Dependencies table

Add a test for the new `_format_dependencies_section` method in the markdown generator.

**Files:**
- Modify: `tests/test_markdown_generator.py`

- [ ] **Step 1: Write the test class**

Add at the end of `tests/test_markdown_generator.py`:

```python
class TestMarkdownGeneratorDependencies:
    """Test external dependencies section generation."""

    def test_empty_dependencies(self):
        gen = MarkdownGenerator()
        result = gen._format_dependencies_section({"dependencies": []})
        assert result == ""

    def test_no_dependencies_key(self):
        gen = MarkdownGenerator()
        result = gen._format_dependencies_section({})
        assert result == ""

    def test_dependencies_table(self):
        gen = MarkdownGenerator()
        inventory = {
            "dependencies": [
                {
                    "type": "cloud",
                    "provider": "AWS",
                    "service": "S3",
                    "dependent_components": [
                        "aws_s3_bucket.logs",
                        "aws_s3_bucket.data",
                    ],
                },
                {
                    "type": "saas",
                    "provider": "Google",
                    "service": "Sign-In",
                    "dependent_components": ["aws_lambda.auth"],
                },
            ]
        }
        result = gen._format_dependencies_section(inventory)
        assert "External Dependencies" in result
        assert "<table" in result
        assert "AWS" in result
        assert "S3" in result
        assert "cloud" in result
        assert "Google" in result
        assert "Sign-In" in result
        assert "saas" in result
        # Dependent components should be rendered as a list
        assert "<ul>" in result
        assert "<li>aws_s3_bucket.logs</li>" in result
        assert "<li>aws_s3_bucket.data</li>" in result
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_markdown_generator.py::TestMarkdownGeneratorDependencies -v`

Expected: FAIL — `_format_dependencies_section` does not exist yet.

- [ ] **Step 3: Commit failing tests**

```bash
git add tests/test_markdown_generator.py
git commit -m "test: add failing tests for External Dependencies table

Tests verify the new _format_dependencies_section method renders
dependency data as an HTML table with type, provider, service, and
dependent component list columns.

Refs #7"
```

---

### Task 4: Write failing test for dependencies in analysis report

Verify the analysis report includes the External Dependencies section.

**Files:**
- Modify: `tests/test_markdown_generator.py`

- [ ] **Step 1: Update the _make_analysis helper**

In `tests/test_markdown_generator.py`, update the `_make_analysis` function. Add a `dependencies` key to the `inventory` dict (after the `"services"` key, around line 36):

```python
            "dependencies": [
                {
                    "type": "cloud",
                    "provider": "AWS",
                    "service": "EC2",
                    "dependent_components": ["web-server"],
                },
            ],
```

- [ ] **Step 2: Add the test**

Add to the `TestGenerateAnalysisReport` class:

```python
    def test_includes_external_dependencies(self):
        gen = MarkdownGenerator()
        report = gen.generate_analysis_report("TM", "tm-1", [_make_analysis()])
        assert "External Dependencies" in report
        assert "AWS" in report
        assert "EC2" in report
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `uv run pytest tests/test_markdown_generator.py::TestGenerateAnalysisReport::test_includes_external_dependencies -v`

Expected: FAIL — the analysis report doesn't call `_format_dependencies_section` yet.

- [ ] **Step 4: Commit failing test**

```bash
git add tests/test_markdown_generator.py
git commit -m "test: add failing test for dependencies in analysis report

Verifies that generate_analysis_report includes the External
Dependencies section when dependency data is present in the inventory.

Refs #7"
```

---

### Task 5: Implement External Dependencies table in markdown generator

Add `_format_dependencies_section` and wire it into the analysis report.

**Files:**
- Modify: `tmi_tf/markdown_generator.py`

- [ ] **Step 1: Add _format_dependencies_section method**

In `tmi_tf/markdown_generator.py`, add the following method to the `MarkdownGenerator` class, after `_format_data_flows_section` (after line 360):

```python
    def _format_dependencies_section(self, inventory: Dict[str, Any]) -> str:
        """Format external dependencies into markdown section with HTML table."""
        dependencies = inventory.get("dependencies", [])
        if not dependencies:
            return ""

        parts = ["### External Dependencies"]

        rows: List[List[str]] = []
        for dep in dependencies:
            dep_type = _esc(dep.get("type", ""))
            provider = _esc(dep.get("provider", ""))
            service = _esc(dep.get("service", ""))
            components = dep.get("dependent_components", [])
            rows.append([dep_type, provider, service, _html_list(components)])

        parts.append(
            _html_table(
                ["Type", "Provider", "Service", "Dependent Components"],
                rows,
                col_widths=["10%", "15%", "20%", "55%"],
            )
        )

        return "\n\n".join(parts)
```

- [ ] **Step 2: Wire into generate_analysis_report**

In the `generate_analysis_report` method (line 590), add a call to `_format_dependencies_section` between the data flows and security sections. Find these lines (around line 610-612):

```python
            parts.append(self._format_data_flows_section(analysis.infrastructure))
            parts.append(self._format_security_section(analysis.security_findings))
```

Insert between them:

```python
            parts.append(self._format_dependencies_section(analysis.inventory))
```

So it becomes:

```python
            parts.append(self._format_data_flows_section(analysis.infrastructure))
            parts.append(self._format_dependencies_section(analysis.inventory))
            parts.append(self._format_security_section(analysis.security_findings))
```

- [ ] **Step 3: Run all markdown generator tests**

Run: `uv run pytest tests/test_markdown_generator.py -v`

Expected: ALL PASS.

- [ ] **Step 4: Run linter and type checker**

Run: `uv run ruff check tmi_tf/markdown_generator.py tests/test_markdown_generator.py`
Run: `uv run ruff format --check tmi_tf/markdown_generator.py tests/test_markdown_generator.py`
Run: `uv run pyright`

Expected: No errors.

- [ ] **Step 5: Commit**

```bash
git add tmi_tf/markdown_generator.py
git commit -m "feat: add External Dependencies table to analysis report

New _format_dependencies_section renders dependency data (type, provider,
service, dependent components) as an HTML table. Placed between Data Flows
and Security Observations in the analysis report.

Refs #7"
```

---

### Task 6: Full test suite and final verification

Run the complete test suite and verify everything passes.

**Files:**
- None (verification only)

- [ ] **Step 1: Run full test suite**

Run: `uv run pytest tests/ -v`

Expected: ALL PASS (except pre-existing test_config.py failures).

- [ ] **Step 2: Run full lint and type check**

Run: `uv run ruff check tmi_tf/ tests/`
Run: `uv run ruff format --check tmi_tf/ tests/`
Run: `uv run pyright`

Expected: No errors.

- [ ] **Step 3: Review all changes**

Run: `git log --oneline 37f2d3a..HEAD` to verify commits:
1. Inventory prompt — dependency extraction
2. DFD prompt — dependency metadata
3. Tests — failing tests for dependencies table
4. Tests — failing test for analysis report
5. Implementation — `_format_dependencies_section` + wiring
