# Environment Selection, Status Tracking, and Report Splitting

**Date:** 2026-03-18
**Status:** Draft

## Overview

Four interconnected changes to tmi-tf:

1. **Environment detection & selection** — detect Terraform root modules in cloned repos, prompt the user to pick one if multiple exist, resolve module dependencies, analyze only the selected environment
2. **Status tracking note** — create a well-known TMI note that tracks analysis progress with timestamped status lines, updated at each processing step
3. **Report splitting** — separate the single markdown report into an inventory report and an analysis report, each stored as its own TMI note
4. **Artifact naming with environment** — include the selected environment name in all generated artifact names (notes, diagrams), with no truncation

## Feature 1: Environment Detection & Selection

### Data Model

New dataclass in `repo_analyzer.py`:

```python
@dataclass
class TerraformEnvironment:
    name: str          # e.g. "oci-private" or "terraform/environments/oci-private" if disambiguation needed
    path: Path         # absolute path to the environment directory
    tf_files: list[Path]  # .tf/.tfvars files in the environment directory (non-recursive)
```

`TerraformRepository` gains two fields:

```python
environment_name: str | None    # selected environment name, None if no environments detected
environments_found: list[str]   # all detected environment names (for reporting)
```

### Environment Detection

New method `detect_environments(clone_path: Path) -> list[TerraformEnvironment]`:

1. Recursively find all directories containing `main.tf` or `backend.tf`
2. Exclude directories where any path segment is `modules` (these are shared modules, not environments)
3. For each candidate directory:
   - Derive `name` from the directory name relative to the repo root
   - If duplicate names exist (e.g. two directories both named `prod` at different depths), use the relative path from the repo root to disambiguate
   - Collect all `.tf` and `.tfvars` files directly in that directory (non-recursive)
4. Return sorted list of `TerraformEnvironment` objects

**Scope limitation:** Detection uses `main.tf` or `backend.tf` as root module indicators. Projects using other conventions (e.g. Terragrunt with `terragrunt.hcl`, or root modules without `main.tf`/`backend.tf`) are not detected and fall back to analyzing all `.tf` files. This can be extended in the future.

### Module Resolution

New method `resolve_modules(environment: TerraformEnvironment, clone_path: Path) -> list[Path]`:

1. Parse each `.tf` file in the environment directory for `module` blocks
2. Extract `source` attribute values using regex (pattern: `source\s*=\s*"([^"]+)"`)
3. Filter to relative paths only (starting with `./` or `../`). Log a debug message for non-relative sources (registry, absolute) so the user knows those modules were skipped.
4. Resolve each relative path from the environment directory
5. For each resolved module directory that exists, recursively collect all `.tf` files
6. Return combined list: environment `.tf`/`.tfvars` files + all resolved module `.tf` files
7. Deduplicate paths (a module could be referenced multiple times)

**Regex approach note:** The regex `source\s*=\s*"([^"]+)"` is intentionally broad — it matches `source` attributes in any block type, not just `module` blocks. This is acceptable because the subsequent filtering (relative paths only, path must exist on disk) discards false positives. This avoids the complexity of a full HCL parser.

**Transitive modules:** Module resolution is one level deep. If module A references module B, B's files are included via recursive `.tf` collection within A's directory. Cross-directory transitive references (module A at `modules/network/` referencing module B at `modules/dns/`) are not followed. This is acceptable for the common pattern where environments reference top-level modules.

**Sparse checkout compatibility:** The existing sparse checkout patterns (`*.tf`, `*.tfvars`) already check out files at any directory depth, so module `.tf` files are available without changes to the clone logic.

### CLI Flow

New CLI flag: `--environment` / `-e` (optional string) — pre-selects an environment by name, skipping the interactive prompt. Useful for scripting and when the same environment should be analyzed across multiple repos.

In `cli.py`, after cloning a repository:

1. Call `detect_environments(clone_path)`
2. **0 environments found:** Fall back to current behavior — analyze all `.tf` files in the repo. Set `environment_name = None`.
3. **1 environment found:** Auto-select it. Log the selection. Set `environment_name` to the environment name.
4. **Multiple environments found:**
   - If `--environment` flag was provided, match by name (case-insensitive). Error if no match.
   - Otherwise, print a numbered list of environment names
   - Use `click.prompt()` with type `click.IntRange(1, len(environments))` for selection
   - Set `environment_name` to the selected environment name
5. Call `resolve_modules()` for the selected environment
6. Replace `TerraformRepository.terraform_files` with the resolved file list
7. Set `TerraformRepository.environment_name` and `TerraformRepository.environments_found`

The environment prompt is per-repo. If the `--environment` flag is provided, it applies to all repos (matched by name).

**Ctrl+C handling:** If the user presses Ctrl+C during the environment selection prompt, catch `click.Abort` and exit cleanly with message "Analysis cancelled by user" (no stack trace).

## Feature 2: Status Tracking Note

### Implementation

New method on `TMIClientWrapper`:

```python
def update_status_note(self, threat_model_id: str, message: str) -> None
```

Behavior:

- Note name is a constant: `"TMI-TF Analysis Status"`
- Timestamps formatted as `YYYY-MM-DD HH:MM:SS UTC` (UTC, consistent with artifact naming)
- First call per run: finds existing note by name (or creates new one), overwrites content with `[timestamp] message`. This means each run replaces the previous run's status.
- Subsequent calls: appends `\n[timestamp] message` to existing content
- Caches the note ID after first lookup to avoid repeated searches
- If the status note update fails, logs a warning but does not fail the analysis

Internal state:

- `_status_note_id: str | None` — cached note ID, None until first call
- `_status_note_initialized: bool` — False until first update completes, controls overwrite vs append

### Status Update Points

Updates in `cli.py` at these milestones:

| # | Message | When |
|---|---------|------|
| 1 | `Analysis started` | After TMI client initialization |
| 2 | `Cloning repository: <url>` | Before each repo clone |
| 3 | `Clone complete: <repo_name>` | After successful clone |
| 4 | `Found <N> Terraform environment(s): <comma-separated names>` | After environment detection |
| 5 | `Selected environment: <name>` | After auto-select or user pick |
| 6 | `Resolving modules for environment: <name>` | Before module resolution |
| 7 | `Phase 1 (Inventory) started` | Via callback from LLM analyzer |
| 8 | `Phase 1 (Inventory) complete` | Via callback from LLM analyzer |
| 9 | `Phase 2 (Infrastructure) started` | Via callback from LLM analyzer |
| 10 | `Phase 2 (Infrastructure) complete` | Via callback from LLM analyzer |
| 11 | `Phase 3 (Security) started` | Via callback from LLM analyzer |
| 12 | `Phase 3 (Security) complete` | Via callback from LLM analyzer |
| 13 | `Generating inventory report` | Before inventory report generation |
| 14 | `Generating analysis report` | Before analysis report generation |
| 15 | `Generating DFD diagram` | Before DFD generation |
| 16 | `Creating threats` | Before threat creation |
| 17 | `Analysis complete` | At the end of the analyze command |

### LLM Analyzer Callback

`llm_analyzer.py` changes:

- `analyze_repository()` accepts optional parameter `status_callback: Callable[[str], None] | None = None`
- Calls `status_callback("Phase N (Name) started")` before each phase
- Calls `status_callback("Phase N (Name) complete")` after each phase
- If `status_callback` is None, no calls are made (backward compatible)

## Feature 3: Report Splitting

### Two Report Methods

Replace `MarkdownGenerator.generate_report()` with:

**`generate_inventory_report(threat_model_name, threat_model_id, analyses, environment_name=None) -> str`**

Contents:
- Title: "Terraform Infrastructure Inventory" (with environment name if present)
- Per-repo sections:
  - Infrastructure Inventory (component tables grouped by type)
  - Services listing
- Analysis Job Information (metadata, tokens, cost)

**`generate_analysis_report(threat_model_name, threat_model_id, analyses, environment_name=None) -> str`**

Contents:
- Title: "Terraform Infrastructure Analysis" (with environment name if present)
- Per-repo sections:
  - Architecture Summary + Mermaid diagram
  - Component Relationships
  - Data Flows
  - Security Observations
- Consolidated Findings
- Analysis Job Information (metadata, tokens, cost)

### Shared Code

Existing private helper methods (`_html_table()`, `_format_component_table()`, etc.) remain as methods on `MarkdownGenerator` and are used by both report methods.

### CLI Changes

The single "generate report + create note" block in `cli.py` becomes two sequential blocks:

1. Generate inventory markdown → create/update inventory note in TMI → set metadata
2. Generate analysis markdown → create/update analysis note in TMI → set metadata

**`--output` flag:** When `--output` is specified, write both reports to files. If the output path is `report.md`, write `report-inventory.md` and `report-analysis.md` (insert suffix before extension).

## Feature 4: Artifact Naming with Environment

### Name Patterns

All names constructed with simple f-strings, no truncation applied to any component:

| Artifact | With Environment | Without Environment (fallback) |
|----------|-----------------|-------------------------------|
| Inventory note | `Terraform Inventory - {env} ({model}, {timestamp})` | `Terraform Inventory ({model}, {timestamp})` |
| Analysis note | `Terraform Analysis - {env} ({model}, {timestamp})` | `Terraform Analysis ({model}, {timestamp})` |
| DFD diagram | `Infrastructure Data Flow Diagram - {env} ({model}, {timestamp})` | `Infrastructure Data Flow Diagram ({model}, {timestamp})` |
| Status note | `TMI-TF Analysis Status` | `TMI-TF Analysis Status` |
| Threats | No change (LLM-generated names) | No change |

### Name Construction

Names are constructed in `cli.py` directly rather than through `config.py`, since the environment name is determined at runtime after cloning.

`config.py` changes:
- Remove `analysis_note_name` and `diagram_name` properties
- Remove `ANALYSIS_NOTE_NAME` and `DIAGRAM_NAME` env var support (these are no longer used since naming is fully dynamic)
- Keep `effective_model` and timestamp accessible for name construction in CLI
- Timestamp uses UTC consistently: `datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")`

If the TMI API has a server-side length limit on names, the tool will let the API error rather than silently truncating.

### Compare Command Compatibility

`analysis_comparer.py` must be updated:
- Update `NOTE_NAME_PATTERN` regex to match both old format (`Terraform Analysis Report (...)`) and new formats (`Terraform Analysis - {env} (...)` and `Terraform Analysis (...)`)
- New pattern: `r"Terraform Analysis(?:\s+Report)?(?:\s+-\s+[^(]+)?\s*\(([^)]+)\)"`
- This matches all three naming variants and extracts the `(model, timestamp)` portion

## Files Modified

| File | Changes |
|------|---------|
| `tmi_tf/repo_analyzer.py` | `TerraformEnvironment` dataclass, `detect_environments()`, `resolve_modules()`, updated `TerraformRepository` |
| `tmi_tf/cli.py` | `--environment` flag, environment selection flow, Ctrl+C handling, status note updates at all milestones, two report creation blocks, split `--output` files, dynamic artifact naming, update `config_info` command to remove references to `config.analysis_note_name` and `config.diagram_name` (show `effective_model` and timestamp instead, since full artifact names are now determined at runtime) |
| `tmi_tf/tmi_client_wrapper.py` | `update_status_note()` method with note ID caching |
| `tmi_tf/llm_analyzer.py` | `status_callback` parameter on `analyze_repository()` |
| `tmi_tf/markdown_generator.py` | `generate_report()` replaced by `generate_inventory_report()` + `generate_analysis_report()` |
| `tmi_tf/config.py` | Remove `analysis_note_name` and `diagram_name` (moved to dynamic construction in CLI) |
| `tmi_tf/analysis_comparer.py` | Update `NOTE_NAME_PATTERN` regex to match old and new note naming formats |

## Files NOT Modified

| File | Reason |
|------|--------|
| `tmi_tf/dfd_llm_generator.py` | Diagram name is passed in from CLI, no internal changes needed |
| `tmi_tf/diagram_builder.py` | No changes needed |
| `tmi_tf/threat_processor.py` | Threat names are LLM-generated, no changes needed |
| `prompts/*` | No prompt template changes needed |

## Error Handling

- **Environment detection fails:** Fall back to analyzing all `.tf` files (current behavior)
- **Module resolution finds no modules:** Analyze only the environment directory's files
- **Status note update fails:** Log warning, continue analysis
- **One report note creation fails:** Log error, continue with other report and remaining steps
- **Ctrl+C during environment prompt:** Clean exit with "Analysis cancelled by user" message
- **`--environment` flag doesn't match:** Raise `click.ClickException` with the list of available environment names
