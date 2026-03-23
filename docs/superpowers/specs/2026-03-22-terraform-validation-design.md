# Terraform File Validation and Sanitization

## Problem

After cloning Terraform repositories from git, the tool sends file contents directly to the LLM for analysis with no validation. This wastes LLM tokens on malformed or irrelevant files and passes unsanitized content (embedded scripts) that isn't useful for threat modeling.

## Goals

1. **Syntax validation** — Reject `.tf` files with invalid HCL syntax before analysis begins
2. **Scope filtering** — Remove files that won't contribute to threat modeling (empty, auto-generated, oversized)
3. **Content sanitization** — Strip embedded scripts (`user_data`, `provisioner`, `connection` blocks) that add noise without aiding infrastructure-level threat analysis
4. **Fail-fast behavior** — If any file fails validation (Steps 1 or 2), abort the entire analysis for that repository and report what went wrong

## Non-Goals

- Full semantic validation (provider initialization, resource type checking)
- Stripping comments (may contain useful threat modeling context)
- Filtering variable-only or output-only files (provide useful context)
- Filtering test fixtures or example files

## Approach

### Tooling

- **`terraform fmt`** (without `-check`) for syntax validation. Running `terraform fmt` on a file reformats it in place and only returns a non-zero exit code if the file is unparseable HCL. This validates syntax without false positives on formatting differences. Requires `terraform` binary installed. No provider initialization needed.
- **Line-by-line state machine** for content sanitization. No HCL parser library required.

### Integration Point

Validation runs in `analyzer.py`, after environment detection and module resolution but before LLM analysis. This ensures:
- Only files that will actually be analyzed are validated (not files from other environments)
- Module files discovered by `resolve_modules()` are included in validation
- Validation failures abort analysis for that repository

Specifically, `validate_and_sanitize()` is called:
1. In `_analyze_single_environment()` — after `resolve_modules()` updates `tf_repo.terraform_files`, before calling `llm_analyzer.analyze_repository()`
2. In the no-environment fallback path in `run_analysis()` — before calling `llm_analyzer.analyze_repository()` on the full file set

## New Module: `tf_validator.py`

### Public Interface

```python
@dataclass
class RejectedFile:
    path: Path
    reason: str

@dataclass
class ValidationResult:
    valid_files: List[Path]
    sanitization_log: List[str]  # e.g., "Stripped 2 provisioner blocks from main.tf"

class TerraformValidationError(Exception):
    """Raised when one or more Terraform files fail validation."""
    def __init__(self, rejected_files: List[RejectedFile]):
        self.rejected_files = rejected_files
        details = "; ".join(f"{r.path.name}: {r.reason}" for r in rejected_files)
        super().__init__(f"Terraform validation failed: {details}")

def validate_and_sanitize(terraform_files: List[Path], clone_path: Path) -> ValidationResult:
    """Validate and sanitize a list of Terraform files.

    Runs the three-step validation pipeline (filtering, syntax, sanitization).
    Sanitized content is written back to the files on disk.

    Args:
        terraform_files: List of .tf and .tfvars file paths to validate.
        clone_path: Root of the cloned repository, used for computing
            relative paths in log messages and RejectedFile entries.

    Raises:
        TerraformValidationError: If any file fails Steps 1 or 2.
        RuntimeError: If the terraform binary is not found on PATH.

    Returns:
        ValidationResult with the list of validated files and sanitization log.
    """
```

### Handling of `.tfvars` Files

`.tfvars` files contain only variable assignments (e.g., `region = "us-east-1"`) — they never contain top-level Terraform keywords or embedded scripts. They are handled as follows:

- **Step 1 (filtering)**: `.tfvars` files are subject to the empty, auto-generated, and oversized checks, but they are **exempt from the keyword scan**. A `.tfvars` file with only variable assignments is valid.
- **Step 2 (syntax)**: `.tfvars` files are validated with `terraform fmt` like `.tf` files.
- **Step 3 (sanitization)**: `.tfvars` files are **skipped** — they cannot contain `user_data`, `provisioner`, or `connection` blocks.

### Terraform Binary Check

At the start of `validate_and_sanitize()`, check that `terraform` is available on PATH using `shutil.which("terraform")`. If not found, raise `RuntimeError("terraform binary not found on PATH — required for Terraform file validation")`. This runs once per call to `validate_and_sanitize()`, not at module import time (so importing `tf_validator` in tests without terraform installed does not fail).

### Validation Pipeline

Each file passes through three sequential checks. A file must pass each step to proceed to the next. Files rejected in Step 1 skip Step 2. If any file fails Steps 1 or 2, `TerraformValidationError` is raised after checking all files (so the error reports all failures, not just the first).

#### Step 1 — File-Level Filtering (Scope/Relevance)

Reject files that match any of:

| Check | Threshold | Reason |
|-------|-----------|--------|
| Empty file | 0 bytes | No content to analyze |
| Auto-generated file | `.terraform.lock.hcl`, anything under `.terraform/` | Not authored infrastructure code |
| Oversized file | > 1 MB | Likely generated; too large for useful analysis |
| Comments/whitespace only (`.tf` files only) | No HCL constructs found | No meaningful Terraform content |

For the "comments/whitespace only" check (applied only to `.tf` files, not `.tfvars`): scan the file line by line for lines where the first non-whitespace token is a known Terraform top-level keyword (`resource`, `data`, `module`, `variable`, `output`, `provider`, `terraform`, `locals`). If none are found, reject. This is a word-boundary match — `terraform` in `terraform {` matches, but `my_terraform` does not.

#### Step 2 — Syntax Validation (Correctness)

Run `terraform fmt` (without `-check`) on each file that passed Step 1, individually. `terraform fmt` reformats valid HCL in place and exits with code 0. If the file contains unparseable HCL, it exits with a non-zero code and writes an error message to stderr — reject the file with that error message as the reason.

Use a 30-second timeout for the `subprocess.run` call, consistent with the project's existing subprocess timeout pattern. If `terraform fmt` times out, reject the file with reason "terraform fmt timed out".

**Note:** Running `terraform fmt` without `-check` modifies files in place (canonical formatting). This is acceptable because these are temporary clones.

#### Step 3 — Content Sanitization (`.tf` files only)

Strip embedded scripts from `.tf` files that passed Steps 1 and 2. `.tfvars` files skip this step. Sanitized content is written back to the files on disk (these are temporary clones — originals are in the remote repo).

**Constructs to strip:**

| Construct | Marker replacement |
|-----------|--------------------|
| `user_data` attribute values | `user_data = "[embedded script removed]"` |
| `provisioner` block bodies | `provisioner "type" {\n  # [provisioner script removed]\n}` |
| `connection` block bodies | `connection {\n  # [connection details removed]\n}` |

**Pattern matching rules:**

All pattern matches are anchored: the keyword must be the first non-whitespace token on the line. Leading whitespace (indentation) is preserved in the output.

- **`user_data`**: Match lines where the first non-whitespace token is exactly `user_data` followed by optional whitespace and `=`. This is a whole-word match — `base64_user_data` or `admin_user_data` do not match. Lines where `user_data` appears inside a comment (`#` or `//` before the keyword) do not match. Regex: `^\s*user_data\s*=`.
- **`provisioner`**: Match lines where the first non-whitespace token is exactly `provisioner`, followed by a quoted string and `{`. Example: `  provisioner "remote-exec" {`. Regex: `^\s*provisioner\s+"[^"]+"\s*\{`.
- **`connection`**: Match lines where the first non-whitespace token is exactly `connection` followed by optional whitespace and `{`. Regex: `^\s*connection\s*\{`. This matches the standalone `connection` block used inside provisioners. It does **not** match resource type strings like `resource "aws_dx_connection" "main" {` because `connection` is not the first token on those lines.

**Sanitization algorithm — line-by-line state machine:**

The state machine uses `elif` semantics: only one state block runs per line. State transitions take effect on the **next** line, not the current one.

```
States: NORMAL, STRIPPING_BLOCK, STRIPPING_VALUE, STRIPPING_HEREDOC

depth = 0  (tracks nesting depth of braces/parens)

STRIPPING_BLOCK is used for provisioner/connection blocks — writes a closing `}`
  when depth reaches 0. Tracks braces only.
STRIPPING_VALUE is used for user_data multi-line values — does NOT write any
  closing delimiter when depth reaches 0 (the replacement line is already
  complete). Tracks both braces and parens together, since user_data values
  commonly mix them (e.g., `jsonencode({ ... })`).

For each line in input file:
  If state is NORMAL:
    If line matches `user_data =` pattern:
      Preserve leading whitespace, write: <indent>user_data = "[embedded script removed]"
      Examine the remainder of the line after `=` (the value portion only):
        - Starts with `<<` or `<<-`: heredoc
            Extract terminator: strip leading `<<` or `<<-`, strip optional
            surrounding quotes (single or double), take the remaining
            identifier. Example: `<<-"EOF"` → terminator is `EOF`.
            Set state to STRIPPING_HEREDOC, record terminator
        - Contains `(` or `{` (check both together):
            Count all `(` and `{` as +1, all `)` and `}` as -1,
            in the value portion only → depth
            If depth == 0: stay NORMAL (single-line balanced value)
            Else: set state to STRIPPING_VALUE
        - Otherwise (simple quoted string, number, bool, reference):
            Stay NORMAL (single-line value, already replaced)

    Elif line matches `provisioner "..." {` pattern:
      Preserve leading whitespace
      Write: <indent>provisioner "..." {
      Write: <indent>  # [provisioner script removed]
      Set state to STRIPPING_BLOCK, depth = 1

    Elif line matches `connection {` pattern:
      Preserve leading whitespace
      Write: <indent>connection {
      Write: <indent>  # [connection details removed]
      Set state to STRIPPING_BLOCK, depth = 1

    Else:
      Write line to output

  Elif state is STRIPPING_BLOCK:
    For each char on current line:
      If `{`: depth += 1
      If `}`: depth -= 1
    If depth <= 0:
      Write: <indent>}   (using indentation of the opening line)
      Set state to NORMAL

  Elif state is STRIPPING_VALUE:
    For each char on current line:
      If `(` or `{`: depth += 1
      If `)` or `}`: depth -= 1
    If depth <= 0:
      Set state to NORMAL
      (No closing delimiter — the user_data replacement line is already complete)

  Elif state is STRIPPING_HEREDOC:
    If line (stripped of leading/trailing whitespace) matches the recorded
    terminator exactly:
      Set state to NORMAL
    (Do not write any lines while in heredoc)
```

**Known limitation:** Braces/parentheses inside string literals or comments within stripped blocks could theoretically throw off the depth counter. In practice, `provisioner`, `connection`, and `user_data` values rarely contain unmatched delimiters in strings. This edge case is accepted and documented in code comments.

**Logging:** Each sanitization action is logged, e.g., "Stripped 2 provisioner blocks, 1 user_data attribute from main.tf".

## Changes to Existing Code

### `analyzer.py`

**In `_analyze_single_environment()`**, add validation after module resolution and before LLM analysis:

```python
def _analyze_single_environment(
    tf_repo, selected, repo_analyzer, llm_analyzer, tmi_client, threat_model_id, repo_name
) -> TerraformAnalysis:
    tf_repo.environment_name = selected.name
    # ... existing module resolution code ...
    tf_repo.terraform_files = RepositoryAnalyzer.resolve_modules(
        selected, tf_repo.clone_path
    )

    # Validate and sanitize resolved files before LLM analysis
    result = validate_and_sanitize(tf_repo.terraform_files, tf_repo.clone_path)
    tf_repo.terraform_files = result.valid_files
    for msg in result.sanitization_log:
        logger.info(msg)

    # ... existing LLM analysis call ...
    return llm_analyzer.analyze_repository(tf_repo, status_callback=_status_cb)
```

**In the no-environment fallback path** (where `len(envs) == 0`), add validation before `llm_analyzer.analyze_repository()`:

```python
# No environments detected, analyzing all files
result = validate_and_sanitize(tf_repo.terraform_files, tf_repo.clone_path)
tf_repo.terraform_files = result.valid_files
for msg in result.sanitization_log:
    logger.info(msg)

analysis = llm_analyzer.analyze_repository(tf_repo, status_callback=_status_cb)
```

The `TerraformValidationError` propagates up and is caught by the existing `except Exception as e` block around each repository's analysis in `run_analysis()`.

### `repo_analyzer.py` (no changes)

Validation is no longer called here. `clone_repository_sparse()` continues to yield the raw `TerraformRepository`.

### `TerraformRepository` (no changes)

`get_terraform_content()` continues to read from disk. Since sanitized content is written back to the cloned files, this works without modification.

## Error Behavior

- **Any file fails validation (Steps 1 or 2)** → all files are still checked → `TerraformValidationError` raised with complete list of failures → analysis aborted for that repository
- **`terraform` binary not found** → `RuntimeError` raised at the start of `validate_and_sanitize()`, before any file processing
- **`terraform fmt` times out** → file rejected with reason "terraform fmt timed out"
- **All repositories fail validation** → pipeline reports "No repositories were successfully analyzed" (existing behavior)
- **Repository has 0 `.tf` files from clone** → `_sparse_clone` returns `None`, repository silently skipped (existing behavior, unchanged). This is distinct from a repository with `.tf` files that all fail validation, which raises `TerraformValidationError`.

## Dependencies

- **`terraform` CLI** — must be installed and on PATH. The tool already requires git; this adds terraform as a second external dependency.

## Testing Strategy

- **Unit tests for the state machine**: Test sanitization against fixture files covering each construct type (simple `user_data`, heredoc `user_data`, indented heredoc with `<<-`, function-call `user_data` with parens, `provisioner`, `connection`, nested blocks, mixed constructs)
- **Unit tests for filtering**: Empty files, oversized files, auto-generated files, comment-only files, `.tfvars` files (should pass filtering without keyword scan)
- **Unit tests for pattern matching**: Verify `user_data` matches exactly (not `base64_user_data`), `connection` doesn't match resource types, commented-out constructs are ignored
- **Unit test for terraform binary absence**: Mock `shutil.which` to return `None`, verify `RuntimeError` is raised with clear message
- **Unit test for terraform fmt timeout**: Mock `subprocess.run` to raise `TimeoutExpired`, verify file is rejected
- **Integration test**: Clone a test repo, run validation, verify sanitized output and that rejected files raise `TerraformValidationError`
- **Edge case tests**: Braces in comments (known limitation), files with no constructs, files with only variables/outputs (should pass), heredocs with quoted terminators (`<<-"EOF"`)
