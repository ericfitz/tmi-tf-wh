# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

TMI Terraform Analysis Tool (`tmi-tf`) — a Python CLI that analyzes Terraform infrastructure code for threat models in the TMI (Threat Modeling Improved) platform. It uses LLM providers via LiteLLM to run a 3-phase analysis pipeline, then creates notes, data flow diagrams, and STRIDE-classified threats in TMI.

## Build, Lint, Test Commands

```bash
uv sync                          # Install dependencies
uv run ruff check tmi_tf/ tests/ # Lint
uv run ruff format --check tmi_tf/ tests/  # Format check
uv run pyright                   # Type check
uv run pytest tests/             # Run all tests
uv run pytest tests/test_repo_analyzer.py  # Run a single test file
uv run pytest tests/test_repo_analyzer.py::TestDetectEnvironments::test_finds_single_environment  # Single test
```

The CLI entry point is `uv run tmi-tf <command>`.

## External Dependency: TMI Python Client

The TMI API client is **not** installed as a package. It is loaded at runtime from `~/Projects/tmi-clients/python-client-generated` via `sys.path.insert` in `tmi_client_wrapper.py`. All `tmi_client` imports use `# type: ignore` suppression. Pyright is configured to accept this.

## Architecture

### 3-Phase LLM Analysis Pipeline

The core analysis (`llm_analyzer.py`) runs Terraform code through 3 sequential LLM calls:
1. **Phase 1 — Inventory Extraction**: Enumerates cloud components and services → JSON
2. **Phase 2 — Infrastructure Analysis**: Maps relationships, data flows, trust boundaries using Phase 1 output → JSON
3. **Phase 3 — Security Analysis**: STRIDE-classified security findings using Phase 1+2 output → JSON array

Each phase has its own system/user prompt pair in `prompts/`. The user prompts are Python format-string templates (using `{repo_name}`, `{terraform_contents}`, etc.).

### Key Modules

- **`cli.py`** — Click CLI. Orchestrates the full pipeline: auth → fetch repos → clone → analyze → generate reports → create TMI artifacts.
- **`llm_analyzer.py`** — `LLMAnalyzer` class. Manages all 3 LLM phases via LiteLLM. Handles JSON extraction from LLM responses (code blocks, raw JSON, embedded JSON).
- **`repo_analyzer.py`** — Sparse git clone, Terraform environment detection, module resolution. `TerraformRepository` and `TerraformEnvironment` dataclasses.
- **`dfd_llm_generator.py`** — Separate LLM call to generate structured DFD component/flow data from analysis JSON.
- **`diagram_builder.py`** — `DFDBuilder` converts structured data into AntV X6 v2 cell format for TMI diagrams.
- **`threat_processor.py`** — Converts Phase 3 security findings into TMI threat objects.
- **`tmi_client_wrapper.py`** — Wraps the generated TMI Python client. Handles auth, CRUD for notes/diagrams/threats, HTML sanitization via `nh3`.
- **`auth.py`** — OAuth flows: Google PKCE (browser) or TMI client_credentials.
- **`retry.py`** — Retry logic for transient LLM and API errors with exponential backoff.
- **`config.py`** — `Config` class loads `.env` file. Also provides `save_llm_response()` for dumping raw LLM output to temp files for debugging.

### LLM Provider Support

Configured via `LLM_PROVIDER` env var. Supported: `anthropic`, `openai`, `xai`, `gemini`, `oci`. All calls go through LiteLLM with provider-prefixed model names (e.g., `anthropic/claude-opus-4-6`).

### Type Checking Notes

Many imports use `# pyright: ignore` / `# ty:ignore` comments because:
- `tmi_client` is loaded at runtime via sys.path
- `litellm`, `click`, `dotenv` are runtime dependencies that pyright may not resolve in all environments
