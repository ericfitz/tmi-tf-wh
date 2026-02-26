# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TMI Terraform Analysis Tool (`tmi-tf`) is a Python CLI that analyzes Terraform infrastructure code for threat modeling. It integrates with the TMI (Threat Modeling Improved) platform, using LLMs via LiteLLM to analyze GitHub repos containing Terraform, then stores analysis reports, data flow diagrams, and STRIDE-classified threats back in TMI.

## Commands

### Install dependencies
```bash
uv sync
```

### Run the CLI
```bash
uv run tmi-tf <command> [options]
```

### Lint
```bash
uv run ruff check .
uv run ruff format --check .
```

### Fix lint issues
```bash
uv run ruff check --fix .
uv run ruff format .
```

### Type check
```bash
uv run pyright
```

### Run tests
```bash
uv run pytest
```

## Architecture

### CLI Entry Point
[cli.py](tmi_tf/cli.py) — Click-based CLI with commands: `analyze`, `auth`, `list-repos`, `clear-auth`, `config-info`, `compare`. The `analyze` command is the main workflow orchestrator.

### Analysis Pipeline (analyze command)
1. **Config** ([config.py](tmi_tf/config.py)) — Loads `.env`, validates LLM provider credentials, resolves model names with LiteLLM provider prefixes
2. **Auth** ([auth.py](tmi_tf/auth.py)) — Google OAuth 2.0 with PKCE, local callback server on port 8888, token cached at `~/.tmi-tf/token.json`
3. **TMI Client** ([tmi_client_wrapper.py](tmi_tf/tmi_client_wrapper.py)) — Wraps the external TMI Python client (from `~/Projects/tmi-clients/python-client-generated`, added to `sys.path` at import time). Includes monkey-patching for bearer auth and content sanitization for API XSS protection
4. **Repo Discovery** — Fetches threat model repos via TMI API, filters for GitHub URLs
5. **Cloning** ([repo_analyzer.py](tmi_tf/repo_analyzer.py)) — Sparse git checkout of `.tf`, `.tfvars`, and documentation files only
6. **LLM Analysis** ([llm_analyzer.py](tmi_tf/llm_analyzer.py)) — Sends Terraform code to LLM via LiteLLM. Tracks token usage and cost
7. **Report** ([markdown_generator.py](tmi_tf/markdown_generator.py)) — Generates markdown report with per-repo analysis and consolidated findings
8. **DFD Generation** ([dfd_llm_generator.py](tmi_tf/dfd_llm_generator.py) + [diagram_builder.py](tmi_tf/diagram_builder.py)) — Uses LLM for structured component extraction, then builds AntV X6 v2 diagram cells with hierarchical layout and 7 component types (tenancy, container, network, gateway, compute, storage, actor)
9. **Threat Extraction** ([threat_processor.py](tmi_tf/threat_processor.py)) — Extracts STRIDE-classified threats from analysis and creates threat objects in TMI

### Prompt Templates
Located in [prompts/](prompts/) — System and user prompts for Terraform analysis, DFD generation, and model comparison. These are loaded and formatted at runtime with template variables.

### External Dependency: TMI Python Client
The TMI API client is **not** a pip dependency — it lives at `~/Projects/tmi-clients/python-client-generated` and is added to `sys.path` in [tmi_client_wrapper.py](tmi_tf/tmi_client_wrapper.py). This is a generated OpenAPI client.

## Key Design Decisions

- **LiteLLM as abstraction layer**: All LLM calls go through LiteLLM with provider-prefixed model names (e.g., `anthropic/claude-opus-4-5-20251101`). Provider switching is config-only.
- **Content sanitization**: All content sent to TMI API is sanitized (HTML tags stripped, control characters removed) to prevent server-side XSS rejection. See `sanitize_content_for_api()` in [tmi_client_wrapper.py](tmi_tf/tmi_client_wrapper.py).
- **Graceful degradation**: If one repo fails analysis, the tool continues with remaining repos.
- **Idempotent artifacts**: Notes and diagrams are created-or-updated by name, so re-running overwrites previous results for the same model.

## Configuration

All config is via `.env` file (see `.env.example`). Key variables:
- `LLM_PROVIDER` (anthropic/openai/xai/gemini) + corresponding `*_API_KEY`
- `LLM_MODEL` — Optional override; auto-prefixed with provider if no `/` present
- `TMI_SERVER_URL`, `GITHUB_TOKEN`, `MAX_REPOS`, `CLONE_TIMEOUT`
