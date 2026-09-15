# CLAUDE.md

TMI Terraform Analysis Tool (`tmi-tf`): a Python CLI that runs Terraform code through a 3-phase LLM pipeline (via LiteLLM) and creates notes, data flow diagrams, and STRIDE-classified threats in TMI (Threat Modeling Improved).

## Commands

```bash
uv sync                                     # install
uv run tmi-tf <command>                     # CLI entry point
uv run ruff check tmi_tf/ tests/            # lint
uv run ruff format --check tmi_tf/ tests/   # format check
uv run pyright                              # type check
uv run pytest tests/                        # all tests
uv run pytest tests/test_repo_analyzer.py::TestDetectEnvironments::test_finds_single_environment  # one test
```

## External dependency: TMI Python client

The TMI API client is **not** installed as a package. `tmi_client_wrapper.py` loads it at runtime from `~/Projects/tmi-clients/python-client-generated` via `sys.path.insert`. All `tmi_client` imports carry `# type: ignore`; pyright is configured to accept this. `litellm`, `click`, and `dotenv` imports may also carry `# pyright: ignore` / `# ty:ignore` because pyright cannot always resolve them.

## Architecture

### 3-phase LLM pipeline (`llm_analyzer.py`)

1. **Inventory extraction** — enumerate cloud components and services → JSON
2. **Infrastructure analysis** — relationships, data flows, trust boundaries from phase 1 → JSON
3. **Security analysis** — STRIDE-classified findings from phases 1+2 → JSON array

Each phase has a system/user prompt pair in `prompts/`; user prompts are Python format-string templates (`{repo_name}`, `{terraform_contents}`, ...).

### Modules

- **`cli.py`** — Click CLI; orchestrates auth → fetch repos → clone → analyze → reports → TMI artifacts
- **`llm_analyzer.py`** — `LLMAnalyzer`; runs the 3 phases through LiteLLM; extracts JSON from responses (code blocks, raw, embedded)
- **`repo_analyzer.py`** — sparse git clone, Terraform environment detection, module resolution; `TerraformRepository` / `TerraformEnvironment` dataclasses
- **`dfd_llm_generator.py`** — separate LLM call producing structured DFD component/flow data
- **`diagram_builder.py`** — `DFDBuilder` converts that data to AntV X6 v2 cells for TMI diagrams
- **`threat_processor.py`** — converts phase 3 findings into TMI threat objects
- **`tmi_client_wrapper.py`** — wraps the generated client: auth, CRUD for notes/diagrams/threats, HTML sanitization via `nh3`
- **`auth.py`** — Google PKCE (browser) or TMI client_credentials
- **`retry.py`** — exponential backoff for transient LLM/API errors
- **`config.py`** — `Config` loads `.env`; `save_llm_response()` dumps raw LLM output to temp files for debugging

### LLM providers

`LLM_PROVIDER` env var: `anthropic`, `openai`, `xai`, `gemini`, `oci`. All calls go through LiteLLM with provider-prefixed model names (e.g. `anthropic/claude-opus-4-6`).
