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

Done gate: `uv run ruff check tmi_tf/ tests/ scripts/ && uv run ruff format --check tmi_tf/ tests/ scripts/ && uv run pyright && uv run pytest tests/`

## Deploy (AWS EKS)

Cluster `tmi-eks` (us-east-1), namespace `tmi-tf`, `AWS_PROFILE=tmi`. Deploys are Eric's call.

1. `./scripts/push-aws.sh --tag <sha>` (tag = HEAD sha of the built commit). It ends with a grype scan; exit 3 means fixable high/critical findings, so do not deploy that tag. ECR's BASIC scan-on-push misses these.
2. Set `app_image_tag` in `infra/aws/terraform.tfvars` (git-ignored, non-secret).
3. `cd infra/aws && AWS_PROFILE=tmi terraform plan -out=x.tfplan && terraform apply x.tfplan; rm x.tfplan` (plan files embed variable values).
4. Verify: `kubectl --context tmi-eks -n tmi-tf rollout status deploy/tmi-tf-wh` and `https://webhook.tmi.dev/tf/health`.

Decision: EKS is the only deploy target; k3s-rp is skipped (see ADR-0002).

## External dependency: TMI Python client

The TMI API client is **not** installed as a package. `tmi_client_wrapper.py` loads it at runtime from `~/Projects/tmi-clients/python-client-generated` via `sys.path.insert`. All `tmi_client` imports carry `# type: ignore`; pyright is configured to accept this. `litellm`, `click`, and `dotenv` imports may also carry `# pyright: ignore` / `# ty:ignore` because pyright cannot always resolve them.

## Architecture

### 3-phase LLM pipeline (`llm_analyzer.py`)

1. **Inventory extraction** — static parse + registry filter build the component list; the LLM only adds names, purposes, services, dependencies (`inventory_semantic_*.txt`); full-LLM `inventory_*.txt` fallback when nothing parses → JSON
2. **Infrastructure analysis** — relationships, data flows, trust boundaries from phase 1 → JSON
3. **Security analysis** — STRIDE-classified findings from phases 1+2 → JSON array

Each phase has a system/user prompt pair in `prompts/`; user prompts are Python format-string templates (`{repo_name}`, `{terraform_contents}`, ...).

### Modules

- **`cli.py`** — Click CLI; orchestrates auth → fetch repos → clone → analyze → reports → TMI artifacts
- **`llm_analyzer.py`** — `LLMAnalyzer`; runs the 3 phases through LiteLLM; extracts JSON from responses (code blocks, raw, embedded); phase 3b sends the shared inventory/infrastructure JSON as a cache prefix (`cache_prefix`, split at the `<!-- cache-breakpoint -->` line of `threat_analysis_user.txt`) and counts unanalyzed threats in `ThreatGaps`
- **`repo_analyzer.py`** — sparse git clone, Terraform environment detection, module resolution; `TerraformRepository` / `TerraformEnvironment` dataclasses
- **`tf_parser.py`** — static HCL parsing with python-hcl2 (8.x dict shape: quoted literals, `${expr}`, `__is_block__`); `StaticInventory`; files that fail to parse are listed in `unparsed_files`
- **`tf_filter.py`** — applies `data/resource_registry.yaml` (category + security attrs per resource type; unknown types keep everything) to produce filtered HCL via `hcl2.dumps` and the pre-built inventory; `merge_phase1` folds the LLM's semantic answer back into the phase-1 schema
- **`script_scan.py`** — static script rules (`data/script_rules.yaml`, linear-time), `extract_scripts` (script-carrying values incl. `file()`/`templatefile()` in-repo only) and `omit_scripts` (replace script spans with the phase-1 digest so phases 2/3a never see script bodies); `mask_secrets`
- **`metadata_scan.py`** — prompt-injection detectors over descriptions, defaults, tags (incl. `merge()` leaves, provider `default_tags`), names, comments; `redact_contents` removes flagged strings from every file before any prompt is built
- **`script_review.py`** — isolated, nonce-delimited LLM script review (60k-char cap), strict response validation, merge of static/LLM/injection hits into phase-3a-shaped threats (`finding_source`, `rule_id`, `digest`)
- **`jev_shadow.py`** — optional TypeSafe Jev comparison (`JEV_SHADOW=1` + `JEV_API_KEY` + `uv sync --extra jev`); secrets masked before sending; never affects output. Offline eval: `scripts/eval_jev.py` on the frozen corpus `evals/jev/` (never edit it)
- **`dfd_llm_generator.py`** — separate LLM call producing structured DFD component/flow data
- **`diagram_builder.py`** — `DFDBuilder` normalizes components/flows (malformed flows skipped), calls `compound_layout`, and maps boxes/routes to AntV X6 v2 cells for TMI diagrams, with direction-based ports
- **`cell_schema.py`** — TMI conformance for DFD cells (#107): `clean_metadata` (omit empty values and bad keys, truncate at 1024, cap 100) and `validate_cells` (vendored Node/Edge schema `data/tmi_cell_schema.json` plus reference/port invariants), called at the end of `build_cells` so nothing non-conforming reaches TMI. Refresh the schema with `scripts/sync_cell_schema.py --spec <tmi-openapi.json> --source ericfitz/tmi@<sha>`
- **`layout/`** — layered DFD layout: `layered.py` flat Sugiyama + Brandes-Koepf; `compound.py` nested boundaries, lifted edges, border ports, `LAYOUT_DIRECTION` ("LR" default), `EMIT_BORDER_VERTICES`; `pack.py` disconnected-part packing; `routes.py` vertex/fan/label helpers. Ported from Pele (MIT), see `THIRD_PARTY_NOTICES.md`
- **`scripts/export_tmi_dfd.py`**, **`scripts/preview_dfd.py`** — anonymized fixture export from TMI diagrams; SVG preview of a layout
- **`threat_processor.py`** — converts phase 3 findings into TMI threat objects
- **`tmi_client_wrapper.py`** — wraps the generated client: auth, CRUD for notes/diagrams/threats, HTML sanitization via `nh3`
- **`auth.py`** — Google PKCE (browser) or TMI client_credentials
- **`retry.py`** — LLM retry: waits for `retry-after`, else the `anthropic-ratelimit-*-reset` headers, else jittered exponential backoff; attempt limits per error class; `RetryBudget` stops waits at the job deadline; `DeadlineReached` is raised when the DFD's per-attempt timeout finds under 60 s of budget left. Also the TMI API 429 wait (`tmi_retry_wait`)
- **`error_hints.py`** — `error_hint` (HTTP status + fixed label, never exception text) and `step_row` for status-note outcome rows; `dfd_gap_text` / `DFD_REFUSED` build the "DFD not generated (...)" gap phrase
- **`config.py`** — `Config` loads `.env`; `save_llm_response()` dumps raw LLM output to temp files for debugging

### LLM providers

Named profiles in `llm-profiles.yaml` (`llm_profiles.py`) set provider, model, `auth`, the key's env var name, `api` (chat/responses), and optional `base_url`. `LLM_PROFILE` is the default; `--profile` / `user_data.profile` select per run. Providers: `anthropic`, `openai`, `xai`, `gemini`, `oci`; the LiteLLM model string is built from the profile (e.g. `openai/responses/gpt-5.6-cyber`). Keys are passed per call, never written to `os.environ`. Provider `anthropic` marks a `cache_prefix` with `cache_control`; other providers get it concatenated. `num_retries=0`: `retry.py` is the only retry.

Profile names are the model name with `.` replaced by `_` (ADR 0004); after adding or removing a profile and deploying, an admin re-runs `scripts/addon-profile-param.py --apply` to sync the TMI addon's `profile` picker.
