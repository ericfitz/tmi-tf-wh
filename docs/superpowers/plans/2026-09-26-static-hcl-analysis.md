# Static HCL Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the mechanical part of phase 1 (resource catalog, category, security-relevant configuration, references) out of the LLM into static `python-hcl2` parsing, so the LLM only infers names, purposes, services and dependencies from a smaller prompt.

**Architecture:** `tf_parser.py` parses the already-collected `.tf`/`.tfvars` contents (environment plus resolved modules, post-sanitization) with `python-hcl2` into a `StaticInventory`. `tf_filter.py` applies `tmi_tf/data/resource_registry.yaml` to produce filtered HCL (regenerated with `hcl2.dumps`) and a pre-built inventory JSON, and merges the LLM's semantic answer back into the exact current phase-1 schema. `LLMAnalyzer.analyze_repository` runs static parse -> filter -> semantic prompt -> merge, and falls back to today's full-LLM phase 1 when static analysis yields nothing. Phases 2/3, DFD, markdown and threats are untouched.

**Tech Stack:** python-hcl2 8.x (lark-based; verified 8.1.4), PyYAML (already a dependency), existing LiteLLM provider layer, pytest.

**Spec:** `docs/superpowers/specs/2026-04-06-static-hcl-analysis-design.md`

## Global Constraints

- Python floor is 3.10 (`requires-python = ">=3.10"`; CI runs 3.10 and 3.13). python-hcl2 8.x requires >=3.8, fine.
- Add the dependency with `uv add python-hcl2` (writes pyproject and `uv.lock`); no other new dependencies. PyYAML is already present (`pyyaml>=6.0`).
- Allowed component categories (spec): `compute`, `storage`, `network`, `gateway`, `security_control`, `identity`, `monitoring`, `dns`, `cdn`, `other`.
- Unrecognized resource types: category `other`, all attributes kept (`unknown_attrs: all`). Nothing is silently dropped.
- Files python-hcl2 cannot parse go to the LLM unfiltered. If static analysis yields no components at all (or raises), phase 1 falls back to the current full-LLM prompt with a logged warning.
- The merged phase-1 output keys are exactly today's: `components[{id, name, type, resource_type, configuration, purpose, dependencies[{type, provider, service}]}]`, `services[]`, `dependencies[{type, provider, service, dependent_components}]`. Downstream (phase 2/3 prompts, `markdown_generator.py`, `dfd_llm_generator.py`, `threat_processor.py`) is not modified.
- Preserve: phase-1 retry-once-then-fail-loudly (#68, `_call_llm_json(attempts=2)` and the `"2 attempts"` error text), streaming and `save_llm_response` in the provider layer, profile-based model selection, token/cost accounting through `_call_llm_json` return tuples.
- `user_data`-like script attributes: presence and hash only, never content (in filtered HCL and in `configuration`).
- No LLM API calls anywhere in this plan: tests mock `LLMProvider.complete`; the measurement script only counts tokens locally.
- Every task ends with `uv run ruff check tmi_tf/ tests/ scripts/`, `uv run ruff format --check tmi_tf/ tests/ scripts/`, `uv run pyright`, `uv run pytest tests/` all green, then a commit. Run `uv run ruff format tmi_tf/ tests/ scripts/` before the format check. Commit messages: `feat(#10): ...`, trailer lines:

```
Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
```

- Phase 1 prompts today are `prompts/inventory_system.txt` / `prompts/inventory_user.txt` (loaded in `LLMAnalyzer._load_phase_prompts`). `prompts/terraform_analysis_*.txt` are legacy and unused; do not touch them.

## Review Focus

1. Two resolved modules define the same address (e.g. `aws_iam_role.this` in `modules/secrets` and `modules/logging`): both must appear in the inventory (distinct `file`), nothing silently dropped. Test: Task 1 `test_duplicate_addresses_across_files_are_both_kept`.
2. A `.tfvars` or comment-only/empty file: parses to no blocks, produces no components, and is rendered through unchanged (no crash on `__comments__` or attribute-only dicts). Tests: Task 1 `test_empty_and_comment_only_files_parse_to_nothing`, Task 3 `test_tfvars_file_passes_through`.
3. A registry entry names attributes the resource block does not have: the block is kept with only meta-args/references, the omitted count is correct, no crash. Test: Task 3 `test_registry_attrs_absent_from_block`.
4. Malformed semantic LLM output (`components` not a list, `dependent_components` a string, unknown ids, reclassifying a non-`other` component): merge must never raise and must never change a static `type` that is not `other`. Tests: Task 4 `test_merge_tolerates_malformed_semantic_output`, `test_merge_only_reclassifies_other`.
5. A real environment where one file hits a python-hcl2 bug (`tmi/terraform/modules/kubernetes/oci/k8s_resources.tf` raises `AttributeError` on 8.1.4, not a lark error): the file must land in `unparsed_files` and the rest of the environment must still be statically analyzed. Test: Task 1 `test_unparsable_file_is_reported_not_fatal` (catches `Exception`, not only lark errors), Task 5 `test_phase1_partial_parse_sends_unparsed_raw`.

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `pyproject.toml`, `uv.lock` | Modify | add `python-hcl2` |
| `tmi_tf/tf_parser.py` | Create | `hcl2.loads` per file -> `StaticInventory`; literal unquoting; reference detection |
| `tmi_tf/data/resource_registry.yaml` | Create | resource type -> category + security attrs; provider prefixes; hash-only script attrs |
| `tmi_tf/tf_filter.py` | Create | `load_registry`, `filter_terraform` (filtered HCL + pre-built inventory), `merge_phase1` |
| `prompts/inventory_semantic_system.txt`, `prompts/inventory_semantic_user.txt` | Create | semantic-only phase-1 prompts (the old `inventory_*.txt` stay for the fallback) |
| `tmi_tf/llm_analyzer.py` | Modify | `_run_phase1`: static path with fallback; module-level `format_terraform_contents` |
| `scripts/measure_phase1_prompt.py` | Create | before/after prompt size on a local Terraform checkout, no LLM |
| `tests/fixtures/tf/{aws,azure,gcp,oci,broken}.tf`, `tests/fixtures/tf/tmi_network_aws/*.tf` | Create | per-provider fixtures, one unparsable, one real module copy |
| `tests/test_tf_parser.py`, `tests/test_resource_registry.py`, `tests/test_tf_filter.py` | Create | unit tests |
| `tests/test_llm_analyzer.py` | Modify | `TestPhase1Static` |
| `README.md`, `.claude/CLAUDE.md`, `PROGRESS.md` | Modify | docs and results |

`analyzer.py` is **not** modified: both of its `analyze_repository` call sites (no-environment path and `_analyze_single_environment`) and the CLI go through `LLMAnalyzer.analyze_repository`, which is where the static path lives. That is one choke point instead of three.

## How the current flow feeds phase 1 (read before Task 1)

- `analyzer.py` clones, picks an environment, `RepositoryAnalyzer.resolve_modules` adds `.tf` files of relative-source modules, `tf_validator.validate_and_sanitize` rewrites files on disk (strips `user_data` values to `"[embedded script removed]"`, provisioner and connection blocks) and then `LLMAnalyzer.analyze_repository(tf_repo)` runs.
- `TerraformRepository.get_terraform_content()` returns `dict[relative_path, text]` for `.tf` and `.tfvars` files. `_format_terraform_contents` wraps each in a `### File: path` + fenced `hcl` block. That text is the `{terraform_contents}` of phases 1, 2 and 3a today and stays so for 2 and 3a.
- Phase 1 = `_call_llm_json(inventory_system, inventory_user, phase_name="inventory", attempts=2)`; `None` -> `ValueError("Phase 1 (inventory) returned no usable JSON after 2 attempts ...")`.

## python-hcl2 8.x facts (verified with 8.1.4; Task 1 step 2 re-verifies)

- `hcl2.loads(text) -> dict`. Block types are top-level keys holding lists: `{"resource": [{'"aws_instance"': {'"web"': {...body...}}}, ...]}`. Labels are returned **with their quotes** (`'"aws_instance"'`).
- String literals keep their quotes (`'"ami-123"'`); expressions are wrapped (`'${aws_subnet.private.id}'`, `'${var.n}'`); interpolated strings look like `'"web-${var.env}"'`; heredocs become `'"<<-EOT\n...\nEOT"'`; bare identifiers (a variable's `type = number`) come back unquoted (`'number'`).
- Nested blocks are lists of dicts tagged `"__is_block__": True`; object attributes (`tags = {...}`) are plain dicts. Comments show up as `"__comments__": [{"value": ...}]` inside the enclosing dict and are dropped by `hcl2.dumps`.
- Attribute-only files (`.tfvars`) parse to a flat dict; an empty file to `{}`; a comment-only file to `{"__comments__": [...]}`.
- `hcl2.dumps(dict) -> str` regenerates HCL from a (possibly filtered) dict, honouring the quote convention above. Output ends with `}\n` for a block. It round-trips all 111 parsable files of `~/Projects/tmi/terraform`.
- Parse failures raise lark exceptions **or** plain `AttributeError` (transformer bug on `modules/kubernetes/oci/k8s_resources.tf`). Catch `Exception`.

---

### Task 1: Dependency, API probe, and static parser

**Files:**
- Modify: `pyproject.toml` (via `uv add`), `uv.lock`
- Create: `tmi_tf/tf_parser.py`
- Create: `tests/fixtures/tf/aws.tf`, `tests/fixtures/tf/broken.tf`
- Test: `tests/test_tf_parser.py`

**Interfaces:**
- Consumes: nothing new.
- Produces (used by Tasks 3-6):
  - `BLOCK_MARKER = "__is_block__"`
  - `unquote_literal(s: str) -> str`
  - `clean_value(value: Any) -> Any` (drops `__is_block__`, unquotes literals, unwraps single `${...}`)
  - `find_references(value: Any, exclude: str = "") -> list[str]` (sorted, unique addresses `type.name`, `data.type.name`, `module.name`)
  - dataclasses `ParsedResource(resource_type, local_name, address, file, attributes, references)`, `ParsedDataSource(data_type, local_name, address, file, attributes, references)`, `ParsedVariable(name, type_expr, default, description, sensitive)`, `ParsedOutput(name, value_expr, description, sensitive)`, `ParsedModule(name, source, inputs, file)`, `ParsedProvider(name, alias, config)`, `StaticInventory(resources, data_sources, variables, outputs, modules, providers, unparsed_files, parsed_files)`
  - `parse_terraform(tf_contents: dict[str, str]) -> StaticInventory`

- [ ] **Step 1: Add the dependency**

Run: `uv add python-hcl2`
Expected: `pyproject.toml` gains `"python-hcl2>=8.1.4"` (or whatever 8.x resolves) in `dependencies`; `uv.lock` updated. If the resolved version is not 8.x, stop and report: this plan's code assumes the 8.x dict shape.

- [ ] **Step 2: Probe the installed API before writing parser code**

Write `/tmp` is not allowed; use the scratchpad. Create `probe.tf` with this content and run the probe; compare to the facts listed above.

```hcl
resource "aws_instance" "web" {
  ami                    = "ami-123"
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.web.id, "sg-lit"]
  user_data              = base64encode(file("${path.module}/init.sh"))
  count                  = var.n
  tags = { Name = "web-${var.env}" }
  ebs_block_device {
    device_name = "/dev/sda1"
    encrypted   = true
  }
  depends_on = [aws_iam_role.r]
}
data "aws_ami" "x" { most_recent = true }
variable "n" { type = number
 default = 1 }
output "ip" { value = aws_instance.web[0].public_ip
 sensitive = true }
module "net" { source = "../../modules/network/aws"
 cidr = var.cidr }
provider "aws" { region = "us-east-1"
 alias = "east" }
```

```bash
uv run python - <<'EOF'
import hcl2, json, importlib.metadata as m
print("python-hcl2", m.version("python-hcl2"))
d = hcl2.loads(open("probe.tf").read())
print(json.dumps(d, indent=1))
print(hcl2.dumps(d))
try:
    hcl2.loads('resource "a" "b" {\n  x = \n}')
except Exception as e:
    print("parse error type:", type(e).__name__)
EOF
```

Expected: labels quoted (`"\"aws_instance\""`), literals quoted (`"\"ami-123\""`), expressions `${...}`, `__is_block__` markers, `hcl2.dumps` prints valid HCL, the broken input raises (lark `UnexpectedToken`). If any of these differ, stop and report before continuing.

- [ ] **Step 3: Create the fixtures**

`tests/fixtures/tf/aws.tf`:

```hcl
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  type        = string
  default     = "us-east-1"
  description = "AWS region"
}

variable "db_password" {
  type      = string
  sensitive = true
  default   = "hunter2"
}

locals {
  name = "web-${var.region}"
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]
}

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  tags                 = { Name = local.name }
}

resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = false
}

resource "aws_security_group" "web" {
  name   = "web"
  vpc_id = aws_vpc.main.id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "web" {
  name               = "web-role"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [] })
}

resource "aws_instance" "web" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.private.id
  vpc_security_group_ids      = [aws_security_group.web.id]
  associate_public_ip_address = false
  monitoring                  = true
  user_data                   = "#!/bin/bash\necho hello"
  tags                        = { Name = local.name }
  ebs_block_device {
    device_name = "/dev/sda1"
    encrypted   = true
    volume_size = 20
  }
  depends_on = [aws_iam_role.web]
}

resource "aws_s3_bucket" "logs" {
  bucket        = "${local.name}-logs"
  force_destroy = true
  tags          = { Name = "logs" }
}

resource "mycorp_widget" "custom" {
  size  = 3
  color = "blue"
}

module "dns" {
  source  = "../../modules/dns/aws"
  zone    = "example.com"
  vpc_id  = aws_vpc.main.id
}

output "instance_ip" {
  value       = aws_instance.web.private_ip
  description = "Private IP"
}

output "db_password" {
  value     = var.db_password
  sensitive = true
}
```

`tests/fixtures/tf/broken.tf` (deliberately unparsable):

```hcl
resource "aws_instance" "broken" {
  ami =
}
```

- [ ] **Step 4: Write the failing parser tests**

`tests/test_tf_parser.py`:

```python
"""Tests for static HCL parsing (issue #10)."""

from pathlib import Path

from tmi_tf.tf_parser import (
    StaticInventory,
    clean_value,
    find_references,
    parse_terraform,
    unquote_literal,
)

FIXTURES = Path(__file__).parent / "fixtures" / "tf"


def _load(*names: str) -> dict[str, str]:
    return {n: (FIXTURES / n).read_text(encoding="utf-8") for n in names}


class TestHelpers:
    def test_unquote_literal(self):
        assert unquote_literal('"ami-123"') == "ami-123"
        assert unquote_literal("number") == "number"
        assert unquote_literal('"') == '"'

    def test_clean_value_unwraps_expressions_and_drops_marker(self):
        raw = {
            "ami": '"x"',
            "subnet_id": "${aws_subnet.private.id}",
            "name": '"web-${var.env}"',
            "ebs": [{"encrypted": True, "__is_block__": True}],
            "__comments__": [{"value": "a comment"}],
            "__is_block__": True,
        }
        assert clean_value(raw) == {
            "ami": "x",
            "subnet_id": "aws_subnet.private.id",
            "name": "web-${var.env}",
            "ebs": [{"encrypted": True}],
        }

    def test_find_references(self):
        value = {
            "a": "${aws_subnet.private.id}",
            "b": ["${data.aws_ami.ubuntu.id}", "${module.net.vpc_id}"],
            "c": "${var.x}-${local.y}-${each.value}-${path.module}",
            "d": "${data.http.remote.body}",
            "e": '"literal_with.dot"',
            "self": "${aws_instance.web.id}",
        }
        assert find_references(value, exclude="aws_instance.web") == [
            "aws_subnet.private",
            "data.aws_ami.ubuntu",
            "data.http.remote",
            "module.net",
        ]


class TestParseTerraform:
    def test_resources_and_addresses(self):
        inv = parse_terraform(_load("aws.tf"))
        assert isinstance(inv, StaticInventory)
        addresses = [r.address for r in inv.resources]
        assert addresses == [
            "aws_vpc.main",
            "aws_subnet.private",
            "aws_security_group.web",
            "aws_iam_role.web",
            "aws_instance.web",
            "aws_s3_bucket.logs",
            "mycorp_widget.custom",
        ]
        web = next(r for r in inv.resources if r.address == "aws_instance.web")
        assert web.resource_type == "aws_instance"
        assert web.local_name == "web"
        assert web.file == "aws.tf"
        assert web.attributes["instance_type"] == "t3.micro"
        assert web.attributes["ebs_block_device"] == [
            {"device_name": "/dev/sda1", "encrypted": True, "volume_size": 20}
        ]
        assert web.references == [
            "aws_iam_role.web",
            "aws_security_group.web",
            "aws_subnet.private",
            "data.aws_ami.ubuntu",
        ]
        assert inv.unparsed_files == []
        assert set(inv.parsed_files) == {"aws.tf"}

    def test_data_sources_variables_outputs_modules_providers(self):
        inv = parse_terraform(_load("aws.tf"))
        assert [d.address for d in inv.data_sources] == ["data.aws_ami.ubuntu"]
        assert inv.data_sources[0].data_type == "aws_ami"
        assert inv.data_sources[0].attributes["most_recent"] is True

        by_name = {v.name: v for v in inv.variables}
        assert by_name["region"].type_expr == "string"
        assert by_name["region"].default == "us-east-1"
        assert by_name["region"].description == "AWS region"
        assert by_name["region"].sensitive is False
        assert by_name["db_password"].sensitive is True

        outs = {o.name: o for o in inv.outputs}
        assert outs["instance_ip"].value_expr == "aws_instance.web.private_ip"
        assert outs["instance_ip"].sensitive is False
        assert outs["db_password"].sensitive is True

        assert len(inv.modules) == 1
        assert inv.modules[0].name == "dns"
        assert inv.modules[0].source == "../../modules/dns/aws"
        assert inv.modules[0].inputs == {
            "zone": "example.com",
            "vpc_id": "aws_vpc.main.id",
        }
        assert inv.modules[0].file == "aws.tf"

        assert len(inv.providers) == 1
        assert inv.providers[0].name == "aws"
        assert inv.providers[0].alias is None
        assert inv.providers[0].config == {"region": "var.region"}

    def test_unparsable_file_is_reported_not_fatal(self):
        inv = parse_terraform(_load("aws.tf", "broken.tf"))
        assert inv.unparsed_files == ["broken.tf"]
        assert len(inv.resources) == 7
        assert "broken.tf" not in inv.parsed_files

    def test_any_exception_from_hcl2_marks_file_unparsed(self, monkeypatch):
        import tmi_tf.tf_parser as mod

        def boom(_text):
            raise AttributeError("'ConditionalRule' object has no attribute 'expression'")

        monkeypatch.setattr(mod.hcl2, "loads", boom)
        inv = parse_terraform({"a.tf": 'resource "x_y" "z" {}'})
        assert inv.unparsed_files == ["a.tf"]
        assert inv.resources == []

    def test_empty_and_comment_only_files_parse_to_nothing(self):
        inv = parse_terraform({"empty.tf": "", "c.tf": "# nothing\n"})
        assert inv.unparsed_files == []
        assert inv.resources == [] and inv.data_sources == []
        assert set(inv.parsed_files) == {"empty.tf", "c.tf"}

    def test_tfvars_parses_without_blocks(self):
        inv = parse_terraform({"terraform.tfvars": 'region = "us-east-1"\n'})
        assert inv.resources == []
        assert inv.parsed_files["terraform.tfvars"] == {"region": '"us-east-1"'}

    def test_duplicate_addresses_across_files_are_both_kept(self):
        body = 'resource "aws_iam_role" "this" {\n  name = "r"\n}\n'
        inv = parse_terraform({"modules/a/main.tf": body, "modules/b/main.tf": body})
        assert [r.address for r in inv.resources] == [
            "aws_iam_role.this",
            "aws_iam_role.this",
        ]
        assert sorted(r.file for r in inv.resources) == [
            "modules/a/main.tf",
            "modules/b/main.tf",
        ]

    def test_provider_alias(self):
        inv = parse_terraform(
            {"p.tf": 'provider "aws" {\n  region = "us-west-2"\n  alias = "west"\n}\n'}
        )
        assert inv.providers[0].alias == "west"
        assert inv.providers[0].config == {"region": "us-west-2"}
```

- [ ] **Step 5: Run the tests to verify they fail**

Run: `uv run pytest tests/test_tf_parser.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'tmi_tf.tf_parser'`.

- [ ] **Step 6: Implement `tmi_tf/tf_parser.py`**

```python
"""Static HCL parsing of Terraform files with python-hcl2 (issue #10).

python-hcl2 8.x conventions this module relies on:
  string literals keep their quotes   '"ami-123"'
  expressions are wrapped             '${aws_subnet.private.id}'
  nested blocks are lists of dicts    [{"encrypted": True, "__is_block__": True}]
  block labels keep their quotes      {'"aws_instance"': {'"web"': body}}
"""

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

import hcl2

logger = logging.getLogger(__name__)

BLOCK_MARKER = "__is_block__"

# resource_type.name | data.type.name | module.name -- never var./local./each./
# path./count./self.: the lookbehind refuses a match right after a dot and the
# resource alternative requires an underscore in the type.
_REF_RE = re.compile(
    r"(?<![\w.])(data\.[a-z][a-z0-9_]*|module|[a-z][a-z0-9]*_[a-z0-9_]*)"
    r"\.([A-Za-z_][\w-]*)"
)


@dataclass
class ParsedResource:
    resource_type: str
    local_name: str
    address: str
    file: str
    attributes: dict[str, Any]
    references: list[str]


@dataclass
class ParsedDataSource:
    data_type: str
    local_name: str
    address: str
    file: str
    attributes: dict[str, Any]
    references: list[str]


@dataclass
class ParsedVariable:
    name: str
    type_expr: str | None
    default: Any
    description: str | None
    sensitive: bool


@dataclass
class ParsedOutput:
    name: str
    value_expr: str
    description: str | None
    sensitive: bool


@dataclass
class ParsedModule:
    name: str
    source: str
    inputs: dict[str, Any]
    file: str


@dataclass
class ParsedProvider:
    name: str
    alias: str | None
    config: dict[str, Any]


@dataclass
class StaticInventory:
    resources: list[ParsedResource] = field(default_factory=list)
    data_sources: list[ParsedDataSource] = field(default_factory=list)
    variables: list[ParsedVariable] = field(default_factory=list)
    outputs: list[ParsedOutput] = field(default_factory=list)
    modules: list[ParsedModule] = field(default_factory=list)
    providers: list[ParsedProvider] = field(default_factory=list)
    unparsed_files: list[str] = field(default_factory=list)
    # Raw hcl2 dict per parsed file; tf_filter regenerates HCL from these.
    parsed_files: dict[str, dict[str, Any]] = field(default_factory=dict)


def unquote_literal(s: str) -> str:
    """'"x"' -> 'x'; anything else unchanged."""
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1]
    return s


def clean_value(value: Any) -> Any:
    """Human-readable form: drop hcl2 bookkeeping keys (``__is_block__``,
    ``__comments__``), unquote literals, unwrap ${expr}."""
    if isinstance(value, dict):
        return {k: clean_value(v) for k, v in value.items() if not k.startswith("__")}
    if isinstance(value, list):
        return [clean_value(v) for v in value]
    if isinstance(value, str):
        if value.startswith("${") and value.endswith("}") and value.count("${") == 1:
            return value[2:-1]
        return unquote_literal(value)
    return value


def find_references(value: Any, exclude: str = "") -> list[str]:
    """Terraform addresses referenced anywhere inside ``value``.

    Only expression strings (containing ``${``) are scanned, so a quoted literal
    such as ``"owner_team.name"`` is not mistaken for a reference.
    """
    refs: set[str] = set()

    def walk(v: Any) -> None:
        if isinstance(v, dict):
            for item in v.values():
                walk(item)
        elif isinstance(v, list):
            for item in v:
                walk(item)
        elif isinstance(v, str) and "${" in v:
            for m in _REF_RE.finditer(v):
                refs.add(f"{m.group(1)}.{m.group(2)}")

    walk(value)
    refs.discard(exclude)
    return sorted(refs)


def _labelled(item: dict[str, Any]) -> list[tuple[str, Any]]:
    """[(label, body)] for a one-label block item like {'"aws"': body}."""
    return [(unquote_literal(k), v) for k, v in item.items()]


def _optional_str(body: dict[str, Any], key: str) -> str | None:
    value = body.get(key)
    return None if value is None else str(clean_value(value))


def _collect(inv: StaticInventory, path: str, parsed: dict[str, Any]) -> None:
    for item in parsed.get("resource", []):
        for rtype, by_name in _labelled(item):
            for name, body in _labelled(by_name):
                address = f"{rtype}.{name}"
                inv.resources.append(
                    ParsedResource(
                        resource_type=rtype,
                        local_name=name,
                        address=address,
                        file=path,
                        attributes=clean_value(body),
                        references=find_references(body, exclude=address),
                    )
                )
    for item in parsed.get("data", []):
        for dtype, by_name in _labelled(item):
            for name, body in _labelled(by_name):
                address = f"data.{dtype}.{name}"
                inv.data_sources.append(
                    ParsedDataSource(
                        data_type=dtype,
                        local_name=name,
                        address=address,
                        file=path,
                        attributes=clean_value(body),
                        references=find_references(body, exclude=address),
                    )
                )
    for item in parsed.get("variable", []):
        for name, body in _labelled(item):
            inv.variables.append(
                ParsedVariable(
                    name=name,
                    type_expr=_optional_str(body, "type"),
                    default=clean_value(body.get("default")),
                    description=_optional_str(body, "description"),
                    sensitive=body.get("sensitive") is True,
                )
            )
    for item in parsed.get("output", []):
        for name, body in _labelled(item):
            inv.outputs.append(
                ParsedOutput(
                    name=name,
                    value_expr=str(clean_value(body.get("value", ""))),
                    description=_optional_str(body, "description"),
                    sensitive=body.get("sensitive") is True,
                )
            )
    for item in parsed.get("module", []):
        for name, body in _labelled(item):
            attrs = clean_value(body)
            source = str(attrs.pop("source", ""))
            for meta in ("version", "providers", "depends_on", "count", "for_each"):
                attrs.pop(meta, None)
            inv.modules.append(
                ParsedModule(name=name, source=source, inputs=attrs, file=path)
            )
    for item in parsed.get("provider", []):
        for name, body in _labelled(item):
            config = clean_value(body)
            alias = config.pop("alias", None)
            inv.providers.append(
                ParsedProvider(
                    name=name,
                    alias=None if alias is None else str(alias),
                    config=config,
                )
            )


def parse_terraform(tf_contents: dict[str, str]) -> StaticInventory:
    """Parse every file; files python-hcl2 rejects go to ``unparsed_files``.

    ``tf_contents`` is ``TerraformRepository.get_terraform_content()`` output
    (relative path -> text), i.e. the environment plus resolved modules after
    sanitization.
    """
    inv = StaticInventory()
    for path in sorted(tf_contents):
        try:
            parsed = hcl2.loads(tf_contents[path])
        except Exception as e:
            # lark errors and the occasional transformer bug (AttributeError on
            # python-hcl2 8.1.4) alike: the LLM still sees the raw file.
            logger.warning("Static HCL parse failed for %s: %s", path, e)
            inv.unparsed_files.append(path)
            continue
        inv.parsed_files[path] = parsed
        _collect(inv, path, parsed)
    return inv
```

Note on the address-order assertion in `test_resources_and_addresses`: `parse_terraform` sorts file names, and hcl2 keeps block order within a file, so the order is deterministic.

- [ ] **Step 7: Run the tests to verify they pass**

Run: `uv run pytest tests/test_tf_parser.py -q`
Expected: all PASS. If `find_references` ordering or `type_expr` differ, check the probe output from step 2 rather than loosening the assertions.

- [ ] **Step 8: Lint, type-check, full suite**

Run: `uv run ruff format tmi_tf/ tests/ && uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright && uv run pytest tests/ -q`
Expected: all green. python-hcl2 ships `py.typed`, so no pyright ignore is needed on `import hcl2`.

- [ ] **Step 9: Commit**

```bash
git add pyproject.toml uv.lock tmi_tf/tf_parser.py tests/test_tf_parser.py tests/fixtures/tf/aws.tf tests/fixtures/tf/broken.tf
git commit -m "feat(#10): static HCL parser on python-hcl2

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Resource registry

**Files:**
- Create: `tmi_tf/data/resource_registry.yaml`
- Test: `tests/test_resource_registry.py`

**Interfaces:**
- Consumes: nothing (pure data; Task 3 adds the loader).
- Produces: YAML with top-level `providers` (prefix -> `{name, type}`), `resources` (type -> `{category, security_attrs: [...]}`), `defaults` (`unknown_category: other`, `unknown_attrs: all`, `hash_only_attrs: [...]`). Attribute paths use dot notation for nested blocks/objects (`ebs_block_device.encrypted`). The file ships inside the package (`COPY tmi_tf/ tmi_tf/` in every Dockerfile; hatchling includes non-Python files under the package).

- [ ] **Step 1: Write the failing registry tests**

`tests/test_resource_registry.py`:

```python
"""Validity tests for tmi_tf/data/resource_registry.yaml (issue #10)."""

import re
from pathlib import Path

import yaml  # pyright: ignore[reportMissingModuleSource]

REGISTRY_PATH = Path(__file__).parent.parent / "tmi_tf" / "data" / "resource_registry.yaml"

ALLOWED_CATEGORIES = {
    "compute",
    "storage",
    "network",
    "gateway",
    "security_control",
    "identity",
    "monitoring",
    "dns",
    "cdn",
    "other",
}
ATTR_PATH_RE = re.compile(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)*$")


def _registry() -> dict:
    return yaml.safe_load(REGISTRY_PATH.read_text(encoding="utf-8"))


class TestRegistryStructure:
    def test_top_level_keys(self):
        reg = _registry()
        assert set(reg) == {"providers", "resources", "defaults"}
        assert reg["defaults"]["unknown_category"] == "other"
        assert reg["defaults"]["unknown_attrs"] == "all"
        assert "user_data" in reg["defaults"]["hash_only_attrs"]

    def test_provider_prefixes(self):
        for prefix, info in _registry()["providers"].items():
            assert prefix.endswith("_"), prefix
            assert info["name"] and info["type"], prefix

    def test_every_resource_is_well_formed(self):
        reg = _registry()
        prefixes = tuple(reg["providers"])
        for rtype, entry in reg["resources"].items():
            assert entry["category"] in ALLOWED_CATEGORIES, rtype
            attrs = entry["security_attrs"]
            assert isinstance(attrs, list), rtype
            assert len(attrs) == len(set(attrs)), f"{rtype}: duplicate attrs"
            for a in attrs:
                assert ATTR_PATH_RE.match(a), f"{rtype}: bad attr path {a!r}"
            assert rtype.startswith(prefixes), f"{rtype}: no provider prefix"

    def test_four_cloud_providers_are_covered(self):
        types = set(_registry()["resources"])
        expected = {
            "aws": ["aws_instance", "aws_s3_bucket", "aws_security_group", "aws_iam_role",
                    "aws_vpc", "aws_db_instance", "aws_lambda_function", "aws_eks_cluster"],
            "azurerm": ["azurerm_linux_virtual_machine", "azurerm_storage_account",
                        "azurerm_network_security_group", "azurerm_key_vault",
                        "azurerm_kubernetes_cluster", "azurerm_postgresql_flexible_server"],
            "google": ["google_compute_instance", "google_storage_bucket",
                       "google_compute_firewall", "google_container_cluster",
                       "google_sql_database_instance", "google_service_account"],
            "oci": ["oci_core_instance", "oci_objectstorage_bucket", "oci_core_security_list",
                    "oci_core_network_security_group", "oci_containerengine_cluster",
                    "oci_database_autonomous_database", "oci_vault_secret"],
        }
        for provider, names in expected.items():
            missing = [n for n in names if n not in types]
            assert not missing, f"{provider}: missing {missing}"

    def test_tmi_repo_resource_types_are_covered(self):
        """Every type used by ~/Projects/tmi/terraform that is not a utility provider."""
        types = set(_registry()["resources"])
        used = [
            "aws_accessanalyzer_analyzer", "aws_acm_certificate", "aws_cloudtrail",
            "aws_cloudwatch_log_group", "aws_db_instance", "aws_ecr_repository",
            "aws_eip", "aws_eks_addon", "aws_eks_cluster", "aws_eks_node_group",
            "aws_flow_log", "aws_iam_openid_connect_provider", "aws_iam_policy",
            "aws_iam_role", "aws_iam_role_policy", "aws_iam_role_policy_attachment",
            "aws_internet_gateway", "aws_launch_template", "aws_nat_gateway",
            "aws_route53_record", "aws_route_table", "aws_s3_bucket",
            "aws_s3_bucket_policy", "aws_s3_bucket_public_access_block",
            "aws_s3_bucket_server_side_encryption_configuration",
            "aws_secretsmanager_secret", "aws_security_group", "aws_sns_topic",
            "aws_subnet", "aws_vpc", "aws_vpc_security_group_ingress_rule",
            "aws_vpc_security_group_egress_rule",
            "azurerm_container_registry", "azurerm_key_vault", "azurerm_key_vault_secret",
            "azurerm_kubernetes_cluster", "azurerm_log_analytics_workspace",
            "azurerm_nat_gateway", "azurerm_network_security_group",
            "azurerm_postgresql_flexible_server", "azurerm_public_ip",
            "azurerm_role_assignment", "azurerm_subnet", "azurerm_virtual_network",
            "google_artifact_registry_repository", "google_compute_firewall",
            "google_compute_network", "google_compute_router_nat",
            "google_compute_subnetwork", "google_container_cluster",
            "google_secret_manager_secret", "google_service_account",
            "google_sql_database_instance", "google_storage_bucket",
            "oci_containerengine_cluster", "oci_containerengine_node_pool",
            "oci_core_internet_gateway", "oci_core_nat_gateway",
            "oci_core_network_security_group", "oci_core_route_table",
            "oci_core_security_list", "oci_core_subnet", "oci_core_vcn",
            "oci_database_autonomous_database", "oci_functions_function",
            "oci_identity_policy", "oci_kms_key", "oci_kms_vault",
            "oci_load_balancer_load_balancer", "oci_logging_log",
            "oci_objectstorage_bucket", "oci_vault_secret",
            "kubernetes_deployment_v1", "kubernetes_service_v1", "kubernetes_ingress_v1",
            "kubernetes_secret_v1", "helm_release",
        ]
        missing = [t for t in used if t not in types]
        assert not missing, missing
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_resource_registry.py -q`
Expected: FAIL with `FileNotFoundError` for the registry path.

- [ ] **Step 3: Create `tmi_tf/data/resource_registry.yaml`**

Write the file below verbatim. Every entry: `category` from the allowed set, `security_attrs` flow-style list. Comments record why an attribute matters where it is not obvious.

```yaml
# Resource registry for static HCL analysis (issue #10).
#
# resources: Terraform resource type -> component category and the attributes
#   worth showing an LLM for threat modeling (identity/IAM references,
#   encryption, network placement, exposure, access control, logging, images).
#   Dot paths reach into nested blocks or objects: ebs_block_device.encrypted.
#   Everything not listed is stripped from the filtered HCL and replaced by a
#   "# N non-security attributes omitted" comment. Meta-arguments (count,
#   for_each, depends_on, provider, lifecycle) and any attribute holding a
#   resource/data/module reference are always kept.
# providers: resource type prefix -> provider label sent with each component.
# defaults: unknown resource types get category `other` and keep ALL
#   attributes (unknown_attrs: all); hash_only_attrs are script-carrying
#   attributes (any nesting depth) replaced by a sha256 digest + size.
#
# Categories: compute, storage, network, gateway, security_control, identity,
#             monitoring, dns, cdn, other

providers:
  aws_: { name: "AWS", type: "cloud" }
  azurerm_: { name: "Microsoft Azure", type: "cloud" }
  azuread_: { name: "Microsoft Entra ID", type: "cloud" }
  google_: { name: "Google Cloud", type: "cloud" }
  oci_: { name: "Oracle Cloud", type: "cloud" }
  kubernetes_: { name: "Kubernetes", type: "platform" }
  helm_: { name: "Helm", type: "platform" }
  random_: { name: "Terraform random provider", type: "utility" }
  null_: { name: "Terraform null provider", type: "utility" }
  tls_: { name: "Terraform tls provider", type: "utility" }
  time_: { name: "Terraform time provider", type: "utility" }
  local_: { name: "Terraform local provider", type: "utility" }

resources:
  # ---------------------------------------------------------------- AWS compute
  aws_instance:
    category: compute
    security_attrs: [ami, iam_instance_profile, vpc_security_group_ids, security_groups, subnet_id,
      associate_public_ip_address, key_name, monitoring, metadata_options, user_data,
      user_data_base64, root_block_device.encrypted, root_block_device.kms_key_id,
      ebs_block_device.encrypted, ebs_block_device.kms_key_id]
  aws_launch_template:
    category: compute
    security_attrs: [image_id, iam_instance_profile, vpc_security_group_ids,
      network_interfaces.security_groups, network_interfaces.associate_public_ip_address,
      network_interfaces.subnet_id, metadata_options, user_data, key_name, monitoring,
      block_device_mappings.ebs.encrypted, block_device_mappings.ebs.kms_key_id]
  aws_launch_configuration:
    category: compute
    security_attrs: [image_id, iam_instance_profile, security_groups, associate_public_ip_address,
      user_data, user_data_base64, key_name, root_block_device.encrypted]
  aws_autoscaling_group:
    category: compute
    security_attrs: [launch_template, launch_configuration, vpc_zone_identifier, target_group_arns,
      min_size, max_size, desired_capacity, service_linked_role_arn]
  aws_lambda_function:
    category: compute
    security_attrs: [role, runtime, handler, vpc_config, environment, kms_key_arn,
      reserved_concurrent_executions, tracing_config, layers, image_uri, source_code_hash]
  aws_lambda_permission:
    category: security_control
    security_attrs: [action, function_name, principal, source_arn, source_account]
  aws_ecs_cluster:
    category: compute
    security_attrs: [setting, configuration]
  aws_ecs_service:
    category: compute
    security_attrs: [cluster, task_definition, launch_type, network_configuration, load_balancer,
      iam_role, desired_count]
  aws_ecs_task_definition:
    category: compute
    security_attrs: [execution_role_arn, task_role_arn, network_mode, container_definitions,
      requires_compatibilities]
  aws_eks_cluster:
    category: compute
    security_attrs: [role_arn, version, vpc_config, encryption_config, enabled_cluster_log_types,
      access_config, kubernetes_network_config]
  aws_eks_node_group:
    category: compute
    security_attrs: [cluster_name, node_role_arn, subnet_ids, remote_access, launch_template,
      scaling_config, ami_type, capacity_type]
  aws_eks_addon:
    category: compute
    security_attrs: [cluster_name, addon_name, addon_version, service_account_role_arn]
  aws_eks_fargate_profile:
    category: compute
    security_attrs: [cluster_name, pod_execution_role_arn, subnet_ids, selector]
  aws_batch_compute_environment:
    category: compute
    security_attrs: [service_role, compute_resources]
  aws_elastic_beanstalk_environment:
    category: compute
    security_attrs: [application, solution_stack_name, setting]
  aws_apprunner_service:
    category: compute
    security_attrs: [source_configuration, instance_configuration, network_configuration,
      encryption_configuration]
  aws_lightsail_instance:
    category: compute
    security_attrs: [blueprint_id, key_pair_name, user_data]

  # ---------------------------------------------------------------- AWS storage
  aws_s3_bucket:
    category: storage
    security_attrs: [bucket, acl, force_destroy, versioning, server_side_encryption_configuration,
      logging, policy, object_lock_enabled, website]
  aws_s3_bucket_policy:
    category: security_control
    security_attrs: [bucket, policy]
  aws_s3_bucket_public_access_block:
    category: security_control
    security_attrs: [bucket, block_public_acls, block_public_policy, ignore_public_acls,
      restrict_public_buckets]
  aws_s3_bucket_server_side_encryption_configuration:
    category: security_control
    security_attrs: [bucket, rule]
  aws_s3_bucket_versioning:
    category: storage
    security_attrs: [bucket, versioning_configuration]
  aws_s3_bucket_logging:
    category: monitoring
    security_attrs: [bucket, target_bucket, target_prefix]
  aws_s3_bucket_acl:
    category: security_control
    security_attrs: [bucket, acl, access_control_policy]
  aws_s3_bucket_ownership_controls:
    category: security_control
    security_attrs: [bucket, rule]
  aws_s3_bucket_object_lock_configuration:
    category: security_control
    security_attrs: [bucket, rule]
  aws_s3_bucket_lifecycle_configuration:
    category: storage
    security_attrs: [bucket, rule.id, rule.status, rule.expiration]
  aws_s3_bucket_website_configuration:
    category: storage
    security_attrs: [bucket, index_document, redirect_all_requests_to]
  aws_ebs_volume:
    category: storage
    security_attrs: [encrypted, kms_key_id, availability_zone, size]
  aws_efs_file_system:
    category: storage
    security_attrs: [encrypted, kms_key_id]
  aws_efs_mount_target:
    category: storage
    security_attrs: [file_system_id, subnet_id, security_groups]
  aws_db_instance:
    category: storage
    security_attrs: [engine, engine_version, instance_class, publicly_accessible, storage_encrypted,
      kms_key_id, vpc_security_group_ids, db_subnet_group_name, iam_database_authentication_enabled,
      multi_az, backup_retention_period, deletion_protection, enabled_cloudwatch_logs_exports,
      manage_master_user_password, master_user_secret_kms_key_id, parameter_group_name, port,
      username, monitoring_role_arn, performance_insights_enabled, ca_cert_identifier]
  aws_db_subnet_group:
    category: network
    security_attrs: [subnet_ids]
  aws_db_parameter_group:
    category: storage
    security_attrs: [family, parameter]
  aws_rds_cluster:
    category: storage
    security_attrs: [engine, engine_version, storage_encrypted, kms_key_id, vpc_security_group_ids,
      db_subnet_group_name, iam_database_authentication_enabled, backup_retention_period,
      deletion_protection, enabled_cloudwatch_logs_exports, master_username,
      manage_master_user_password, port]
  aws_rds_cluster_instance:
    category: storage
    security_attrs: [cluster_identifier, instance_class, publicly_accessible,
      db_subnet_group_name, monitoring_role_arn, performance_insights_enabled]
  aws_dynamodb_table:
    category: storage
    security_attrs: [server_side_encryption, point_in_time_recovery, deletion_protection_enabled,
      billing_mode, stream_enabled]
  aws_elasticache_cluster:
    category: storage
    security_attrs: [engine, subnet_group_name, security_group_ids, port, snapshot_retention_limit]
  aws_elasticache_replication_group:
    category: storage
    security_attrs: [engine, at_rest_encryption_enabled, transit_encryption_enabled, kms_key_id,
      auth_token, subnet_group_name, security_group_ids, port]
  aws_redshift_cluster:
    category: storage
    security_attrs: [encrypted, kms_key_id, publicly_accessible, vpc_security_group_ids,
      cluster_subnet_group_name, iam_roles, logging, master_username, port]
  aws_opensearch_domain:
    category: storage
    security_attrs: [engine_version, encrypt_at_rest, node_to_node_encryption,
      domain_endpoint_options, vpc_options, access_policies, advanced_security_options,
      log_publishing_options]
  aws_ecr_repository:
    category: storage
    security_attrs: [image_tag_mutability, image_scanning_configuration, encryption_configuration,
      force_delete]
  aws_ecr_repository_policy:
    category: security_control
    security_attrs: [repository, policy]
  aws_backup_vault:
    category: storage
    security_attrs: [kms_key_arn]
  aws_glacier_vault:
    category: storage
    security_attrs: [access_policy, notification]

  # ---------------------------------------------------------------- AWS network
  aws_vpc:
    category: network
    security_attrs: [cidr_block, enable_dns_support, enable_dns_hostnames, instance_tenancy]
  aws_subnet:
    category: network
    security_attrs: [vpc_id, cidr_block, availability_zone, map_public_ip_on_launch]
  aws_route_table:
    category: network
    security_attrs: [vpc_id, route]
  aws_route:
    category: network
    security_attrs: [route_table_id, destination_cidr_block, gateway_id, nat_gateway_id,
      transit_gateway_id, vpc_peering_connection_id]
  aws_route_table_association:
    category: network
    security_attrs: [subnet_id, route_table_id, gateway_id]
  aws_vpc_endpoint:
    category: network
    security_attrs: [vpc_id, service_name, vpc_endpoint_type, subnet_ids, security_group_ids,
      policy, private_dns_enabled]
  aws_vpc_peering_connection:
    category: network
    security_attrs: [vpc_id, peer_vpc_id, peer_owner_id, auto_accept]
  aws_ec2_transit_gateway:
    category: network
    security_attrs: [default_route_table_association, default_route_table_propagation,
      auto_accept_shared_attachments]
  aws_ec2_transit_gateway_vpc_attachment:
    category: network
    security_attrs: [transit_gateway_id, vpc_id, subnet_ids]
  aws_network_interface:
    category: network
    security_attrs: [subnet_id, security_groups, private_ips, source_dest_check]
  aws_eip:
    category: network
    security_attrs: [domain, instance, network_interface, vpc]
  aws_eip_association:
    category: network
    security_attrs: [allocation_id, instance_id, network_interface_id]
  aws_flow_log:
    category: monitoring
    security_attrs: [vpc_id, subnet_id, traffic_type, log_destination, log_destination_type,
      iam_role_arn]
  aws_internet_gateway:
    category: gateway
    security_attrs: [vpc_id]
  aws_nat_gateway:
    category: gateway
    security_attrs: [subnet_id, allocation_id, connectivity_type]
  aws_lb:
    category: gateway
    security_attrs: [load_balancer_type, internal, security_groups, subnets, subnet_mapping,
      access_logs, drop_invalid_header_fields, enable_deletion_protection]
  aws_alb:
    category: gateway
    security_attrs: [load_balancer_type, internal, security_groups, subnets, access_logs,
      enable_deletion_protection]
  aws_elb:
    category: gateway
    security_attrs: [internal, security_groups, subnets, listener, access_logs]
  aws_lb_listener:
    category: gateway
    security_attrs: [load_balancer_arn, port, protocol, ssl_policy, certificate_arn, default_action]
  aws_lb_listener_rule:
    category: gateway
    security_attrs: [listener_arn, action, condition]
  aws_lb_target_group:
    category: network
    security_attrs: [port, protocol, vpc_id, target_type, health_check]
  aws_lb_target_group_attachment:
    category: network
    security_attrs: [target_group_arn, target_id, port]
  aws_api_gateway_rest_api:
    category: gateway
    security_attrs: [endpoint_configuration, policy, disable_execute_api_endpoint]
  aws_api_gateway_stage:
    category: gateway
    security_attrs: [rest_api_id, stage_name, access_log_settings, xray_tracing_enabled,
      client_certificate_id]
  aws_api_gateway_method:
    category: gateway
    security_attrs: [rest_api_id, http_method, authorization, authorizer_id, api_key_required]
  aws_api_gateway_authorizer:
    category: security_control
    security_attrs: [rest_api_id, type, authorizer_uri, provider_arns]
  aws_apigatewayv2_api:
    category: gateway
    security_attrs: [protocol_type, cors_configuration, disable_execute_api_endpoint]
  aws_apigatewayv2_stage:
    category: gateway
    security_attrs: [api_id, access_log_settings, default_route_settings]
  aws_apigatewayv2_authorizer:
    category: security_control
    security_attrs: [api_id, authorizer_type, jwt_configuration, authorizer_uri]
  aws_cloudfront_distribution:
    category: cdn
    security_attrs: [enabled, origin, default_cache_behavior.viewer_protocol_policy,
      viewer_certificate, restrictions, web_acl_id, logging_config, aliases]
  aws_cloudfront_origin_access_control:
    category: security_control
    security_attrs: [origin_access_control_origin_type, signing_behavior, signing_protocol]
  aws_route53_zone:
    category: dns
    security_attrs: [name, vpc]
  aws_route53_record:
    category: dns
    security_attrs: [zone_id, name, type, alias, records]
  aws_route53_resolver_endpoint:
    category: dns
    security_attrs: [direction, security_group_ids, ip_address]
  aws_globalaccelerator_accelerator:
    category: gateway
    security_attrs: [enabled, ip_address_type, attributes]

  # ------------------------------------------------------ AWS security controls
  aws_security_group:
    category: security_control
    security_attrs: [name, vpc_id, ingress, egress]
  aws_security_group_rule:
    category: security_control
    security_attrs: [security_group_id, type, from_port, to_port, protocol, cidr_blocks,
      ipv6_cidr_blocks, source_security_group_id, self]
  aws_vpc_security_group_ingress_rule:
    category: security_control
    security_attrs: [security_group_id, from_port, to_port, ip_protocol, cidr_ipv4, cidr_ipv6,
      referenced_security_group_id, prefix_list_id]
  aws_vpc_security_group_egress_rule:
    category: security_control
    security_attrs: [security_group_id, from_port, to_port, ip_protocol, cidr_ipv4, cidr_ipv6,
      referenced_security_group_id, prefix_list_id]
  aws_network_acl:
    category: security_control
    security_attrs: [vpc_id, subnet_ids, ingress, egress]
  aws_network_acl_rule:
    category: security_control
    security_attrs: [network_acl_id, rule_number, egress, protocol, rule_action, cidr_block,
      from_port, to_port]
  aws_wafv2_web_acl:
    category: security_control
    security_attrs: [scope, default_action, rule.name, rule.action, rule.override_action,
      visibility_config]
  aws_wafv2_web_acl_association:
    category: security_control
    security_attrs: [resource_arn, web_acl_arn]
  aws_kms_key:
    category: security_control
    security_attrs: [description, enable_key_rotation, deletion_window_in_days, policy,
      key_usage, multi_region]
  aws_kms_alias:
    category: security_control
    security_attrs: [name, target_key_id]
  aws_secretsmanager_secret:
    category: security_control
    security_attrs: [name, kms_key_id, recovery_window_in_days, policy, replica]
  aws_secretsmanager_secret_version:
    category: security_control
    security_attrs: [secret_id]
  aws_secretsmanager_secret_rotation:
    category: security_control
    security_attrs: [secret_id, rotation_lambda_arn, rotation_rules]
  aws_ssm_parameter:
    category: security_control
    security_attrs: [name, type, key_id, tier]
  aws_acm_certificate:
    category: security_control
    security_attrs: [domain_name, subject_alternative_names, validation_method, key_algorithm]
  aws_acm_certificate_validation:
    category: security_control
    security_attrs: [certificate_arn, validation_record_fqdns]
  aws_shield_protection:
    category: security_control
    security_attrs: [resource_arn]
  aws_guardduty_detector:
    category: monitoring
    security_attrs: [enable, finding_publishing_frequency, datasources]
  aws_securityhub_account:
    category: monitoring
    security_attrs: [enable_default_standards, auto_enable_controls]
  aws_accessanalyzer_analyzer:
    category: monitoring
    security_attrs: [analyzer_name, type]
  aws_config_configuration_recorder:
    category: monitoring
    security_attrs: [role_arn, recording_group]
  aws_inspector2_enabler:
    category: monitoring
    security_attrs: [account_ids, resource_types]

  # --------------------------------------------------------------- AWS identity
  aws_iam_role:
    category: identity
    security_attrs: [name, assume_role_policy, managed_policy_arns, inline_policy,
      permissions_boundary, max_session_duration]
  aws_iam_policy:
    category: identity
    security_attrs: [name, policy]
  aws_iam_role_policy:
    category: identity
    security_attrs: [role, policy]
  aws_iam_role_policy_attachment:
    category: identity
    security_attrs: [role, policy_arn]
  aws_iam_policy_attachment:
    category: identity
    security_attrs: [policy_arn, roles, users, groups]
  aws_iam_user:
    category: identity
    security_attrs: [name, permissions_boundary, force_destroy]
  aws_iam_user_policy:
    category: identity
    security_attrs: [user, policy]
  aws_iam_user_policy_attachment:
    category: identity
    security_attrs: [user, policy_arn]
  aws_iam_access_key:
    category: identity
    security_attrs: [user, status, pgp_key]
  aws_iam_group:
    category: identity
    security_attrs: [name]
  aws_iam_group_policy_attachment:
    category: identity
    security_attrs: [group, policy_arn]
  aws_iam_instance_profile:
    category: identity
    security_attrs: [name, role]
  aws_iam_openid_connect_provider:
    category: identity
    security_attrs: [url, client_id_list, thumbprint_list]
  aws_iam_saml_provider:
    category: identity
    security_attrs: [name]
  aws_iam_account_password_policy:
    category: identity
    security_attrs: [minimum_password_length, require_symbols, require_numbers,
      require_uppercase_characters, require_lowercase_characters, max_password_age,
      password_reuse_prevention]
  aws_cognito_user_pool:
    category: identity
    security_attrs: [name, mfa_configuration, password_policy, admin_create_user_config,
      user_pool_add_ons, account_recovery_setting]
  aws_cognito_user_pool_client:
    category: identity
    security_attrs: [user_pool_id, generate_secret, allowed_oauth_flows, callback_urls,
      explicit_auth_flows, prevent_user_existence_errors]
  aws_cognito_identity_pool:
    category: identity
    security_attrs: [allow_unauthenticated_identities, cognito_identity_providers]

  # ------------------------------------------------------------- AWS monitoring
  aws_cloudwatch_log_group:
    category: monitoring
    security_attrs: [name, retention_in_days, kms_key_id]
  aws_cloudwatch_metric_alarm:
    category: monitoring
    security_attrs: [alarm_name, metric_name, namespace, alarm_actions, threshold]
  aws_cloudwatch_event_rule:
    category: monitoring
    security_attrs: [name, event_pattern, schedule_expression, role_arn]
  aws_cloudwatch_event_target:
    category: monitoring
    security_attrs: [rule, arn, role_arn]
  aws_cloudtrail:
    category: monitoring
    security_attrs: [name, s3_bucket_name, is_multi_region_trail, enable_log_file_validation,
      kms_key_id, cloud_watch_logs_group_arn, cloud_watch_logs_role_arn, include_global_service_events,
      event_selector]
  aws_sns_topic:
    category: other
    security_attrs: [name, kms_master_key_id, policy]
  aws_sns_topic_subscription:
    category: other
    security_attrs: [topic_arn, protocol, endpoint]
  aws_sns_topic_policy:
    category: security_control
    security_attrs: [arn, policy]
  aws_sqs_queue:
    category: other
    security_attrs: [name, kms_master_key_id, sqs_managed_sse_enabled, policy,
      redrive_policy, fifo_queue]
  aws_sqs_queue_policy:
    category: security_control
    security_attrs: [queue_url, policy]
  aws_kinesis_stream:
    category: other
    security_attrs: [name, encryption_type, kms_key_id, shard_count]
  aws_mq_broker:
    category: other
    security_attrs: [engine_type, publicly_accessible, subnet_ids, security_groups,
      encryption_options, logs]
  aws_ses_domain_identity:
    category: other
    security_attrs: [domain]

  # --------------------------------------------------------------- Azure compute
  azurerm_linux_virtual_machine:
    category: compute
    security_attrs: [size, admin_username, disable_password_authentication, admin_ssh_key,
      network_interface_ids, source_image_reference, source_image_id, identity, custom_data,
      os_disk.disk_encryption_set_id, encryption_at_host_enabled, secure_boot_enabled,
      vtpm_enabled]
  azurerm_windows_virtual_machine:
    category: compute
    security_attrs: [size, admin_username, network_interface_ids, source_image_reference,
      identity, custom_data, os_disk.disk_encryption_set_id, encryption_at_host_enabled]
  azurerm_virtual_machine:
    category: compute
    security_attrs: [vm_size, network_interface_ids, storage_image_reference, identity,
      os_profile.custom_data, os_profile_linux_config.disable_password_authentication,
      storage_os_disk.encryption_settings]
  azurerm_linux_virtual_machine_scale_set:
    category: compute
    security_attrs: [sku, instances, admin_username, disable_password_authentication,
      network_interface, source_image_reference, identity, custom_data, encryption_at_host_enabled]
  azurerm_kubernetes_cluster:
    category: compute
    security_attrs: [dns_prefix, kubernetes_version, private_cluster_enabled, identity,
      default_node_pool.vnet_subnet_id, default_node_pool.node_count, network_profile,
      azure_active_directory_role_based_access_control, role_based_access_control_enabled,
      api_server_access_profile, oms_agent, local_account_disabled, azure_policy_enabled,
      key_vault_secrets_provider, workload_identity_enabled, oidc_issuer_enabled]
  azurerm_kubernetes_cluster_node_pool:
    category: compute
    security_attrs: [kubernetes_cluster_id, vm_size, node_count, vnet_subnet_id,
      enable_node_public_ip]
  azurerm_container_group:
    category: compute
    security_attrs: [ip_address_type, subnet_ids, identity, image_registry_credential,
      container.image, container.ports, exposed_port]
  azurerm_container_app:
    category: compute
    security_attrs: [container_app_environment_id, identity, ingress, secret, registry]
  azurerm_container_app_environment:
    category: compute
    security_attrs: [infrastructure_subnet_id, internal_load_balancer_enabled,
      log_analytics_workspace_id]
  azurerm_linux_web_app:
    category: compute
    security_attrs: [service_plan_id, https_only, identity, site_config.ftps_state,
      site_config.minimum_tls_version, site_config.ip_restriction, auth_settings,
      virtual_network_subnet_id, client_certificate_enabled]
  azurerm_windows_web_app:
    category: compute
    security_attrs: [service_plan_id, https_only, identity, site_config.minimum_tls_version,
      site_config.ip_restriction, auth_settings, virtual_network_subnet_id]
  azurerm_linux_function_app:
    category: compute
    security_attrs: [service_plan_id, storage_account_name, https_only, identity,
      site_config.minimum_tls_version, site_config.ip_restriction, virtual_network_subnet_id]
  azurerm_app_service:
    category: compute
    security_attrs: [app_service_plan_id, https_only, identity, site_config, auth_settings]
  azurerm_service_plan:
    category: compute
    security_attrs: [os_type, sku_name]

  # --------------------------------------------------------------- Azure storage
  azurerm_storage_account:
    category: storage
    security_attrs: [account_tier, account_replication_type, account_kind,
      https_traffic_only_enabled, enable_https_traffic_only, min_tls_version,
      allow_nested_items_to_be_public, public_network_access_enabled, shared_access_key_enabled,
      network_rules, blob_properties.versioning_enabled, blob_properties.delete_retention_policy,
      identity, customer_managed_key, infrastructure_encryption_enabled, queue_properties.logging]
  azurerm_storage_container:
    category: storage
    security_attrs: [storage_account_name, storage_account_id, container_access_type]
  azurerm_storage_account_network_rules:
    category: security_control
    security_attrs: [storage_account_id, default_action, ip_rules, virtual_network_subnet_ids,
      bypass]
  azurerm_storage_share:
    category: storage
    security_attrs: [storage_account_name, quota, acl]
  azurerm_managed_disk:
    category: storage
    security_attrs: [storage_account_type, disk_encryption_set_id, encryption_settings,
      network_access_policy, public_network_access_enabled]
  azurerm_postgresql_flexible_server:
    category: storage
    security_attrs: [version, sku_name, administrator_login, delegated_subnet_id,
      private_dns_zone_id, public_network_access_enabled, backup_retention_days,
      geo_redundant_backup_enabled, high_availability, authentication, customer_managed_key,
      identity]
  azurerm_postgresql_flexible_server_firewall_rule:
    category: security_control
    security_attrs: [server_id, start_ip_address, end_ip_address]
  azurerm_postgresql_flexible_server_database:
    category: storage
    security_attrs: [server_id, name]
  azurerm_postgresql_server:
    category: storage
    security_attrs: [version, sku_name, administrator_login, ssl_enforcement_enabled,
      ssl_minimal_tls_version_enforced, public_network_access_enabled, geo_redundant_backup_enabled,
      threat_detection_policy, identity]
  azurerm_mssql_server:
    category: storage
    security_attrs: [version, administrator_login, minimum_tls_version,
      public_network_access_enabled, azuread_administrator, identity,
      transparent_data_encryption_key_vault_key_id]
  azurerm_mssql_database:
    category: storage
    security_attrs: [server_id, sku_name, transparent_data_encryption_enabled,
      threat_detection_policy, ledger_enabled]
  azurerm_mssql_firewall_rule:
    category: security_control
    security_attrs: [server_id, start_ip_address, end_ip_address]
  azurerm_mysql_flexible_server:
    category: storage
    security_attrs: [version, sku_name, administrator_login, delegated_subnet_id,
      private_dns_zone_id, backup_retention_days, geo_redundant_backup_enabled, identity]
  azurerm_cosmosdb_account:
    category: storage
    security_attrs: [offer_type, kind, public_network_access_enabled, ip_range_filter,
      is_virtual_network_filter_enabled, virtual_network_rule, key_vault_key_id,
      local_authentication_disabled, backup, identity]
  azurerm_redis_cache:
    category: storage
    security_attrs: [sku_name, enable_non_ssl_port, non_ssl_port_enabled, minimum_tls_version,
      public_network_access_enabled, subnet_id, redis_configuration]
  azurerm_container_registry:
    category: storage
    security_attrs: [sku, admin_enabled, public_network_access_enabled, network_rule_set,
      identity, encryption, anonymous_pull_enabled, zone_redundancy_enabled, georeplications]

  # --------------------------------------------------------------- Azure network
  azurerm_resource_group:
    category: other
    security_attrs: [name, location]
  azurerm_management_lock:
    category: security_control
    security_attrs: [scope, lock_level]
  azurerm_virtual_network:
    category: network
    security_attrs: [address_space, dns_servers, subnet]
  azurerm_subnet:
    category: network
    security_attrs: [virtual_network_name, address_prefixes, service_endpoints, delegation,
      private_endpoint_network_policies, private_endpoint_network_policies_enabled,
      private_link_service_network_policies_enabled]
  azurerm_subnet_network_security_group_association:
    category: security_control
    security_attrs: [subnet_id, network_security_group_id]
  azurerm_subnet_route_table_association:
    category: network
    security_attrs: [subnet_id, route_table_id]
  azurerm_subnet_nat_gateway_association:
    category: network
    security_attrs: [subnet_id, nat_gateway_id]
  azurerm_route_table:
    category: network
    security_attrs: [route, disable_bgp_route_propagation]
  azurerm_route:
    category: network
    security_attrs: [route_table_name, address_prefix, next_hop_type, next_hop_in_ip_address]
  azurerm_network_interface:
    category: network
    security_attrs: [ip_configuration.subnet_id, ip_configuration.public_ip_address_id,
      ip_configuration.private_ip_address_allocation, enable_ip_forwarding, ip_forwarding_enabled]
  azurerm_network_interface_security_group_association:
    category: security_control
    security_attrs: [network_interface_id, network_security_group_id]
  azurerm_public_ip:
    category: network
    security_attrs: [allocation_method, sku, ip_version, ddos_protection_mode]
  azurerm_nat_gateway:
    category: gateway
    security_attrs: [sku_name, idle_timeout_in_minutes]
  azurerm_nat_gateway_public_ip_association:
    category: gateway
    security_attrs: [nat_gateway_id, public_ip_address_id]
  azurerm_virtual_network_peering:
    category: network
    security_attrs: [virtual_network_name, remote_virtual_network_id, allow_forwarded_traffic,
      allow_gateway_transit, use_remote_gateways]
  azurerm_private_endpoint:
    category: network
    security_attrs: [subnet_id, private_service_connection, private_dns_zone_group]
  azurerm_private_dns_zone:
    category: dns
    security_attrs: [name]
  azurerm_private_dns_zone_virtual_network_link:
    category: dns
    security_attrs: [private_dns_zone_name, virtual_network_id, registration_enabled]
  azurerm_dns_zone:
    category: dns
    security_attrs: [name]
  azurerm_dns_a_record:
    category: dns
    security_attrs: [zone_name, name, records, target_resource_id]
  azurerm_dns_cname_record:
    category: dns
    security_attrs: [zone_name, name, record, target_resource_id]
  azurerm_lb:
    category: gateway
    security_attrs: [sku, frontend_ip_configuration]
  azurerm_lb_rule:
    category: gateway
    security_attrs: [loadbalancer_id, protocol, frontend_port, backend_port,
      backend_address_pool_ids, probe_id]
  azurerm_application_gateway:
    category: gateway
    security_attrs: [sku, gateway_ip_configuration, frontend_ip_configuration, ssl_policy,
      ssl_certificate.name, waf_configuration, firewall_policy_id, http_listener.protocol,
      identity, enable_http2]
  azurerm_web_application_firewall_policy:
    category: security_control
    security_attrs: [policy_settings, managed_rules, custom_rules]
  azurerm_firewall:
    category: security_control
    security_attrs: [sku_name, sku_tier, firewall_policy_id, ip_configuration, threat_intel_mode]
  azurerm_firewall_policy:
    category: security_control
    security_attrs: [sku, threat_intelligence_mode, dns, intrusion_detection]
  azurerm_bastion_host:
    category: gateway
    security_attrs: [sku, ip_configuration, tunneling_enabled, ip_connect_enabled]
  azurerm_virtual_network_gateway:
    category: gateway
    security_attrs: [type, vpn_type, sku, ip_configuration, vpn_client_configuration]
  azurerm_frontdoor:
    category: cdn
    security_attrs: [frontend_endpoint, routing_rule, backend_pool]
  azurerm_cdn_frontdoor_profile:
    category: cdn
    security_attrs: [sku_name]
  azurerm_cdn_frontdoor_endpoint:
    category: cdn
    security_attrs: [cdn_frontdoor_profile_id, enabled]
  azurerm_cdn_endpoint:
    category: cdn
    security_attrs: [profile_name, origin, is_http_allowed, is_https_allowed]

  # ------------------------------------------------------ Azure security/identity
  azurerm_network_security_group:
    category: security_control
    security_attrs: [security_rule]
  azurerm_network_security_rule:
    category: security_control
    security_attrs: [network_security_group_name, priority, direction, access, protocol,
      source_port_range, destination_port_range, destination_port_ranges, source_address_prefix,
      source_address_prefixes, destination_address_prefix, source_application_security_group_ids]
  azurerm_key_vault:
    category: security_control
    security_attrs: [sku_name, tenant_id, enable_rbac_authorization, rbac_authorization_enabled,
      purge_protection_enabled, soft_delete_retention_days, public_network_access_enabled,
      network_acls, access_policy, enabled_for_deployment, enabled_for_disk_encryption,
      enabled_for_template_deployment]
  azurerm_key_vault_secret:
    category: security_control
    security_attrs: [key_vault_id, name, expiration_date, content_type]
  azurerm_key_vault_key:
    category: security_control
    security_attrs: [key_vault_id, name, key_type, key_size, key_opts, rotation_policy,
      expiration_date]
  azurerm_key_vault_certificate:
    category: security_control
    security_attrs: [key_vault_id, name, certificate_policy.key_properties,
      certificate_policy.issuer_parameters]
  azurerm_key_vault_access_policy:
    category: security_control
    security_attrs: [key_vault_id, tenant_id, object_id, key_permissions, secret_permissions,
      certificate_permissions]
  azurerm_disk_encryption_set:
    category: security_control
    security_attrs: [key_vault_key_id, identity, encryption_type]
  azurerm_role_assignment:
    category: identity
    security_attrs: [scope, role_definition_name, role_definition_id, principal_id, principal_type,
      condition]
  azurerm_role_definition:
    category: identity
    security_attrs: [name, scope, permissions, assignable_scopes]
  azurerm_user_assigned_identity:
    category: identity
    security_attrs: [name]
  azurerm_federated_identity_credential:
    category: identity
    security_attrs: [parent_id, issuer, subject, audience]
  azuread_application:
    category: identity
    security_attrs: [display_name, sign_in_audience, web, required_resource_access, api]
  azuread_service_principal:
    category: identity
    security_attrs: [client_id, application_id, app_role_assignment_required]
  azuread_group:
    category: identity
    security_attrs: [display_name, security_enabled, owners, members]
  azurerm_log_analytics_workspace:
    category: monitoring
    security_attrs: [sku, retention_in_days, internet_ingestion_enabled, internet_query_enabled]
  azurerm_log_analytics_solution:
    category: monitoring
    security_attrs: [solution_name, workspace_resource_id, plan]
  azurerm_monitor_diagnostic_setting:
    category: monitoring
    security_attrs: [target_resource_id, log_analytics_workspace_id, storage_account_id,
      enabled_log, log, metric]
  azurerm_monitor_action_group:
    category: monitoring
    security_attrs: [short_name, email_receiver, webhook_receiver]
  azurerm_monitor_metric_alert:
    category: monitoring
    security_attrs: [scopes, criteria, action]
  azurerm_application_insights:
    category: monitoring
    security_attrs: [application_type, workspace_id, internet_ingestion_enabled,
      internet_query_enabled]
  azurerm_security_center_subscription_pricing:
    category: monitoring
    security_attrs: [tier, resource_type]
  azurerm_servicebus_namespace:
    category: other
    security_attrs: [sku, public_network_access_enabled, minimum_tls_version, local_auth_enabled,
      identity, network_rule_set]
  azurerm_eventhub_namespace:
    category: other
    security_attrs: [sku, public_network_access_enabled, minimum_tls_version, network_rulesets,
      identity]

  # ----------------------------------------------------------------- GCP compute
  google_compute_instance:
    category: compute
    security_attrs: [machine_type, zone, boot_disk.initialize_params.image,
      boot_disk.disk_encryption_key_raw, boot_disk.kms_key_self_link, network_interface.network,
      network_interface.subnetwork, network_interface.access_config, service_account, tags,
      metadata, metadata_startup_script, shielded_instance_config, can_ip_forward,
      confidential_instance_config, deletion_protection]
  google_compute_instance_template:
    category: compute
    security_attrs: [machine_type, disk.source_image, disk.disk_encryption_key,
      network_interface.network, network_interface.subnetwork, network_interface.access_config,
      service_account, tags, metadata, metadata_startup_script, shielded_instance_config,
      can_ip_forward]
  google_compute_instance_group_manager:
    category: compute
    security_attrs: [version, target_size, named_port, auto_healing_policies]
  google_compute_region_instance_group_manager:
    category: compute
    security_attrs: [version, target_size, named_port, auto_healing_policies]
  google_container_cluster:
    category: compute
    security_attrs: [location, network, subnetwork, private_cluster_config,
      master_authorized_networks_config, ip_allocation_policy, workload_identity_config,
      release_channel, logging_config, monitoring_config, database_encryption,
      binary_authorization, enable_shielded_nodes, network_policy, addons_config,
      master_auth, node_config.service_account, node_config.oauth_scopes,
      remove_default_node_pool, enable_legacy_abac, datapath_provider, deletion_protection,
      security_posture_config]
  google_container_node_pool:
    category: compute
    security_attrs: [cluster, location, node_count, autoscaling, node_config.service_account,
      node_config.oauth_scopes, node_config.machine_type, node_config.shielded_instance_config,
      node_config.workload_metadata_config, node_config.image_type, management]
  google_cloudfunctions_function:
    category: compute
    security_attrs: [runtime, entry_point, service_account_email, trigger_http,
      ingress_settings, vpc_connector, vpc_connector_egress_settings, environment_variables,
      kms_key_name, event_trigger]
  google_cloudfunctions2_function:
    category: compute
    security_attrs: [build_config.runtime, build_config.entry_point,
      service_config.service_account_email, service_config.ingress_settings,
      service_config.vpc_connector, service_config.environment_variables, event_trigger,
      kms_key_name]
  google_cloud_run_service:
    category: compute
    security_attrs: [location, template.spec.service_account_name, template.spec.containers,
      template.metadata.annotations, metadata.annotations]
  google_cloud_run_v2_service:
    category: compute
    security_attrs: [location, ingress, template.service_account, template.containers,
      template.vpc_access, template.encryption_key, binary_authorization]
  google_cloud_run_service_iam_member:
    category: identity
    security_attrs: [service, role, member]
  google_cloud_run_v2_service_iam_member:
    category: identity
    security_attrs: [name, role, member]
  google_app_engine_application:
    category: compute
    security_attrs: [location_id, auth_domain, iap]

  # ----------------------------------------------------------------- GCP storage
  google_storage_bucket:
    category: storage
    security_attrs: [location, storage_class, uniform_bucket_level_access, public_access_prevention,
      versioning, encryption, logging, retention_policy, lifecycle_rule, force_destroy, website,
      cors]
  google_storage_bucket_iam_member:
    category: identity
    security_attrs: [bucket, role, member, condition]
  google_storage_bucket_iam_binding:
    category: identity
    security_attrs: [bucket, role, members, condition]
  google_storage_bucket_iam_policy:
    category: identity
    security_attrs: [bucket, policy_data]
  google_compute_disk:
    category: storage
    security_attrs: [type, size, image, disk_encryption_key]
  google_sql_database_instance:
    category: storage
    security_attrs: [database_version, region, deletion_protection, encryption_key_name,
      settings.tier, settings.availability_type, settings.ip_configuration,
      settings.backup_configuration, settings.database_flags, settings.password_validation_policy,
      settings.user_labels]
  google_sql_database:
    category: storage
    security_attrs: [instance, name]
  google_sql_user:
    category: identity
    security_attrs: [instance, name, type, host]
  google_bigquery_dataset:
    category: storage
    security_attrs: [location, default_encryption_configuration, access,
      default_table_expiration_ms]
  google_bigquery_table:
    category: storage
    security_attrs: [dataset_id, encryption_configuration, deletion_protection]
  google_bigtable_instance:
    category: storage
    security_attrs: [cluster, deletion_protection]
  google_firestore_database:
    category: storage
    security_attrs: [location_id, type, point_in_time_recovery_enablement, delete_protection_state]
  google_redis_instance:
    category: storage
    security_attrs: [tier, authorized_network, connect_mode, auth_enabled,
      transit_encryption_mode, customer_managed_key]
  google_spanner_instance:
    category: storage
    security_attrs: [config, num_nodes]
  google_artifact_registry_repository:
    category: storage
    security_attrs: [location, format, kms_key_name, mode, cleanup_policies]
  google_artifact_registry_repository_iam_member:
    category: identity
    security_attrs: [repository, role, member]
  google_filestore_instance:
    category: storage
    security_attrs: [tier, networks, kms_key_name]

  # ----------------------------------------------------------------- GCP network
  google_compute_network:
    category: network
    security_attrs: [auto_create_subnetworks, routing_mode, delete_default_routes_on_create]
  google_compute_subnetwork:
    category: network
    security_attrs: [network, ip_cidr_range, region, private_ip_google_access,
      secondary_ip_range, log_config, purpose]
  google_compute_route:
    category: network
    security_attrs: [network, dest_range, next_hop_gateway, next_hop_instance, next_hop_ip,
      priority, tags]
  google_compute_router:
    category: network
    security_attrs: [network, region, bgp]
  google_compute_router_nat:
    category: gateway
    security_attrs: [router, nat_ip_allocate_option, source_subnetwork_ip_ranges_to_nat,
      subnetwork, log_config]
  google_compute_address:
    category: network
    security_attrs: [address_type, subnetwork, purpose]
  google_compute_global_address:
    category: network
    security_attrs: [address_type, purpose, network, prefix_length]
  google_compute_network_peering:
    category: network
    security_attrs: [network, peer_network, export_custom_routes, import_custom_routes]
  google_service_networking_connection:
    category: network
    security_attrs: [network, service, reserved_peering_ranges]
  google_vpc_access_connector:
    category: network
    security_attrs: [network, ip_cidr_range, subnet]
  google_compute_global_forwarding_rule:
    category: gateway
    security_attrs: [target, port_range, ip_protocol, load_balancing_scheme, ip_address]
  google_compute_forwarding_rule:
    category: gateway
    security_attrs: [target, backend_service, port_range, ports, ip_protocol,
      load_balancing_scheme, network, subnetwork, allow_global_access]
  google_compute_target_https_proxy:
    category: gateway
    security_attrs: [url_map, ssl_certificates, ssl_policy, certificate_map]
  google_compute_target_http_proxy:
    category: gateway
    security_attrs: [url_map]
  google_compute_url_map:
    category: gateway
    security_attrs: [default_service, host_rule, path_matcher]
  google_compute_backend_service:
    category: gateway
    security_attrs: [protocol, port_name, backend, health_checks, security_policy, iap,
      log_config, load_balancing_scheme, cdn_policy, enable_cdn]
  google_compute_region_backend_service:
    category: gateway
    security_attrs: [protocol, backend, health_checks, load_balancing_scheme, network]
  google_compute_managed_ssl_certificate:
    category: security_control
    security_attrs: [managed]
  google_compute_ssl_certificate:
    category: security_control
    security_attrs: [name]
  google_compute_ssl_policy:
    category: security_control
    security_attrs: [profile, min_tls_version, custom_features]
  google_compute_security_policy:
    category: security_control
    security_attrs: [type, rule, adaptive_protection_config]
  google_compute_health_check:
    category: monitoring
    security_attrs: [http_health_check, https_health_check, tcp_health_check]
  google_dns_managed_zone:
    category: dns
    security_attrs: [dns_name, visibility, private_visibility_config, dnssec_config]
  google_dns_record_set:
    category: dns
    security_attrs: [managed_zone, name, type, rrdatas]

  # ---------------------------------------------------- GCP security & identity
  google_compute_firewall:
    category: security_control
    security_attrs: [network, direction, priority, allow, deny, source_ranges,
      destination_ranges, source_tags, target_tags, source_service_accounts,
      target_service_accounts, disabled, log_config]
  google_kms_key_ring:
    category: security_control
    security_attrs: [location]
  google_kms_crypto_key:
    category: security_control
    security_attrs: [key_ring, purpose, rotation_period, version_template]
  google_kms_crypto_key_iam_member:
    category: identity
    security_attrs: [crypto_key_id, role, member]
  google_secret_manager_secret:
    category: security_control
    security_attrs: [secret_id, replication, rotation, expire_time, topics]
  google_secret_manager_secret_version:
    category: security_control
    security_attrs: [secret, enabled]
  google_secret_manager_secret_iam_member:
    category: identity
    security_attrs: [secret_id, role, member, condition]
  google_service_account:
    category: identity
    security_attrs: [account_id, display_name, disabled]
  google_service_account_key:
    category: identity
    security_attrs: [service_account_id, key_algorithm, public_key_type]
  google_service_account_iam_member:
    category: identity
    security_attrs: [service_account_id, role, member, condition]
  google_service_account_iam_binding:
    category: identity
    security_attrs: [service_account_id, role, members]
  google_project_iam_member:
    category: identity
    security_attrs: [project, role, member, condition]
  google_project_iam_binding:
    category: identity
    security_attrs: [project, role, members, condition]
  google_project_iam_custom_role:
    category: identity
    security_attrs: [role_id, permissions, stage]
  google_project_service:
    category: other
    security_attrs: [service, disable_on_destroy]
  google_project:
    category: other
    security_attrs: [project_id, org_id, folder_id]
  google_iap_web_iam_member:
    category: identity
    security_attrs: [role, member]
  google_iap_client:
    category: identity
    security_attrs: [display_name, brand]
  google_logging_project_sink:
    category: monitoring
    security_attrs: [destination, filter, unique_writer_identity, exclusions]
  google_logging_project_bucket_config:
    category: monitoring
    security_attrs: [bucket_id, location, retention_days, enable_analytics, cmek_settings]
  google_logging_metric:
    category: monitoring
    security_attrs: [filter, metric_descriptor]
  google_monitoring_alert_policy:
    category: monitoring
    security_attrs: [display_name, combiner, conditions, notification_channels, enabled]
  google_monitoring_notification_channel:
    category: monitoring
    security_attrs: [type, labels]
  google_pubsub_topic:
    category: other
    security_attrs: [kms_key_name, message_retention_duration, message_storage_policy]
  google_pubsub_subscription:
    category: other
    security_attrs: [topic, push_config, dead_letter_policy, expiration_policy]
  google_pubsub_topic_iam_member:
    category: identity
    security_attrs: [topic, role, member]

  # ----------------------------------------------------------------- OCI compute
  oci_core_instance:
    category: compute
    security_attrs: [compartment_id, shape, availability_domain, source_details,
      create_vnic_details.subnet_id, create_vnic_details.assign_public_ip,
      create_vnic_details.nsg_ids, metadata, launch_options, agent_config, is_pv_encryption_in_transit_enabled,
      platform_config]
  oci_core_instance_configuration:
    category: compute
    security_attrs: [compartment_id, instance_details.launch_details.shape,
      instance_details.launch_details.source_details,
      instance_details.launch_details.create_vnic_details, instance_details.launch_details.metadata]
  oci_core_instance_pool:
    category: compute
    security_attrs: [compartment_id, instance_configuration_id, size, placement_configurations,
      load_balancers]
  oci_containerengine_cluster:
    category: compute
    security_attrs: [compartment_id, kubernetes_version, vcn_id, type, endpoint_config,
      cluster_pod_network_options, options.service_lb_subnet_ids, options.kubernetes_network_config,
      options.admission_controller_options, options.add_ons, image_policy_config, kms_key_id]
  oci_containerengine_node_pool:
    category: compute
    security_attrs: [cluster_id, compartment_id, kubernetes_version, node_shape,
      node_config_details.placement_configs, node_config_details.nsg_ids, node_config_details.size,
      node_config_details.is_pv_encryption_in_transit_enabled, node_config_details.kms_key_id,
      node_source_details, node_metadata, ssh_public_key, node_pool_pod_network_option_details]
  oci_containerengine_addon:
    category: compute
    security_attrs: [cluster_id, addon_name, version]
  oci_containerengine_virtual_node_pool:
    category: compute
    security_attrs: [cluster_id, compartment_id, placement_configurations, nsg_ids, size]
  oci_container_instances_container_instance:
    category: compute
    security_attrs: [compartment_id, shape, vnics, containers.image_url, containers.environment_variables,
      image_pull_secrets, availability_domain]
  oci_functions_application:
    category: compute
    security_attrs: [compartment_id, subnet_ids, network_security_group_ids, config,
      syslog_url, trace_config, shape]
  oci_functions_function:
    category: compute
    security_attrs: [application_id, image, memory_in_mbs, config, provisioned_concurrency_config,
      source_details, trace_config]
  oci_functions_invoke_function:
    category: compute
    security_attrs: [function_id]

  # ----------------------------------------------------------------- OCI storage
  oci_objectstorage_bucket:
    category: storage
    security_attrs: [compartment_id, namespace, access_type, versioning, kms_key_id,
      object_events_enabled, retention_rules, storage_tier, auto_tiering]
  oci_objectstorage_object:
    category: storage
    security_attrs: [bucket, namespace, object]
  oci_objectstorage_preauthrequest:
    category: security_control
    security_attrs: [bucket, namespace, access_type, time_expires, object_name, bucket_listing_action]
  oci_core_volume:
    category: storage
    security_attrs: [compartment_id, kms_key_id, size_in_gbs, availability_domain]
  oci_core_boot_volume:
    category: storage
    security_attrs: [compartment_id, kms_key_id, size_in_gbs]
  oci_core_volume_attachment:
    category: storage
    security_attrs: [instance_id, volume_id, attachment_type, is_pv_encryption_in_transit_enabled,
      is_read_only]
  oci_file_storage_file_system:
    category: storage
    security_attrs: [compartment_id, availability_domain, kms_key_id]
  oci_file_storage_mount_target:
    category: storage
    security_attrs: [compartment_id, subnet_id, nsg_ids]
  oci_file_storage_export:
    category: storage
    security_attrs: [export_set_id, file_system_id, path, export_options]
  oci_database_autonomous_database:
    category: storage
    security_attrs: [compartment_id, db_workload, db_version, is_free_tier, is_mtls_connection_required,
      subnet_id, nsg_ids, whitelisted_ips, is_access_control_enabled, private_endpoint_label,
      kms_key_id, vault_id, is_data_guard_enabled, is_auto_scaling_enabled, cpu_core_count,
      data_storage_size_in_tbs, license_model, admin_password]
  oci_database_autonomous_database_wallet:
    category: security_control
    security_attrs: [autonomous_database_id, generate_type, password]
  oci_database_db_system:
    category: storage
    security_attrs: [compartment_id, shape, subnet_id, nsg_ids, ssh_public_keys, database_edition,
      db_home.database.db_name, db_home.database.admin_password, kms_key_id, license_model,
      private_ip]
  oci_mysql_mysql_db_system:
    category: storage
    security_attrs: [compartment_id, shape_name, subnet_id, admin_username, is_highly_available,
      backup_policy, deletion_policy, data_storage_size_in_gb]
  oci_nosql_table:
    category: storage
    security_attrs: [compartment_id, name, table_limits]
  oci_artifacts_container_repository:
    category: storage
    security_attrs: [compartment_id, display_name, is_public, is_immutable, readme]
  oci_artifacts_repository:
    category: storage
    security_attrs: [compartment_id, display_name, is_immutable, repository_type]

  # ----------------------------------------------------------------- OCI network
  oci_core_vcn:
    category: network
    security_attrs: [compartment_id, cidr_block, cidr_blocks, dns_label, is_ipv6enabled]
  oci_core_subnet:
    category: network
    security_attrs: [compartment_id, vcn_id, cidr_block, prohibit_public_ip_on_vnic,
      prohibit_internet_ingress, route_table_id, security_list_ids, dhcp_options_id, dns_label,
      availability_domain]
  oci_core_route_table:
    category: network
    security_attrs: [compartment_id, vcn_id, route_rules]
  oci_core_route_table_attachment:
    category: network
    security_attrs: [subnet_id, route_table_id]
  oci_core_dhcp_options:
    category: network
    security_attrs: [compartment_id, vcn_id, options]
  oci_core_internet_gateway:
    category: gateway
    security_attrs: [compartment_id, vcn_id, enabled, route_table_id]
  oci_core_nat_gateway:
    category: gateway
    security_attrs: [compartment_id, vcn_id, block_traffic, public_ip_id, route_table_id]
  oci_core_service_gateway:
    category: gateway
    security_attrs: [compartment_id, vcn_id, services, route_table_id]
  oci_core_drg:
    category: gateway
    security_attrs: [compartment_id]
  oci_core_drg_attachment:
    category: gateway
    security_attrs: [drg_id, vcn_id, network_details, route_table_id]
  oci_core_local_peering_gateway:
    category: gateway
    security_attrs: [compartment_id, vcn_id, peer_id, route_table_id]
  oci_core_public_ip:
    category: network
    security_attrs: [compartment_id, lifetime, private_ip_id]
  oci_core_vnic_attachment:
    category: network
    security_attrs: [instance_id, create_vnic_details.subnet_id, create_vnic_details.assign_public_ip,
      create_vnic_details.nsg_ids]
  oci_load_balancer_load_balancer:
    category: gateway
    security_attrs: [compartment_id, shape, subnet_ids, is_private, network_security_group_ids,
      shape_details, ip_mode, reserved_ips]
  oci_load_balancer_listener:
    category: gateway
    security_attrs: [load_balancer_id, port, protocol, default_backend_set_name, ssl_configuration,
      rule_set_names, routing_policy_name, connection_configuration]
  oci_load_balancer_backend_set:
    category: network
    security_attrs: [load_balancer_id, policy, health_checker, ssl_configuration, session_persistence_configuration]
  oci_load_balancer_backend:
    category: network
    security_attrs: [load_balancer_id, backendset_name, ip_address, port, weight]
  oci_load_balancer_certificate:
    category: security_control
    security_attrs: [load_balancer_id, certificate_name, ca_certificate, public_certificate]
  oci_load_balancer_rule_set:
    category: gateway
    security_attrs: [load_balancer_id, name, items]
  oci_load_balancer_load_balancer_routing_policy:
    category: gateway
    security_attrs: [load_balancer_id, name, condition_language_version, rules]
  oci_network_load_balancer_network_load_balancer:
    category: gateway
    security_attrs: [compartment_id, subnet_id, is_private, network_security_group_ids,
      is_preserve_source_destination]
  oci_apigateway_gateway:
    category: gateway
    security_attrs: [compartment_id, endpoint_type, subnet_id, network_security_group_ids,
      certificate_id]
  oci_apigateway_deployment:
    category: gateway
    security_attrs: [gateway_id, path_prefix, specification.request_policies,
      specification.logging_policies, specification.routes]
  oci_dns_zone:
    category: dns
    security_attrs: [compartment_id, name, zone_type, scope, view_id]
  oci_dns_rrset:
    category: dns
    security_attrs: [zone_name_or_id, domain, rtype, items]
  oci_dns_record:
    category: dns
    security_attrs: [zone_name_or_id, domain, rtype, rdata]
  oci_waf_web_app_firewall:
    category: security_control
    security_attrs: [compartment_id, backend_type, load_balancer_id, web_app_firewall_policy_id]
  oci_waf_web_app_firewall_policy:
    category: security_control
    security_attrs: [compartment_id, actions, request_access_control, request_protection,
      request_rate_limiting]

  # ---------------------------------------------------- OCI security & identity
  oci_core_security_list:
    category: security_control
    security_attrs: [compartment_id, vcn_id, ingress_security_rules, egress_security_rules]
  oci_core_network_security_group:
    category: security_control
    security_attrs: [compartment_id, vcn_id, display_name]
  oci_core_network_security_group_security_rule:
    category: security_control
    security_attrs: [network_security_group_id, direction, protocol, source, source_type,
      destination, destination_type, tcp_options, udp_options, icmp_options, stateless]
  oci_kms_vault:
    category: security_control
    security_attrs: [compartment_id, vault_type, display_name]
  oci_kms_key:
    category: security_control
    security_attrs: [compartment_id, management_endpoint, key_shape, protection_mode,
      is_auto_rotation_enabled, auto_key_rotation_details]
  oci_vault_secret:
    category: security_control
    security_attrs: [compartment_id, vault_id, key_id, secret_name, secret_rules,
      rotation_config]
  oci_certificates_management_certificate:
    category: security_control
    security_attrs: [compartment_id, certificate_config, name]
  oci_certificates_management_certificate_authority:
    category: security_control
    security_attrs: [compartment_id, kms_key_id, certificate_authority_config]
  oci_identity_compartment:
    category: other
    security_attrs: [compartment_id, name, enable_delete]
  oci_identity_policy:
    category: identity
    security_attrs: [compartment_id, name, statements]
  oci_identity_dynamic_group:
    category: identity
    security_attrs: [compartment_id, name, matching_rule]
  oci_identity_group:
    category: identity
    security_attrs: [compartment_id, name]
  oci_identity_user:
    category: identity
    security_attrs: [compartment_id, name, email]
  oci_identity_user_group_membership:
    category: identity
    security_attrs: [user_id, group_id]
  oci_identity_auth_token:
    category: identity
    security_attrs: [user_id, description]
  oci_identity_api_key:
    category: identity
    security_attrs: [user_id]
  oci_identity_domain:
    category: identity
    security_attrs: [compartment_id, display_name, license_type, is_hidden_on_login]
  oci_identity_tag_namespace:
    category: other
    security_attrs: [compartment_id, name]
  oci_logging_log_group:
    category: monitoring
    security_attrs: [compartment_id, display_name]
  oci_logging_log:
    category: monitoring
    security_attrs: [log_group_id, log_type, is_enabled, retention_duration,
      configuration.source, configuration.compartment_id]
  oci_logging_unified_agent_configuration:
    category: monitoring
    security_attrs: [compartment_id, is_enabled, service_configuration, group_association]
  oci_monitoring_alarm:
    category: monitoring
    security_attrs: [compartment_id, namespace, query, severity, destinations, is_enabled]
  oci_ons_notification_topic:
    category: monitoring
    security_attrs: [compartment_id, name]
  oci_ons_subscription:
    category: monitoring
    security_attrs: [topic_id, protocol, endpoint]
  oci_sch_service_connector:
    category: monitoring
    security_attrs: [compartment_id, source, target, tasks]
  oci_audit_configuration:
    category: monitoring
    security_attrs: [compartment_id, retention_period_days]
  oci_cloud_guard_cloud_guard_configuration:
    category: monitoring
    security_attrs: [compartment_id, reporting_region, status]
  oci_bastion_bastion:
    category: gateway
    security_attrs: [compartment_id, bastion_type, target_subnet_id, client_cidr_block_allow_list,
      max_session_ttl_in_seconds]
  oci_streaming_stream:
    category: other
    security_attrs: [compartment_id, partitions, retention_in_hours, stream_pool_id]
  oci_queue_queue:
    category: other
    security_attrs: [compartment_id, display_name, custom_encryption_key_id,
      retention_in_seconds, dead_letter_queue_delivery_count]

  # ------------------------------------------------------------ Kubernetes/Helm
  kubernetes_namespace_v1:
    category: other
    security_attrs: [metadata.name, metadata.labels]
  kubernetes_namespace:
    category: other
    security_attrs: [metadata.name, metadata.labels]
  kubernetes_deployment_v1:
    category: compute
    security_attrs: [metadata.name, metadata.namespace, spec.replicas,
      spec.template.spec.service_account_name, spec.template.spec.security_context,
      spec.template.spec.container.image, spec.template.spec.container.port,
      spec.template.spec.container.security_context, spec.template.spec.container.env_from,
      spec.template.spec.host_network, spec.template.spec.automount_service_account_token,
      spec.template.spec.image_pull_secrets]
  kubernetes_deployment:
    category: compute
    security_attrs: [metadata.name, metadata.namespace, spec.replicas,
      spec.template.spec.service_account_name, spec.template.spec.container.image,
      spec.template.spec.container.port, spec.template.spec.container.security_context]
  kubernetes_stateful_set_v1:
    category: compute
    security_attrs: [metadata.name, metadata.namespace, spec.replicas, spec.service_name,
      spec.template.spec.service_account_name, spec.template.spec.container.image,
      spec.template.spec.container.security_context, spec.volume_claim_template]
  kubernetes_daemon_set_v1:
    category: compute
    security_attrs: [metadata.name, metadata.namespace, spec.template.spec.service_account_name,
      spec.template.spec.container.image, spec.template.spec.container.security_context,
      spec.template.spec.host_network, spec.template.spec.host_pid]
  kubernetes_cron_job_v1:
    category: compute
    security_attrs: [metadata.name, metadata.namespace, spec.schedule,
      spec.job_template.spec.template.spec.service_account_name,
      spec.job_template.spec.template.spec.container.image]
  kubernetes_job_v1:
    category: compute
    security_attrs: [metadata.name, metadata.namespace, spec.template.spec.service_account_name,
      spec.template.spec.container.image]
  kubernetes_pod_v1:
    category: compute
    security_attrs: [metadata.name, metadata.namespace, spec.service_account_name,
      spec.container.image, spec.container.security_context, spec.host_network]
  kubernetes_service_v1:
    category: network
    security_attrs: [metadata.name, metadata.namespace, metadata.annotations, spec.type,
      spec.selector, spec.port, spec.load_balancer_source_ranges, spec.external_traffic_policy]
  kubernetes_service:
    category: network
    security_attrs: [metadata.name, metadata.namespace, metadata.annotations, spec.type,
      spec.selector, spec.port]
  kubernetes_ingress_v1:
    category: gateway
    security_attrs: [metadata.name, metadata.namespace, metadata.annotations,
      spec.ingress_class_name, spec.tls, spec.rule.host, spec.rule.http.path]
  kubernetes_ingress_class_v1:
    category: gateway
    security_attrs: [metadata.name, spec.controller]
  kubernetes_network_policy_v1:
    category: security_control
    security_attrs: [metadata.name, metadata.namespace, spec.pod_selector, spec.policy_types,
      spec.ingress, spec.egress]
  kubernetes_secret_v1:
    category: storage
    security_attrs: [metadata.name, metadata.namespace, type]
  kubernetes_secret:
    category: storage
    security_attrs: [metadata.name, metadata.namespace, type]
  kubernetes_config_map_v1:
    category: storage
    security_attrs: [metadata.name, metadata.namespace]
  kubernetes_config_map:
    category: storage
    security_attrs: [metadata.name, metadata.namespace]
  kubernetes_persistent_volume_claim_v1:
    category: storage
    security_attrs: [metadata.name, metadata.namespace, spec.storage_class_name,
      spec.access_modes, spec.resources]
  kubernetes_storage_class_v1:
    category: storage
    security_attrs: [metadata.name, storage_provisioner, parameters, reclaim_policy]
  kubernetes_service_account_v1:
    category: identity
    security_attrs: [metadata.name, metadata.namespace, metadata.annotations,
      automount_service_account_token]
  kubernetes_service_account:
    category: identity
    security_attrs: [metadata.name, metadata.namespace, metadata.annotations]
  kubernetes_role_v1:
    category: identity
    security_attrs: [metadata.name, metadata.namespace, rule]
  kubernetes_role_binding_v1:
    category: identity
    security_attrs: [metadata.name, metadata.namespace, role_ref, subject]
  kubernetes_cluster_role_v1:
    category: identity
    security_attrs: [metadata.name, rule]
  kubernetes_cluster_role_binding_v1:
    category: identity
    security_attrs: [metadata.name, role_ref, subject]
  kubernetes_cluster_role:
    category: identity
    security_attrs: [metadata.name, rule]
  kubernetes_cluster_role_binding:
    category: identity
    security_attrs: [metadata.name, role_ref, subject]
  kubernetes_pod_security_policy:
    category: security_control
    security_attrs: [metadata.name, spec]
  kubernetes_manifest:
    category: other
    security_attrs: [manifest.kind, manifest.apiVersion, manifest.metadata, manifest.spec]
  kubernetes_horizontal_pod_autoscaler_v2:
    category: compute
    security_attrs: [metadata.name, metadata.namespace, spec.scale_target_ref, spec.min_replicas,
      spec.max_replicas]
  helm_release:
    category: compute
    security_attrs: [name, namespace, repository, chart, version, create_namespace, set,
      set_sensitive, values, wait, atomic]

  # --------------------------------------------------------- utility providers
  random_password:
    category: other
    security_attrs: [length, special, min_special, min_upper, min_lower, min_numeric, keepers]
  random_id:
    category: other
    security_attrs: [byte_length, keepers]
  random_string:
    category: other
    security_attrs: [length, special, keepers]
  random_uuid:
    category: other
    security_attrs: [keepers]
  random_pet:
    category: other
    security_attrs: [length, prefix]
  null_resource:
    category: other
    security_attrs: [triggers]
  time_sleep:
    category: other
    security_attrs: [create_duration, destroy_duration]
  time_static:
    category: other
    security_attrs: [triggers]
  tls_private_key:
    category: security_control
    security_attrs: [algorithm, rsa_bits, ecdsa_curve]
  tls_self_signed_cert:
    category: security_control
    security_attrs: [subject, validity_period_hours, allowed_uses, dns_names, is_ca_certificate]
  tls_cert_request:
    category: security_control
    security_attrs: [subject, dns_names, ip_addresses]
  tls_locally_signed_cert:
    category: security_control
    security_attrs: [validity_period_hours, allowed_uses, is_ca_certificate]
  local_file:
    category: other
    security_attrs: [filename, file_permission]
  local_sensitive_file:
    category: other
    security_attrs: [filename, file_permission]

defaults:
  unknown_category: other
  unknown_attrs: all
  # Script-carrying attribute names (matched at any nesting depth). Their value
  # is replaced by "[script omitted: sha256:<12 hex>, <N> chars]" everywhere.
  hash_only_attrs:
    - user_data
    - user_data_base64
    - custom_data
    - metadata_startup_script
    - startup-script
    - startup_script
    - cloud_init
    - cloud-init
```

- [ ] **Step 4: Run the registry tests**

Run: `uv run pytest tests/test_resource_registry.py -q`
Expected: all PASS. If a `used` type is reported missing, add it to the YAML (do not delete it from the test).

- [ ] **Step 5: Lint, type-check, full suite**

Run: `uv run ruff format tmi_tf/ tests/ && uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright && uv run pytest tests/ -q`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add tmi_tf/data/resource_registry.yaml tests/test_resource_registry.py
git commit -m "feat(#10): resource registry for AWS, Azure, GCP, OCI, Kubernetes

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: HCL filter and pre-built inventory

**Files:**
- Create: `tmi_tf/tf_filter.py`
- Create: `tests/fixtures/tf/azure.tf`, `tests/fixtures/tf/gcp.tf`, `tests/fixtures/tf/oci.tf`
- Create: `tests/fixtures/tf/tmi_network_aws/main.tf`, `outputs.tf`, `variables.tf` (copies)
- Test: `tests/test_tf_filter.py`

**Interfaces:**
- Consumes (Task 1): `BLOCK_MARKER`, `StaticInventory`, `ParsedResource`, `clean_value`, `find_references`, `parse_terraform`, `unquote_literal`.
- Consumes (Task 2): `tmi_tf/data/resource_registry.yaml`.
- Produces (used by Tasks 4-6):
  - `ALLOWED_CATEGORIES: frozenset[str]`, `META_ARGS: frozenset[str]`, `REGISTRY_PATH: Path`
  - `Registry` dataclass with `category(resource_type) -> str`, `security_attrs(resource_type) -> list[str] | None` (None = unknown type, keep all), `provider_name(resource_type) -> str | None`
  - `load_registry(path: Path = REGISTRY_PATH) -> Registry`
  - `FilterResult(filtered_files: dict[str, str], prebuilt_inventory: dict[str, Any], omitted_attributes: int)`
  - `filter_terraform(inventory: StaticInventory, tf_contents: dict[str, str], registry: Registry) -> FilterResult`
  - Pre-built inventory JSON shape:

```json
{
  "components": [
    {"id": "aws_instance.web", "resource_type": "aws_instance", "type": "compute",
     "provider": "AWS", "file": "main.tf",
     "configuration": {"ami": "data.aws_ami.ubuntu.id", "...": "..."},
     "references": ["aws_subnet.private"], "name": null, "purpose": null}
  ],
  "variables": [{"name": "region", "type": "string", "default": "us-east-1", "description": "AWS region"}],
  "outputs": [{"name": "instance_ip", "description": "Private IP", "sensitive": false, "value": "aws_instance.web.private_ip"}],
  "modules": [{"id": "module.dns", "source": "../../modules/dns/aws", "file": "main.tf"}],
  "unparsed_files": []
}
```

  Data sources are components with `id` `data.<type>.<name>` and their full cleaned attributes; modules are components with `id` `module.<name>`, `resource_type` `"module"`, `type` `"other"`, `configuration` `{"source": ..., "inputs": {...}}` (and also listed under `modules`). Sensitive variables carry no `default`.

- [ ] **Step 1: Create the provider fixtures**

`tests/fixtures/tf/azure.tf`:

```hcl
resource "azurerm_resource_group" "main" {
  name     = "tmi-rg"
  location = "eastus"
}

resource "azurerm_virtual_network" "main" {
  name                = "tmi-vnet"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  address_space       = ["10.1.0.0/16"]
}

resource "azurerm_subnet" "aks" {
  name                 = "aks"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.1.1.0/24"]
}

resource "azurerm_network_security_group" "aks" {
  name                = "aks-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  security_rule {
    name                       = "https"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_key_vault" "main" {
  name                       = "tmi-kv"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  tenant_id                  = "00000000-0000-0000-0000-000000000000"
  sku_name                   = "standard"
  purge_protection_enabled   = true
  soft_delete_retention_days = 7
  tags                       = { env = "test" }
}

resource "azurerm_linux_virtual_machine" "web" {
  name                            = "web"
  resource_group_name             = azurerm_resource_group.main.name
  location                        = azurerm_resource_group.main.location
  size                            = "Standard_B1s"
  admin_username                  = "azureuser"
  disable_password_authentication = true
  network_interface_ids           = []
  custom_data                     = base64encode("#!/bin/bash\necho hi")
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }
  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }
}
```

`tests/fixtures/tf/gcp.tf`:

```hcl
resource "google_compute_network" "main" {
  name                    = "tmi-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "private" {
  name                     = "private"
  network                  = google_compute_network.main.id
  ip_cidr_range            = "10.2.0.0/24"
  region                   = "us-central1"
  private_ip_google_access = true
}

resource "google_compute_firewall" "allow_https" {
  name          = "allow-https"
  network       = google_compute_network.main.name
  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

resource "google_service_account" "app" {
  account_id   = "app"
  display_name = "App"
}

resource "google_storage_bucket" "data" {
  name                        = "tmi-data"
  location                    = "US"
  uniform_bucket_level_access = true
  force_destroy               = false
  labels                      = { env = "test" }
}

resource "google_compute_instance" "web" {
  name         = "web"
  machine_type = "e2-micro"
  zone         = "us-central1-a"
  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 10
    }
  }
  network_interface {
    subnetwork = google_compute_subnetwork.private.id
  }
  metadata = {
    startup-script = "#!/bin/bash\necho hi"
    enable-oslogin = "TRUE"
  }
  service_account {
    email  = google_service_account.app.email
    scopes = ["cloud-platform"]
  }
}
```

`tests/fixtures/tf/oci.tf`:

```hcl
resource "oci_core_vcn" "main" {
  compartment_id = var.compartment_id
  cidr_block     = "10.3.0.0/16"
  display_name   = "tmi-vcn"
  dns_label      = "tmi"
}

resource "oci_core_subnet" "private" {
  compartment_id             = var.compartment_id
  vcn_id                     = oci_core_vcn.main.id
  cidr_block                 = "10.3.1.0/24"
  prohibit_public_ip_on_vnic = true
  display_name               = "private"
}

resource "oci_core_security_list" "private" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "private"
  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "all"
  }
}

resource "oci_core_network_security_group" "app" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "app"
}

resource "oci_objectstorage_bucket" "data" {
  compartment_id = var.compartment_id
  namespace      = "ns"
  name           = "tmi-data"
  access_type    = "NoPublicAccess"
  versioning     = "Enabled"
  freeform_tags  = { env = "test" }
}

resource "oci_core_instance" "web" {
  compartment_id      = var.compartment_id
  availability_domain = "AD-1"
  shape               = "VM.Standard.E4.Flex"
  display_name        = "web"
  create_vnic_details {
    subnet_id        = oci_core_subnet.private.id
    assign_public_ip = false
    nsg_ids          = [oci_core_network_security_group.app.id]
  }
  source_details {
    source_type = "image"
    source_id   = "ocid1.image.oc1..example"
  }
  metadata = {
    ssh_authorized_keys = "ssh-ed25519 AAAA"
    user_data           = base64encode("#!/bin/bash\necho hi")
  }
}

variable "compartment_id" {
  type = string
}
```

Real module copy (integration material):

```bash
mkdir -p tests/fixtures/tf/tmi_network_aws
cp /Users/efitz/Projects/tmi/terraform/modules/network/aws/main.tf \
   /Users/efitz/Projects/tmi/terraform/modules/network/aws/outputs.tf \
   /Users/efitz/Projects/tmi/terraform/modules/network/aws/variables.tf \
   tests/fixtures/tf/tmi_network_aws/
rg -c '^resource "' tests/fixtures/tf/tmi_network_aws/*.tf
```

Expected: `main.tf:37` (the two other files report 0 or are not listed). If the count differs, the module changed upstream; the test below counts `resource` blocks itself so it still holds.

- [ ] **Step 2: Write the failing filter tests**

`tests/test_tf_filter.py`:

```python
"""Tests for registry-driven filtering and the pre-built inventory (issue #10)."""

import json
import re
from pathlib import Path

import pytest  # type: ignore

from tmi_tf.tf_filter import (
    ALLOWED_CATEGORIES,
    REGISTRY_PATH,
    FilterResult,
    Registry,
    filter_terraform,
    load_registry,
)
from tmi_tf.tf_parser import parse_terraform

FIXTURES = Path(__file__).parent / "fixtures" / "tf"
RESOURCE_BLOCK_RE = re.compile(r'^resource\s+"', re.MULTILINE)


def _load(*names: str) -> dict[str, str]:
    return {n: (FIXTURES / n).read_text(encoding="utf-8") for n in names}


@pytest.fixture(scope="module")
def registry() -> Registry:
    return load_registry()


def _run(registry: Registry, *names: str) -> FilterResult:
    contents = _load(*names)
    return filter_terraform(parse_terraform(contents), contents, registry)


def _component(result: FilterResult, cid: str) -> dict:
    return next(c for c in result.prebuilt_inventory["components"] if c["id"] == cid)


class TestRegistry:
    def test_load_registry_from_package(self, registry):
        assert REGISTRY_PATH.exists()
        assert registry.category("aws_instance") == "compute"
        assert registry.category("mycorp_widget") == "other"
        assert registry.security_attrs("mycorp_widget") is None
        assert "ami" in (registry.security_attrs("aws_instance") or [])
        assert registry.provider_name("aws_instance") == "AWS"
        assert registry.provider_name("azurerm_subnet") == "Microsoft Azure"
        assert registry.provider_name("mycorp_widget") is None
        assert "user_data" in registry.hash_only_attrs

    def test_invalid_category_is_rejected(self, tmp_path):
        bad = tmp_path / "r.yaml"
        bad.write_text(
            "providers: {aws_: {name: AWS, type: cloud}}\n"
            "resources: {aws_x: {category: bogus, security_attrs: []}}\n"
            "defaults: {unknown_category: other, unknown_attrs: all, hash_only_attrs: []}\n"
        )
        with pytest.raises(ValueError, match="aws_x"):
            load_registry(bad)


class TestFilteredHcl:
    def test_security_attrs_kept_others_omitted_with_comment(self, registry):
        hcl = _run(registry, "aws.tf").filtered_files["aws.tf"]
        block = hcl[hcl.index('resource "aws_instance" "web"') :]
        block = block[: block.index("\n}") + 2]
        assert "ami" in block
        assert "subnet_id" in block
        assert "associate_public_ip_address = false" in block
        assert "encrypted = true" in block
        assert "volume_size" not in block  # nested attr not in registry path list
        assert "instance_type" not in block
        assert "tags" not in block
        # count/for_each/depends_on/provider/lifecycle are always kept
        assert "depends_on" in block
        assert "# 2 non-security attributes omitted" in block  # instance_type, tags

    def test_reference_attributes_are_kept_even_if_not_security(self, registry):
        # "tags" is not a security attr of aws_s3_bucket, but it holds a reference
        contents = {
            "m.tf": (
                'resource "aws_s3_bucket" "b" {\n'
                '  bucket = "x"\n'
                "  tags   = { owner = aws_iam_role.web.name }\n"
                '  region = "us-east-1"\n'
                "}\n"
            )
        }
        res = filter_terraform(parse_terraform(contents), contents, registry)
        hcl = res.filtered_files["m.tf"]
        assert "aws_iam_role.web.name" in hcl
        assert "region" not in hcl
        assert "# 1 non-security attributes omitted" in hcl

    def test_unknown_resource_keeps_everything(self, registry):
        hcl = _run(registry, "aws.tf").filtered_files["aws.tf"]
        assert 'resource "mycorp_widget" "custom"' in hcl
        assert "size  = 3" in hcl or "size = 3" in hcl
        assert 'color = "blue"' in hcl
        widget = hcl[hcl.index('resource "mycorp_widget"') :]
        widget = widget[: widget.index("\n}") + 2]
        assert "omitted" not in widget

    def test_non_resource_blocks_pass_through(self, registry):
        hcl = _run(registry, "aws.tf").filtered_files["aws.tf"]
        for needle in (
            'data "aws_ami" "ubuntu"',
            'variable "region"',
            'output "instance_ip"',
            'module "dns"',
            'provider "aws"',
            "terraform {",
            "locals {",
        ):
            assert needle in hcl, needle

    def test_unparsed_file_passes_through_raw(self, registry):
        res = _run(registry, "aws.tf", "broken.tf")
        assert res.filtered_files["broken.tf"] == (FIXTURES / "broken.tf").read_text()
        assert res.prebuilt_inventory["unparsed_files"] == ["broken.tf"]

    def test_tfvars_file_passes_through(self, registry):
        contents = {"terraform.tfvars": 'region = "us-east-1"\n', "e.tf": "", "c.tf": "# c\n"}
        res = filter_terraform(parse_terraform(contents), contents, registry)
        assert 'region = "us-east-1"' in res.filtered_files["terraform.tfvars"]
        assert res.filtered_files["e.tf"] == ""
        assert res.prebuilt_inventory["components"] == []

    def test_registry_attrs_absent_from_block(self, registry):
        contents = {"m.tf": 'resource "aws_kms_alias" "a" {\n  foo = 1\n  bar = 2\n}\n'}
        res = filter_terraform(parse_terraform(contents), contents, registry)
        hcl = res.filtered_files["m.tf"]
        assert 'resource "aws_kms_alias" "a"' in hcl
        assert "foo" not in hcl and "bar" not in hcl
        assert "# 2 non-security attributes omitted" in hcl
        assert res.omitted_attributes == 2

    def test_comments_are_not_attributes(self, registry):
        contents = {
            "m.tf": (
                'resource "aws_kms_alias" "a" {\n'
                "  # why this alias exists\n"
                '  name = "alias/x" # trailing\n'
                "}\n"
            )
        }
        res = filter_terraform(parse_terraform(contents), contents, registry)
        assert res.omitted_attributes == 0
        assert "omitted" not in res.filtered_files["m.tf"]
        assert _component(res, "aws_kms_alias.a")["configuration"] == {"name": "alias/x"}

    def test_script_attributes_are_hashed_everywhere(self, registry):
        res = _run(registry, "aws.tf", "azure.tf", "gcp.tf", "oci.tf")
        for path in ("aws.tf", "azure.tf", "gcp.tf", "oci.tf"):
            assert "echo hi" not in res.filtered_files[path]
            assert "echo hello" not in res.filtered_files[path]
        dumped = json.dumps(res.prebuilt_inventory)
        assert "echo hi" not in dumped and "echo hello" not in dumped
        aws = _component(res, "aws_instance.web")
        assert aws["configuration"]["user_data"].startswith("[script omitted: sha256:")
        gcp = _component(res, "google_compute_instance.web")
        assert gcp["configuration"]["metadata"]["startup-script"].startswith(
            "[script omitted: sha256:"
        )
        oci = _component(res, "oci_core_instance.web")
        assert oci["configuration"]["metadata"]["user_data"].startswith(
            "[script omitted: sha256:"
        )


class TestPrebuiltInventory:
    def test_components_from_all_four_providers(self, registry):
        res = _run(registry, "aws.tf", "azure.tf", "gcp.tf", "oci.tf")
        comps = res.prebuilt_inventory["components"]
        ids = {c["id"] for c in comps}
        assert {
            "aws_instance.web",
            "azurerm_key_vault.main",
            "google_compute_firewall.allow_https",
            "oci_core_subnet.private",
            "data.aws_ami.ubuntu",
            "module.dns",
        } <= ids
        for c in comps:
            assert c["type"] in ALLOWED_CATEGORIES, c["id"]
            assert c["name"] is None and c["purpose"] is None
            assert isinstance(c["configuration"], dict)
            assert isinstance(c["references"], list)
        assert _component(res, "azurerm_key_vault.main")["type"] == "security_control"
        assert _component(res, "azurerm_key_vault.main")["provider"] == "Microsoft Azure"
        assert _component(res, "oci_core_subnet.private")["type"] == "network"
        assert _component(res, "google_service_account.app")["type"] == "identity"
        assert _component(res, "mycorp_widget.custom")["type"] == "other"
        assert _component(res, "mycorp_widget.custom")["configuration"] == {
            "size": 3,
            "color": "blue",
        }

    def test_component_configuration_and_references(self, registry):
        res = _run(registry, "aws.tf")
        web = _component(res, "aws_instance.web")
        assert web["resource_type"] == "aws_instance"
        assert web["file"] == "aws.tf"
        assert web["configuration"]["ami"] == "data.aws_ami.ubuntu.id"
        assert web["configuration"]["ebs_block_device"] == [{"encrypted": True}]
        assert "instance_type" not in web["configuration"]
        assert "lifecycle" not in web["configuration"]
        assert "depends_on" not in web["configuration"]
        assert web["references"] == [
            "aws_iam_role.web",
            "aws_security_group.web",
            "aws_subnet.private",
            "data.aws_ami.ubuntu",
        ]
        mod = _component(res, "module.dns")
        assert mod["resource_type"] == "module"
        assert mod["configuration"]["source"] == "../../modules/dns/aws"
        assert mod["configuration"]["inputs"]["vpc_id"] == "aws_vpc.main.id"
        assert mod["references"] == ["aws_vpc.main"]

    def test_variables_outputs_modules(self, registry):
        inv = _run(registry, "aws.tf").prebuilt_inventory
        var = {v["name"]: v for v in inv["variables"]}
        assert var["region"] == {
            "name": "region",
            "type": "string",
            "default": "us-east-1",
            "description": "AWS region",
        }
        assert "default" not in var["db_password"]  # sensitive
        out = {o["name"]: o for o in inv["outputs"]}
        assert out["instance_ip"]["value"] == "aws_instance.web.private_ip"
        assert out["db_password"]["sensitive"] is True
        assert inv["modules"] == [
            {"id": "module.dns", "source": "../../modules/dns/aws", "file": "aws.tf"}
        ]

    def test_prebuilt_inventory_is_json_serializable(self, registry):
        res = _run(registry, "aws.tf", "azure.tf", "gcp.tf", "oci.tf", "broken.tf")
        json.dumps(res.prebuilt_inventory)


class TestRealModule:
    """Static parse + filter over a copy of tmi/terraform/modules/network/aws."""

    def test_resource_count_matches_resource_blocks(self, registry):
        files = sorted((FIXTURES / "tmi_network_aws").glob("*.tf"))
        contents = {f"tmi_network_aws/{f.name}": f.read_text(encoding="utf-8") for f in files}
        expected = sum(len(RESOURCE_BLOCK_RE.findall(t)) for t in contents.values())
        assert expected > 20

        inv = parse_terraform(contents)
        assert inv.unparsed_files == []
        assert len(inv.resources) == expected

        res = filter_terraform(inv, contents, registry)
        resource_components = [
            c
            for c in res.prebuilt_inventory["components"]
            if not c["id"].startswith(("data.", "module."))
        ]
        assert len(resource_components) == expected
        assert all(c["type"] in ALLOWED_CATEGORIES for c in res.prebuilt_inventory["components"])
        # every filtered file still parses, and the filter shrank the module
        for path, text in res.filtered_files.items():
            assert len(RESOURCE_BLOCK_RE.findall(text)) == len(
                RESOURCE_BLOCK_RE.findall(contents[path])
            ), path
        assert sum(map(len, res.filtered_files.values())) < sum(map(len, contents.values()))
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `uv run pytest tests/test_tf_filter.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'tmi_tf.tf_filter'`.

- [ ] **Step 4: Implement `tmi_tf/tf_filter.py`**

```python
"""Registry-driven filtering of parsed Terraform (issue #10).

Produces the two phase-1 inputs -- filtered HCL and a pre-built inventory --
from a ``StaticInventory`` and ``tmi_tf/data/resource_registry.yaml``.
"""

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import hcl2
import yaml  # pyright: ignore[reportMissingModuleSource]

from tmi_tf.tf_parser import (
    BLOCK_MARKER,
    StaticInventory,
    clean_value,
    find_references,
    unquote_literal,
)

logger = logging.getLogger(__name__)

ALLOWED_CATEGORIES = frozenset(
    {
        "compute",
        "storage",
        "network",
        "gateway",
        "security_control",
        "identity",
        "monitoring",
        "dns",
        "cdn",
        "other",
    }
)
META_ARGS = frozenset({"count", "for_each", "depends_on", "provider", "lifecycle"})
# Meta-args that say nothing about the resource itself; kept in the HCL, not
# repeated in the inventory "configuration".
_CONFIG_EXCLUDED = frozenset({"depends_on", "provider", "lifecycle"})
REGISTRY_PATH = Path(__file__).parent / "data" / "resource_registry.yaml"


@dataclass(frozen=True)
class Registry:
    providers: dict[str, dict[str, str]]
    resources: dict[str, dict[str, Any]]
    hash_only_attrs: frozenset[str]
    unknown_category: str = "other"

    def category(self, resource_type: str) -> str:
        entry = self.resources.get(resource_type)
        return entry["category"] if entry else self.unknown_category

    def security_attrs(self, resource_type: str) -> list[str] | None:
        """Attribute paths to keep, or None for an unknown type (keep all)."""
        entry = self.resources.get(resource_type)
        return list(entry["security_attrs"]) if entry else None

    def provider_name(self, resource_type: str) -> str | None:
        best = ""
        for prefix in self.providers:
            if resource_type.startswith(prefix) and len(prefix) > len(best):
                best = prefix
        return self.providers[best]["name"] if best else None


def load_registry(path: Path = REGISTRY_PATH) -> Registry:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    for rtype, entry in raw["resources"].items():
        if entry.get("category") not in ALLOWED_CATEGORIES:
            raise ValueError(
                f"resource registry: {rtype} has invalid category {entry.get('category')!r}"
            )
        if not isinstance(entry.get("security_attrs"), list):
            raise ValueError(f"resource registry: {rtype} security_attrs must be a list")
    defaults = raw.get("defaults", {})
    return Registry(
        providers=raw["providers"],
        resources=raw["resources"],
        hash_only_attrs=frozenset(defaults.get("hash_only_attrs", [])),
        unknown_category=defaults.get("unknown_category", "other"),
    )


@dataclass
class FilterResult:
    filtered_files: dict[str, str] = field(default_factory=dict)
    prebuilt_inventory: dict[str, Any] = field(default_factory=dict)
    omitted_attributes: int = 0


# --- attribute selection ---------------------------------------------------


def _attr_tree(paths: list[str]) -> dict[str, Any]:
    """{"ami": None, "ebs_block_device": {"encrypted": None}}; None = keep whole."""
    tree: dict[str, Any] = {}
    for path in paths:
        node = tree
        parts = path.split(".")
        for part in parts[:-1]:
            if part in node and node[part] is None:
                break  # a parent path already keeps the whole subtree
            node = node.setdefault(part, {})
        else:
            node[parts[-1]] = None
    return tree


def _select(value: Any, tree: dict[str, Any]) -> Any:
    """Keep only keys present in ``tree`` (recursively through blocks/objects)."""
    if isinstance(value, list):
        return [_select(v, tree) for v in value]
    if not isinstance(value, dict):
        return value
    out: dict[str, Any] = {}
    for k, v in value.items():
        if k == BLOCK_MARKER:
            out[k] = v
        elif k in tree:
            out[k] = v if tree[k] is None else _select(v, tree[k])
    return out


def _filter_body(
    body: dict[str, Any], resource_type: str, registry: Registry
) -> tuple[dict[str, Any], int]:
    """(kept attributes in source order, number of omitted top-level attrs)."""
    attrs = registry.security_attrs(resource_type)
    if attrs is None:
        return dict(body), 0
    selected = _select(body, _attr_tree(attrs))
    kept: dict[str, Any] = {}
    for k, v in body.items():
        if k in selected:
            kept[k] = selected[k]
        elif k in META_ARGS or find_references(v):
            kept[k] = v
    # "__comments__"/"__is_block__" are hcl2 bookkeeping, not attributes
    omitted = sum(1 for k in body if not k.startswith("__") and k not in kept)
    return kept, omitted


def _script_digest(value: Any) -> str:
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
    return f"[script omitted: sha256:{digest}, {len(text)} chars]"


def _hash_scripts(value: Any, names: frozenset[str], quoted: bool) -> Any:
    """Replace script-carrying attributes at any depth by a digest string.

    ``quoted`` wraps the digest in quotes so ``hcl2.dumps`` emits a literal.
    """
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if k in names:
                digest = _script_digest(v)
                out[k] = f'"{digest}"' if quoted else digest
            else:
                out[k] = _hash_scripts(v, names, quoted)
        return out
    if isinstance(value, list):
        return [_hash_scripts(v, names, quoted) for v in value]
    return value


# --- filtered HCL ------------------------------------------------------------


def _render_resource(
    rtype_q: str, name_q: str, body: dict[str, Any], registry: Registry
) -> tuple[str, int]:
    kept, omitted = _filter_body(body, unquote_literal(rtype_q), registry)
    kept = _hash_scripts(kept, registry.hash_only_attrs, quoted=True)
    text = hcl2.dumps({"resource": [{rtype_q: {name_q: kept}}]}).rstrip()
    if omitted and text.endswith("}"):
        text = f"{text[:-1].rstrip()}\n  # {omitted} non-security attributes omitted\n}}"
    return text, omitted


def _render_file(parsed: dict[str, Any], registry: Registry) -> tuple[str, int]:
    """Regenerate one file's HCL with resource bodies filtered."""
    chunks: list[str] = []
    omitted_total = 0
    for block_type, items in parsed.items():
        if block_type.startswith("__"):
            continue  # __comments__ and friends
        if not isinstance(items, list) or not all(isinstance(i, dict) for i in items):
            # top-level attribute (.tfvars); block lists are lists of dicts
            chunks.append(hcl2.dumps({block_type: items}).rstrip())
            continue
        for item in items:
            if block_type == "resource":
                for rtype_q, by_name in item.items():
                    for name_q, body in by_name.items():
                        text, omitted = _render_resource(rtype_q, name_q, body, registry)
                        chunks.append(text)
                        omitted_total += omitted
            else:
                chunks.append(hcl2.dumps({block_type: [item]}).rstrip())
    return ("\n\n".join(chunks) + "\n") if chunks else "", omitted_total


# --- pre-built inventory ------------------------------------------------------


def _configuration(
    attributes: dict[str, Any], resource_type: str, registry: Registry
) -> dict[str, Any]:
    attrs = registry.security_attrs(resource_type)
    cfg = attributes if attrs is None else _select(attributes, _attr_tree(attrs))
    cfg = {k: v for k, v in cfg.items() if k not in _CONFIG_EXCLUDED}
    return _hash_scripts(cfg, registry.hash_only_attrs, quoted=False)


def _component(
    cid: str,
    resource_type: str,
    category: str,
    provider: str | None,
    file: str,
    configuration: dict[str, Any],
    references: list[str],
) -> dict[str, Any]:
    return {
        "id": cid,
        "resource_type": resource_type,
        "type": category,
        "provider": provider,
        "file": file,
        "configuration": configuration,
        "references": references,
        "name": None,
        "purpose": None,
    }


def _prebuilt_inventory(inventory: StaticInventory, registry: Registry) -> dict[str, Any]:
    components: list[dict[str, Any]] = []
    for r in inventory.resources:
        components.append(
            _component(
                r.address,
                r.resource_type,
                registry.category(r.resource_type),
                registry.provider_name(r.resource_type),
                r.file,
                _configuration(r.attributes, r.resource_type, registry),
                r.references,
            )
        )
    for d in inventory.data_sources:
        components.append(
            _component(
                d.address,
                d.data_type,
                registry.category(d.data_type),
                registry.provider_name(d.data_type),
                d.file,
                _hash_scripts(d.attributes, registry.hash_only_attrs, quoted=False),
                d.references,
            )
        )
    for m in inventory.modules:
        components.append(
            _component(
                f"module.{m.name}",
                "module",
                "other",
                None,
                m.file,
                {"source": m.source, "inputs": m.inputs},
                find_references({"inputs": _requote(m.inputs)}),
            )
        )
    variables = []
    for v in inventory.variables:
        entry: dict[str, Any] = {"name": v.name, "type": v.type_expr}
        if not v.sensitive:
            entry["default"] = v.default
        entry["description"] = v.description
        variables.append(entry)
    return {
        "components": components,
        "variables": variables,
        "outputs": [
            {
                "name": o.name,
                "description": o.description,
                "sensitive": o.sensitive,
                "value": o.value_expr,
            }
            for o in inventory.outputs
        ],
        "modules": [
            {"id": f"module.{m.name}", "source": m.source, "file": m.file}
            for m in inventory.modules
        ],
        "unparsed_files": list(inventory.unparsed_files),
    }


def _requote(value: Any) -> Any:
    """Cleaned values back to the ``${...}`` form so find_references sees them."""
    if isinstance(value, dict):
        return {k: _requote(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_requote(v) for v in value]
    if isinstance(value, str):
        return f"${{{value}}}"
    return value


def filter_terraform(
    inventory: StaticInventory, tf_contents: dict[str, str], registry: Registry
) -> FilterResult:
    """Filtered HCL per file (raw for unparsed files) plus the pre-built inventory."""
    result = FilterResult(prebuilt_inventory=_prebuilt_inventory(inventory, registry))
    for path in sorted(tf_contents):
        if path in inventory.parsed_files:
            text, omitted = _render_file(inventory.parsed_files[path], registry)
            result.filtered_files[path] = text
            result.omitted_attributes += omitted
        else:
            result.filtered_files[path] = tf_contents[path]
    logger.info(
        "Static HCL filter: %d components, %d attributes omitted, %d/%d files unparsed",
        len(result.prebuilt_inventory["components"]),
        result.omitted_attributes,
        len(inventory.unparsed_files),
        len(tf_contents),
    )
    return result
```

Note on `_requote` for module references: `ParsedModule.inputs` is already cleaned (no `${}`), and `find_references` only scans expression strings. Wrapping every string back in `${...}` is a cheap way to reuse the same detector; a literal like `"example.com"` has no underscore-type token so it yields nothing.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/test_tf_filter.py -q`
Expected: all PASS. Two assertions depend on `hcl2.dumps` formatting: `"encrypted = true"` (single space; the nested block only has one key left) and the omitted comment placement. If `dumps` in the installed version aligns differently, fix the assertion to match the probe from Task 1 step 2, not the implementation.

- [ ] **Step 6: Lint, type-check, full suite**

Run: `uv run ruff format tmi_tf/ tests/ && uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright && uv run pytest tests/ -q`
Expected: all green.

- [ ] **Step 7: Commit**

```bash
git add tmi_tf/tf_filter.py tests/test_tf_filter.py tests/fixtures/tf/
git commit -m "feat(#10): registry-driven HCL filter and pre-built inventory

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Semantic phase-1 prompts and merge

**Files:**
- Create: `prompts/inventory_semantic_system.txt`, `prompts/inventory_semantic_user.txt`
- Modify: `tmi_tf/tf_filter.py` (append `merge_phase1`, `display_name`)
- Test: `tests/test_tf_filter.py` (append `TestMergePhase1`), `tests/test_prompts_semantic.py` (new, tiny)

**Interfaces:**
- Consumes (Task 3): `ALLOWED_CATEGORIES`, the pre-built inventory shape.
- Produces (used by Task 5):
  - `display_name(component_id: str) -> str` (`"aws_instance.web_server"` -> `"Web Server"`, `"data.aws_ami.ubuntu"` -> `"Ubuntu (data)"`, `"module.dns"` -> `"Dns (module)"`)
  - `merge_phase1(prebuilt: dict[str, Any], semantic: dict[str, Any]) -> dict[str, Any]` returning exactly `{"components": [...], "services": [...], "dependencies": [...]}` in the current phase-1 schema.
  - Semantic LLM output contract (what the new prompts ask for):

```json
{
  "components": [
    {"id": "aws_instance.web", "name": "Web Server", "purpose": "Serves the public site", "type": "compute"}
  ],
  "services": [
    {"name": "web-frontend", "criteria": ["..."], "compute_units": ["aws_instance.web"], "associated_resources": ["aws_lb.web"]}
  ],
  "dependencies": [
    {"type": "cloud", "provider": "AWS", "service": "EC2", "dependent_components": ["aws_instance.web"]}
  ]
}
```

  `type` is optional and only honoured when the static category is `other`. Per-component `dependencies` in the merged output are derived by inverting the top-level `dependencies` (`dependent_components`), so the LLM does not repeat them per component.

- [ ] **Step 1: Write the prompt files**

`prompts/inventory_semantic_system.txt`:

```
You are an expert infrastructure analyst specializing in Terraform and Infrastructure as Code (IaC) across cloud platforms (AWS, Azure, GCP, OCI).

You will receive a pre-extracted inventory of Terraform components produced by static analysis, plus the Terraform source filtered down to security-relevant attributes. Component ids, resource types, categories, configuration values and references in the inventory are authoritative: do not invent, rename, drop or re-order components.

Your task is semantic inference only:

1. For every component in the inventory, give a human-readable "name" and a one-sentence "purpose" inferred from its resource type, local name, configuration, references, file and surrounding code.
2. Reclassify a component only when its "type" is "other" and a better category is clear. Allowed categories: compute, storage, network, gateway, security_control, identity, monitoring, dns, cdn, other. Never change a type that is not "other".
3. Identify logical "services": cohesive groups of compute components that function together (web tier, API backend, worker pool, Kubernetes workload). Evidence, in priority order: references between components, module boundaries (the "file" field), shared network/security context, naming patterns, functional collaboration. Do not force standalone resources into services.
4. Identify external service "dependencies": for each component, the service that Terraform instructs to instantiate it (most components have at least one), plus any SaaS or on-prem systems referenced.

# Output Requirements

Return ONLY a JSON object. No explanation, preamble, markdown or code fences. Your entire response must be valid JSON starting with { and ending with }.

{
  "components": [
    {"id": "<id from the inventory>", "name": "<display name>", "purpose": "<one sentence>", "type": "<only when reclassifying an 'other' component>"}
  ],
  "services": [
    {"name": "<service name>", "criteria": ["<evidence>"], "compute_units": ["<component id>"], "associated_resources": ["<component id>"]}
  ],
  "dependencies": [
    {"type": "cloud" | "saas" | "on-prem", "provider": "<organization>", "service": "<service name>", "dependent_components": ["<component id>"]}
  ]
}

Rules:
- "components" must contain exactly one entry per inventory component id, and no other ids.
- Omit "type" unless you are reclassifying an "other" component.
- Deduplicate "dependencies" by (type, provider, service) and list every dependent component id.
- Keep names short (2-5 words) and purposes to one sentence.

CRITICAL: Return ONLY the JSON object, no other text.
```

`prompts/inventory_semantic_user.txt`:

```
Repository: {repo_name}
URL: {repo_url}

## Pre-extracted inventory (authoritative)

The ids, resource types, categories, configuration and references below were extracted by static analysis and must be preserved exactly. Fields set to null are for you to fill in.

{inventory_json}

## Filtered Terraform source (security-relevant attributes only)

Non-security attributes were removed on purpose; "# N non-security attributes omitted" marks where. Files listed under "unparsed_files" in the inventory are shown unfiltered.

{filtered_hcl}

---

Fill in name and purpose for every component, group compute components into services, list external dependencies, and reclassify "other" components where a better category is clear. Return ONLY the JSON object.
```

- [ ] **Step 2: Write the failing tests**

Append to `tests/test_tf_filter.py`:

```python
from tmi_tf.tf_filter import display_name, merge_phase1  # noqa: E402


def _prebuilt() -> dict:
    return {
        "components": [
            {
                "id": "aws_instance.web_server",
                "resource_type": "aws_instance",
                "type": "compute",
                "provider": "AWS",
                "file": "main.tf",
                "configuration": {"ami": "ami-1"},
                "references": ["aws_subnet.private"],
                "name": None,
                "purpose": None,
            },
            {
                "id": "mycorp_widget.custom",
                "resource_type": "mycorp_widget",
                "type": "other",
                "provider": None,
                "file": "main.tf",
                "configuration": {"size": 3},
                "references": [],
                "name": None,
                "purpose": None,
            },
        ],
        "variables": [],
        "outputs": [],
        "modules": [],
        "unparsed_files": [],
    }


class TestMergePhase1:
    def test_display_name(self):
        assert display_name("aws_instance.web_server") == "Web Server"
        assert display_name("data.aws_ami.ubuntu") == "Ubuntu (data)"
        assert display_name("module.dns") == "Dns (module)"
        assert display_name("weird") == "Weird"

    def test_merge_produces_current_schema(self):
        semantic = {
            "components": [
                {"id": "aws_instance.web_server", "name": "Web", "purpose": "Serves"},
                {"id": "mycorp_widget.custom", "name": "Widget", "purpose": "?", "type": "storage"},
                {"id": "aws_ghost.nope", "name": "Ghost", "purpose": "hallucinated"},
            ],
            "services": [
                {
                    "name": "web",
                    "criteria": ["naming"],
                    "compute_units": ["aws_instance.web_server"],
                    "associated_resources": [],
                }
            ],
            "dependencies": [
                {
                    "type": "cloud",
                    "provider": "AWS",
                    "service": "EC2",
                    "dependent_components": ["aws_instance.web_server"],
                }
            ],
        }
        merged = merge_phase1(_prebuilt(), semantic)
        assert set(merged) == {"components", "services", "dependencies"}
        assert [c["id"] for c in merged["components"]] == [
            "aws_instance.web_server",
            "mycorp_widget.custom",
        ]
        web = merged["components"][0]
        assert set(web) == {
            "id",
            "name",
            "type",
            "resource_type",
            "configuration",
            "purpose",
            "dependencies",
        }
        assert web["name"] == "Web"
        assert web["purpose"] == "Serves"
        assert web["type"] == "compute"
        assert web["configuration"] == {"ami": "ami-1"}
        assert web["dependencies"] == [{"type": "cloud", "provider": "AWS", "service": "EC2"}]
        widget = merged["components"][1]
        assert widget["type"] == "storage"  # reclassified from other
        assert widget["dependencies"] == []
        assert merged["services"] == semantic["services"]
        assert merged["dependencies"] == semantic["dependencies"]

    def test_merge_only_reclassifies_other(self):
        semantic = {
            "components": [
                {"id": "aws_instance.web_server", "name": "W", "purpose": "p", "type": "storage"},
                {"id": "mycorp_widget.custom", "name": "X", "purpose": "p", "type": "bogus"},
            ]
        }
        merged = merge_phase1(_prebuilt(), semantic)
        assert merged["components"][0]["type"] == "compute"
        assert merged["components"][1]["type"] == "other"

    def test_merge_fills_missing_names(self):
        merged = merge_phase1(_prebuilt(), {})
        assert merged["components"][0]["name"] == "Web Server"
        assert merged["components"][0]["purpose"] == ""
        assert merged["services"] == [] and merged["dependencies"] == []

    def test_merge_tolerates_malformed_semantic_output(self):
        semantic = {
            "components": {"id": "aws_instance.web_server"},  # not a list
            "services": "none",
            "dependencies": [
                {"type": "cloud", "provider": "AWS", "service": "EC2",
                 "dependent_components": "aws_instance.web_server"},
                "garbage",
                {"type": "saas", "provider": "GitHub", "service": "Actions",
                 "dependent_components": ["aws_instance.web_server", 42]},
            ],
        }
        merged = merge_phase1(_prebuilt(), semantic)
        assert merged["components"][0]["name"] == "Web Server"
        assert merged["services"] == []
        assert merged["dependencies"] == [
            {"type": "cloud", "provider": "AWS", "service": "EC2",
             "dependent_components": ["aws_instance.web_server"]},
            {"type": "saas", "provider": "GitHub", "service": "Actions",
             "dependent_components": ["aws_instance.web_server"]},
        ]
        assert merged["components"][0]["dependencies"] == [
            {"type": "cloud", "provider": "AWS", "service": "EC2"},
            {"type": "saas", "provider": "GitHub", "service": "Actions"},
        ]
```

`tests/test_prompts_semantic.py`:

```python
"""The semantic phase-1 prompt templates format with the placeholders Task 5 passes."""

from tmi_tf.config import prompts_dir


def test_semantic_user_template_placeholders():
    template = (prompts_dir() / "inventory_semantic_user.txt").read_text(encoding="utf-8")
    rendered = template.format(
        repo_name="r", repo_url="u", inventory_json='{"components": []}', filtered_hcl="x"
    )
    assert '{"components": []}' in rendered
    assert "Pre-extracted inventory" in rendered


def test_semantic_system_prompt_exists_and_names_categories():
    text = (prompts_dir() / "inventory_semantic_system.txt").read_text(encoding="utf-8")
    assert "security_control" in text
    assert "Return ONLY a JSON object" in text
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `uv run pytest tests/test_tf_filter.py::TestMergePhase1 tests/test_prompts_semantic.py -q`
Expected: `ImportError: cannot import name 'display_name'` (and the prompt tests fail until step 1's files exist).

- [ ] **Step 4: Append `display_name` and `merge_phase1` to `tmi_tf/tf_filter.py`**

```python
# --- merge of the LLM's semantic answer ---------------------------------------


def display_name(component_id: str) -> str:
    """Fallback display name from an address: aws_instance.web_server -> Web Server."""
    parts = component_id.split(".")
    suffix = ""
    if parts[0] in ("data", "module") and len(parts) > 1:
        suffix = f" ({parts[0]})"
    local = parts[-1].replace("_", " ").replace("-", " ").strip()
    return f"{local.title()}{suffix}" if local else component_id


def _as_dict_list(value: Any) -> list[dict[str, Any]]:
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _id_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def merge_phase1(prebuilt: dict[str, Any], semantic: dict[str, Any]) -> dict[str, Any]:
    """Static facts + LLM semantics -> the existing phase-1 inventory schema.

    Static ``id``, ``resource_type``, ``configuration`` win; the LLM supplies
    ``name``, ``purpose``, ``services``, ``dependencies`` and may only
    reclassify components whose static type is ``other``.
    """
    by_id = {
        c["id"]: c for c in _as_dict_list(semantic.get("components")) if "id" in c
    }
    dependencies = []
    for d in _as_dict_list(semantic.get("dependencies")):
        dependencies.append(
            {
                "type": d.get("type", ""),
                "provider": d.get("provider", ""),
                "service": d.get("service", ""),
                "dependent_components": _id_list(d.get("dependent_components")),
            }
        )

    components: list[dict[str, Any]] = []
    for comp in prebuilt.get("components", []):
        cid = comp["id"]
        sem = by_id.pop(cid, {})
        ctype = comp["type"]
        if ctype == "other" and sem.get("type") in ALLOWED_CATEGORIES:
            ctype = sem["type"]
        components.append(
            {
                "id": cid,
                "name": sem.get("name") or display_name(cid),
                "type": ctype,
                "resource_type": comp["resource_type"],
                "configuration": comp["configuration"],
                "purpose": sem.get("purpose") or "",
                "dependencies": [
                    {"type": d["type"], "provider": d["provider"], "service": d["service"]}
                    for d in dependencies
                    if cid in d["dependent_components"]
                ],
            }
        )
    if by_id:
        logger.warning(
            "Phase 1: LLM returned %d component id(s) not in the static inventory; ignored: %s",
            len(by_id),
            ", ".join(sorted(by_id)[:10]),
        )
    return {
        "components": components,
        "services": _as_dict_list(semantic.get("services")),
        "dependencies": dependencies,
    }
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/test_tf_filter.py tests/test_prompts_semantic.py -q`
Expected: all PASS.

- [ ] **Step 6: Lint, type-check, full suite**

Run: `uv run ruff format tmi_tf/ tests/ && uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright && uv run pytest tests/ -q`
Expected: all green. (`ruff` may move the appended test import to the top of `tests/test_tf_filter.py`; let it.)

- [ ] **Step 7: Commit**

```bash
git add prompts/inventory_semantic_system.txt prompts/inventory_semantic_user.txt tmi_tf/tf_filter.py tests/test_tf_filter.py tests/test_prompts_semantic.py
git commit -m "feat(#10): semantic phase-1 prompts and static/LLM merge

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Pipeline integration in `LLMAnalyzer` with fallback

**Files:**
- Modify: `tmi_tf/llm_analyzer.py` (`__init__`, `_load_phase_prompts`, `analyze_repository` lines ~195-235, `_format_terraform_contents`)
- Test: `tests/test_llm_analyzer.py` (append `TestPhase1Static`)

**Interfaces:**
- Consumes (Tasks 1, 3, 4): `parse_terraform`, `load_registry`, `filter_terraform`, `merge_phase1`, `Registry`, `FilterResult`.
- Produces (used by Task 6): module-level `format_terraform_contents(tf_contents: dict[str, str]) -> str` in `tmi_tf/llm_analyzer.py` (the existing method body, now a function; the method delegates to it), and `LLMAnalyzer._run_phase1(terraform_repo, tf_contents, terraform_text) -> tuple[dict | None, int, int, float]`.
- Behavior: phases 2 and 3 keep receiving the full raw `terraform_text` exactly as today. Only phase 1 changes.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_llm_analyzer.py`:

```python
AWS_TF = (
    'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n  tags = { a = "b" }\n}\n'
    'resource "aws_instance" "web" {\n  ami = "ami-1"\n  instance_type = "t3.micro"\n'
    "  subnet_id = aws_subnet.private.id\n}\n"
)


def _make_static_repo(files: dict[str, str]):
    repo = MagicMock()
    repo.name = "test-repo"
    repo.url = "https://github.com/test/repo"
    repo.get_terraform_content.return_value = files
    return repo


def _tail_responses():
    """Phase 2, 3a responses so analyze_repository runs to completion."""
    return [
        _make_llm_response(json.dumps({"relationships": [], "data_flows": []})),
        _make_llm_response("[]"),
    ]


class TestPhase1Static:
    def test_static_path_sends_prebuilt_inventory_and_filtered_hcl(self):
        semantic = {
            "components": [
                {"id": "aws_vpc.main", "name": "Main VPC", "purpose": "Network"},
                {"id": "aws_instance.web", "name": "Web", "purpose": "Serves"},
            ],
            "services": [],
            "dependencies": [
                {"type": "cloud", "provider": "AWS", "service": "EC2",
                 "dependent_components": ["aws_instance.web"]}
            ],
        }
        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response(json.dumps(semantic)),
            *_tail_responses(),
        ]
        result = LLMAnalyzer(provider).analyze_repository(
            _make_static_repo({"main.tf": AWS_TF})
        )
        assert result.success is True

        system_prompt, user_prompt = provider.complete.call_args_list[0].args[:2]
        assert "semantic inference only" in system_prompt
        assert "Pre-extracted inventory" in user_prompt
        assert '"id": "aws_instance.web"' in user_prompt
        assert '"type": "compute"' in user_prompt
        assert "instance_type" not in user_prompt  # filtered out of the HCL
        assert "### File: main.tf" in user_prompt

        comps = {c["id"]: c for c in result.inventory["components"]}
        assert comps["aws_instance.web"]["name"] == "Web"
        assert comps["aws_instance.web"]["type"] == "compute"
        assert comps["aws_instance.web"]["resource_type"] == "aws_instance"
        assert comps["aws_instance.web"]["configuration"]["ami"] == "ami-1"
        assert comps["aws_instance.web"]["dependencies"] == [
            {"type": "cloud", "provider": "AWS", "service": "EC2"}
        ]
        assert result.inventory["dependencies"] == semantic["dependencies"]

        # phase 2 still receives the full raw Terraform text
        phase2_user = provider.complete.call_args_list[1].args[1]
        assert "instance_type" in phase2_user

    def test_phase1_partial_parse_sends_unparsed_raw(self):
        broken = 'resource "aws_instance" "broken" {\n  ami =\n}\n'
        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response(json.dumps({"components": []})),
            *_tail_responses(),
        ]
        result = LLMAnalyzer(provider).analyze_repository(
            _make_static_repo({"main.tf": AWS_TF, "broken.tf": broken})
        )
        assert result.success is True
        user_prompt = provider.complete.call_args_list[0].args[1]
        assert "Pre-extracted inventory" in user_prompt
        assert '"unparsed_files": [\n    "broken.tf"\n  ]' in user_prompt
        assert "ami =\n}" in user_prompt  # raw broken file passed through
        assert [c["id"] for c in result.inventory["components"]] == [
            "aws_vpc.main",
            "aws_instance.web",
        ]

    def test_falls_back_to_full_llm_when_nothing_parses(self, caplog):
        broken = 'resource "aws_instance" "broken" {\n  ami =\n}\n'
        inventory = {"components": [{"id": "aws_instance.broken"}], "services": []}
        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response(json.dumps(inventory)),
            *_tail_responses(),
        ]
        with caplog.at_level("WARNING"):
            result = LLMAnalyzer(provider).analyze_repository(
                _make_static_repo({"broken.tf": broken})
            )
        assert result.success is True
        system_prompt, user_prompt = provider.complete.call_args_list[0].args[:2]
        assert "semantic inference only" not in system_prompt
        assert "## Terraform Configuration Files" in user_prompt
        assert result.inventory == inventory  # untouched full-LLM answer
        assert "full-LLM phase 1" in caplog.text

    def test_falls_back_when_static_analysis_raises(self, monkeypatch, caplog):
        import tmi_tf.llm_analyzer as mod

        def boom(_contents):
            raise RuntimeError("registry exploded")

        monkeypatch.setattr(mod, "parse_terraform", boom)
        inventory = {"components": [], "services": []}
        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response(json.dumps(inventory)),
            *_tail_responses(),
        ]
        with caplog.at_level("WARNING"):
            result = LLMAnalyzer(provider).analyze_repository(
                _make_static_repo({"main.tf": AWS_TF})
            )
        assert result.success is True
        assert "registry exploded" in caplog.text
        assert "## Terraform Configuration Files" in provider.complete.call_args_list[0].args[1]

    def test_static_path_keeps_retry_once_then_fail_loudly(self):
        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response("not json"),
            _make_llm_response("still not json"),
        ]
        result = LLMAnalyzer(provider).analyze_repository(
            _make_static_repo({"main.tf": AWS_TF})
        )
        assert result.success is False
        assert provider.complete.call_count == 2
        assert "Phase 1" in result.error_message and "2 attempts" in result.error_message

    def test_static_path_counts_tokens_from_both_attempts(self):
        semantic = {"components": []}
        truncated = _make_llm_response('{"components": [')
        truncated.finish_reason = "length"
        provider = _make_provider()
        provider.complete.side_effect = [
            truncated,
            _make_llm_response(json.dumps(semantic)),
            *_tail_responses(),
        ]
        result = LLMAnalyzer(provider).analyze_repository(
            _make_static_repo({"main.tf": AWS_TF})
        )
        assert result.success is True
        assert provider.complete.call_count == 4
        assert result.input_tokens >= 400


def test_format_terraform_contents_is_module_level():
    from tmi_tf.llm_analyzer import format_terraform_contents

    assert format_terraform_contents({}) == "(No Terraform files found)"
    text = format_terraform_contents({"b.tf": "x", "a.tf": "y"})
    assert text.index("### File: a.tf") < text.index("### File: b.tf")
    assert "```hcl\ny\n```" in text
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_llm_analyzer.py -q`
Expected: `TestPhase1Static` fails (the first call's system prompt is the old `inventory_system.txt`; `format_terraform_contents` import fails). The pre-existing tests still pass.

- [ ] **Step 3: Modify `tmi_tf/llm_analyzer.py`**

Imports (add after the existing `from tmi_tf.retry import ...`):

```python
from tmi_tf.tf_filter import filter_terraform, load_registry, merge_phase1
from tmi_tf.tf_parser import parse_terraform
```

In `__init__`, after `self._load_phase_prompts()`:

```python
        self.registry = load_registry()
```

In `_load_phase_prompts`, after the two `inventory_*` lines:

```python
        self.inventory_semantic_system = self._load_prompt("inventory_semantic_system.txt")
        self.inventory_semantic_user_template = self._load_prompt(
            "inventory_semantic_user.txt"
        )
```

In `analyze_repository`, replace the block from `# Phase 1: Inventory Extraction` through the `total_cost += cost` after the phase-1 call with:

```python
            # Phase 1: Inventory Extraction (static analysis + semantic LLM,
            # or the full-LLM prompt when static analysis yields nothing)
            if status_callback:
                status_callback("Phase 1 (Inventory) started")
            logger.info("Phase 1: Extracting inventory for %s", terraform_repo.name)
            inventory, tokens_in, tokens_out, cost = self._run_phase1(
                terraform_repo, tf_contents, terraform_text
            )
            total_input_tokens += tokens_in
            total_output_tokens += tokens_out
            total_cost += cost
```

Add the method to `LLMAnalyzer` (after `analyze_repository`):

```python
    def _run_phase1(
        self,
        terraform_repo: TerraformRepository,
        tf_contents: dict[str, str],
        terraform_text: str,
    ) -> tuple[dict[str, Any] | None, int, int, float]:
        """Phase 1 with static HCL analysis; full-LLM fallback (#10).

        Returns the same tuple as ``_call_llm_json``: the merged inventory (or
        None when the LLM gave no usable JSON after 2 attempts, which the
        caller turns into the #68 failure) plus tokens and cost.
        """
        prebuilt: dict[str, Any] | None = None
        filtered_text = ""
        try:
            static = parse_terraform(tf_contents)
            if static.unparsed_files:
                logger.warning(
                    "Phase 1: %d/%d file(s) not statically parsable, sent unfiltered: %s",
                    len(static.unparsed_files),
                    len(tf_contents),
                    ", ".join(static.unparsed_files),
                )
            if static.resources or static.data_sources or static.modules:
                filtered = filter_terraform(static, tf_contents, self.registry)
                prebuilt = filtered.prebuilt_inventory
                filtered_text = format_terraform_contents(filtered.filtered_files)
                logger.info(
                    "Phase 1 static: %d resources, %d data sources, %d modules; "
                    "HCL %d -> %d chars, inventory JSON %d chars",
                    len(static.resources),
                    len(static.data_sources),
                    len(static.modules),
                    len(terraform_text),
                    len(filtered_text),
                    len(json.dumps(prebuilt)),
                )
            else:
                logger.warning(
                    "Phase 1: static analysis found no components in %d file(s); "
                    "using full-LLM phase 1",
                    len(tf_contents),
                )
        except Exception as e:
            logger.warning(
                "Phase 1: static HCL analysis failed (%s); using full-LLM phase 1", e
            )
            prebuilt = None

        if prebuilt is None:
            inventory_user = self.inventory_user_template.format(
                repo_name=terraform_repo.name,
                repo_url=terraform_repo.url,
                terraform_contents=terraform_text,
            )
            return self._call_llm_json(
                system_prompt=self.inventory_system,
                user_prompt=inventory_user,
                phase_name="inventory",
                attempts=2,
            )

        semantic_user = self.inventory_semantic_user_template.format(
            repo_name=terraform_repo.name,
            repo_url=terraform_repo.url,
            inventory_json=json.dumps(prebuilt, indent=2),
            filtered_hcl=filtered_text,
        )
        semantic, tokens_in, tokens_out, cost = self._call_llm_json(
            system_prompt=self.inventory_semantic_system,
            user_prompt=semantic_user,
            phase_name="inventory",
            attempts=2,
        )
        if not semantic:
            return None, tokens_in, tokens_out, cost
        return merge_phase1(prebuilt, semantic), tokens_in, tokens_out, cost
```

Replace the `_format_terraform_contents` method body with a delegation and add the module-level function (above the `LLMAnalyzer` class or just before the alias at the bottom):

```python
def format_terraform_contents(tf_contents: dict[str, str]) -> str:
    """One ``### File: path`` section with a fenced hcl block per file, sorted."""
    if not tf_contents:
        return "(No Terraform files found)"
    sections = []
    for filepath, content in sorted(tf_contents.items()):
        sections.append(f"### File: {filepath}\n```hcl\n{content}\n```\n")
    return "\n".join(sections)
```

```python
    def _format_terraform_contents(self, tf_contents: dict[str, str]) -> str:
        """Kept for callers/tests that use the method form."""
        return format_terraform_contents(tf_contents)
```

Do not touch `_call_llm_json`, `_call_llm`, the phase-2/3 code, or the `ValueError` raised when `inventory` is falsy.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_llm_analyzer.py -q`
Expected: all PASS, including the pre-existing `TestPhase3Decomposition`, `TestPhase1Retry` and `TestCweRedirect` (their `_make_tf_repo` content parses statically; their full-inventory mock answers merge fine because `merge_phase1` ignores unknown ids and fills names).

- [ ] **Step 5: Lint, type-check, full suite**

Run: `uv run ruff format tmi_tf/ tests/ && uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright && uv run pytest tests/ -q`
Expected: all green. `tests/test_analyzer.py` patches `tmi_tf.analyzer.LLMAnalyzer`, so it is unaffected.

- [ ] **Step 6: Commit**

```bash
git add tmi_tf/llm_analyzer.py tests/test_llm_analyzer.py
git commit -m "feat(#10): phase 1 runs on static HCL analysis with full-LLM fallback

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Prompt-size measurement, docs, results

**Files:**
- Create: `scripts/measure_phase1_prompt.py`
- Modify: `README.md` (How It Works step 5, Project Structure), `.claude/CLAUDE.md` (Modules list), `PROGRESS.md` (one line), this plan (Results section below)

**Interfaces:**
- Consumes (Tasks 1, 3, 5): `parse_terraform`, `load_registry`, `filter_terraform`, `format_terraform_contents`, `RepositoryAnalyzer.detect_environments`, `RepositoryAnalyzer.resolve_modules`, `prompts_dir`.
- Produces: a CLI `uv run python scripts/measure_phase1_prompt.py <terraform_root> <environment>` that prints one line per metric and never calls an LLM. `litellm.token_counter` (local tokenizer; may download a tokenizer file once) with a `chars // 4` fallback.

- [ ] **Step 1: Write the script**

`scripts/measure_phase1_prompt.py`:

```python
"""Measure phase-1 prompt size before/after static HCL analysis (issue #10).

Reads a local Terraform checkout, resolves one environment exactly like the
pipeline (environment files + relative-source modules), builds both phase-1
prompts and prints their sizes. Never calls an LLM. Files are read only; the
validator/sanitizer is NOT run, so the "before" number includes any user_data
the pipeline would have stripped.

Usage:
  uv run python scripts/measure_phase1_prompt.py /Users/efitz/Projects/tmi/terraform aws-public
"""

import argparse
import json
import sys
from pathlib import Path

from tmi_tf.config import prompts_dir
from tmi_tf.llm_analyzer import format_terraform_contents
from tmi_tf.repo_analyzer import RepositoryAnalyzer
from tmi_tf.tf_filter import filter_terraform, load_registry
from tmi_tf.tf_parser import parse_terraform


def count_tokens(text: str) -> int:
    try:
        import litellm  # pyright: ignore[reportMissingImports]

        return int(litellm.token_counter(model="gpt-4o", text=text))
    except Exception as e:  # no tokenizer available offline
        print(f"token_counter unavailable ({e}); using chars // 4", file=sys.stderr)
        return len(text) // 4


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("terraform_root", type=Path)
    ap.add_argument("environment")
    args = ap.parse_args()
    root = args.terraform_root.resolve()

    envs = RepositoryAnalyzer.detect_environments(root)
    env = next((e for e in envs if e.name == args.environment), None)
    if env is None:
        print(
            f"environment {args.environment!r} not found; available: "
            f"{', '.join(e.name for e in envs) or 'none'}",
            file=sys.stderr,
        )
        return 2

    files = RepositoryAnalyzer.resolve_modules(env, root)
    contents: dict[str, str] = {}
    for f in files:
        try:
            contents[str(f.relative_to(root))] = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            print(f"skipping {f}: {e}", file=sys.stderr)

    prompts = prompts_dir()
    old_system = (prompts / "inventory_system.txt").read_text(encoding="utf-8")
    old_user = (prompts / "inventory_user.txt").read_text(encoding="utf-8")
    new_system = (prompts / "inventory_semantic_system.txt").read_text(encoding="utf-8")
    new_user = (prompts / "inventory_semantic_user.txt").read_text(encoding="utf-8")

    raw_text = format_terraform_contents(contents)
    before = old_system + old_user.format(
        repo_name="measure", repo_url="local", terraform_contents=raw_text
    )

    static = parse_terraform(contents)
    filtered = filter_terraform(static, contents, load_registry())
    filtered_text = format_terraform_contents(filtered.filtered_files)
    inventory_json = json.dumps(filtered.prebuilt_inventory, indent=2)
    after = new_system + new_user.format(
        repo_name="measure",
        repo_url="local",
        inventory_json=inventory_json,
        filtered_hcl=filtered_text,
    )

    before_tokens = count_tokens(before)
    after_tokens = count_tokens(after)
    rows = [
        ("environment", args.environment),
        ("files", len(contents)),
        ("unparsed files", ", ".join(static.unparsed_files) or "none"),
        ("resources / data sources / modules",
         f"{len(static.resources)} / {len(static.data_sources)} / {len(static.modules)}"),
        ("components in pre-built inventory", len(filtered.prebuilt_inventory["components"])),
        ("attributes omitted", filtered.omitted_attributes),
        ("raw HCL chars", len(raw_text)),
        ("filtered HCL chars", len(filtered_text)),
        ("pre-built inventory JSON chars", len(inventory_json)),
        ("phase-1 prompt chars before -> after", f"{len(before)} -> {len(after)}"),
        ("phase-1 prompt tokens before -> after", f"{before_tokens} -> {after_tokens}"),
        ("input delta", f"{(after_tokens - before_tokens) / max(before_tokens, 1):+.1%}"),
    ]
    width = max(len(k) for k, _ in rows)
    for k, v in rows:
        print(f"{k:<{width}}  {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Run it on the real tmi environments (no LLM)**

```bash
for env in aws-public oci-private azure-public gcp-public; do
  echo "== $env"; uv run python scripts/measure_phase1_prompt.py /Users/efitz/Projects/tmi/terraform "$env"
done
```

Expected: four tables; `oci-private`/`oci-public` report `modules/kubernetes/oci/k8s_resources.tf` under "unparsed files" (python-hcl2 8.1.4 bug), everything else parses. If the environment names differ (`detect_environments` shortens names), run once with a bogus name to print the available ones. If `terraform_root` detects the `vendor/` directory as an environment, ignore it.

- [ ] **Step 3: Record the results**

Replace the table in the **Results** section at the end of this plan with the printed numbers (one row per environment: files, unparsed, components, raw HCL chars, filtered HCL chars, inventory JSON chars, prompt tokens before -> after, delta). Output-token savings cannot be measured without an LLM run; note that they are expected from the smaller response contract and will be read from the first production run's `Phase inventory: ... output tokens` log line.

Add one line to `PROGRESS.md` in its existing style, e.g.:

```
- 2026-09-XX #10 subtask 1 (<sha>): phase 1 now runs static HCL analysis (python-hcl2) + a semantic-only LLM prompt, merged into the unchanged inventory schema; full-LLM fallback when nothing parses. Measured on tmi aws-public: phase-1 prompt N -> M tokens (-P%); oci-private: ... (k8s_resources.tf unparsable on python-hcl2 8.1.4, sent raw). Not deployed.
```

- [ ] **Step 4: Update the docs**

`README.md` "How It Works", replace step 5:

```
5. **Analysis**: Parses the Terraform statically (python-hcl2) into a pre-built inventory, sends it with security-attribute-filtered HCL to the LLM for naming, purposes, services and dependencies (falling back to the full-LLM prompt when nothing parses), then runs the infrastructure and security phases
```

`README.md` "Project Structure": add after the `repo_analyzer.py` line

```
│   ├── tf_parser.py            # Static HCL parsing (python-hcl2) -> StaticInventory
│   ├── tf_filter.py            # Registry-driven filtering, pre-built inventory, merge
│   ├── data/resource_registry.yaml  # Resource type -> category + security attributes
```

and replace the two `prompts/` lines with

```
├── prompts/
│   ├── inventory_semantic_*.txt  # Phase 1 (static inventory + semantic LLM)
│   ├── inventory_*.txt           # Phase 1 full-LLM fallback
│   └── ...                       # Phases 2, 3a, 3b, DFD
```

`.claude/CLAUDE.md` "Modules" list, add after `repo_analyzer.py`:

```
- **`tf_parser.py`** — static HCL parsing with python-hcl2 (8.x dict shape: quoted literals, `${expr}`, `__is_block__`); `StaticInventory`; files that fail to parse are listed in `unparsed_files`
- **`tf_filter.py`** — applies `data/resource_registry.yaml` (category + security attrs per resource type; unknown types keep everything) to produce filtered HCL via `hcl2.dumps` and the pre-built inventory; `merge_phase1` folds the LLM's semantic answer back into the phase-1 schema
```

and in the pipeline description change item 1 to:

```
1. **Inventory extraction** — static parse + registry filter build the component list; the LLM only adds names, purposes, services, dependencies (`inventory_semantic_*.txt`); full-LLM `inventory_*.txt` fallback when nothing parses → JSON
```

- [ ] **Step 5: Lint, type-check, full suite (scripts included)**

Run: `uv run ruff format tmi_tf/ tests/ scripts/ && uv run ruff check tmi_tf/ tests/ scripts/ && uv run ruff format --check tmi_tf/ tests/ scripts/ && uv run pyright && uv run pytest tests/ -q`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add scripts/measure_phase1_prompt.py README.md .claude/CLAUDE.md PROGRESS.md docs/superpowers/plans/2026-09-26-static-hcl-analysis.md
git commit -m "feat(#10): phase-1 prompt size measurement, docs, results

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Results

Measured with `uv run python scripts/measure_phase1_prompt.py /Users/efitz/Projects/tmi/terraform <environment>` (python-hcl2 8.1.4, `litellm.token_counter(model="gpt-4o", ...)`, no network fallback needed).

**Task 7 correction:** Task 6's measurement (below the line) showed the new phase-1 prompt was *larger* than the old full-LLM prompt in every environment (+52% to +91%), because `json.dumps(prebuilt, indent=2)` duplicated every component's full `configuration` (already present in the filtered HCL) and carried `variables`/`outputs` (also already in the filtered HCL), pretty-printed. Task 7 added `tf_filter.prompt_inventory()`/`prompt_inventory_json()` -- a compact `{id, resource_type, type, provider, file, references}`-only inventory, `json.dumps(..., separators=(",", ":"))` -- used by both `LLMAnalyzer._run_phase1` and this measurement script, plus whitespace normalization of the filtered HCL (drop whitespace-only lines, collapse blank-line runs, heredoc bodies untouched). The merged phase-1 *output* (what `merge_phase1` produces) is unchanged; only the prompt shrank.

| environment | files | unparsed | components | raw HCL chars | filtered HCL chars | prompt inventory JSON chars | prompt tokens before -> after | delta |
|-------------|-------|----------|------------|---------------|--------------------|------------------------------|-------------------------------|-------|
| aws-public | 23 | none | 108 | 115,940 | 71,529 | 22,466 | 29,184 -> 24,106 | -17.4% |
| oci-private | 22 | none | 135 | 145,738 | 113,292 | 32,352 | 36,736 -> 36,827 | +0.2% |
| azure-public | 19 | none | 46 | 56,857 | 45,064 | 10,297 | 15,108 -> 14,532 | -3.8% |
| gcp-public | 19 | none | 54 | 58,532 | 46,074 | 11,950 | 15,177 -> 14,759 | -2.8% |

`modules/kubernetes/oci/k8s_resources.tf` (the python-hcl2 8.1.4 transformer bug the spec expected) now parses cleanly on this checkout of `~/Projects/tmi/terraform`; all four environments are fully statically analyzed, so "unparsed" is "none" throughout.

Input tokens now go down in three of four environments (aws-public -17.4%, azure-public -3.8%, gcp-public -2.8%), matching the spec's goal. **oci-private is still marginally larger (+0.2%, +91 tokens)**, not the +90.7% Task 6 measured but still not a net reduction: oci-private has the most components (135) with many `other`-category (unrecognized) resource types whose registry entry keeps every attribute, so its filtered HCL is proportionally less trimmed than the other environments' and the compact inventory's per-component overhead (six short keys, still one row per component) isn't fully absorbed by the HCL-side savings. Not further optimized in Task 7 (out of scope: would mean shrinking the registry-unknown passthrough or filtered-HCL comments, not the prompt-assembly change this task specified). Output-token savings are still not measurable without an LLM run; they're still expected because the semantic contract omits `resource_type`, `type`, `configuration` and per-component `dependencies` for every component, and the first production run's `Phase inventory: ... output tokens` log line will confirm.

<details>
<summary>Task 6's original (superseded) measurement</summary>

| environment | files | unparsed | components | raw HCL chars | filtered HCL chars | inventory JSON chars | prompt tokens before -> after | delta |
|-------------|-------|----------|------------|---------------|--------------------|----------------------|-------------------------------|-------|
| aws-public | 23 | none | 108 | 115,940 | 71,639 | 99,318 | 29,184 -> 44,308 | +51.8% |
| oci-private | 22 | none | 135 | 145,738 | 113,963 | 163,542 | 36,736 -> 70,062 | +90.7% |
| azure-public | 19 | none | 46 | 56,857 | 45,280 | 60,296 | 15,108 -> 27,014 | +78.8% |
| gcp-public | 19 | none | 54 | 58,532 | 46,314 | 66,028 | 15,177 -> 28,091 | +85.1% |

</details>

## Deviations from the spec (decided while planning; revisit if they matter)

1. **Parser input is the content dict, not file paths.** `parse_terraform(tf_contents)` takes `TerraformRepository.get_terraform_content()` output, which already contains the environment plus resolved modules, post-sanitization. Avoids re-reading files and keeps the parser pure/testable.
2. **Integration lives in `LLMAnalyzer.analyze_repository`, not `analyzer.py`.** Every caller (both `analyzer.py` paths and the CLI) goes through it; the fallback and the #68 retry sit next to the call they protect. `analyzer.py` is unchanged.
3. **New prompt files instead of modifying `inventory_*.txt`.** The fallback needs the old prompts intact.
4. **`StaticInventory` gains `parsed_files`; resources/data sources/modules gain `file`.** Needed to regenerate filtered HCL with `hcl2.dumps` without re-parsing, and `file` gives the LLM module boundaries for service grouping.
5. **Filtered HCL is regenerated with `hcl2.dumps`** rather than a hand-written emitter; comments are added by text insertion before the block's closing brace. Block grouping follows hcl2's dict (all resources, then data, ...) rather than source interleaving.
6. **Per-component `dependencies` are derived** from the top-level `dependencies` array instead of asked for twice; the merged schema is unchanged.
7. **Merged output contains only today's keys.** `provider`, `file`, `references` are sent to the LLM in the pre-built inventory but not carried into the merged phase-1 result, so phases 2/3, markdown, DFD and threats see exactly the schema they see today.

## Self-review (done while writing)

- Spec coverage: Component 1 (parser, all six dataclasses, references, unparsed handling) -> Task 1; Component 2 (registry YAML, providers, defaults, dot paths, allowed categories, four providers) -> Task 2; Component 3 (filtered HCL, keep rules incl. meta-args and references, unknown passthrough, unparsed passthrough, omitted comment, pre-built inventory with null name/purpose) -> Task 3; Component 4 (revised prompt, output contract, merge to existing schema) -> Task 4; Component 5 (pipeline integration, `python-hcl2` dependency, error resilience both levels) -> Tasks 1 and 5; Token impact -> Task 6; Testing strategy (per-provider fixtures, unparsable fixture, registry validity, merge, fallback) -> Tasks 1-5.
- Placeholder scan: the Results table is filled in by Task 6 step 3 from a printed measurement; no TBD/TODO elsewhere.
- Type consistency: `Registry.security_attrs -> list[str] | None`, `FilterResult.filtered_files/prebuilt_inventory/omitted_attributes`, `merge_phase1(prebuilt, semantic)`, `format_terraform_contents` and `_run_phase1` names match across Tasks 3-6.
- Review Focus: each of the five lines names its owning test in Tasks 1, 3, 4, 5.
