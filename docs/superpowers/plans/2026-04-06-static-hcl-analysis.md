# Static HCL Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move mechanical Terraform inventory extraction out of the LLM into static Python-based HCL parsing, so the LLM only performs semantic analysis (names, purpose, service groupings, dependencies).

**Architecture:** New `tf_parser.py` parses HCL with `python-hcl2`. New `tf_filter.py` applies a configurable YAML resource registry to classify resources and filter to security-relevant attributes. The existing Phase 1 LLM call receives a compact pre-built inventory plus filtered HCL instead of raw Terraform files. A merge step combines static + LLM output into the existing Phase 1 schema.

**Tech Stack:** python-hcl2 (HCL parsing), PyYAML (registry loading), existing LiteLLM pipeline

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `tmi_tf/tf_parser.py` | Create | HCL parsing, produces `StaticInventory` dataclass |
| `tmi_tf/tf_filter.py` | Create | Loads registry, filters attributes, produces filtered HCL + pre-built inventory JSON |
| `tmi_tf/data/resource_registry.yaml` | Create | Resource type → category mapping + security-relevant attribute lists |
| `prompts/inventory_system.txt` | Modify | New Phase 1 system prompt for semantic-only analysis |
| `prompts/inventory_user.txt` | Modify | New Phase 1 user prompt with inventory_json + filtered_hcl |
| `tmi_tf/llm_analyzer.py` | Modify | Phase 1 accepts static inventory, uses new prompts, merges output |
| `tmi_tf/analyzer.py` | Modify | Orchestrate static parse → filter before LLM call |
| `pyproject.toml` | Modify | Add python-hcl2 and pyyaml dependencies |
| `tests/test_tf_parser.py` | Create | Unit tests for HCL parsing |
| `tests/test_tf_filter.py` | Create | Unit tests for filtering and registry loading |
| `tests/test_resource_registry.py` | Create | Validation tests for the YAML registry |
| `tests/test_llm_analyzer.py` | Modify | Add Phase 1 merge/fallback tests |
| `tests/fixtures/` | Create | Small .tf files for test fixtures |

---

## Task 1: Add Dependencies

**Files:**
- Modify: `pyproject.toml:6-24`

- [ ] **Step 1: Add python-hcl2 and pyyaml to dependencies**

In `pyproject.toml`, add to the `dependencies` list:

```toml
    "python-hcl2>=6.1.0",
    "pyyaml>=6.0",
```

Add after the `"oci>=2.168.2",` line (line 21).

- [ ] **Step 2: Sync dependencies**

Run: `uv sync`
Expected: Clean install, no errors.

- [ ] **Step 3: Verify imports work**

Run: `uv run python -c "import hcl2; import yaml; print('OK')"`
Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml uv.lock
git commit -m "chore(#10): add python-hcl2 and pyyaml dependencies"
```

---

## Task 2: Static HCL Parser — Dataclasses and File Parsing

**Files:**
- Create: `tmi_tf/tf_parser.py`
- Create: `tests/test_tf_parser.py`
- Create: `tests/fixtures/aws_basic.tf`

- [ ] **Step 1: Create test fixture**

Create `tests/fixtures/aws_basic.tf`:

```hcl
variable "region" {
  type        = string
  default     = "us-east-1"
  description = "AWS region"
}

provider "aws" {
  region = var.region
}

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name = "main-vpc"
  }
}

resource "aws_instance" "web_server" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.web.id]
  iam_instance_profile        = aws_iam_instance_profile.web.name
  associate_public_ip_address = true

  metadata_options {
    http_tokens = "required"
  }

  tags = {
    Name = "web-server"
  }
}

resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Security group for web tier"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-*-amd64-server-*"]
  }
}

output "web_server_ip" {
  value       = aws_instance.web_server.public_ip
  description = "Public IP of the web server"
  sensitive   = false
}

module "rds" {
  source = "./modules/rds"

  vpc_id    = aws_vpc.main.id
  subnet_id = aws_subnet.private.id
}
```

- [ ] **Step 2: Write failing tests for dataclasses and parse_tf_files**

Create `tests/test_tf_parser.py`:

```python
"""Tests for tmi_tf.tf_parser — static HCL parsing."""

import textwrap
from pathlib import Path

import pytest

from tmi_tf.tf_parser import (
    ParsedDataSource,
    ParsedModule,
    ParsedOutput,
    ParsedProvider,
    ParsedResource,
    ParsedVariable,
    StaticInventory,
    parse_tf_files,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestParseTfFiles:
    def test_parses_resources(self):
        inventory = parse_tf_files([FIXTURES_DIR / "aws_basic.tf"])
        resource_addresses = [r.address for r in inventory.resources]
        assert "aws_vpc.main" in resource_addresses
        assert "aws_instance.web_server" in resource_addresses
        assert "aws_security_group.web" in resource_addresses

    def test_resource_fields(self):
        inventory = parse_tf_files([FIXTURES_DIR / "aws_basic.tf"])
        vpc = next(r for r in inventory.resources if r.address == "aws_vpc.main")
        assert vpc.resource_type == "aws_vpc"
        assert vpc.local_name == "main"
        assert vpc.attributes["cidr_block"] == "10.0.0.0/16"

    def test_parses_data_sources(self):
        inventory = parse_tf_files([FIXTURES_DIR / "aws_basic.tf"])
        assert len(inventory.data_sources) == 1
        ds = inventory.data_sources[0]
        assert ds.data_type == "aws_ami"
        assert ds.local_name == "ubuntu"
        assert ds.address == "data.aws_ami.ubuntu"

    def test_parses_variables(self):
        inventory = parse_tf_files([FIXTURES_DIR / "aws_basic.tf"])
        assert len(inventory.variables) == 1
        var = inventory.variables[0]
        assert var.name == "region"
        assert var.default == "us-east-1"
        assert var.description == "AWS region"

    def test_parses_outputs(self):
        inventory = parse_tf_files([FIXTURES_DIR / "aws_basic.tf"])
        assert len(inventory.outputs) == 1
        out = inventory.outputs[0]
        assert out.name == "web_server_ip"
        assert out.sensitive is False
        assert out.description == "Public IP of the web server"

    def test_parses_modules(self):
        inventory = parse_tf_files([FIXTURES_DIR / "aws_basic.tf"])
        assert len(inventory.modules) == 1
        mod = inventory.modules[0]
        assert mod.name == "rds"
        assert mod.source == "./modules/rds"
        assert "vpc_id" in mod.inputs

    def test_parses_providers(self):
        inventory = parse_tf_files([FIXTURES_DIR / "aws_basic.tf"])
        assert len(inventory.providers) == 1
        prov = inventory.providers[0]
        assert prov.name == "aws"
        assert prov.alias is None

    def test_detects_references(self):
        inventory = parse_tf_files([FIXTURES_DIR / "aws_basic.tf"])
        instance = next(
            r for r in inventory.resources if r.address == "aws_instance.web_server"
        )
        # Should detect references to other resources in attribute values
        assert any("aws_security_group.web" in ref for ref in instance.references)
        assert any("aws_iam_instance_profile.web" in ref for ref in instance.references)

    def test_unparsable_file_recorded(self, tmp_path):
        bad_file = tmp_path / "bad.tf"
        bad_file.write_text("this is not valid { { { HCL at all !!!", encoding="utf-8")
        inventory = parse_tf_files([bad_file])
        assert str(bad_file) in inventory.unparsed_files
        assert len(inventory.resources) == 0

    def test_mixed_good_and_bad_files(self, tmp_path):
        bad_file = tmp_path / "bad.tf"
        bad_file.write_text("not valid HCL {{{", encoding="utf-8")
        good_file = FIXTURES_DIR / "aws_basic.tf"
        inventory = parse_tf_files([good_file, bad_file])
        assert len(inventory.resources) >= 3  # from aws_basic.tf
        assert str(bad_file) in inventory.unparsed_files

    def test_empty_file_list(self):
        inventory = parse_tf_files([])
        assert len(inventory.resources) == 0
        assert len(inventory.unparsed_files) == 0
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/test_tf_parser.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'tmi_tf.tf_parser'`

- [ ] **Step 4: Implement tf_parser.py**

Create `tmi_tf/tf_parser.py`:

```python
"""Static HCL parser for Terraform files.

Parses .tf files using python-hcl2 to extract a structured inventory
of resources, data sources, variables, outputs, modules, and providers.
This mechanical extraction provides the ground-truth baseline that
the LLM enriches with semantic analysis.
"""

import io
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import hcl2  # pyright: ignore[reportMissingModuleSource]

logger = logging.getLogger(__name__)

# Pattern to detect Terraform resource references in attribute values.
# Matches: resource_type.local_name or resource_type.local_name.attribute
_REF_PATTERN = re.compile(
    r"\b([a-z][a-z0-9_]*\.[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*)\b"
)

# Known Terraform top-level block types — used to filter false-positive
# references that happen to match the pattern but aren't resource refs.
_TF_BLOCK_TYPES = frozenset(
    {
        "resource",
        "data",
        "variable",
        "output",
        "module",
        "provider",
        "terraform",
        "locals",
    }
)


@dataclass
class ParsedResource:
    resource_type: str
    local_name: str
    address: str
    attributes: dict[str, Any]
    references: list[str] = field(default_factory=list)


@dataclass
class ParsedDataSource:
    data_type: str
    local_name: str
    address: str
    attributes: dict[str, Any]
    references: list[str] = field(default_factory=list)


@dataclass
class ParsedVariable:
    name: str
    type_expr: str | None = None
    default: Any = None
    description: str | None = None


@dataclass
class ParsedOutput:
    name: str
    value_expr: str = ""
    description: str | None = None
    sensitive: bool = False


@dataclass
class ParsedModule:
    name: str
    source: str
    inputs: dict[str, Any] = field(default_factory=dict)


@dataclass
class ParsedProvider:
    name: str
    alias: str | None = None
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class StaticInventory:
    resources: list[ParsedResource] = field(default_factory=list)
    data_sources: list[ParsedDataSource] = field(default_factory=list)
    variables: list[ParsedVariable] = field(default_factory=list)
    outputs: list[ParsedOutput] = field(default_factory=list)
    modules: list[ParsedModule] = field(default_factory=list)
    providers: list[ParsedProvider] = field(default_factory=list)
    unparsed_files: list[str] = field(default_factory=list)


def parse_tf_files(tf_files: list[Path]) -> StaticInventory:
    """Parse a list of .tf files into a StaticInventory.

    Files that fail to parse are recorded in unparsed_files rather
    than raising an exception, so the LLM can still process them.
    """
    inventory = StaticInventory()

    for tf_file in tf_files:
        try:
            content = tf_file.read_text(encoding="utf-8")
            parsed = hcl2.load(io.StringIO(content))
            _extract_blocks(parsed, inventory)
        except Exception:
            logger.warning("Failed to parse HCL file: %s", tf_file)
            inventory.unparsed_files.append(str(tf_file))

    return inventory


def _extract_blocks(parsed: dict[str, Any], inventory: StaticInventory) -> None:
    """Extract all block types from a parsed HCL dict."""
    # Resources: {"resource": [{"aws_instance": {"web": {...}}}]}
    for resource_block in parsed.get("resource", []):
        for resource_type, instances in resource_block.items():
            for local_name, attrs in instances.items():
                refs = _find_references(attrs, resource_type, local_name)
                inventory.resources.append(
                    ParsedResource(
                        resource_type=resource_type,
                        local_name=local_name,
                        address=f"{resource_type}.{local_name}",
                        attributes=attrs,
                        references=refs,
                    )
                )

    # Data sources: {"data": [{"aws_ami": {"ubuntu": {...}}}]}
    for data_block in parsed.get("data", []):
        for data_type, instances in data_block.items():
            for local_name, attrs in instances.items():
                refs = _find_references(attrs, data_type, local_name)
                inventory.data_sources.append(
                    ParsedDataSource(
                        data_type=data_type,
                        local_name=local_name,
                        address=f"data.{data_type}.{local_name}",
                        attributes=attrs,
                        references=refs,
                    )
                )

    # Variables: {"variable": [{"region": {"type": "string", ...}}]}
    for var_block in parsed.get("variable", []):
        for var_name, attrs in var_block.items():
            inventory.variables.append(
                ParsedVariable(
                    name=var_name,
                    type_expr=attrs.get("type"),
                    default=attrs.get("default"),
                    description=attrs.get("description"),
                )
            )

    # Outputs: {"output": [{"web_ip": {"value": "...", ...}}]}
    for output_block in parsed.get("output", []):
        for out_name, attrs in output_block.items():
            value = attrs.get("value", "")
            inventory.outputs.append(
                ParsedOutput(
                    name=out_name,
                    value_expr=str(value) if value else "",
                    description=attrs.get("description"),
                    sensitive=attrs.get("sensitive", False),
                )
            )

    # Modules: {"module": [{"rds": {"source": "./modules/rds", ...}}]}
    for module_block in parsed.get("module", []):
        for mod_name, attrs in module_block.items():
            source = attrs.pop("source", "")
            # Remove meta-arguments from inputs
            inputs = {
                k: v
                for k, v in attrs.items()
                if k not in ("version", "providers", "depends_on", "count", "for_each")
            }
            inventory.modules.append(
                ParsedModule(name=mod_name, source=source, inputs=inputs)
            )

    # Providers: {"provider": [{"aws": {"region": "us-east-1"}}]}
    for provider_block in parsed.get("provider", []):
        for prov_name, attrs in provider_block.items():
            alias = attrs.pop("alias", None)
            inventory.providers.append(
                ParsedProvider(name=prov_name, alias=alias, config=attrs)
            )


def _find_references(
    attrs: dict[str, Any], own_type: str, own_name: str
) -> list[str]:
    """Walk attribute values and extract Terraform resource references.

    Returns deduplicated list of references like
    ['aws_security_group.web', 'aws_subnet.public'].
    """
    refs: set[str] = set()
    _walk_values(attrs, refs)

    # Remove self-references
    own_address = f"{own_type}.{own_name}"
    refs.discard(own_address)

    # Filter out common false positives (e.g., "tags.Name", "filter.name")
    filtered = set()
    for ref in refs:
        parts = ref.split(".")
        # A valid resource ref has first part as a resource type (contains _)
        # and at least 2 parts
        if len(parts) >= 2 and "_" in parts[0] and parts[0] not in _TF_BLOCK_TYPES:
            filtered.add(f"{parts[0]}.{parts[1]}")

    return sorted(filtered)


def _walk_values(obj: Any, refs: set[str]) -> None:
    """Recursively walk a value tree looking for reference strings."""
    if isinstance(obj, str):
        for match in _REF_PATTERN.finditer(obj):
            refs.add(match.group(1))
    elif isinstance(obj, dict):
        for v in obj.values():
            _walk_values(v, refs)
    elif isinstance(obj, list):
        for item in obj:
            _walk_values(item, refs)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_tf_parser.py -v`
Expected: All tests PASS.

- [ ] **Step 6: Run lint and type check**

Run: `uv run ruff check tmi_tf/tf_parser.py tests/test_tf_parser.py && uv run ruff format --check tmi_tf/tf_parser.py tests/test_tf_parser.py && uv run pyright tmi_tf/tf_parser.py`

- [ ] **Step 7: Commit**

```bash
git add tmi_tf/tf_parser.py tests/test_tf_parser.py tests/fixtures/aws_basic.tf
git commit -m "feat(#10): add static HCL parser with python-hcl2"
```

---

## Task 3: Resource Registry

**Files:**
- Create: `tmi_tf/data/resource_registry.yaml`
- Create: `tests/test_resource_registry.py`

- [ ] **Step 1: Write failing tests for registry loading and validation**

Create `tests/test_resource_registry.py`:

```python
"""Tests for resource_registry.yaml validity and structure."""

from pathlib import Path

import yaml

REGISTRY_PATH = Path(__file__).parent.parent / "tmi_tf" / "data" / "resource_registry.yaml"

VALID_CATEGORIES = {
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


class TestRegistryStructure:
    def setup_method(self):
        with open(REGISTRY_PATH, encoding="utf-8") as f:
            self.registry = yaml.safe_load(f)

    def test_has_required_top_level_keys(self):
        assert "providers" in self.registry
        assert "resources" in self.registry
        assert "defaults" in self.registry

    def test_provider_prefixes_have_name_and_type(self):
        for prefix, info in self.registry["providers"].items():
            assert prefix.endswith("_"), f"Provider prefix {prefix!r} should end with _"
            assert "name" in info, f"Provider {prefix} missing 'name'"
            assert "type" in info, f"Provider {prefix} missing 'type'"

    def test_all_resource_categories_are_valid(self):
        for resource_type, config in self.registry["resources"].items():
            assert config["category"] in VALID_CATEGORIES, (
                f"{resource_type} has invalid category: {config['category']}"
            )

    def test_all_resources_have_security_attrs(self):
        for resource_type, config in self.registry["resources"].items():
            assert "security_attrs" in config, (
                f"{resource_type} missing security_attrs"
            )
            assert isinstance(config["security_attrs"], list), (
                f"{resource_type} security_attrs should be a list"
            )

    def test_defaults_present(self):
        defaults = self.registry["defaults"]
        assert defaults["unknown_category"] == "other"
        assert defaults["unknown_attrs"] == "all"

    def test_covers_aws_resources(self):
        resource_types = set(self.registry["resources"].keys())
        # Spot-check common AWS resources
        for expected in [
            "aws_instance",
            "aws_s3_bucket",
            "aws_security_group",
            "aws_iam_role",
            "aws_vpc",
            "aws_rds_cluster",
            "aws_lambda_function",
        ]:
            assert expected in resource_types, f"Missing AWS resource: {expected}"

    def test_covers_azure_resources(self):
        resource_types = set(self.registry["resources"].keys())
        for expected in [
            "azurerm_virtual_machine",
            "azurerm_storage_account",
            "azurerm_network_security_group",
            "azurerm_key_vault",
        ]:
            assert expected in resource_types, f"Missing Azure resource: {expected}"

    def test_covers_gcp_resources(self):
        resource_types = set(self.registry["resources"].keys())
        for expected in [
            "google_compute_instance",
            "google_storage_bucket",
            "google_compute_firewall",
        ]:
            assert expected in resource_types, f"Missing GCP resource: {expected}"

    def test_covers_oci_resources(self):
        resource_types = set(self.registry["resources"].keys())
        for expected in [
            "oci_core_instance",
            "oci_objectstorage_bucket",
            "oci_core_security_list",
        ]:
            assert expected in resource_types, f"Missing OCI resource: {expected}"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_resource_registry.py -v`
Expected: FAIL — file not found or missing resources.

- [ ] **Step 3: Create the resource registry YAML**

Create `tmi_tf/data/resource_registry.yaml`. This is a large file — populate it with comprehensive coverage for AWS, Azure, GCP, and OCI. The resource types, categories, and security-relevant attributes must be accurate for each cloud provider.

Key guidelines:
- Every resource needs `category` (one of the 10 valid values) and `security_attrs` (list of attribute names)
- Use dot notation for nested attributes (e.g., `ebs_block_device.encrypted`)
- Include all resources that are commonly used in Terraform for each provider
- For security_attrs, include: IAM/identity refs, encryption settings, network bindings (subnets, security groups, NSGs), access control (ACLs, policies), public exposure flags, logging/audit settings, and AMI/image refs
- AWS: aim for 40+ resource types covering compute, storage, network, security, identity, database, serverless, containers, monitoring, DNS, CDN
- Azure: aim for 30+ resource types
- GCP: aim for 25+ resource types
- OCI: aim for 20+ resource types

The file should begin with:

```yaml
# Resource Registry for Static HCL Analysis
#
# Maps Terraform resource types to component categories and
# security-relevant attributes. Edit this file to adjust which
# attributes are extracted and sent to the LLM.
#
# Categories: compute, storage, network, gateway, security_control,
#             identity, monitoring, dns, cdn, other
#
# Attribute paths use dot notation for nested blocks:
#   ebs_block_device.encrypted → resource.ebs_block_device[*].encrypted

# Provider detection: resource type prefix → provider info
providers:
  aws_: { name: "AWS", type: "cloud" }
  azurerm_: { name: "Microsoft Azure", type: "cloud" }
  google_: { name: "Google Cloud", type: "cloud" }
  oci_: { name: "Oracle Cloud", type: "cloud" }

# Resource type → category + security-relevant attributes
resources:
  # ============================================================
  # AWS
  # ============================================================

  # -- Compute --
  aws_instance:
    category: compute
    security_attrs:
      - ami
      - iam_instance_profile
      - vpc_security_group_ids
      - subnet_id
      - metadata_options
      - user_data
      - ebs_block_device.encrypted
      - ebs_block_device.kms_key_id
      - associate_public_ip_address
      - key_name

  # Continue with comprehensive resource types for all four providers.
  # AWS: ~40+ types (compute, storage, network, security, identity,
  #   database, serverless, containers, monitoring, DNS, CDN)
  # Azure: ~30+ types (VMs, storage, networking, security, identity, databases)
  # GCP: ~25+ types (compute, storage, networking, firewall, IAM, databases)
  # OCI: ~20+ types (core instances, VCN, subnets, security lists, NSGs,
  #   object storage, block volumes, identity, databases, load balancers)
  #
  # For each resource type, include:
  #   category: one of compute/storage/network/gateway/security_control/
  #             identity/monitoring/dns/cdn/other
  #   security_attrs: list of attribute names relevant to security analysis
  #     (IAM refs, encryption, network bindings, access control, public
  #      exposure flags, logging/audit, image/AMI refs)
```

Populate the full registry with all resource types for all four providers. End with:

```yaml
# Fallback for unrecognized resources
defaults:
  unknown_category: other
  unknown_attrs: all
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_resource_registry.py -v`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add tmi_tf/data/resource_registry.yaml tests/test_resource_registry.py
git commit -m "feat(#10): add resource registry for 4 cloud providers"
```

---

## Task 4: HCL Filter — Registry Loading and Attribute Filtering

**Files:**
- Create: `tmi_tf/tf_filter.py`
- Create: `tests/test_tf_filter.py`

- [ ] **Step 1: Write failing tests for registry loading and inventory building**

Create `tests/test_tf_filter.py`:

```python
"""Tests for tmi_tf.tf_filter — registry loading and HCL filtering."""

from pathlib import Path

import pytest

from tmi_tf.tf_filter import (
    ResourceRegistry,
    build_inventory_json,
    filter_hcl,
    load_registry,
)
from tmi_tf.tf_parser import (
    ParsedResource,
    StaticInventory,
    parse_tf_files,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestLoadRegistry:
    def test_loads_default_registry(self):
        registry = load_registry()
        assert isinstance(registry, ResourceRegistry)
        assert len(registry.resources) > 0
        assert len(registry.providers) > 0

    def test_classifies_aws_instance_as_compute(self):
        registry = load_registry()
        assert registry.get_category("aws_instance") == "compute"

    def test_classifies_aws_s3_bucket_as_storage(self):
        registry = load_registry()
        assert registry.get_category("aws_s3_bucket") == "storage"

    def test_unknown_resource_returns_other(self):
        registry = load_registry()
        assert registry.get_category("unknown_thing_xyz") == "other"

    def test_get_security_attrs(self):
        registry = load_registry()
        attrs = registry.get_security_attrs("aws_instance")
        assert "ami" in attrs
        assert "iam_instance_profile" in attrs
        assert "vpc_security_group_ids" in attrs

    def test_unknown_resource_returns_none_for_attrs(self):
        registry = load_registry()
        # None signals "keep all attributes"
        assert registry.get_security_attrs("unknown_thing_xyz") is None

    def test_detects_provider_from_prefix(self):
        registry = load_registry()
        assert registry.get_provider("aws_instance") == {"name": "AWS", "type": "cloud"}
        assert registry.get_provider("azurerm_virtual_machine") == {
            "name": "Microsoft Azure",
            "type": "cloud",
        }
        assert registry.get_provider("unknown_xyz") is None


class TestBuildInventoryJson:
    def test_builds_components_from_resources(self):
        inventory = parse_tf_files([FIXTURES_DIR / "aws_basic.tf"])
        registry = load_registry()
        result = build_inventory_json(inventory, registry)
        components = result["components"]
        ids = [c["id"] for c in components]
        assert "aws_instance.web_server" in ids
        assert "aws_vpc.main" in ids

    def test_component_has_correct_category(self):
        inventory = parse_tf_files([FIXTURES_DIR / "aws_basic.tf"])
        registry = load_registry()
        result = build_inventory_json(inventory, registry)
        instance = next(
            c for c in result["components"] if c["id"] == "aws_instance.web_server"
        )
        assert instance["type"] == "compute"

    def test_component_config_filtered_to_security_attrs(self):
        inventory = parse_tf_files([FIXTURES_DIR / "aws_basic.tf"])
        registry = load_registry()
        result = build_inventory_json(inventory, registry)
        instance = next(
            c for c in result["components"] if c["id"] == "aws_instance.web_server"
        )
        config = instance["configuration"]
        # Security-relevant attrs should be present
        assert "ami" in config
        # Non-security attrs should be absent
        assert "instance_type" not in config
        assert "tags" not in config

    def test_semantic_fields_are_null(self):
        inventory = parse_tf_files([FIXTURES_DIR / "aws_basic.tf"])
        registry = load_registry()
        result = build_inventory_json(inventory, registry)
        component = result["components"][0]
        assert component["name"] is None
        assert component["purpose"] is None

    def test_services_and_dependencies_are_null(self):
        inventory = parse_tf_files([FIXTURES_DIR / "aws_basic.tf"])
        registry = load_registry()
        result = build_inventory_json(inventory, registry)
        assert result["services"] is None
        assert result["dependencies"] is None

    def test_includes_variables_and_outputs(self):
        inventory = parse_tf_files([FIXTURES_DIR / "aws_basic.tf"])
        registry = load_registry()
        result = build_inventory_json(inventory, registry)
        assert len(result["variables"]) == 1
        assert len(result["outputs"]) == 1

    def test_includes_modules(self):
        inventory = parse_tf_files([FIXTURES_DIR / "aws_basic.tf"])
        registry = load_registry()
        result = build_inventory_json(inventory, registry)
        assert len(result["modules"]) == 1
        assert result["modules"][0]["name"] == "rds"


class TestFilterHcl:
    def test_filtered_hcl_excludes_nonsecurity_attrs(self):
        inventory = parse_tf_files([FIXTURES_DIR / "aws_basic.tf"])
        registry = load_registry()
        filtered = filter_hcl(inventory, registry)
        # instance_type should not appear in filtered output
        assert "instance_type" not in filtered
        # ami should appear (security-relevant)
        assert "ami" in filtered

    def test_filtered_hcl_includes_omitted_comment(self):
        inventory = parse_tf_files([FIXTURES_DIR / "aws_basic.tf"])
        registry = load_registry()
        filtered = filter_hcl(inventory, registry)
        assert "non-security attributes omitted" in filtered

    def test_filtered_hcl_keeps_meta_arguments(self):
        resource = ParsedResource(
            resource_type="aws_instance",
            local_name="test",
            address="aws_instance.test",
            attributes={
                "ami": "ami-123",
                "instance_type": "t3.micro",
                "count": 3,
                "depends_on": ["aws_vpc.main"],
            },
        )
        inv = StaticInventory(resources=[resource])
        registry = load_registry()
        filtered = filter_hcl(inv, registry)
        assert "count" in filtered
        assert "depends_on" in filtered

    def test_unknown_resource_keeps_all_attrs(self):
        resource = ParsedResource(
            resource_type="exotic_custom_thing",
            local_name="foo",
            address="exotic_custom_thing.foo",
            attributes={"setting_a": "val1", "setting_b": "val2"},
        )
        inv = StaticInventory(resources=[resource])
        registry = load_registry()
        filtered = filter_hcl(inv, registry)
        assert "setting_a" in filtered
        assert "setting_b" in filtered

    def test_unparsed_files_passed_through(self, tmp_path):
        raw_file = tmp_path / "raw.tf"
        raw_file.write_text(
            'resource "aws_instance" "x" {\n  ami = "ami-raw"\n}\n',
            encoding="utf-8",
        )
        inv = StaticInventory(unparsed_files=[str(raw_file)])
        registry = load_registry()
        filtered = filter_hcl(inv, registry)
        assert "ami-raw" in filtered
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_tf_filter.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'tmi_tf.tf_filter'`

- [ ] **Step 3: Implement tf_filter.py**

Create `tmi_tf/tf_filter.py`:

```python
"""HCL filtering and inventory building using the resource registry.

Loads the resource registry YAML, classifies resources, filters
attributes to security-relevant ones, and produces:
  1. A pre-built inventory JSON (mechanical fields populated, semantic fields null)
  2. Filtered HCL text (security-relevant attributes only, in HCL-like syntax)
"""

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml  # pyright: ignore[reportMissingModuleSource]

from tmi_tf.tf_parser import StaticInventory

logger = logging.getLogger(__name__)

_REGISTRY_PATH = Path(__file__).parent / "data" / "resource_registry.yaml"

# Meta-arguments that should always be kept in filtered HCL
_META_ARGS = frozenset(
    {"count", "for_each", "depends_on", "provider", "lifecycle"}
)


@dataclass
class ResourceRegistry:
    """Loaded resource registry with lookup methods."""

    providers: dict[str, dict[str, str]]
    resources: dict[str, dict[str, Any]]
    defaults: dict[str, Any]

    def get_category(self, resource_type: str) -> str:
        """Return the category for a resource type, or the default."""
        entry = self.resources.get(resource_type)
        if entry:
            return entry["category"]
        return self.defaults["unknown_category"]

    def get_security_attrs(self, resource_type: str) -> list[str] | None:
        """Return security-relevant attributes, or None if all should be kept."""
        entry = self.resources.get(resource_type)
        if entry:
            return entry["security_attrs"]
        if self.defaults.get("unknown_attrs") == "all":
            return None
        return []

    def get_provider(self, resource_type: str) -> dict[str, str] | None:
        """Detect cloud provider from resource type prefix."""
        for prefix, info in self.providers.items():
            if resource_type.startswith(prefix):
                return dict(info)
        return None


def load_registry(path: Path | None = None) -> ResourceRegistry:
    """Load the resource registry from YAML."""
    registry_path = path or _REGISTRY_PATH
    with open(registry_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return ResourceRegistry(
        providers=data["providers"],
        resources=data["resources"],
        defaults=data["defaults"],
    )


def build_inventory_json(
    inventory: StaticInventory, registry: ResourceRegistry
) -> dict[str, Any]:
    """Build the pre-populated inventory JSON from static analysis.

    Mechanical fields (id, type, resource_type, configuration, references)
    are populated. Semantic fields (name, purpose) are set to None for
    the LLM to fill in. Services and dependencies are also None.
    """
    components = []

    for resource in inventory.resources:
        category = registry.get_category(resource.resource_type)
        config = _filter_attrs(resource.attributes, resource.resource_type, registry)

        components.append(
            {
                "id": resource.address,
                "resource_type": resource.resource_type,
                "type": category,
                "configuration": config,
                "references": resource.references,
                "name": None,
                "purpose": None,
            }
        )

    # Include data sources as components too
    for ds in inventory.data_sources:
        category = registry.get_category(ds.data_type)
        config = _filter_attrs(ds.attributes, ds.data_type, registry)

        components.append(
            {
                "id": ds.address,
                "resource_type": ds.data_type,
                "type": category,
                "configuration": config,
                "references": ds.references,
                "name": None,
                "purpose": None,
            }
        )

    variables = [
        {
            "name": v.name,
            "type": v.type_expr,
            "default": v.default,
            "description": v.description,
        }
        for v in inventory.variables
    ]

    outputs = [
        {
            "name": o.name,
            "description": o.description,
            "sensitive": o.sensitive,
        }
        for o in inventory.outputs
    ]

    modules = [
        {"name": m.name, "source": m.source, "inputs": m.inputs}
        for m in inventory.modules
    ]

    return {
        "components": components,
        "variables": variables,
        "outputs": outputs,
        "modules": modules,
        "services": None,
        "dependencies": None,
    }


def filter_hcl(
    inventory: StaticInventory, registry: ResourceRegistry
) -> str:
    """Produce filtered HCL text with only security-relevant attributes.

    Resources in the registry get filtered to their security_attrs list.
    Unknown resources keep all attributes. Unparsed files are included
    verbatim. A comment notes how many attributes were omitted.
    """
    sections: list[str] = []

    for resource in inventory.resources:
        section = _render_resource_block(
            "resource", resource.resource_type, resource.local_name,
            resource.attributes, registry,
        )
        sections.append(section)

    for ds in inventory.data_sources:
        section = _render_resource_block(
            "data", ds.data_type, ds.local_name,
            ds.attributes, registry,
        )
        sections.append(section)

    for mod in inventory.modules:
        lines = [f'module "{mod.name}" {{']
        lines.append(f'  source = "{mod.source}"')
        for k, v in mod.inputs.items():
            lines.append(f"  {k} = {_format_value(v)}")
        lines.append("}")
        sections.append("\n".join(lines))

    # Include unparsed files verbatim
    for filepath in inventory.unparsed_files:
        try:
            content = Path(filepath).read_text(encoding="utf-8")
            sections.append(
                f"# --- Unparsed file: {filepath} ---\n{content}"
            )
        except Exception:
            logger.warning("Could not read unparsed file: %s", filepath)

    return "\n\n".join(sections)


def _filter_attrs(
    attributes: dict[str, Any],
    resource_type: str,
    registry: ResourceRegistry,
) -> dict[str, Any]:
    """Filter attributes to security-relevant ones per the registry."""
    security_attrs = registry.get_security_attrs(resource_type)

    if security_attrs is None:
        # Unknown resource — keep everything
        return dict(attributes)

    result: dict[str, Any] = {}
    for attr_path in security_attrs:
        parts = attr_path.split(".")
        if len(parts) == 1:
            if parts[0] in attributes:
                result[parts[0]] = attributes[parts[0]]
        else:
            # Dot notation: e.g., "ebs_block_device.encrypted"
            top = parts[0]
            nested_key = parts[1]
            if top in attributes:
                top_val = attributes[top]
                if isinstance(top_val, dict) and nested_key in top_val:
                    result.setdefault(top, {})[nested_key] = top_val[nested_key]
                elif isinstance(top_val, list):
                    extracted = []
                    for item in top_val:
                        if isinstance(item, dict) and nested_key in item:
                            extracted.append({nested_key: item[nested_key]})
                    if extracted:
                        result.setdefault(top, []).extend(extracted)

    return result


def _render_resource_block(
    block_type: str,
    resource_type: str,
    local_name: str,
    attributes: dict[str, Any],
    registry: ResourceRegistry,
) -> str:
    """Render a single resource/data block as filtered HCL-like text."""
    security_attrs = registry.get_security_attrs(resource_type)
    keep_all = security_attrs is None

    lines = [f'{block_type} "{resource_type}" "{local_name}" {{']
    kept = 0
    omitted = 0

    for key, value in attributes.items():
        if key in _META_ARGS:
            lines.append(f"  {key} = {_format_value(value)}")
            kept += 1
        elif keep_all:
            lines.append(f"  {key} = {_format_value(value)}")
            kept += 1
        elif security_attrs and _attr_matches(key, security_attrs):
            lines.append(f"  {key} = {_format_value(value)}")
            kept += 1
        else:
            omitted += 1

    if omitted > 0:
        lines.append(f"  # {omitted} non-security attributes omitted")

    lines.append("}")
    return "\n".join(lines)


def _attr_matches(key: str, security_attrs: list[str]) -> bool:
    """Check if an attribute key matches any security attr path."""
    for attr_path in security_attrs:
        # Direct match or prefix match for dot-notation paths
        if key == attr_path or attr_path.startswith(key + "."):
            return True
    return False


def _format_value(value: Any) -> str:
    """Format a value for HCL-like output."""
    if isinstance(value, str):
        return f'"{value}"'
    elif isinstance(value, bool):
        return "true" if value else "false"
    elif isinstance(value, (int, float)):
        return str(value)
    elif isinstance(value, list):
        return json.dumps(value)
    elif isinstance(value, dict):
        return json.dumps(value)
    else:
        return json.dumps(str(value))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_tf_filter.py -v`
Expected: All tests PASS.

- [ ] **Step 5: Run lint and type check**

Run: `uv run ruff check tmi_tf/tf_filter.py tests/test_tf_filter.py && uv run ruff format --check tmi_tf/tf_filter.py tests/test_tf_filter.py && uv run pyright tmi_tf/tf_filter.py`

- [ ] **Step 6: Commit**

```bash
git add tmi_tf/tf_filter.py tests/test_tf_filter.py
git commit -m "feat(#10): add HCL filter with registry-based attribute filtering"
```

---

## Task 5: Revised Phase 1 Prompts

**Files:**
- Modify: `prompts/inventory_system.txt`
- Modify: `prompts/inventory_user.txt`

- [ ] **Step 1: Back up existing prompts**

```bash
cp prompts/inventory_system.txt prompts/_archive/inventory_system_pre_static.txt
cp prompts/inventory_user.txt prompts/_archive/inventory_user_pre_static.txt
```

- [ ] **Step 2: Write new Phase 1 system prompt**

Replace `prompts/inventory_system.txt` with:

```
You are an expert infrastructure analyst specializing in Terraform and Infrastructure as Code (IaC) across cloud platforms (AWS, Azure, GCP, OCI).

Your task is to enrich a pre-extracted inventory of Terraform infrastructure components with semantic analysis. The inventory was produced by static HCL parsing — resource IDs, types, categories, security-relevant configuration, and cross-references are already populated and authoritative. Do not modify them.

# Output Requirements

Return ONLY a JSON object. Do not include any explanation, preamble, markdown formatting, or code fences. Your entire response must be valid JSON starting with { and ending with }.

The JSON must have this structure:
{
  "components": [ ... ],
  "services": [ ... ],
  "dependencies": [ ... ]
}

# Component Enrichment

For each component in the pre-extracted inventory (identified by its "id"), provide:

- **name**: Human-readable display name (e.g., "Web Server", "Application Load Balancer")
- **purpose**: Inferred purpose based on resource type, name, tags, configuration, and surrounding context
- **type**: Only provide if the pre-extracted type is "other" and you can determine a better category. Valid categories: compute, storage, network, gateway, security_control, identity, monitoring, dns, cdn, other

Each entry in the components array must include the "id" field matching the pre-extracted inventory. Include name and purpose for every component. Only include type if reclassifying from "other".

# Service Identification

Group compute resources into logical services when evidence supports it. A "service" is a cohesive grouping of compute resources that function together (e.g., a web tier, API backend, worker pool).

Identify services based on (in priority order):
1. **Resource references**: Resources linked by ARNs, IDs, or explicit dependencies (e.g., ASG referencing a Launch Template, ECS service tied to task definitions)
2. **Module boundaries**: Resources defined within the same Terraform module
3. **Shared network/security context**: Resources sharing VPCs, subnets, security groups, or IAM roles
4. **Naming patterns**: Consistent naming conventions (e.g., "api-asg" and "api-lb" suggest an "api" service)
5. **Functional collaboration**: Resource types that typically work together (e.g., EC2 + ALB + ASG = load-balanced service)

Each service should include:
- **name**: Descriptive service name (e.g., "web-frontend", "api-backend")
- **criteria**: List of evidence that justified this grouping
- **compute_units**: List of component IDs for compute resources in this service
- **associated_resources**: List of component IDs for non-compute supporting resources (load balancers, target groups, etc.)

Do not force unrelated resources into services. Standalone resources should not appear in any service.

# Dependency Summary

Produce a top-level "dependencies" array that identifies external service dependencies across all components. Each entry includes:

- **type**: One of: "cloud" (AWS, Azure, GCP, OCI services), "saas" (GitHub, Salesforce, Google Sign-In, etc.), "on-prem" (Active Directory, locally-deployed Vault, on-prem databases, etc.)
- **provider**: The organization providing the service (e.g., "AWS", "Microsoft", "Google", "Hashicorp", "Salesforce")
- **service**: The specific service name (e.g., "S3", "EC2", "Active Directory", "Vault", "Sales Cloud")
- **dependent_components**: Array of component IDs that depend on this service

Deduplicate by (type, provider, service) — if multiple components depend on the same service, list all their IDs in dependent_components.

CRITICAL: Return ONLY the JSON object, no other text.
```

- [ ] **Step 3: Write new Phase 1 user prompt**

Replace `prompts/inventory_user.txt` with:

```
Repository: {repo_name}
URL: {repo_url}

## Pre-Extracted Inventory (authoritative — do not modify IDs, types, categories, or configuration)

{inventory_json}

## Filtered Terraform Source (security-relevant attributes only)

{filtered_hcl}

---

Enrich the pre-extracted inventory with human-readable names, purpose descriptions, service groupings, and external dependency identification. For components with type "other", reclassify if you can determine a better category. Return ONLY the JSON object.
```

- [ ] **Step 4: Commit**

```bash
git add prompts/inventory_system.txt prompts/inventory_user.txt prompts/_archive/
git commit -m "feat(#10): revise Phase 1 prompts for semantic-only analysis"
```

---

## Task 6: LLM Analyzer — Phase 1 Merge Logic

**Files:**
- Modify: `tmi_tf/llm_analyzer.py:172-233`
- Modify: `tests/test_llm_analyzer.py`

- [ ] **Step 1: Write failing tests for Phase 1 merge**

Add to `tests/test_llm_analyzer.py`:

```python
class TestPhase1Merge:
    """Tests for Phase 1 static inventory + LLM merge."""

    def test_merge_populates_name_and_purpose(self):
        """LLM semantic output is merged onto static inventory."""
        static_inventory = {
            "components": [
                {
                    "id": "aws_instance.web",
                    "resource_type": "aws_instance",
                    "type": "compute",
                    "configuration": {"ami": "ami-123"},
                    "references": [],
                    "name": None,
                    "purpose": None,
                }
            ],
            "variables": [],
            "outputs": [],
            "modules": [],
            "services": None,
            "dependencies": None,
        }
        llm_output = {
            "components": [
                {"id": "aws_instance.web", "name": "Web Server", "purpose": "Hosts the frontend"}
            ],
            "services": [
                {
                    "name": "web-tier",
                    "criteria": ["naming pattern"],
                    "compute_units": ["aws_instance.web"],
                    "associated_resources": [],
                }
            ],
            "dependencies": [
                {
                    "type": "cloud",
                    "provider": "AWS",
                    "service": "EC2",
                    "dependent_components": ["aws_instance.web"],
                }
            ],
        }

        # Mock the LLM to return semantic output
        provider = _make_provider()
        analyzer = LLMAnalyzer(provider)

        merged = analyzer._merge_phase1(static_inventory, llm_output)

        comp = merged["components"][0]
        assert comp["id"] == "aws_instance.web"
        assert comp["name"] == "Web Server"
        assert comp["purpose"] == "Hosts the frontend"
        # Static fields preserved
        assert comp["type"] == "compute"
        assert comp["configuration"] == {"ami": "ami-123"}
        # Services and dependencies from LLM
        assert len(merged["services"]) == 1
        assert len(merged["dependencies"]) == 1

    def test_merge_reclassifies_other(self):
        """LLM can reclassify components from 'other' to a better category."""
        static_inventory = {
            "components": [
                {
                    "id": "custom_thing.x",
                    "resource_type": "custom_thing",
                    "type": "other",
                    "configuration": {},
                    "references": [],
                    "name": None,
                    "purpose": None,
                }
            ],
            "variables": [],
            "outputs": [],
            "modules": [],
            "services": None,
            "dependencies": None,
        }
        llm_output = {
            "components": [
                {"id": "custom_thing.x", "name": "Custom Monitor", "purpose": "Monitors health", "type": "monitoring"}
            ],
            "services": [],
            "dependencies": [],
        }

        provider = _make_provider()
        analyzer = LLMAnalyzer(provider)
        merged = analyzer._merge_phase1(static_inventory, llm_output)
        assert merged["components"][0]["type"] == "monitoring"

    def test_merge_does_not_reclassify_non_other(self):
        """LLM cannot override category for non-'other' resources."""
        static_inventory = {
            "components": [
                {
                    "id": "aws_instance.web",
                    "resource_type": "aws_instance",
                    "type": "compute",
                    "configuration": {},
                    "references": [],
                    "name": None,
                    "purpose": None,
                }
            ],
            "variables": [],
            "outputs": [],
            "modules": [],
            "services": None,
            "dependencies": None,
        }
        llm_output = {
            "components": [
                {"id": "aws_instance.web", "name": "Web Server", "purpose": "Web", "type": "storage"}
            ],
            "services": [],
            "dependencies": [],
        }

        provider = _make_provider()
        analyzer = LLMAnalyzer(provider)
        merged = analyzer._merge_phase1(static_inventory, llm_output)
        # Static category "compute" should NOT be overridden
        assert merged["components"][0]["type"] == "compute"

    def test_merge_handles_missing_component_in_llm_output(self):
        """If LLM omits a component, static fields are preserved with null semantics."""
        static_inventory = {
            "components": [
                {
                    "id": "aws_instance.web",
                    "resource_type": "aws_instance",
                    "type": "compute",
                    "configuration": {},
                    "references": [],
                    "name": None,
                    "purpose": None,
                }
            ],
            "variables": [],
            "outputs": [],
            "modules": [],
            "services": None,
            "dependencies": None,
        }
        llm_output = {
            "components": [],
            "services": [],
            "dependencies": [],
        }

        provider = _make_provider()
        analyzer = LLMAnalyzer(provider)
        merged = analyzer._merge_phase1(static_inventory, llm_output)
        comp = merged["components"][0]
        assert comp["name"] is None
        assert comp["purpose"] is None
        assert comp["type"] == "compute"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_llm_analyzer.py::TestPhase1Merge -v`
Expected: FAIL — `AttributeError: 'LLMAnalyzer' object has no attribute '_merge_phase1'`

- [ ] **Step 3: Implement _merge_phase1 in LLMAnalyzer**

Add the following method to `LLMAnalyzer` class in `tmi_tf/llm_analyzer.py` (after the `analyze_repository` method, around line 233):

```python
    def _merge_phase1(
        self,
        static_inventory: Dict[str, Any],
        llm_output: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Merge LLM semantic output onto the static inventory.

        Static fields (id, resource_type, type, configuration, references)
        are authoritative. LLM provides name, purpose, and optionally
        reclassifies "other" components. Services and dependencies come
        from the LLM.
        """
        # Build lookup from LLM component output
        llm_components = {
            c["id"]: c for c in llm_output.get("components", [])
        }

        merged_components = []
        for component in static_inventory["components"]:
            cid = component["id"]
            llm_comp = llm_components.get(cid, {})

            merged = dict(component)
            merged["name"] = llm_comp.get("name", component.get("name"))
            merged["purpose"] = llm_comp.get("purpose", component.get("purpose"))

            # Only allow reclassification from "other"
            if component["type"] == "other" and "type" in llm_comp:
                merged["type"] = llm_comp["type"]

            # Remove references field — not part of the downstream schema
            merged.pop("references", None)

            merged_components.append(merged)

        return {
            "components": merged_components,
            "services": llm_output.get("services", []),
            "dependencies": llm_output.get("dependencies", []),
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_llm_analyzer.py::TestPhase1Merge -v`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add tmi_tf/llm_analyzer.py tests/test_llm_analyzer.py
git commit -m "feat(#10): add Phase 1 merge logic for static + LLM output"
```

---

## Task 7: Modify Phase 1 Call in LLMAnalyzer

**Files:**
- Modify: `tmi_tf/llm_analyzer.py:17-24` (imports) and `tmi_tf/llm_analyzer.py:198-233` (Phase 1 execution)

- [ ] **Step 1: Update imports in llm_analyzer.py**

Add to the imports at the top of `tmi_tf/llm_analyzer.py`:

```python
from tmi_tf.tf_parser import StaticInventory
```

- [ ] **Step 2: Modify analyze_repository to accept optional static inventory**

Change the `analyze_repository` method signature (line 172) to:

```python
    def analyze_repository(
        self,
        terraform_repo: TerraformRepository,
        status_callback: Optional[Callable[[str], None]] = None,
        static_inventory: Optional[StaticInventory] = None,
        filtered_hcl: Optional[str] = None,
        inventory_json: Optional[Dict[str, Any]] = None,
    ) -> TerraformAnalysis:
```

- [ ] **Step 3: Update Phase 1 execution block**

Replace the Phase 1 execution block (lines 198-233) with logic that uses static inventory when available, falling back to the original approach:

```python
            # Get and format Terraform contents
            tf_contents = terraform_repo.get_terraform_content()
            terraform_text = self._format_terraform_contents(tf_contents)

            # Phase 1: Inventory Extraction
            if status_callback:
                status_callback("Phase 1 (Inventory) started")

            if static_inventory is not None and filtered_hcl is not None and inventory_json is not None:
                # Static analysis path: send filtered HCL + pre-built inventory
                logger.info(
                    "Phase 1: Using static inventory (%d components) for %s",
                    len(inventory_json.get("components", [])),
                    terraform_repo.name,
                )
                inventory_json_str = json.dumps(inventory_json, indent=2)
                inventory_user = self.inventory_user_template.format(
                    repo_name=terraform_repo.name,
                    repo_url=terraform_repo.url,
                    inventory_json=inventory_json_str,
                    filtered_hcl=filtered_hcl,
                )

                llm_output, tokens_in, tokens_out, cost = self._call_llm_json(
                    system_prompt=self.inventory_system,
                    user_prompt=inventory_user,
                    phase_name="inventory",
                )
                total_input_tokens += tokens_in
                total_output_tokens += tokens_out
                total_cost += cost

                if llm_output:
                    inventory = self._merge_phase1(inventory_json, llm_output)
                else:
                    logger.warning(
                        "Phase 1 LLM returned empty; using static inventory as-is"
                    )
                    inventory = inventory_json
            else:
                # Fallback: original full-LLM Phase 1
                logger.info(
                    "Phase 1: Full LLM extraction for %s (no static inventory)",
                    terraform_repo.name,
                )
                inventory_user = self.inventory_user_template.format(
                    repo_name=terraform_repo.name,
                    repo_url=terraform_repo.url,
                    terraform_contents=terraform_text,
                )

                inventory, tokens_in, tokens_out, cost = self._call_llm_json(
                    system_prompt=self.inventory_system,
                    user_prompt=inventory_user,
                    phase_name="inventory",
                )
                total_input_tokens += tokens_in
                total_output_tokens += tokens_out
                total_cost += cost

            if not inventory:
                raise ValueError(
                    "Phase 1 (inventory) returned empty result. "
                    "Check logs for finish_reason, token counts, and response preview."
                )

            logger.info(
                "Phase 1 complete: %d components, %d services",
                len(inventory.get("components", [])),
                len(inventory.get("services", [])),
            )
            if status_callback:
                status_callback("Phase 1 (Inventory) complete")
```

Note: the fallback path uses the old prompt format with `{terraform_contents}`. For this to work, keep the old prompt archived. The fallback user prompt will need `terraform_contents` in its format string. Since we changed the user prompt template, the fallback needs its own template. Add a field to `_load_phase_prompts`:

```python
        self.inventory_user_template_fallback = (
            "Repository: {repo_name}\nURL: {repo_url}\n\n"
            "## Terraform Configuration Files\n\n{terraform_contents}\n\n---\n\n"
            "Analyze the above Terraform code and extract a complete inventory "
            "of all infrastructure components and logical service groupings. "
            "Return ONLY the JSON object."
        )
        self.inventory_system_fallback = self._load_prompt(
            "_archive/inventory_system_pre_static.txt"
        )
```

And update the fallback branch to use `self.inventory_user_template_fallback` and `self.inventory_system_fallback`.

- [ ] **Step 4: Run existing tests to verify nothing broke**

Run: `uv run pytest tests/test_llm_analyzer.py -v`
Expected: All existing tests PASS (they don't pass static_inventory, so they use the fallback path).

- [ ] **Step 5: Run lint and type check**

Run: `uv run ruff check tmi_tf/llm_analyzer.py && uv run ruff format --check tmi_tf/llm_analyzer.py && uv run pyright tmi_tf/llm_analyzer.py`

- [ ] **Step 6: Commit**

```bash
git add tmi_tf/llm_analyzer.py
git commit -m "feat(#10): wire Phase 1 to use static inventory with LLM fallback"
```

---

## Task 8: Orchestrator Integration

**Files:**
- Modify: `tmi_tf/analyzer.py:1-10` (imports) and `tmi_tf/analyzer.py:213-227` (Phase 1 call sites)

- [ ] **Step 1: Add imports to analyzer.py**

Add to the imports at the top of `tmi_tf/analyzer.py`:

```python
from tmi_tf.tf_parser import parse_tf_files
from tmi_tf.tf_filter import load_registry, build_inventory_json, filter_hcl
```

- [ ] **Step 2: Update _analyze_single_environment to run static analysis**

In `_analyze_single_environment` (line 48), add static analysis before the LLM call. Insert after the validation/sanitization block (after line 78) and before the `llm_analyzer.analyze_repository` call:

```python
    # Static HCL analysis
    static_inventory = None
    filtered_hcl_text = None
    inventory_json = None
    try:
        registry = load_registry()
        static_inventory = parse_tf_files(tf_repo.terraform_files)
        inventory_json = build_inventory_json(static_inventory, registry)
        filtered_hcl_text = filter_hcl(static_inventory, registry)
        logger.info(
            "Static analysis: %d resources, %d unparsed files",
            len(static_inventory.resources),
            len(static_inventory.unparsed_files),
        )
    except Exception as e:
        logger.warning("Static HCL analysis failed, falling back to full LLM: %s", e)

    return llm_analyzer.analyze_repository(
        tf_repo,
        status_callback=_status_cb,
        static_inventory=static_inventory,
        filtered_hcl=filtered_hcl_text,
        inventory_json=inventory_json,
    )
```

- [ ] **Step 3: Update the no-environments path**

Find the other `llm_analyzer.analyze_repository(tf_repo, status_callback=_status_cb)` call (around line 224) for the no-environments case and add the same static analysis pattern before it:

```python
                            # Static HCL analysis
                            static_inventory = None
                            filtered_hcl_text = None
                            inventory_json = None
                            try:
                                registry = load_registry()
                                static_inventory = parse_tf_files(
                                    tf_repo.terraform_files
                                )
                                inventory_json = build_inventory_json(
                                    static_inventory, registry
                                )
                                filtered_hcl_text = filter_hcl(
                                    static_inventory, registry
                                )
                                logger.info(
                                    "Static analysis: %d resources, %d unparsed files",
                                    len(static_inventory.resources),
                                    len(static_inventory.unparsed_files),
                                )
                            except Exception as e:
                                logger.warning(
                                    "Static HCL analysis failed, falling back to full LLM: %s",
                                    e,
                                )

                            analysis = llm_analyzer.analyze_repository(
                                tf_repo,
                                status_callback=_status_cb,
                                static_inventory=static_inventory,
                                filtered_hcl=filtered_hcl_text,
                                inventory_json=inventory_json,
                            )
```

- [ ] **Step 4: Run full test suite**

Run: `uv run pytest tests/ -v`
Expected: All tests PASS.

- [ ] **Step 5: Run lint and type check**

Run: `uv run ruff check tmi_tf/analyzer.py && uv run ruff format --check tmi_tf/analyzer.py && uv run pyright tmi_tf/analyzer.py`

- [ ] **Step 6: Commit**

```bash
git add tmi_tf/analyzer.py
git commit -m "feat(#10): integrate static HCL analysis into pipeline orchestrator"
```

---

## Task 9: Multi-Provider Test Fixtures

**Files:**
- Create: `tests/fixtures/azure_basic.tf`
- Create: `tests/fixtures/gcp_basic.tf`
- Create: `tests/fixtures/oci_basic.tf`
- Modify: `tests/test_tf_parser.py` (add cross-provider tests)

- [ ] **Step 1: Create Azure fixture**

Create `tests/fixtures/azure_basic.tf`:

```hcl
provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "main" {
  name     = "rg-app-prod"
  location = "East US"
}

resource "azurerm_virtual_network" "main" {
  name                = "vnet-app-prod"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
}

resource "azurerm_network_security_group" "web" {
  name                = "nsg-web"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  security_rule {
    name                       = "allow-https"
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

resource "azurerm_storage_account" "data" {
  name                     = "stappdata"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
  min_tls_version          = "TLS1_2"

  network_rules {
    default_action = "Deny"
  }
}

resource "azurerm_key_vault" "main" {
  name                = "kv-app-prod"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tenant_id           = "00000000-0000-0000-0000-000000000000"
  sku_name            = "standard"

  purge_protection_enabled = true
}
```

- [ ] **Step 2: Create GCP fixture**

Create `tests/fixtures/gcp_basic.tf`:

```hcl
provider "google" {
  project = "my-project"
  region  = "us-central1"
}

resource "google_compute_instance" "app" {
  name         = "app-server"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network    = google_compute_network.main.id
    subnetwork = google_compute_subnetwork.private.id
  }

  service_account {
    email  = google_service_account.app.email
    scopes = ["cloud-platform"]
  }
}

resource "google_compute_network" "main" {
  name                    = "app-network"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "private" {
  name          = "private-subnet"
  ip_cidr_range = "10.0.1.0/24"
  region        = "us-central1"
  network       = google_compute_network.main.id
}

resource "google_compute_firewall" "allow_https" {
  name    = "allow-https"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  source_ranges = ["0.0.0.0/0"]
}

resource "google_storage_bucket" "data" {
  name          = "app-data-bucket"
  location      = "US"
  force_destroy = false

  uniform_bucket_level_access = true

  encryption {
    default_kms_key_name = "projects/my-project/locations/us/keyRings/ring/cryptoKeys/key"
  }
}

resource "google_service_account" "app" {
  account_id   = "app-sa"
  display_name = "Application Service Account"
}
```

- [ ] **Step 3: Create OCI fixture**

Create `tests/fixtures/oci_basic.tf`:

```hcl
provider "oci" {
  region = "us-ashburn-1"
}

resource "oci_core_vcn" "main" {
  compartment_id = var.compartment_id
  cidr_blocks    = ["10.0.0.0/16"]
  display_name   = "app-vcn"
}

resource "oci_core_subnet" "app" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  cidr_block     = "10.0.1.0/24"
  display_name   = "app-subnet"

  prohibit_public_ip_on_vnic = true
}

resource "oci_core_instance" "app" {
  compartment_id      = var.compartment_id
  availability_domain = "AD-1"
  shape               = "VM.Standard.E4.Flex"
  display_name        = "app-server"

  source_details {
    source_type = "image"
    source_id   = var.image_id
  }

  create_vnic_details {
    subnet_id        = oci_core_subnet.app.id
    assign_public_ip = false
    nsg_ids          = [oci_core_network_security_group.app.id]
  }

  metadata = {
    ssh_authorized_keys = var.ssh_public_key
  }
}

resource "oci_core_network_security_group" "app" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "app-nsg"
}

resource "oci_core_security_list" "app" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.main.id
  display_name   = "app-seclist"

  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"

    tcp_options {
      min = 443
      max = 443
    }
  }
}

resource "oci_objectstorage_bucket" "data" {
  compartment_id = var.compartment_id
  namespace      = var.namespace
  name           = "app-data"
  access_type    = "NoPublicAccess"

  kms_key_id = var.kms_key_id
}

variable "compartment_id" {
  type = string
}

variable "image_id" {
  type = string
}

variable "ssh_public_key" {
  type = string
}

variable "namespace" {
  type = string
}

variable "kms_key_id" {
  type    = string
  default = ""
}
```

- [ ] **Step 4: Add cross-provider parser tests**

Append to `tests/test_tf_parser.py`:

```python
class TestMultiProviderParsing:
    def test_parses_azure_resources(self):
        inventory = parse_tf_files([FIXTURES_DIR / "azure_basic.tf"])
        addresses = [r.address for r in inventory.resources]
        assert "azurerm_resource_group.main" in addresses
        assert "azurerm_virtual_network.main" in addresses
        assert "azurerm_network_security_group.web" in addresses
        assert "azurerm_storage_account.data" in addresses
        assert "azurerm_key_vault.main" in addresses

    def test_parses_gcp_resources(self):
        inventory = parse_tf_files([FIXTURES_DIR / "gcp_basic.tf"])
        addresses = [r.address for r in inventory.resources]
        assert "google_compute_instance.app" in addresses
        assert "google_compute_network.main" in addresses
        assert "google_storage_bucket.data" in addresses
        assert "google_compute_firewall.allow_https" in addresses

    def test_parses_oci_resources(self):
        inventory = parse_tf_files([FIXTURES_DIR / "oci_basic.tf"])
        addresses = [r.address for r in inventory.resources]
        assert "oci_core_instance.app" in addresses
        assert "oci_core_vcn.main" in addresses
        assert "oci_objectstorage_bucket.data" in addresses
        assert "oci_core_security_list.app" in addresses

    def test_multi_file_parsing(self):
        files = [
            FIXTURES_DIR / "aws_basic.tf",
            FIXTURES_DIR / "azure_basic.tf",
            FIXTURES_DIR / "gcp_basic.tf",
            FIXTURES_DIR / "oci_basic.tf",
        ]
        inventory = parse_tf_files(files)
        # Should have resources from all providers
        prefixes = {r.resource_type.split("_")[0] for r in inventory.resources}
        assert "aws" in prefixes
        assert "azurerm" in prefixes
        assert "google" in prefixes
        assert "oci" in prefixes
```

- [ ] **Step 5: Run all parser tests**

Run: `uv run pytest tests/test_tf_parser.py -v`
Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add tests/fixtures/azure_basic.tf tests/fixtures/gcp_basic.tf tests/fixtures/oci_basic.tf tests/test_tf_parser.py
git commit -m "test(#10): add multi-provider test fixtures and cross-provider parser tests"
```

---

## Task 10: Full Integration Test and Final Validation

**Files:**
- No new files — validation of the full pipeline.

- [ ] **Step 1: Run complete test suite**

Run: `uv run pytest tests/ -v`
Expected: All tests PASS.

- [ ] **Step 2: Run lint on all modified/new files**

Run: `uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/`
Expected: No issues.

- [ ] **Step 3: Run type check**

Run: `uv run pyright`
Expected: No new errors (existing suppressions are fine).

- [ ] **Step 4: Commit any remaining fixes**

If lint/type check revealed issues, fix and commit:

```bash
git add -A
git commit -m "chore(#10): fix lint/type issues from static HCL analysis"
```
