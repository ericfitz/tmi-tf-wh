# Static HCL Analysis for Terraform Inventory Extraction

**Date:** 2026-04-06
**Issue:** #10 (subtask 1)
**Status:** Approved

## Problem

Phase 1 of the LLM analysis pipeline sends raw Terraform HCL to the LLM and asks it to extract everything — resource catalog, classification, configuration, purpose, service groupings, and dependencies. This has two problems:

1. **Accuracy** — the LLM occasionally misses resources or hallucinates configuration values. There is no ground-truth baseline to catch these errors.
2. **Speed** — large Terraform codebases produce huge prompts (input tokens) and large inventory JSON responses (output tokens), taking several minutes per analysis.

## Solution

Move mechanical analysis out of the LLM and into static Python-based HCL parsing. The LLM receives filtered HCL (familiar syntax, smaller) and a pre-extracted inventory, and only performs semantic inference (names, purpose, service groupings, dependencies).

## Design

### Component 1: Static HCL Parser (`tf_parser.py`)

A new module that uses `python-hcl2` to parse `.tf` files into a structured inventory.

**Input:** List of Terraform file paths (from existing `TerraformEnvironment`).

**Output:** `StaticInventory` dataclass:

```python
@dataclass
class ParsedResource:
    resource_type: str          # e.g., "aws_instance"
    local_name: str             # e.g., "web_server"
    address: str                # e.g., "aws_instance.web_server"
    attributes: dict[str, Any]  # raw HCL attributes
    references: list[str]       # detected Terraform references

@dataclass
class ParsedDataSource:
    data_type: str
    local_name: str
    address: str
    attributes: dict[str, Any]
    references: list[str]

@dataclass
class ParsedVariable:
    name: str
    type_expr: str | None
    default: Any
    description: str | None

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

@dataclass
class ParsedProvider:
    name: str
    alias: str | None
    config: dict[str, Any]

@dataclass
class StaticInventory:
    resources: list[ParsedResource]
    data_sources: list[ParsedDataSource]
    variables: list[ParsedVariable]
    outputs: list[ParsedOutput]
    modules: list[ParsedModule]
    providers: list[ParsedProvider]
    unparsed_files: list[str]       # files that python-hcl2 could not parse
```

**Reference detection:** Walk attribute values looking for Terraform reference patterns (`resource_type.name.attribute`). Stored as `references: list[str]` on each resource — these are explicit dependency edges.

**Error handling:** If `python-hcl2` fails on a file, log a warning and add the file path to `unparsed_files` so the LLM still receives those files unfiltered.

### Component 2: Resource Registry (`data/resource_registry.yaml`)

A standalone YAML data file mapping resource types to component categories and security-relevant attributes.

```yaml
# Provider detection: resource type prefix → provider info
providers:
  aws_: { name: "AWS", type: "cloud" }
  azurerm_: { name: "Microsoft Azure", type: "cloud" }
  google_: { name: "Google Cloud", type: "cloud" }
  oci_: { name: "Oracle Cloud", type: "cloud" }

# Resource type → category + security-relevant attributes
resources:
  aws_instance:
    category: compute
    security_attrs:
      - ami
      - iam_instance_profile
      - vpc_security_group_ids
      - subnet_id
      - metadata_options
      - user_data                        # presence/hash only, not content
      - ebs_block_device.encrypted
      - ebs_block_device.kms_key_id
      - associate_public_ip_address

  aws_s3_bucket:
    category: storage
    security_attrs:
      - acl
      - versioning
      - server_side_encryption_configuration
      - logging
      - policy
      - public_access_block

  # ... comprehensive coverage for AWS, Azure, GCP, OCI

# Fallback for unrecognized resources
defaults:
  unknown_category: other
  unknown_attrs: all    # send all attributes for unrecognized resources
```

**Design decisions:**

- **YAML over JSON** — supports comments documenting why attributes matter, easier to edit.
- **`unknown_attrs: all`** — unrecognized resources send full config so the LLM can classify them. No information is silently dropped.
- **Dot notation for nested attributes** — e.g., `ebs_block_device.encrypted` reaches into nested blocks.
- **Provider detection by prefix** — simple heuristic that covers the vast majority of Terraform resource types.
- **Allowed categories:** `compute`, `storage`, `network`, `gateway`, `security_control`, `identity`, `monitoring`, `dns`, `cdn`, `other` (matches existing Phase 1 schema).

The registry ships with comprehensive coverage for all four major cloud providers (AWS, Azure, GCP, OCI).

### Component 3: HCL Filtering (`tf_filter.py`)

Takes a `StaticInventory` + the resource registry and produces two outputs:

**1. Filtered HCL** — original `.tf` files with non-security-relevant attributes stripped. The LLM reads familiar HCL syntax, just less of it.

Filtering rules:
- **Keep:** security-relevant attributes (per registry), all meta-arguments (`count`, `for_each`, `depends_on`, `provider`, `lifecycle`), and all reference expressions (even in non-security attrs, since they reveal relationships).
- **Remove:** everything else.
- **Unrecognized resources:** keep all attributes (per `unknown_attrs: all`).
- **Unparsed files:** pass through raw HCL unfiltered.
- **Comment annotation:** append `# N non-security attributes omitted` to each filtered resource block so the LLM knows attributes were removed intentionally.

Example output:

```hcl
resource "aws_instance" "web_server" {
  ami                         = "ami-0c55b159cbfafe1f0"
  iam_instance_profile        = aws_iam_instance_profile.web.name
  vpc_security_group_ids      = [aws_security_group.web.id]
  subnet_id                   = aws_subnet.private.id
  associate_public_ip_address = false
  # 4 non-security attributes omitted
}
```

**2. Pre-built inventory JSON** — mechanical fields populated from static analysis:

```json
{
  "components": [
    {
      "id": "aws_instance.web_server",
      "resource_type": "aws_instance",
      "type": "compute",
      "configuration": { "ami": "ami-0c55b159cbfafe1f0", "...": "..." },
      "references": ["aws_iam_instance_profile.web", "aws_security_group.web", "aws_subnet.private"],
      "name": null,
      "purpose": null
    }
  ],
  "variables": [...],
  "outputs": [...],
  "modules": [...],
  "services": null,
  "dependencies": null
}
```

Fields set to `null` are what the LLM fills in. Pre-populated fields are authoritative.

### Component 4: Revised Phase 1 LLM Prompt

The Phase 1 prompt changes from "extract everything from raw HCL" to focused semantic analysis.

**User prompt structure:**

```
Here is a pre-extracted inventory of Terraform resources for {repo_name}.
The resource IDs, types, categories, and security-relevant configuration
were extracted via static analysis and are authoritative — do not modify them.

Your task:
1. For each component, infer a human-readable "name" and "purpose"
2. Identify logical "services" — groups of components that work together
   (based on module boundaries, naming patterns, shared network/security context)
3. Identify external "dependencies" (cloud services, SaaS, on-prem)
4. For any component with type "other", reclassify if you can determine
   a better category

Pre-extracted inventory:
{inventory_json}

Filtered Terraform source (security-relevant attributes only):
{filtered_hcl}
```

**Output schema:** The LLM generates only:
- `name` and `purpose` for each component (keyed by `id`)
- `services` array
- `dependencies` array
- Any `type` reclassifications for "other" components

**Merge step:** After the LLM responds, merge semantic output onto the static inventory to produce the full Phase 1 result. The merged output matches the existing Phase 1 schema exactly.

### Component 5: Pipeline Integration

```
Existing:  clone → collect .tf files → [Phase 1 LLM: everything]     → Phase 2 → Phase 3
New:       clone → collect .tf files → static parse → filter → [Phase 1 LLM: semantic only] → merge → Phase 2 → Phase 3
```

**Module changes:**

| Module | Change |
|--------|--------|
| `tf_parser.py` | **New** — HCL parsing, produces `StaticInventory` |
| `tf_filter.py` | **New** — applies registry, produces filtered HCL + pre-built inventory |
| `data/resource_registry.yaml` | **New** — resource type mappings and security attribute lists |
| `llm_analyzer.py` | **Modified** — Phase 1 accepts static inventory, uses new prompt, merges output |
| `prompts/phase1_*` | **Modified** — new system and user prompt templates |
| `analyzer.py` | **Modified** — orchestrates static parse → filter → LLM call |
| `pyproject.toml` | **Modified** — add `python-hcl2` dependency |

**Unchanged:** Phase 2, Phase 3, report generation, diagram builder, threat processor, `repo_analyzer.py`, CLI interface. The Phase 1 output schema is preserved — downstream consumers are unaffected.

**Error resilience:**
- If `python-hcl2` fails on some files, those go to the LLM unfiltered via `unparsed_files`.
- If the entire static parse fails, fall back to the current full-LLM Phase 1 with a logged warning. The pipeline does not break.

### New Dependency

`python-hcl2` — actively maintained, pure Python, no native extensions. Handles most HCL2 syntax. Known limitations with complex expressions and dynamic blocks are handled by the unparsed-file fallback.

## Token Impact Estimate

- **Input:** filtered HCL ~40-60% smaller than raw HCL; pre-built inventory JSON adds some tokens but replaces what the LLM inferred.
- **Output:** ~50-70% smaller since the LLM skips id, resource_type, type, configuration, and references for every component.
- **Net effect:** significant reduction in both input and output tokens, translating to faster responses and lower cost.

## Testing Strategy

**Unit tests:**

| Test file | Coverage |
|-----------|----------|
| `test_tf_parser.py` | HCL parsing: resources, data sources, variables, outputs, modules, providers, reference detection, graceful failure on unparsable files |
| `test_tf_filter.py` | Registry loading, attribute filtering, filtered HCL generation, unrecognized resource passthrough, unparsed file passthrough, omitted-attribute comments |
| `test_resource_registry.py` | Registry YAML validity, all 4 providers have coverage, category values are from the allowed set, dot-notation paths resolve correctly |

**Integration tests:**

| Test file | Coverage |
|-----------|----------|
| `test_llm_analyzer.py` (updated) | Phase 1 with static inventory input, merge logic, fallback to full-LLM when static parse fails |

**Test fixtures:** Small `.tf` files per provider (AWS, Azure, GCP, OCI) with known resources, plus a deliberately unparsable `.tf` file to test fallback. Expected `StaticInventory` and filtered output for each fixture.

**Not tested:** LLM output quality (subjective, model-dependent), `python-hcl2` internals.
