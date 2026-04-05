# Design: External Dependency Tracking (Sub-project A of Issue #7)

**Date**: 2026-04-04
**Issue**: [#7](https://github.com/ericfitz/tmi-tf-wh/issues/7) (Sub-project A)

## Goal

Add external service dependency tracking to the Terraform analysis pipeline. Each inventoried component identifies the services that host or provide it (cloud, SaaS, or on-prem). Dependencies appear in the inventory, DFD metadata, and analysis report.

Sub-project B (architecture Mermaid diagram) will be a separate spec.

## Scope

This sub-project covers:
- Per-component dependency tracking in Phase 1 inventory
- Top-level dependency summary in Phase 1 inventory
- Dependency metadata on DFD diagram components
- External Dependencies table in the markdown analysis report

## Decisions

- **Extraction point**: Phase 1 (inventory). The LLM already reads every Terraform resource and has full context to identify service dependencies.
- **Dependency fields**: `type` (cloud | saas | on-prem), `provider` (e.g., "AWS", "Salesforce"), `service` (e.g., "S3", "Vault").
- **DFD metadata encoding**: Option B — JSON array serialized into a single metadata value string. Key: `dependencies`. Value: JSON array of `{type, provider, service}` objects. Filed ericfitz/tmi#229 to improve metadata limits (array support, increased value length).
- **Report placement**: New "External Dependencies" HTML table in the analysis report, near relationships/data flows/trust boundaries tables.
- **Dependency types**: `cloud` (AWS, Azure, GCP, OCI services), `saas` (GitHub, Salesforce, Google Sign-In, etc.), `on-prem` (Active Directory, locally-deployed Vault, on-prem databases, etc.).

## Changes

### Phase 1 Inventory Prompt

**File**: `prompts/inventory_system.txt`

Add per-component `dependencies` array to the component schema:
```json
{
  "id": "aws_s3_bucket.logs",
  "name": "Logs Bucket",
  "type": "storage",
  "resource_type": "aws_s3_bucket",
  "configuration": {},
  "purpose": "Stores application logs",
  "dependencies": [
    {"type": "cloud", "provider": "AWS", "service": "S3"}
  ]
}
```

Add top-level `dependencies` summary to the inventory output:
```json
{
  "components": [],
  "services": [],
  "dependencies": [
    {
      "type": "cloud",
      "provider": "AWS",
      "service": "S3",
      "dependent_components": ["aws_s3_bucket.logs", "aws_s3_bucket.data"]
    }
  ]
}
```

Instruct the LLM to:
- Identify the service that hosts/provides each Terraform resource
- Classify as `cloud`, `saas`, or `on-prem`
- Identify the provider and specific service name
- Note that most Terraform resources have at least one dependency (Terraform instructs a provider to instantiate the resource)
- Deduplicate in the top-level summary, aggregating dependent_components

### DFD Generation Prompt

**File**: `prompts/dfd_generation_system.txt`

Add instructions to transfer per-component dependencies from inventory into DFD component metadata:
```json
{"key": "dependencies", "value": "[{\"type\":\"cloud\",\"provider\":\"AWS\",\"service\":\"S3\"}]"}
```

The DFD generation prompt already receives the inventory JSON. The LLM reads each component's `dependencies` array and serializes it as a JSON string in metadata.

### Markdown Report

**File**: `tmi_tf/markdown_generator.py`

Add an "External Dependencies" HTML table in the analysis report, placed near the existing Component Relationships, Data Flows, and Trust Boundaries tables. Columns: Type, Provider, Service, Dependent Components.

Data source: `analysis.inventory["dependencies"]` (the top-level dependency summary).

Omit the section if no dependencies are present.

### No Changes To

- `tmi_tf/diagram_builder.py` — already passes through arbitrary metadata
- `tmi_tf/llm_analyzer.py` — pipeline unchanged
- `tmi_tf/analyzer.py` — orchestration unchanged
- `tmi_tf/dfd_llm_generator.py` — passes data to LLM, no structural change
- `tmi_tf/cli.py` — CLI unchanged
- `tmi_tf/threat_processor.py` — threat processing unchanged

## Testing

- **Markdown generator**: Test that External Dependencies table renders when dependency data is present, and is omitted when absent.
- **No diagram_builder tests**: No code changes to diagram_builder.
- **No LLM integration tests**: Prompt changes validated by LLM output at runtime.
