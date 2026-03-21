# CVSS 4.0 Scoring & Phase 3 Decomposition

**Date:** 2026-03-20
**Status:** Draft

## Overview

Integrate CVSS 4.0 scoring into the threat analysis pipeline and decompose Phase 3 (Security Analysis) into focused sub-phases. Additionally, filter out "positive" security findings so only actual risks become TMI threat objects.

## Goals

1. Replace CVSS 3.1 with CVSS 4.0 vector scoring throughout the pipeline
2. Decompose Phase 3 into sub-phases that each focus on one task
3. Validate LLM-produced CVSS vectors with the `cvss` Python library and compute numeric scores deterministically
4. Exclude positive/non-actionable findings from threat output
5. Move per-threat classification (STRIDE, CWE, mitigation) out of the bulk security call into a dedicated per-threat LLM pass

## Non-Goals

- Changing Phases 1 or 2 prompt content (Phase 1 is already clean — inventory only)
- Modifying the TMI client API interface
- Changing the markdown report generator code (it already uses the same data fields)
- Removing the `extract_threats_from_analysis()` LLM-based re-extraction path in `threat_processor.py` (future cleanup candidate). Note: this method loads its own prompts (`threat_extraction_system.txt` / `threat_extraction_user.txt`) which are unaffected by this change.

## Architecture

### Current Pipeline

```
Phase 1 (Inventory) → Phase 2 (Infrastructure) → Phase 3 (Security Analysis)
                                                       ↓
                                                  All findings with STRIDE, CVSS 3.1,
                                                  CWE, mitigation in one LLM call
```

### New Pipeline

```
Phase 1 (Inventory) → Phase 2 (Infrastructure) → Phase 3a (Threat Identification)
                                                       ↓
                                                  List of threats (name, description,
                                                  affected_components only)
                                                       ↓
                                                  Phase 3b (Per-Threat Analysis) × N
                                                       ↓
                                                  Each threat gets: STRIDE, CVSS 4.0
                                                  vector, CWE, mitigation, category
                                                       ↓
                                                  Python CVSS validation & scoring
                                                       ↓
                                                  Merged findings list
```

## Detailed Design

### Phase 3a — Threat Identification

**Purpose:** Identify all actual security risks from the infrastructure analysis. No scoring, no classification, no mitigation.

**LLM Input:** Phase 1 inventory JSON + Phase 2 infrastructure JSON + Terraform source code (same inputs as current Phase 3).

**LLM Output:** JSON array of threat objects:

```json
[
  {
    "name": "Brief threat title (max 256 chars)",
    "description": "What the risk is and why it matters",
    "affected_components": ["component-id-1", "component-id-2"]
  }
]
```

**Key prompt instructions:**
- Only report findings that represent actual security risks or vulnerabilities
- Do NOT include positive observations, good security practices, or things already properly configured
- Do NOT include severity, scores, classification, or mitigation
- Each unique security concern appears exactly once
- Reference specific component IDs from the inventory

**Prompt files:**
- `prompts/threat_identification_system.txt` — new
- `prompts/threat_identification_user.txt` — new

### Phase 3b — Per-Threat Analysis

**Purpose:** For a single threat, produce STRIDE classification, CVSS 4.0 vector, CWE identifiers, mitigation recommendations, and category.

**LLM Input:** The threat's name, description, and affected components from Phase 3a. Also includes a summary of the infrastructure context (inventory + infrastructure JSON) so the LLM can reason about attack vectors, complexity, and impact.

**LLM Output:** JSON object:

```json
{
  "threat_type": "Spoofing, Information Disclosure",
  "severity": "High",
  "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
  "cwe_id": ["CWE-284"],
  "mitigation": "Specific, actionable mitigation recommendation",
  "category": "Authentication/Authorization"
}
```

**Key prompt content:**
- Full CVSS 4.0 metric definitions (from `cvss40_scoring_prompt.md`) including all 11 mandatory base metrics with value tables
- CVSS 4.0 vector string format specification
- STRIDE category definitions with evaluation criteria
- CWE classification guidance
- Category list: Public Exposure, Authentication/Authorization, Encryption, Network Security, Secrets Management, Logging/Monitoring, Compliance, Best Practices

**Called once per threat from Phase 3a.** Token/cost tracking accumulates across all 3b calls.

**Prompt files:**
- `prompts/threat_analysis_system.txt` — new
- `prompts/threat_analysis_user.txt` — new

### CVSS 4.0 Validation & Scoring Module

**New module:** `tmi_tf/cvss_scorer.py`

```python
def score_cvss4_vector(vector: str) -> tuple[float | None, str | None, str | None]:
    """Validate and score a CVSS 4.0 vector string.

    Args:
        vector: CVSS 4.0 vector string

    Returns:
        Tuple of (score, severity, error).
        On success: (float score, severity label, None)
        On failure: (None, None, error message)
    """
```

Uses the `cvss` PyPI library (`CVSS4` class) to:
1. Validate the vector string format
2. Compute the numeric base score via `c.base_score`
3. Derive the severity label via `c.severities()[0]` (returns a string: "None", "Low", "Medium", "High", or "Critical")

**Edge case — score of 0.0:** If the library returns a severity of `"None"` (CVSS score 0.0), map it to `"Low"` for consistency with TMI's severity model which does not use "None" as a severity level.

**Integration after each Phase 3b call:**
1. Extract `cvss_vector` from LLM response
2. Call `score_cvss4_vector()`
3. If valid: set `score` to computed value, build `cvss` list as `[{"vector": vector, "score": score}]`, set `severity` from library (overrides LLM severity for consistency with the numeric score)
4. If invalid: log warning, set `score=None`, `cvss=[]`, keep LLM-assigned `severity` as fallback

**New dependency:** `cvss>=3.2` added to `pyproject.toml`. (CVSS 4.0 support was introduced in v3.2 of the `cvss` PyPI package.)

### Pipeline Integration in `llm_analyzer.py`

The `analyze_repository` method changes from:

```
Phase 1 → Phase 2 → Phase 3 (_call_llm_json_array)
```

To:

```
Phase 1 → Phase 2 → Phase 3a (_call_llm_json_array) → Phase 3b loop (_call_llm_json per threat) → CVSS validation
```

The final `security_findings` list in `TerraformAnalysis` contains merged findings — Phase 3a fields (name, description, affected_components) combined with Phase 3b fields (threat_type, severity, score, cvss, cwe_id, mitigation, category). The data structure is identical to what `threats_from_findings()` already expects.

Token and cost tracking: `security_input_tokens`, `security_output_tokens`, and `security_cost` on `TerraformAnalysis` represent the sum of Phase 3a plus all Phase 3b calls combined. These flow into threat metadata via `analyzer.py`.

**Execution strategy:** Phase 3b calls are sequential to simplify error handling and avoid API rate limits. Parallelism is a future optimization.

### Changes to `llm_analyzer.py` — Prompt Loading

`_load_phase_prompts()` currently loads `security_analysis_system.txt` and `security_analysis_user.txt` into `self.security_system` and `self.security_user_template`. These are replaced with four new prompt attributes:

- `self.threat_id_system` — loaded from `prompts/threat_identification_system.txt`
- `self.threat_id_user_template` — loaded from `prompts/threat_identification_user.txt`
- `self.threat_analysis_system` — loaded from `prompts/threat_analysis_system.txt`
- `self.threat_analysis_user_template` — loaded from `prompts/threat_analysis_user.txt`

The old `self.security_system` and `self.security_user_template` attributes are removed.

### No Changes Required

- **`threat_processor.py`**: `threats_from_findings()` interface unchanged; it receives the same dict structure with richer data
- **`analyzer.py`**: Already calls `threats_from_findings()` with `analysis.security_findings`; no structural changes
- **`markdown_generator.py`**: Uses the same fields (name, severity, score, cvss, threat_type, etc.); CVSS 4.0 vectors display correctly. **Note:** Reports will no longer include positive/good-practice observations since Phase 3a filters them out. This is an intentional behavioral change.
- **`tmi_client_wrapper.py`**: `create_threat()` already accepts score, cvss, severity; no changes
- **`cli.py`**: No changes
- **`config.py`**, **`auth.py`**, **`retry.py`**: Unrelated

## File Changes Summary

| File | Action | Description |
|------|--------|-------------|
| `tmi_tf/cvss_scorer.py` | Create | CVSS 4.0 validation and scoring module |
| `tmi_tf/llm_analyzer.py` | Modify | Decompose Phase 3 into 3a + 3b loop with CVSS validation; update `_load_phase_prompts()` for new prompt files |
| `prompts/threat_identification_system.txt` | Create | Phase 3a system prompt |
| `prompts/threat_identification_user.txt` | Create | Phase 3a user template |
| `prompts/threat_analysis_system.txt` | Create | Phase 3b system prompt (includes CVSS 4.0 metrics) |
| `prompts/threat_analysis_user.txt` | Create | Phase 3b user template |
| `prompts/security_analysis_system.txt` | Delete | Replaced by 3a + 3b prompts (not used by `threat_processor.py` which has its own prompts) |
| `prompts/security_analysis_user.txt` | Delete | Replaced by 3a + 3b prompts |
| `pyproject.toml` | Modify | Add `cvss>=3.2` dependency |
| `cvss4_score.py` | Delete | Absorbed into `tmi_tf/cvss_scorer.py` |
| `cvss40_scoring_prompt.md` | Delete | Content absorbed into `prompts/threat_analysis_system.txt` |
| `tests/test_cvss_scorer.py` | Create | Tests for CVSS validation module |
| `tests/test_llm_analyzer.py` | Modify | Update Phase 3 tests for 3a/3b flow |

## Error Handling

- **Phase 3a returns empty list:** No threats identified. Pipeline continues normally with zero threats (same as today when Phase 3 finds nothing).
- **Phase 3b LLM call fails for one threat:** Log error, skip that threat, continue with remaining threats. The threat is lost but the pipeline doesn't abort.
- **Phase 3b returns non-parseable JSON:** Same handling as LLM call failure — log warning, skip that threat, continue with remaining threats.
- **CVSS vector validation fails:** Log warning with the invalid vector. Keep the threat with `score=None`, `cvss=[]`, and the LLM's severity as fallback.
- **All Phase 3b calls fail:** Results in zero enriched threats. Log error. Pipeline continues (notes and diagram are already created at this point).

## Testing

- **`tests/test_cvss_scorer.py`**: Valid CVSS 4.0 vector returns correct score and severity. Invalid vector returns None with error message. Edge cases: empty string, CVSS 3.1 vector, missing metrics, garbage input.
- **`tests/test_llm_analyzer.py`**: Mock Phase 3a to return threat list, mock Phase 3b to return per-threat analysis. Verify merged output structure. Test partial failure (one 3b call fails, others succeed). Test empty Phase 3a result.
- **Existing `threat_processor.py` tests**: Should pass unchanged. Update test fixtures if they contained CVSS 3.1 vectors.
