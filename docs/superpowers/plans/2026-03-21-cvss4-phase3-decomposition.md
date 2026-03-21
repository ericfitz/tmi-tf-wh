# CVSS 4.0 Scoring & Phase 3 Decomposition Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace CVSS 3.1 with CVSS 4.0 scoring, decompose Phase 3 into focused sub-phases (3a: threat identification, 3b: per-threat analysis), and filter out positive/non-actionable findings.

**Architecture:** Phase 3 becomes two sub-phases. Phase 3a identifies threats (no scoring). Phase 3b runs once per threat to classify (STRIDE/CWE), score (CVSS 4.0), and recommend mitigations. A new `cvss_scorer.py` module validates LLM-produced vectors via the `cvss` PyPI library.

**Tech Stack:** Python 3.10+, cvss>=3.2 (PyPI), LiteLLM, pytest

**Spec:** `docs/superpowers/specs/2026-03-20-cvss4-phase3-decomposition-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `tmi_tf/cvss_scorer.py` | Create | CVSS 4.0 vector validation and numeric scoring |
| `tests/test_cvss_scorer.py` | Create | Tests for cvss_scorer |
| `prompts/threat_identification_system.txt` | Create | Phase 3a system prompt |
| `prompts/threat_identification_user.txt` | Create | Phase 3a user template |
| `prompts/threat_analysis_system.txt` | Create | Phase 3b system prompt (CVSS 4.0 metrics, STRIDE, CWE) |
| `prompts/threat_analysis_user.txt` | Create | Phase 3b user template |
| `tmi_tf/llm_analyzer.py` | Modify | Replace Phase 3 with 3a+3b loop, update prompt loading |
| `tests/test_llm_analyzer.py` | Create | Tests for Phase 3a/3b flow in LLMAnalyzer |
| `pyproject.toml` | Modify | Add `cvss>=3.2` dependency |
| `prompts/security_analysis_system.txt` | Delete | Replaced by 3a+3b prompts |
| `prompts/security_analysis_user.txt` | Delete | Replaced by 3a+3b prompts |
| `cvss4_score.py` | Delete | Absorbed into cvss_scorer.py |
| `cvss40_scoring_prompt.md` | Delete | Absorbed into threat_analysis_system.txt |

---

### Task 1: Add `cvss` dependency

**Files:**
- Modify: `pyproject.toml:6-23`

- [ ] **Step 1: Add cvss to pyproject.toml**

In `pyproject.toml`, add `"cvss>=3.2",` to the `dependencies` list after `"nh3>=0.3.3",`:

```toml
    "nh3>=0.3.3",
    "cvss>=3.2",
    "oci>=2.168.2",
```

- [ ] **Step 2: Install dependencies**

Run: `cd /Users/efitz/Projects/tmi-tf-wh && uv sync`
Expected: Successful install, `cvss` package now available.

- [ ] **Step 3: Verify cvss library works with CVSS 4.0**

Run: `cd /Users/efitz/Projects/tmi-tf-wh && uv run python -c "from cvss import CVSS4; c = CVSS4('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'); print(c.base_score, c.severities()[0])"`
Expected: Prints a numeric score and severity string (e.g. `10.0 Critical`).

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml uv.lock
git commit -m "chore: add cvss>=3.2 dependency for CVSS 4.0 scoring"
```

---

### Task 2: Create `tmi_tf/cvss_scorer.py` with TDD

**Files:**
- Create: `tmi_tf/cvss_scorer.py`
- Create: `tests/test_cvss_scorer.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_cvss_scorer.py`:

```python
"""Tests for tmi_tf.cvss_scorer module."""

from tmi_tf.cvss_scorer import score_cvss4_vector


class TestScoreCvss4Vector:
    """Tests for score_cvss4_vector function."""

    def test_valid_critical_vector(self):
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        score, severity, error = score_cvss4_vector(vector)
        assert error is None
        assert score is not None
        assert isinstance(score, float)
        assert score >= 9.0
        assert severity == "Critical"

    def test_valid_low_vector(self):
        vector = "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
        score, severity, error = score_cvss4_vector(vector)
        assert error is None
        assert score is not None
        assert isinstance(score, float)
        assert severity in ("Low", "Medium", "High", "Critical")

    def test_invalid_vector_returns_error(self):
        score, severity, error = score_cvss4_vector("not-a-vector")
        assert score is None
        assert severity is None
        assert error is not None

    def test_empty_string_returns_error(self):
        score, severity, error = score_cvss4_vector("")
        assert score is None
        assert severity is None
        assert error is not None

    def test_cvss31_vector_returns_error(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        score, severity, error = score_cvss4_vector(vector)
        assert score is None
        assert severity is None
        assert error is not None

    def test_missing_metrics_returns_error(self):
        vector = "CVSS:4.0/AV:N/AC:L"
        score, severity, error = score_cvss4_vector(vector)
        assert score is None
        assert severity is None
        assert error is not None

    def test_zero_score_maps_none_severity_to_low(self):
        # All impacts None = score 0.0, library returns severity "None"
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
        score, severity, error = score_cvss4_vector(vector)
        assert error is None
        assert score == 0.0
        assert severity == "Low"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/efitz/Projects/tmi-tf-wh && uv run pytest tests/test_cvss_scorer.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'tmi_tf.cvss_scorer'`

- [ ] **Step 3: Write minimal implementation**

Create `tmi_tf/cvss_scorer.py`:

```python
"""CVSS 4.0 vector validation and scoring."""

import logging

from cvss import CVSS4, CVSSError  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

logger = logging.getLogger(__name__)


def score_cvss4_vector(
    vector: str,
) -> tuple[float | None, str | None, str | None]:
    """Validate and score a CVSS 4.0 vector string.

    Args:
        vector: CVSS 4.0 vector string (e.g. "CVSS:4.0/AV:N/AC:L/...")

    Returns:
        Tuple of (score, severity, error).
        On success: (float score, severity label, None)
        On failure: (None, None, error message)
    """
    try:
        c = CVSS4(vector)
        score = float(c.base_score)
        severity = c.severities()[0]
        # TMI does not use "None" as a severity level
        if severity == "None":
            severity = "Low"
        return score, severity, None
    except CVSSError as e:
        return None, None, str(e)
    except Exception as e:
        return None, None, str(e)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/efitz/Projects/tmi-tf-wh && uv run pytest tests/test_cvss_scorer.py -v`
Expected: All 7 tests PASS.

- [ ] **Step 5: Lint**

Run: `cd /Users/efitz/Projects/tmi-tf-wh && uv run ruff check tmi_tf/cvss_scorer.py tests/test_cvss_scorer.py && uv run ruff format --check tmi_tf/cvss_scorer.py tests/test_cvss_scorer.py`
Expected: No errors.

- [ ] **Step 6: Type check**

Run: `cd /Users/efitz/Projects/tmi-tf-wh && uv run pyright tmi_tf/cvss_scorer.py`
Expected: No errors (or only expected pyright ignores for cvss import).

- [ ] **Step 7: Commit**

```bash
git add tmi_tf/cvss_scorer.py tests/test_cvss_scorer.py
git commit -m "feat: add CVSS 4.0 vector validation and scoring module"
```

---

### Task 3: Create Phase 3a prompts (Threat Identification)

**Files:**
- Create: `prompts/threat_identification_system.txt`
- Create: `prompts/threat_identification_user.txt`

- [ ] **Step 1: Create Phase 3a system prompt**

Create `prompts/threat_identification_system.txt`:

```
You are an expert infrastructure security analyst specializing in threat identification for cloud infrastructure.

Your task is to analyze Terraform infrastructure configurations and identify all security threats, risks, and vulnerabilities.

# Output Requirements

Return ONLY a JSON array. Do not include any explanation, preamble, markdown formatting, or code fences. Your entire response must be valid JSON starting with [ and ending with ].

Each element in the array must be an object with exactly these fields:
{
  "name": "Brief threat title (max 256 chars)",
  "description": "Detailed description of the threat, the risk it poses, and its potential impact",
  "affected_components": ["component-id-1", "component-id-2"]
}

# What To Report

Report ONLY findings that represent actual security risks, vulnerabilities, or misconfigurations that could be exploited or that weaken the security posture. These include:
- Missing or weak access controls
- Overly permissive network rules or IAM policies
- Unencrypted data at rest or in transit
- Missing logging, monitoring, or audit trails
- Publicly exposed resources that should be private
- Hardcoded secrets or insecure secret management
- Missing rate limiting, DDoS protection, or availability controls
- Insecure default configurations

# What NOT To Report

Do NOT include any of the following:
- Positive observations or good security practices already in place
- Things that are properly configured
- Informational notes about the architecture
- Recommendations for improvement that are not tied to a specific risk

# Important

- Each unique security concern must appear exactly once — do not duplicate findings
- Reference specific component IDs from the inventory in affected_components
- Do NOT include severity, scores, STRIDE classification, CWE IDs, mitigation, or category — those are handled in a subsequent analysis step
- Do NOT use HTML tags in any field values

CRITICAL: Return ONLY the JSON array, no other text.
```

- [ ] **Step 2: Create Phase 3a user prompt template**

Create `prompts/threat_identification_user.txt`:

```
Repository: {repo_name}
URL: {repo_url}

## Extracted Inventory

{inventory_json}

## Infrastructure Analysis

{infrastructure_json}

## Terraform Configuration Files

{terraform_contents}

---

Using the inventory, infrastructure analysis, and original Terraform code above, identify all security threats and vulnerabilities. Return ONLY the JSON array of threat objects with name, description, and affected_components fields.
```

- [ ] **Step 3: Commit**

```bash
git add prompts/threat_identification_system.txt prompts/threat_identification_user.txt
git commit -m "feat: add Phase 3a threat identification prompts"
```

---

### Task 4: Create Phase 3b prompts (Per-Threat Analysis)

**Files:**
- Create: `prompts/threat_analysis_system.txt`
- Create: `prompts/threat_analysis_user.txt`

- [ ] **Step 1: Create Phase 3b system prompt**

Create `prompts/threat_analysis_system.txt`. This combines STRIDE classification, CWE guidance, category assignment, mitigation, and the full CVSS 4.0 metric definitions from `cvss40_scoring_prompt.md`:

```
You are an expert security threat analyst. Given a single security threat identified in cloud infrastructure, your task is to classify it, score it, and recommend mitigations.

# Output Requirements

Return ONLY a JSON object. Do not include any explanation, preamble, markdown formatting, or code fences. Your entire response must be valid JSON starting with { and ending with }.

The JSON must have exactly these fields:
{
  "threat_type": "Comma-separated STRIDE categories",
  "severity": "Critical|High|Medium|Low",
  "cvss_vector": "CVSS:4.0/AV:?/AC:?/AT:?/PR:?/UI:?/VC:?/VI:?/VA:?/SC:?/SI:?/SA:?",
  "cwe_id": ["CWE-nnn"],
  "mitigation": "Specific, actionable mitigation recommendation",
  "category": "Category name"
}

# STRIDE Classification

Evaluate ALL STRIDE categories and include EVERY applicable one as a comma-separated string:
- **Spoofing**: Could an attacker impersonate a valid user, system, or process?
- **Tampering**: Could an attacker modify data, code, or configurations without authorization?
- **Repudiation**: Could a user or system deny actions without proof otherwise?
- **Information Disclosure**: Could an attacker gain unauthorized access to sensitive data?
- **Denial of Service**: Could an attacker disrupt availability or performance?
- **Elevation of Privilege**: Could an attacker gain higher privileges than entitled?

# CVSS 4.0 Scoring

Assign each of the 11 mandatory CVSS v4.0 Base metrics based on the threat description and infrastructure context.

## Metric Definitions

**ATTACK VECTOR (AV)** — How does the attacker reach the vulnerable component?
| Value | Name | Description |
|-------|------|-------------|
| N | Network | Exploitable remotely over a network (across routers, internet) |
| A | Adjacent | Requires same LAN/subnet, Bluetooth, NFC, Wi-Fi, MPLS, or VPN segment |
| L | Local | Requires local OS access (console, SSH) or tricks a local user into action |
| P | Physical | Requires physical touch or manipulation of the hardware |

**ATTACK COMPLEXITY (AC)** — Must the attacker defeat built-in security mechanisms?
| Value | Name | Description |
|-------|------|-------------|
| L | Low | No security controls to bypass; repeatable, straightforward exploitation |
| H | High | Must defeat active defenses (e.g., ASLR, DEP) or obtain target-specific secrets |

**ATTACK REQUIREMENTS (AT)** — Does success depend on special deployment or execution conditions?
| Value | Name | Description |
|-------|------|-------------|
| N | None | Works reliably regardless of how the system is deployed |
| P | Present | Requires a race condition, or an on-path/MitM network position |

**PRIVILEGES REQUIRED (PR)** — What access must the attacker already have before attacking?
| Value | Name | Description |
|-------|------|-------------|
| N | None | Unauthenticated |
| L | Low | Standard unprivileged user account |
| H | High | Administrative or equivalent elevated account |

**USER INTERACTION (UI)** — Must someone other than the attacker take an action?
| Value | Name | Description |
|-------|------|-------------|
| N | None | Attacker exploits without any user involvement |
| P | Passive | User performs a routine action (visiting a page, running an app) — involuntary |
| A | Active | User must consciously do something specific (open a file, dismiss a warning) |

Score impacts for **both** the Vulnerable System (VC/VI/VA) and any Subsequent Systems (SC/SI/SA). A subsequent system is any component outside the vulnerable system that is affected downstream. If there is no downstream impact, set SC, SI, and SA all to N.

**CONFIDENTIALITY (VC / SC)**
| Value | Name | Description |
|-------|------|-------------|
| H | High | Total loss, or disclosure of critically sensitive data (credentials, keys) |
| L | Low | Partial or limited disclosure; attacker cannot control what is leaked |
| N | None | No confidentiality impact |

**INTEGRITY (VI / SI)**
| Value | Name | Description |
|-------|------|-------------|
| H | High | Total loss, or attacker can make consequential modifications |
| L | Low | Limited or uncontrolled modification with no direct serious consequence |
| N | None | No integrity impact |

**AVAILABILITY (VA / SA)**
| Value | Name | Description |
|-------|------|-------------|
| H | High | Sustained or persistent complete denial of service |
| L | Low | Reduced performance or intermittent interruption; cannot fully deny service |
| N | None | No availability impact |

## Vector String Format

All 11 metrics are mandatory and must appear in this exact order:
CVSS:4.0/AV:[N|A|L|P]/AC:[L|H]/AT:[N|P]/PR:[N|L|H]/UI:[N|P|A]/VC:[H|L|N]/VI:[H|L|N]/VA:[H|L|N]/SC:[H|L|N]/SI:[H|L|N]/SA:[H|L|N]

## Severity Mapping

Assign severity based on the CVSS 4.0 base score:
- **Critical** (9.0-10.0)
- **High** (7.0-8.9)
- **Medium** (4.0-6.9)
- **Low** (0.1-3.9)

# CWE Classification

Include one or more applicable CWE identifiers. Common ones for infrastructure:
- CWE-284: Improper Access Control
- CWE-311: Missing Encryption of Sensitive Data
- CWE-732: Incorrect Permission Assignment for Critical Resource
- CWE-778: Insufficient Logging
- CWE-269: Improper Privilege Management
- CWE-200: Exposure of Sensitive Information
- CWE-693: Protection Mechanism Failure

# Categories

Classify the finding into exactly one of:
- **Public Exposure**: Internet-facing resources, public IPs, open security groups
- **Authentication/Authorization**: IAM policies, roles, permissions, service accounts
- **Encryption**: Data at rest and in transit, key management
- **Network Security**: Firewalls, security groups, network segmentation
- **Secrets Management**: How credentials and secrets are handled
- **Logging/Monitoring**: Audit logs, security monitoring, alerting
- **Compliance**: Configuration that may impact regulatory requirements
- **Best Practices**: Alignment with or deviation from security best practices

# Important

- Do NOT use HTML tags in any field values

CRITICAL: Return ONLY the JSON object, no other text.
```

- [ ] **Step 2: Create Phase 3b user prompt template**

Create `prompts/threat_analysis_user.txt`:

```
## Threat To Analyze

**Name:** {threat_name}

**Description:** {threat_description}

**Affected Components:** {affected_components}

## Infrastructure Context

### Inventory
{inventory_json}

### Infrastructure Analysis
{infrastructure_json}

---

Analyze the above security threat in the context of the infrastructure. Produce STRIDE classification, a CVSS 4.0 vector string, CWE identifiers, a mitigation recommendation, and a category. Return ONLY the JSON object.
```

- [ ] **Step 3: Commit**

```bash
git add prompts/threat_analysis_system.txt prompts/threat_analysis_user.txt
git commit -m "feat: add Phase 3b per-threat analysis prompts with CVSS 4.0"
```

---

### Task 5: Update `llm_analyzer.py` — prompt loading + Phase 3a/3b loop

**Files:**
- Modify: `tmi_tf/llm_analyzer.py:170-177` (prompt loading)
- Modify: `tmi_tf/llm_analyzer.py:329-381` (Phase 3 section)
- Modify: `tmi_tf/llm_analyzer.py:1-10` (module docstring)

Note: prompt loading and Phase 3 replacement are done in a single task/commit to avoid a broken intermediate state (old Phase 3 code referencing removed prompt attributes).

- [ ] **Step 1: Add cvss_scorer import**

At the top of `tmi_tf/llm_analyzer.py`, after the existing imports (around line 24), add:

```python
from tmi_tf.cvss_scorer import score_cvss4_vector
```

- [ ] **Step 2: Update `_load_phase_prompts()` to load new prompts**

In `tmi_tf/llm_analyzer.py`, replace lines 170-177:

Old:
```python
    def _load_phase_prompts(self):
        """Load prompt pairs for all 3 analysis phases."""
        self.inventory_system = self._load_prompt("inventory_system.txt")
        self.inventory_user_template = self._load_prompt("inventory_user.txt")
        self.infra_system = self._load_prompt("infrastructure_analysis_system.txt")
        self.infra_user_template = self._load_prompt("infrastructure_analysis_user.txt")
        self.security_system = self._load_prompt("security_analysis_system.txt")
        self.security_user_template = self._load_prompt("security_analysis_user.txt")
```

New:
```python
    def _load_phase_prompts(self):
        """Load prompt pairs for all analysis phases."""
        self.inventory_system = self._load_prompt("inventory_system.txt")
        self.inventory_user_template = self._load_prompt("inventory_user.txt")
        self.infra_system = self._load_prompt("infrastructure_analysis_system.txt")
        self.infra_user_template = self._load_prompt("infrastructure_analysis_user.txt")
        # Phase 3a: Threat identification
        self.threat_id_system = self._load_prompt("threat_identification_system.txt")
        self.threat_id_user_template = self._load_prompt("threat_identification_user.txt")
        # Phase 3b: Per-threat analysis (STRIDE, CVSS 4.0, CWE, mitigation)
        self.threat_analysis_system = self._load_prompt("threat_analysis_system.txt")
        self.threat_analysis_user_template = self._load_prompt("threat_analysis_user.txt")
```

- [ ] **Step 3: Replace Phase 3 section in `analyze_repository`**

In `tmi_tf/llm_analyzer.py`, replace the Phase 3 block (lines 329-381, from `# Phase 3: Security Analysis` through the `return TerraformAnalysis(...)`) with:

```python
            # Phase 3a: Threat Identification
            if status_callback:
                status_callback("Phase 3a (Threat Identification) started")
            logger.info(f"Phase 3a: Identifying threats for {terraform_repo.name}")
            infrastructure_json_str = json.dumps(infrastructure, indent=2)
            threat_id_user = self.threat_id_user_template.format(
                repo_name=terraform_repo.name,
                repo_url=terraform_repo.url,
                inventory_json=inventory_json_str,
                infrastructure_json=infrastructure_json_str,
                terraform_contents=terraform_text,
            )

            raw_threats, tid_tokens_in, tid_tokens_out, tid_cost = (
                self._call_llm_json_array(
                    system_prompt=self.threat_id_system,
                    user_prompt=threat_id_user,
                    phase_name="threat_identification",
                )
            )

            sec_tokens_in = tid_tokens_in
            sec_tokens_out = tid_tokens_out
            sec_cost = tid_cost
            total_input_tokens += tid_tokens_in
            total_output_tokens += tid_tokens_out
            total_cost += tid_cost

            logger.info(
                f"Phase 3a complete: identified {len(raw_threats)} threats"
            )
            if status_callback:
                status_callback(
                    f"Phase 3a complete: {len(raw_threats)} threats identified"
                )

            # Phase 3b: Per-Threat Analysis (sequential, one LLM call per threat)
            if status_callback:
                status_callback("Phase 3b (Per-Threat Analysis) started")
            security_findings: List[Dict[str, Any]] = []

            for i, raw_threat in enumerate(raw_threats, 1):
                threat_name = raw_threat.get("name", "Unnamed Threat")
                logger.info(
                    f"Phase 3b: Analyzing threat {i}/{len(raw_threats)}: {threat_name}"
                )
                if status_callback:
                    status_callback(
                        f"Phase 3b: Analyzing threat {i}/{len(raw_threats)}"
                    )

                try:
                    affected = ", ".join(
                        raw_threat.get("affected_components", [])
                    )
                    threat_analysis_user = self.threat_analysis_user_template.format(
                        threat_name=threat_name,
                        threat_description=raw_threat.get("description", ""),
                        affected_components=affected,
                        inventory_json=inventory_json_str,
                        infrastructure_json=infrastructure_json_str,
                    )

                    analysis_result, ta_tokens_in, ta_tokens_out, ta_cost = (
                        self._call_llm_json(
                            system_prompt=self.threat_analysis_system,
                            user_prompt=threat_analysis_user,
                            phase_name=f"threat_analysis_{i}",
                            max_tokens=4000,
                            timeout=120.0,
                        )
                    )

                    sec_tokens_in += ta_tokens_in
                    sec_tokens_out += ta_tokens_out
                    sec_cost += ta_cost
                    total_input_tokens += ta_tokens_in
                    total_output_tokens += ta_tokens_out
                    total_cost += ta_cost

                    if not analysis_result:
                        logger.warning(
                            f"Phase 3b: Failed to parse analysis for threat "
                            f"'{threat_name}', skipping"
                        )
                        continue

                    # Validate and score CVSS vector
                    cvss_vector = analysis_result.get("cvss_vector", "")
                    cvss_list: List[Dict[str, Any]] = []
                    score: float | None = None
                    severity = analysis_result.get("severity", "Medium")

                    if cvss_vector:
                        cvss_score, cvss_severity, cvss_error = (
                            score_cvss4_vector(cvss_vector)
                        )
                        if cvss_error:
                            logger.warning(
                                f"Phase 3b: Invalid CVSS vector for "
                                f"'{threat_name}': {cvss_vector} — {cvss_error}"
                            )
                        else:
                            score = cvss_score
                            severity = cvss_severity  # type: ignore[assignment]
                            cvss_list = [
                                {"vector": cvss_vector, "score": cvss_score}
                            ]

                    # Merge Phase 3a + Phase 3b into final finding
                    finding: Dict[str, Any] = {
                        "name": threat_name,
                        "description": raw_threat.get("description", ""),
                        "affected_components": raw_threat.get(
                            "affected_components", []
                        ),
                        "threat_type": analysis_result.get(
                            "threat_type", "Unclassified"
                        ),
                        "severity": severity,
                        "score": score,
                        "cvss": cvss_list,
                        "cwe_id": analysis_result.get("cwe_id", []),
                        "mitigation": analysis_result.get("mitigation", ""),
                        "category": analysis_result.get("category", ""),
                    }
                    security_findings.append(finding)

                except Exception as e:
                    logger.error(
                        f"Phase 3b: Failed to analyze threat "
                        f"'{threat_name}': {e}"
                    )
                    continue

            logger.info(
                f"Phase 3b complete: {len(security_findings)} threats analyzed "
                f"out of {len(raw_threats)} identified"
            )
            if status_callback:
                status_callback("Phase 3 (Security) complete")

            elapsed_time = time.time() - start_time

            logger.info(
                f"All phases complete for {terraform_repo.name} in {elapsed_time:.2f}s. "
                f"Found {len(security_findings)} security findings. "
                f"Total tokens: {total_input_tokens + total_output_tokens}, "
                f"Cost: ${total_cost:.4f}"
            )

            return TerraformAnalysis(
                repo_name=terraform_repo.name,
                repo_url=terraform_repo.url,
                inventory=inventory,
                infrastructure=infrastructure,
                security_findings=security_findings,
                success=True,
                elapsed_time=elapsed_time,
                input_tokens=total_input_tokens,
                output_tokens=total_output_tokens,
                model=self.model,
                provider=self.provider,
                total_cost=total_cost,
                security_input_tokens=sec_tokens_in,
                security_output_tokens=sec_tokens_out,
                security_cost=sec_cost,
            )
```

- [ ] **Step 4: Update module docstring**

Replace the module docstring at the top of `tmi_tf/llm_analyzer.py` (lines 1-10):

Old:
```python
"""Unified LLM analyzer for Terraform analysis using LiteLLM.

This module provides a phased analyzer that supports multiple LLM providers
(Anthropic, OpenAI, x.ai, Google Gemini, etc.) through the LiteLLM library.

Analysis runs in 3 sequential phases:
  Phase 1: Inventory Extraction → inventory JSON
  Phase 2: Infrastructure Analysis → infrastructure JSON
  Phase 3: Security Analysis → security findings JSON
"""
```

New:
```python
"""Unified LLM analyzer for Terraform analysis using LiteLLM.

This module provides a phased analyzer that supports multiple LLM providers
(Anthropic, OpenAI, x.ai, Google Gemini, etc.) through the LiteLLM library.

Analysis runs in sequential phases:
  Phase 1:  Inventory Extraction → inventory JSON
  Phase 2:  Infrastructure Analysis → infrastructure JSON
  Phase 3a: Threat Identification → list of threats (name, description, affected components)
  Phase 3b: Per-Threat Analysis → STRIDE, CVSS 4.0, CWE, mitigation per threat (called N times)
"""
```

- [ ] **Step 5: Lint and type check**

Run: `cd /Users/efitz/Projects/tmi-tf-wh && uv run ruff check tmi_tf/llm_analyzer.py && uv run ruff format --check tmi_tf/llm_analyzer.py && uv run pyright tmi_tf/llm_analyzer.py`
Expected: No errors (or only expected pyright ignores).

- [ ] **Step 6: Commit**

```bash
git add tmi_tf/llm_analyzer.py
git commit -m "feat: decompose Phase 3 into 3a (identification) + 3b (per-threat analysis)"
```

---

### Task 6: Add tests for Phase 3a/3b flow in LLMAnalyzer

**Files:**
- Create: `tests/test_llm_analyzer.py`

- [ ] **Step 1: Write tests**

Create `tests/test_llm_analyzer.py`:

```python
"""Tests for Phase 3a/3b flow in tmi_tf.llm_analyzer."""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from tmi_tf.llm_analyzer import LLMAnalyzer, TerraformAnalysis


def _make_config(**overrides):
    """Create a minimal mock config for LLMAnalyzer."""
    defaults = {
        "llm_provider": "anthropic",
        "llm_model": "anthropic/test-model",
        "anthropic_api_key": "test-key",
        "get_oci_completion_kwargs": lambda: {},
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_llm_response(content: str, tokens_in: int = 100, tokens_out: int = 50):
    """Create a mock LiteLLM response."""
    message = MagicMock()
    message.content = content
    choice = MagicMock()
    choice.message = message
    choice.finish_reason = "stop"
    usage = MagicMock()
    usage.prompt_tokens = tokens_in
    usage.completion_tokens = tokens_out
    response = MagicMock()
    response.choices = [choice]
    response.usage = usage
    return response


def _make_tf_repo(name="test-repo", url="https://github.com/test/repo"):
    """Create a minimal mock TerraformRepository."""
    repo = MagicMock()
    repo.name = name
    repo.url = url
    repo.get_terraform_content.return_value = {"main.tf": 'resource "aws_s3_bucket" "b" {}'}
    return repo


class TestPhase3Decomposition:
    """Tests for the Phase 3a + 3b decomposition in analyze_repository."""

    @patch("tmi_tf.llm_analyzer.litellm")
    @patch("tmi_tf.llm_analyzer.retry_transient_llm_call")
    @patch("tmi_tf.llm_analyzer.save_llm_response")
    def test_phase3a_and_3b_produce_merged_findings(
        self, mock_save, mock_retry, mock_litellm
    ):
        """Phase 3a identifies threats, Phase 3b enriches each one."""
        # Phase 1: inventory
        inventory = {"components": [{"id": "aws_s3_bucket.b"}], "services": []}
        # Phase 2: infrastructure
        infrastructure = {"relationships": [], "data_flows": [], "trust_boundaries": []}
        # Phase 3a: threat identification
        raw_threats = [
            {
                "name": "Public S3 Bucket",
                "description": "S3 bucket is publicly accessible",
                "affected_components": ["aws_s3_bucket.b"],
            }
        ]
        # Phase 3b: per-threat analysis
        threat_analysis = {
            "threat_type": "Information Disclosure",
            "severity": "High",
            "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            "cwe_id": ["CWE-284"],
            "mitigation": "Enable S3 Block Public Access",
            "category": "Public Exposure",
        }

        responses = [
            _make_llm_response(json.dumps(inventory)),
            _make_llm_response(json.dumps(infrastructure)),
            _make_llm_response(json.dumps(raw_threats)),
            _make_llm_response(json.dumps(threat_analysis)),
        ]
        mock_retry.side_effect = responses
        mock_litellm.completion_cost.return_value = 0.01
        mock_save.return_value = "/tmp/test"

        config = _make_config()
        analyzer = LLMAnalyzer(config)
        result = analyzer.analyze_repository(_make_tf_repo())

        assert result.success is True
        assert len(result.security_findings) == 1

        finding = result.security_findings[0]
        assert finding["name"] == "Public S3 Bucket"
        assert finding["threat_type"] == "Information Disclosure"
        assert finding["cwe_id"] == ["CWE-284"]
        assert finding["mitigation"] == "Enable S3 Block Public Access"
        assert finding["score"] is not None
        assert len(finding["cvss"]) == 1
        assert finding["cvss"][0]["vector"].startswith("CVSS:4.0/")

    @patch("tmi_tf.llm_analyzer.litellm")
    @patch("tmi_tf.llm_analyzer.retry_transient_llm_call")
    @patch("tmi_tf.llm_analyzer.save_llm_response")
    def test_phase3a_empty_produces_no_findings(
        self, mock_save, mock_retry, mock_litellm
    ):
        """When Phase 3a finds no threats, result has empty security_findings."""
        inventory = {"components": [], "services": []}
        infrastructure = {"relationships": [], "data_flows": []}

        responses = [
            _make_llm_response(json.dumps(inventory)),
            _make_llm_response(json.dumps(infrastructure)),
            _make_llm_response(json.dumps([])),  # empty threats
        ]
        mock_retry.side_effect = responses
        mock_litellm.completion_cost.return_value = 0.0
        mock_save.return_value = "/tmp/test"

        config = _make_config()
        analyzer = LLMAnalyzer(config)
        result = analyzer.analyze_repository(_make_tf_repo())

        assert result.success is True
        assert result.security_findings == []

    @patch("tmi_tf.llm_analyzer.litellm")
    @patch("tmi_tf.llm_analyzer.retry_transient_llm_call")
    @patch("tmi_tf.llm_analyzer.save_llm_response")
    def test_phase3b_failure_skips_threat(
        self, mock_save, mock_retry, mock_litellm
    ):
        """When Phase 3b fails for one threat, it's skipped but others succeed."""
        inventory = {"components": [], "services": []}
        infrastructure = {"relationships": [], "data_flows": []}
        raw_threats = [
            {"name": "Threat A", "description": "desc A", "affected_components": []},
            {"name": "Threat B", "description": "desc B", "affected_components": []},
        ]
        threat_b_analysis = {
            "threat_type": "Tampering",
            "severity": "Medium",
            "cvss_vector": "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
            "cwe_id": ["CWE-345"],
            "mitigation": "Add integrity checks",
            "category": "Best Practices",
        }

        responses = [
            _make_llm_response(json.dumps(inventory)),
            _make_llm_response(json.dumps(infrastructure)),
            _make_llm_response(json.dumps(raw_threats)),
            _make_llm_response("not valid json"),  # Threat A fails
            _make_llm_response(json.dumps(threat_b_analysis)),  # Threat B succeeds
        ]
        mock_retry.side_effect = responses
        mock_litellm.completion_cost.return_value = 0.0
        mock_save.return_value = "/tmp/test"

        config = _make_config()
        analyzer = LLMAnalyzer(config)
        result = analyzer.analyze_repository(_make_tf_repo())

        assert result.success is True
        assert len(result.security_findings) == 1
        assert result.security_findings[0]["name"] == "Threat B"

    @patch("tmi_tf.llm_analyzer.litellm")
    @patch("tmi_tf.llm_analyzer.retry_transient_llm_call")
    @patch("tmi_tf.llm_analyzer.save_llm_response")
    def test_invalid_cvss_vector_keeps_threat_without_score(
        self, mock_save, mock_retry, mock_litellm
    ):
        """Invalid CVSS vector: threat kept with score=None, severity from LLM."""
        inventory = {"components": [], "services": []}
        infrastructure = {"relationships": [], "data_flows": []}
        raw_threats = [
            {"name": "Threat X", "description": "desc", "affected_components": []},
        ]
        threat_analysis = {
            "threat_type": "Spoofing",
            "severity": "High",
            "cvss_vector": "CVSS:4.0/AV:INVALID",
            "cwe_id": ["CWE-287"],
            "mitigation": "Fix auth",
            "category": "Authentication/Authorization",
        }

        responses = [
            _make_llm_response(json.dumps(inventory)),
            _make_llm_response(json.dumps(infrastructure)),
            _make_llm_response(json.dumps(raw_threats)),
            _make_llm_response(json.dumps(threat_analysis)),
        ]
        mock_retry.side_effect = responses
        mock_litellm.completion_cost.return_value = 0.0
        mock_save.return_value = "/tmp/test"

        config = _make_config()
        analyzer = LLMAnalyzer(config)
        result = analyzer.analyze_repository(_make_tf_repo())

        assert result.success is True
        assert len(result.security_findings) == 1

        finding = result.security_findings[0]
        assert finding["score"] is None
        assert finding["cvss"] == []
        assert finding["severity"] == "High"  # LLM fallback

    @patch("tmi_tf.llm_analyzer.litellm")
    @patch("tmi_tf.llm_analyzer.retry_transient_llm_call")
    @patch("tmi_tf.llm_analyzer.save_llm_response")
    def test_all_phase3b_calls_fail_produces_empty_findings(
        self, mock_save, mock_retry, mock_litellm
    ):
        """When all Phase 3b calls fail, result succeeds with empty findings."""
        inventory = {"components": [], "services": []}
        infrastructure = {"relationships": [], "data_flows": []}
        raw_threats = [
            {"name": "Threat A", "description": "desc A", "affected_components": []},
            {"name": "Threat B", "description": "desc B", "affected_components": []},
        ]

        responses = [
            _make_llm_response(json.dumps(inventory)),
            _make_llm_response(json.dumps(infrastructure)),
            _make_llm_response(json.dumps(raw_threats)),
            _make_llm_response("not valid json"),  # Threat A fails
            _make_llm_response("also not json"),   # Threat B fails
        ]
        mock_retry.side_effect = responses
        mock_litellm.completion_cost.return_value = 0.0
        mock_save.return_value = "/tmp/test"

        config = _make_config()
        analyzer = LLMAnalyzer(config)
        result = analyzer.analyze_repository(_make_tf_repo())

        assert result.success is True
        assert result.security_findings == []
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cd /Users/efitz/Projects/tmi-tf-wh && uv run pytest tests/test_llm_analyzer.py -v`
Expected: All 5 tests PASS.

- [ ] **Step 3: Lint**

Run: `cd /Users/efitz/Projects/tmi-tf-wh && uv run ruff check tests/test_llm_analyzer.py && uv run ruff format --check tests/test_llm_analyzer.py`
Expected: No errors.

- [ ] **Step 4: Commit**

```bash
git add tests/test_llm_analyzer.py
git commit -m "test: add tests for Phase 3a/3b decomposition in LLMAnalyzer"
```

---

### Task 7: Delete old files

**Files:**
- Delete: `prompts/security_analysis_system.txt`
- Delete: `prompts/security_analysis_user.txt`
- Delete: `cvss4_score.py`
- Delete: `cvss40_scoring_prompt.md`

- [ ] **Step 1: Delete old prompt files and standalone scripts**

```bash
cd /Users/efitz/Projects/tmi-tf-wh
rm prompts/security_analysis_system.txt prompts/security_analysis_user.txt
rm cvss4_score.py cvss40_scoring_prompt.md
```

- [ ] **Step 2: Run full test suite to verify nothing breaks**

Run: `cd /Users/efitz/Projects/tmi-tf-wh && uv run pytest tests/ -v`
Expected: All tests PASS. The deleted prompt files are NOT used by `threat_processor.py` (which uses `threat_extraction_*.txt`) or by any test.

- [ ] **Step 3: Lint entire project**

Run: `cd /Users/efitz/Projects/tmi-tf-wh && uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/`
Expected: No errors.

- [ ] **Step 4: Type check**

Run: `cd /Users/efitz/Projects/tmi-tf-wh && uv run pyright`
Expected: No new errors.

- [ ] **Step 5: Commit**

```bash
git add prompts/security_analysis_system.txt prompts/security_analysis_user.txt cvss4_score.py cvss40_scoring_prompt.md
git commit -m "chore: remove old Phase 3 prompts and standalone CVSS scripts

Deleted files:
- prompts/security_analysis_system.txt (replaced by threat_identification + threat_analysis prompts)
- prompts/security_analysis_user.txt (replaced by threat_identification + threat_analysis prompts)
- cvss4_score.py (absorbed into tmi_tf/cvss_scorer.py)
- cvss40_scoring_prompt.md (absorbed into prompts/threat_analysis_system.txt)"
```

---

### Task 8: Final verification

- [ ] **Step 1: Run full test suite**

Run: `cd /Users/efitz/Projects/tmi-tf-wh && uv run pytest tests/ -v`
Expected: All tests PASS.

- [ ] **Step 2: Full lint and type check**

Run: `cd /Users/efitz/Projects/tmi-tf-wh && uv run ruff check tmi_tf/ tests/ && uv run ruff format --check tmi_tf/ tests/ && uv run pyright`
Expected: No errors.

- [ ] **Step 3: Verify git status is clean**

Run: `cd /Users/efitz/Projects/tmi-tf-wh && git status`
Expected: Clean working tree, all changes committed.
