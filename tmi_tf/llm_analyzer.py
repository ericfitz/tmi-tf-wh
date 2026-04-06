"""Unified LLM analyzer for Terraform analysis using LiteLLM.

This module provides a phased analyzer that supports multiple LLM providers
(Anthropic, OpenAI, x.ai, Google Gemini, etc.) through the LiteLLM library.

Analysis runs in sequential phases:
  Phase 1:  Inventory Extraction → inventory JSON
  Phase 2:  Infrastructure Analysis → infrastructure JSON
  Phase 3a: Threat Identification → list of threats (name, description, affected components)
  Phase 3b: Per-Threat Analysis → STRIDE, CVSS 4.0, CWE, mitigation per threat (called N times)
"""

import json
import logging
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from tmi_tf.cvss_scorer import score_cvss4_vector
from tmi_tf.json_extract import extract_json_array, extract_json_object
from tmi_tf.providers import LLMProvider, LLMResponse
from tmi_tf.repo_analyzer import TerraformRepository
from tmi_tf.retry import retry_transient_llm_call

logger = logging.getLogger(__name__)


class TerraformAnalysis:
    """Result of Terraform analysis (3-phase structured output)."""

    def __init__(
        self,
        repo_name: str,
        repo_url: str,
        inventory: Optional[Dict[str, Any]] = None,
        infrastructure: Optional[Dict[str, Any]] = None,
        security_findings: Optional[List[Dict[str, Any]]] = None,
        success: bool = True,
        elapsed_time: float = 0.0,
        input_tokens: int = 0,
        output_tokens: int = 0,
        model: str = "",
        provider: str = "",
        total_cost: float = 0.0,
        error_message: str = "",
        security_input_tokens: int = 0,
        security_output_tokens: int = 0,
        security_cost: float = 0.0,
    ):
        """
        Initialize analysis result.

        Args:
            repo_name: Repository name
            repo_url: Repository URL
            inventory: Phase 1 output - components and services
            infrastructure: Phase 2 output - relationships, flows, boundaries
            security_findings: Phase 3 output - STRIDE-classified threats
            success: Whether analysis was successful
            elapsed_time: Time taken for analysis in seconds
            input_tokens: Number of input tokens sent to LLM (all phases)
            output_tokens: Number of output tokens received from LLM (all phases)
            model: Model used for analysis
            provider: Provider name (anthropic, openai, xai, gemini)
            total_cost: Estimated cost in USD (all phases)
            error_message: Error message if analysis failed
            security_input_tokens: Phase 3 input tokens (for threat metadata)
            security_output_tokens: Phase 3 output tokens (for threat metadata)
            security_cost: Phase 3 cost in USD (for threat metadata)
        """
        self.repo_name = repo_name
        self.repo_url = repo_url
        self.inventory = inventory or {}
        self.infrastructure = infrastructure or {}
        self.security_findings = security_findings or []
        self.success = success
        self.elapsed_time = elapsed_time
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.model = model
        self.provider = provider
        self.total_cost = total_cost
        self.error_message = error_message
        self.security_input_tokens = security_input_tokens
        self.security_output_tokens = security_output_tokens
        self.security_cost = security_cost

    @property
    def analysis_content(self) -> str:
        """Backwards-compatible property that returns error message for failed analyses."""
        if not self.success:
            return self.error_message
        return ""

    def __repr__(self) -> str:
        """Return string representation."""
        status = "success" if self.success else "failed"
        return f"TerraformAnalysis(repo={self.repo_name}, status={status}, model={self.model})"

    def to_dict(self) -> dict:  # type: ignore[type-arg]
        """Convert to dictionary."""
        return {
            "inventory": self.inventory,
            "infrastructure": self.infrastructure,
            "security_findings": self.security_findings,
            "model": self.model,
            "provider": self.provider,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_cost": self.total_cost,
        }


class LLMAnalyzer:
    """Phased LLM analyzer for Terraform files using LiteLLM."""

    def __init__(self, llm_provider: LLMProvider):
        """
        Initialize LLM analyzer.

        Args:
            llm_provider: LLM provider instance to use for completion calls
        """
        self.llm_provider = llm_provider
        self.model = llm_provider.model
        self.provider = llm_provider.provider

        # Load all phase prompts
        self.prompts_dir = Path(__file__).parent.parent / "prompts"
        self._load_phase_prompts()

        logger.info(
            "LLM analyzer initialized: provider=%s, model=%s",
            self.provider,
            self.model,
        )

    def _load_phase_prompts(self) -> None:
        """Load prompt pairs for all analysis phases."""
        self.inventory_system = self._load_prompt("inventory_system.txt")
        self.inventory_user_template = self._load_prompt("inventory_user.txt")
        self.infra_system = self._load_prompt("infrastructure_analysis_system.txt")
        self.infra_user_template = self._load_prompt("infrastructure_analysis_user.txt")
        # Phase 3a: Threat identification
        self.threat_id_system = self._load_prompt("threat_identification_system.txt")
        self.threat_id_user_template = self._load_prompt(
            "threat_identification_user.txt"
        )
        # Phase 3b: Per-threat analysis (STRIDE, CVSS 4.0, CWE, mitigation)
        self.threat_analysis_system = self._load_prompt("threat_analysis_system.txt")
        self.threat_analysis_user_template = self._load_prompt(
            "threat_analysis_user.txt"
        )

    def _load_prompt(self, filename: str) -> str:
        """
        Load prompt from file.

        Args:
            filename: Prompt filename

        Returns:
            Prompt content
        """
        prompt_file = self.prompts_dir / filename
        if prompt_file.exists():
            return prompt_file.read_text(encoding="utf-8")
        else:
            logger.warning("Prompt file not found: %s", prompt_file)
            return ""

    def analyze_repository(
        self,
        terraform_repo: TerraformRepository,
        status_callback: Optional[Callable[[str], None]] = None,
    ) -> TerraformAnalysis:
        """
        Analyze Terraform repository using 3-phase LLM pipeline.

        Phase 1: Inventory Extraction
        Phase 2: Infrastructure Analysis
        Phase 3: Security Analysis

        Args:
            terraform_repo: Terraform repository to analyze

        Returns:
            TerraformAnalysis result with structured JSON from all phases
        """
        logger.info("Analyzing repository: %s", terraform_repo.name)

        total_input_tokens = 0
        total_output_tokens = 0
        total_cost = 0.0
        start_time = time.time()

        try:
            # Get and format Terraform contents
            tf_contents = terraform_repo.get_terraform_content()
            terraform_text = self._format_terraform_contents(tf_contents)

            # Phase 1: Inventory Extraction
            if status_callback:
                status_callback("Phase 1 (Inventory) started")
            logger.info("Phase 1: Extracting inventory for %s", terraform_repo.name)
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

            # Phase 2: Infrastructure Analysis
            if status_callback:
                status_callback("Phase 2 (Infrastructure) started")
            logger.info("Phase 2: Analyzing infrastructure for %s", terraform_repo.name)
            inventory_json_str = json.dumps(inventory, indent=2)
            infra_user = self.infra_user_template.format(
                repo_name=terraform_repo.name,
                repo_url=terraform_repo.url,
                inventory_json=inventory_json_str,
                terraform_contents=terraform_text,
            )

            infrastructure, tokens_in, tokens_out, cost = self._call_llm_json(
                system_prompt=self.infra_system,
                user_prompt=infra_user,
                phase_name="infrastructure",
            )
            total_input_tokens += tokens_in
            total_output_tokens += tokens_out
            total_cost += cost

            if not infrastructure:
                raise ValueError("Phase 2 (infrastructure) returned empty result")

            logger.info(
                "Phase 2 complete: %d relationships, %d data flows",
                len(infrastructure.get("relationships", [])),
                len(infrastructure.get("data_flows", [])),
            )
            if status_callback:
                status_callback("Phase 2 (Infrastructure) complete")

            # Phase 3a: Threat Identification
            if status_callback:
                status_callback("Phase 3a (Threat Identification) started")
            logger.info("Phase 3a: Identifying threats for %s", terraform_repo.name)
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

            logger.info("Phase 3a complete: identified %d threats", len(raw_threats))
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
                    "Phase 3b: Analyzing threat %d/%d: %s",
                    i,
                    len(raw_threats),
                    threat_name,
                )
                if status_callback:
                    status_callback(
                        f"Phase 3b: Analyzing threat {i}/{len(raw_threats)}"
                    )

                try:
                    affected = ", ".join(raw_threat.get("affected_components", []))
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
                            "Phase 3b: Failed to parse analysis for threat "
                            "'%s', skipping",
                            threat_name,
                        )
                        continue

                    # Validate and score CVSS vector
                    cvss_vector = analysis_result.get("cvss_vector", "")
                    cvss_list: List[Dict[str, Any]] = []
                    score: float | None = None
                    severity = analysis_result.get("severity", "Medium")

                    if cvss_vector:
                        cvss_score, cvss_severity, cvss_error = score_cvss4_vector(
                            cvss_vector
                        )
                        if cvss_error:
                            logger.warning(
                                "Phase 3b: Invalid CVSS vector for '%s': %s — %s",
                                threat_name,
                                cvss_vector,
                                cvss_error,
                            )
                        else:
                            score = cvss_score
                            severity = cvss_severity  # type: ignore[assignment]
                            cvss_list = [{"vector": cvss_vector, "score": cvss_score}]

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
                        "Phase 3b: Failed to analyze threat '%s': %s", threat_name, e
                    )
                    continue

            logger.info(
                "Phase 3b complete: %d threats analyzed out of %d identified",
                len(security_findings),
                len(raw_threats),
            )
            if status_callback:
                status_callback("Phase 3 (Security) complete")

            elapsed_time = time.time() - start_time

            logger.info(
                "All phases complete for %s in %.2fs. "
                "Found %d security findings. "
                "Total tokens: %d, Cost: $%.4f",
                terraform_repo.name,
                elapsed_time,
                len(security_findings),
                total_input_tokens + total_output_tokens,
                total_cost,
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

        except Exception as e:
            logger.error("Failed to analyze %s: %s", terraform_repo.name, e)
            elapsed_time = time.time() - start_time
            return TerraformAnalysis(
                repo_name=terraform_repo.name,
                repo_url=terraform_repo.url,
                success=False,
                elapsed_time=elapsed_time,
                input_tokens=total_input_tokens,
                output_tokens=total_output_tokens,
                model=self.model,
                provider=self.provider,
                total_cost=total_cost,
                error_message=f"**Analysis Failed**: {str(e)}",
            )

    def _call_llm(
        self,
        system_prompt: str,
        user_prompt: str,
        phase_name: str,
        max_tokens: int = 16000,
        timeout: float = 300.0,
    ) -> LLMResponse:
        """
        Make a single LLM API call via the provider.

        Args:
            system_prompt: System prompt
            user_prompt: User prompt
            phase_name: Name of the phase (for logging)
            max_tokens: Max output tokens
            timeout: Request timeout in seconds

        Returns:
            LLMResponse with text, tokens, cost, and finish_reason
        """
        logger.info("Phase %s: Calling LLM provider", phase_name)
        response = retry_transient_llm_call(
            lambda: self.llm_provider.complete(
                system_prompt, user_prompt, max_tokens, timeout
            ),
            description=f"Phase {phase_name}",
        )
        logger.info(
            "Phase %s: %d input, %d output tokens, finish_reason=%s, $%.4f",
            phase_name,
            response.input_tokens,
            response.output_tokens,
            response.finish_reason,
            response.cost,
        )
        return response

    def _call_llm_json(
        self,
        system_prompt: str,
        user_prompt: str,
        phase_name: str,
        max_tokens: int = 16000,
        timeout: float = 300.0,
    ) -> tuple[Optional[Dict[str, Any]], int, int, float]:
        """
        Call LLM and parse JSON object response.

        Args:
            system_prompt: System prompt
            user_prompt: User prompt
            phase_name: Name of the phase (for logging)
            max_tokens: Max output tokens
            timeout: Request timeout in seconds

        Returns:
            Tuple of (parsed JSON dict or None, input_tokens, output_tokens, cost)
        """
        response = self._call_llm(
            system_prompt, user_prompt, phase_name, max_tokens, timeout
        )

        if not response.text:
            return None, response.input_tokens, response.output_tokens, response.cost

        parsed = extract_json_object(response.text)
        if not parsed:
            preview = response.text[:500]
            logger.error(
                "Phase %s: Failed to parse JSON object. Length: %d. Preview: %s",
                phase_name,
                len(response.text),
                preview,
            )
        return parsed, response.input_tokens, response.output_tokens, response.cost

    def _call_llm_json_array(
        self,
        system_prompt: str,
        user_prompt: str,
        phase_name: str,
        max_tokens: int = 16000,
        timeout: float = 300.0,
    ) -> tuple[List[Dict[str, Any]], int, int, float]:
        """
        Call LLM and parse JSON array response.

        Args:
            system_prompt: System prompt
            user_prompt: User prompt
            phase_name: Name of the phase (for logging)
            max_tokens: Max output tokens
            timeout: Request timeout in seconds

        Returns:
            Tuple of (parsed JSON list, input_tokens, output_tokens, cost)
        """
        response = self._call_llm(
            system_prompt, user_prompt, phase_name, max_tokens, timeout
        )

        if not response.text:
            return [], response.input_tokens, response.output_tokens, response.cost

        parsed = extract_json_array(response.text)
        if parsed is None:
            logger.error(
                "Phase %s: Failed to parse JSON array from response", phase_name
            )
            return [], response.input_tokens, response.output_tokens, response.cost
        return parsed, response.input_tokens, response.output_tokens, response.cost

    def _format_terraform_contents(self, tf_contents: dict[str, str]) -> str:
        """
        Format Terraform contents for prompt.

        Args:
            tf_contents: Dictionary of file paths to contents

        Returns:
            Formatted string
        """
        if not tf_contents:
            return "(No Terraform files found)"

        sections = []
        for filepath, content in sorted(tf_contents.items()):
            sections.append(f"### File: {filepath}\n```hcl\n{content}\n```\n")

        return "\n".join(sections)

    def estimate_tokens(self, text: str) -> int:
        """
        Rough estimate of token count.

        Args:
            text: Text to estimate

        Returns:
            Estimated token count
        """
        # Rough estimate: ~4 characters per token
        return len(text) // 4


# Keep backward compatibility alias
ClaudeAnalyzer = LLMAnalyzer
