"""Unified LLM analyzer for Terraform analysis using LiteLLM.

This module provides a phased analyzer that supports multiple LLM providers
(Anthropic, OpenAI, x.ai, Google Gemini, etc.) through the LiteLLM library.

Analysis runs in 3 sequential phases:
  Phase 1: Inventory Extraction → inventory JSON
  Phase 2: Infrastructure Analysis → infrastructure JSON
  Phase 3: Security Analysis → security findings JSON
"""

import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import litellm  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

from tmi_tf.retry import retry_transient_llm_call

from tmi_tf.config import save_llm_response
from tmi_tf.repo_analyzer import TerraformRepository

logger = logging.getLogger(__name__)

# Suppress LiteLLM's verbose logging
litellm.suppress_debug_info = True  # type: ignore[assignment]
litellm.drop_params = True  # type: ignore[assignment]


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

    def to_dict(self) -> dict:
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

    # Default models for each provider
    DEFAULT_MODELS = {
        "anthropic": "claude-opus-4-5-20251101",
        "openai": "gpt-5.2",
        "xai": "xai/grok-4-1-fast-non-reasoning",
        "gemini": "gemini/gemini-2.0-flash",
    }

    # LiteLLM model prefixes for each provider
    MODEL_PREFIXES = {
        "anthropic": "anthropic/",
        "openai": "openai/",
        "xai": "xai/",
        "gemini": "gemini/",
    }

    def __init__(self, config):
        """
        Initialize LLM analyzer.

        Args:
            config: Application configuration with LLM provider settings
        """
        self.config = config
        self.provider = getattr(config, "llm_provider", "anthropic")

        # Determine the model to use
        if hasattr(config, "llm_model") and config.llm_model:
            self.model = self._normalize_model_name(config.llm_model)
        else:
            self.model = self.DEFAULT_MODELS.get(
                self.provider, self.DEFAULT_MODELS["anthropic"]
            )

        # Set up API keys for LiteLLM based on provider
        self._configure_api_keys()

        # Load all phase prompts
        self.prompts_dir = Path(__file__).parent.parent / "prompts"
        self._load_phase_prompts()

        logger.info(
            f"LLM analyzer initialized: provider={self.provider}, model={self.model}"
        )

    def _load_phase_prompts(self):
        """Load prompt pairs for all 3 analysis phases."""
        self.inventory_system = self._load_prompt("inventory_system.txt")
        self.inventory_user_template = self._load_prompt("inventory_user.txt")
        self.infra_system = self._load_prompt("infrastructure_analysis_system.txt")
        self.infra_user_template = self._load_prompt("infrastructure_analysis_user.txt")
        self.security_system = self._load_prompt("security_analysis_system.txt")
        self.security_user_template = self._load_prompt("security_analysis_user.txt")

    def _normalize_model_name(self, model: str) -> str:
        """
        Normalize model name to include proper LiteLLM prefix.

        Args:
            model: Model name from config

        Returns:
            Normalized model name with appropriate prefix
        """
        # If model already has a prefix, return as-is
        if "/" in model:
            return model

        # Add prefix based on provider
        prefix = self.MODEL_PREFIXES.get(self.provider, "")
        if prefix and not model.startswith(prefix):
            return f"{prefix}{model}"
        return model

    def _configure_api_keys(self):
        """Configure API keys for LiteLLM based on the selected provider."""
        import os

        if self.provider == "anthropic":
            if (
                hasattr(self.config, "anthropic_api_key")
                and self.config.anthropic_api_key
            ):
                os.environ["ANTHROPIC_API_KEY"] = self.config.anthropic_api_key
        elif self.provider == "openai":
            if hasattr(self.config, "openai_api_key") and self.config.openai_api_key:
                os.environ["OPENAI_API_KEY"] = self.config.openai_api_key
        elif self.provider == "xai":
            if hasattr(self.config, "xai_api_key") and self.config.xai_api_key:
                os.environ["XAI_API_KEY"] = self.config.xai_api_key
        elif self.provider == "gemini":
            if hasattr(self.config, "gemini_api_key") and self.config.gemini_api_key:
                os.environ["GEMINI_API_KEY"] = self.config.gemini_api_key

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
            logger.warning(f"Prompt file not found: {prompt_file}")
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
        logger.info(f"Analyzing repository: {terraform_repo.name}")

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
            logger.info(f"Phase 1: Extracting inventory for {terraform_repo.name}")
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
                raise ValueError("Phase 1 (inventory) returned empty result")

            logger.info(
                f"Phase 1 complete: {len(inventory.get('components', []))} components, "
                f"{len(inventory.get('services', []))} services"
            )
            if status_callback:
                status_callback("Phase 1 (Inventory) complete")

            # Phase 2: Infrastructure Analysis
            if status_callback:
                status_callback("Phase 2 (Infrastructure) started")
            logger.info(f"Phase 2: Analyzing infrastructure for {terraform_repo.name}")
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
                f"Phase 2 complete: {len(infrastructure.get('relationships', []))} relationships, "
                f"{len(infrastructure.get('data_flows', []))} data flows"
            )
            if status_callback:
                status_callback("Phase 2 (Infrastructure) complete")

            # Phase 3: Security Analysis
            if status_callback:
                status_callback("Phase 3 (Security) started")
            logger.info(f"Phase 3: Security analysis for {terraform_repo.name}")
            infrastructure_json_str = json.dumps(infrastructure, indent=2)
            security_user = self.security_user_template.format(
                repo_name=terraform_repo.name,
                repo_url=terraform_repo.url,
                inventory_json=inventory_json_str,
                infrastructure_json=infrastructure_json_str,
                terraform_contents=terraform_text,
            )

            security_findings, sec_tokens_in, sec_tokens_out, sec_cost = (
                self._call_llm_json_array(
                    system_prompt=self.security_system,
                    user_prompt=security_user,
                    phase_name="security",
                )
            )
            total_input_tokens += sec_tokens_in
            total_output_tokens += sec_tokens_out
            total_cost += sec_cost

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

        except Exception as e:
            logger.error(f"Failed to analyze {terraform_repo.name}: {e}")
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
        response_text, tokens_in, tokens_out, cost = self._call_llm(
            system_prompt, user_prompt, phase_name, max_tokens, timeout
        )

        if not response_text:
            return None, tokens_in, tokens_out, cost

        parsed = self._extract_json_object(response_text)
        if not parsed:
            logger.error(
                f"Phase {phase_name}: Failed to parse JSON object from response"
            )
        return parsed, tokens_in, tokens_out, cost

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
        response_text, tokens_in, tokens_out, cost = self._call_llm(
            system_prompt, user_prompt, phase_name, max_tokens, timeout
        )

        if not response_text:
            return [], tokens_in, tokens_out, cost

        parsed = self._extract_json_array(response_text)
        if parsed is None:
            logger.error(
                f"Phase {phase_name}: Failed to parse JSON array from response"
            )
            return [], tokens_in, tokens_out, cost
        return parsed, tokens_in, tokens_out, cost

    def _call_llm(
        self,
        system_prompt: str,
        user_prompt: str,
        phase_name: str,
        max_tokens: int = 16000,
        timeout: float = 300.0,
    ) -> tuple[Optional[str], int, int, float]:
        """
        Make a single LLM API call via LiteLLM.

        Args:
            system_prompt: System prompt
            user_prompt: User prompt
            phase_name: Name of the phase (for logging)
            max_tokens: Max output tokens
            timeout: Request timeout in seconds

        Returns:
            Tuple of (response text or None, input_tokens, output_tokens, cost)
        """
        logger.info(f"Phase {phase_name}: Calling {self.provider} ({self.model})...")

        response = retry_transient_llm_call(
            lambda: litellm.completion(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                max_tokens=max_tokens,
                timeout=timeout,
            ),
            description=f"Phase {phase_name}",
        )

        # Extract token usage
        usage = getattr(response, "usage", None)
        tokens_in = usage.prompt_tokens if usage else 0
        tokens_out = usage.completion_tokens if usage else 0

        # Calculate cost
        try:
            cost = litellm.completion_cost(completion_response=response)
        except Exception:
            cost = 0.0

        logger.info(
            f"Phase {phase_name}: {tokens_in} input, {tokens_out} output tokens, "
            f"${cost:.4f}"
        )

        # LiteLLM returns ModelResponse with choices attribute at runtime
        content = response.choices[0].message.content  # type: ignore[union-attr]
        if not content:
            logger.warning(f"Phase {phase_name}: Empty response from LLM")
            return None, tokens_in, tokens_out, cost

        # Save response to file for debugging
        response_file = save_llm_response(content, phase_name)
        logger.debug(f"Phase {phase_name}: Response saved to {response_file}")

        return content.strip(), tokens_in, tokens_out, cost

    def _extract_json_object(self, text: str) -> Optional[Dict[str, Any]]:
        """
        Extract a JSON object from LLM response text.

        Handles plain JSON, JSON in code blocks, and JSON embedded in text.

        Args:
            text: Response text

        Returns:
            Parsed JSON dict or None
        """
        # Try parsing directly
        try:
            result = json.loads(text)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

        # Try extracting from code block
        code_block_pattern = r"```(?:json)?\s*\n(.*?)\n```"
        matches = re.findall(code_block_pattern, text, re.DOTALL)
        for match in matches:
            try:
                result = json.loads(match)
                if isinstance(result, dict):
                    return result
            except json.JSONDecodeError:
                continue

        # Try finding JSON object in text
        json_pattern = r"\{[\s\S]*\}"
        matches = re.findall(json_pattern, text)
        for match in matches:
            try:
                result = json.loads(match)
                if isinstance(result, dict):
                    return result
            except json.JSONDecodeError:
                continue

        return None

    def _extract_json_array(self, text: str) -> Optional[List[Dict[str, Any]]]:
        """
        Extract a JSON array from LLM response text.

        Args:
            text: Response text

        Returns:
            Parsed JSON list or None
        """
        # Try parsing directly
        try:
            result = json.loads(text)
            if isinstance(result, list):
                return result
        except json.JSONDecodeError:
            pass

        # Try extracting from code block
        code_block_pattern = r"```(?:json)?\s*\n(.*?)\n```"
        matches = re.findall(code_block_pattern, text, re.DOTALL)
        for match in matches:
            try:
                result = json.loads(match)
                if isinstance(result, list):
                    return result
            except json.JSONDecodeError:
                continue

        # Try finding JSON array in text
        json_match = re.search(r"\[[\s\S]*\]", text)
        if json_match:
            try:
                result = json.loads(json_match.group(0))
                if isinstance(result, list):
                    return result
            except json.JSONDecodeError:
                pass

        return None

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
