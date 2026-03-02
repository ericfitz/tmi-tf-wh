"""Threat extraction and processing from security analysis."""

import json
import logging
import os
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Union, cast

import litellm  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]
from litellm import ModelResponse  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

from tmi_tf.config import Config, save_llm_response
from tmi_tf.retry import retry_transient_llm_call

logger = logging.getLogger(__name__)

# Suppress LiteLLM's verbose logging
litellm.suppress_debug_info = True  # type: ignore[assignment]
litellm.drop_params = True  # type: ignore[assignment]


class SecurityThreat:
    """Represents a security threat extracted from analysis."""

    def __init__(
        self,
        name: str,
        description: str,
        threat_type: Union[str, List[str]],
        severity: str = "Medium",
        score: Optional[float] = None,
        cvss: Optional[List[Dict[str, Any]]] = None,
        cwe_id: Optional[List[str]] = None,
        mitigation: Optional[str] = None,
        affected_components: Optional[List[str]] = None,
        status: str = "Open",
    ):
        """
        Initialize security threat.

        Args:
            name: Threat name/title
            description: Detailed description of the threat
            threat_type: Type/category of threat (STRIDE classification as string or list)
            severity: Severity level (Critical, High, Medium, Low)
            score: CVSS base score (0.0-10.0)
            cvss: List of CVSS vector/score dicts
            cwe_id: List of CWE identifiers (e.g., ["CWE-284"])
            mitigation: Recommended mitigation strategies
            affected_components: List of affected infrastructure component names
            status: Threat status (Open, In Progress, Resolved, Accepted)
        """
        self.name = name
        self.description = description
        # Convert threat_type to list if it's a string
        if isinstance(threat_type, str):
            # Split comma-separated values and strip whitespace
            self.threat_type = [t.strip() for t in threat_type.split(",") if t.strip()]
        else:
            self.threat_type = threat_type
        self.severity = severity
        self.score = score
        self.cvss = cvss or []
        self.cwe_id = cwe_id or []
        self.mitigation = mitigation
        self.affected_components = affected_components or []
        self.status = status

    def __repr__(self) -> str:
        """Return string representation."""
        return f"SecurityThreat(name={self.name}, severity={self.severity}, type={self.threat_type})"


class ThreatProcessor:
    """Processes analysis content to extract and structure security threats."""

    # LiteLLM model prefixes for each provider
    MODEL_PREFIXES = {
        "anthropic": "anthropic/",
        "openai": "openai/",
        "xai": "xai/",
        "gemini": "gemini/",
    }

    def __init__(self, config: Config):
        """
        Initialize threat processor.

        Args:
            config: Application configuration
        """
        self.config = config
        self.provider = getattr(config, "llm_provider", "anthropic")
        model_name = config.llm_model or Config.DEFAULT_MODELS.get(
            self.provider, Config.DEFAULT_MODELS["anthropic"]
        )
        self.model = self._normalize_model_name(model_name)
        self._configure_api_keys()
        self._load_prompts()

        # Token and cost tracking for threat extraction
        self.input_tokens = 0
        self.output_tokens = 0
        self.total_cost = 0.0

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
        if prefix:
            return f"{prefix}{model}"
        return model

    def _load_prompts(self):
        """Load threat extraction prompts from files."""
        prompts_dir = Path(__file__).parent.parent / "prompts"
        system_path = prompts_dir / "threat_extraction_system.txt"
        user_path = prompts_dir / "threat_extraction_user.txt"

        try:
            self.system_prompt = system_path.read_text(encoding="utf-8")
            self.user_prompt_template = user_path.read_text(encoding="utf-8")
            logger.info("Loaded threat extraction prompts from %s", prompts_dir)
        except FileNotFoundError as e:
            logger.warning(
                "Threat extraction prompt file not found: %s, using defaults", e
            )
            self.system_prompt = self._get_default_system_prompt()
            self.user_prompt_template = self._get_default_user_prompt()

    def _get_default_system_prompt(self) -> str:
        """Return default system prompt if file not found."""
        return (
            "You are a security threat modeling expert specializing in the STRIDE framework. "
            "Extract and structure security threats from infrastructure analysis content. "
            "Return ONLY a JSON array of threat objects with fields: name, description, "
            "threat_type, severity, score, mitigation, affected_components."
        )

    def _get_default_user_prompt(self) -> str:
        """Return default user prompt template if file not found."""
        return (
            'Analyze the following infrastructure security analysis for repository "{repo_name}" '
            "and extract all security threats.\n\nAnalysis Content:\n---\n{analysis_content}\n---\n\n"
            "Extract and structure all security threats. Respond with ONLY the JSON array."
        )

    def _configure_api_keys(self):
        """Configure API keys for LiteLLM based on the selected provider."""
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

    def extract_threats_from_analysis(
        self, analysis_content: str, repo_name: str
    ) -> List[SecurityThreat]:
        """
        Extract structured threats from analysis markdown content using Claude.

        Args:
            analysis_content: Markdown content from Terraform analysis
            repo_name: Repository name for context

        Returns:
            List of SecurityThreat objects
        """
        logger.info(f"Extracting threats from analysis for {repo_name}")

        # Build prompts from templates
        system_prompt = self.system_prompt
        user_prompt = self.user_prompt_template.format(
            repo_name=repo_name,
            analysis_content=analysis_content,
        )

        try:
            response = cast(
                ModelResponse,
                retry_transient_llm_call(
                    lambda: litellm.completion(
                        model=self.model,
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt},
                        ],
                        max_tokens=16000,
                        timeout=180.0,
                    ),
                    description=f"Threat extraction for {repo_name}",
                ),
            )

            # Extract token usage from response and accumulate
            usage = getattr(response, "usage", None)
            if usage:
                self.input_tokens += getattr(usage, "prompt_tokens", 0) or 0
                self.output_tokens += getattr(usage, "completion_tokens", 0) or 0
                # Calculate cost using litellm's cost calculator
                try:
                    call_cost = litellm.completion_cost(completion_response=response)
                    self.total_cost += call_cost
                except Exception:
                    pass
                logger.info(
                    f"Threat extraction for {repo_name}: "
                    f"{getattr(usage, 'prompt_tokens', 0)} input tokens, "
                    f"{getattr(usage, 'completion_tokens', 0)} output tokens"
                )

            # Extract JSON from response
            content = response.choices[0].message.content  # type: ignore[union-attr]
            if not content:
                logger.warning(f"Empty response from LLM for {repo_name}")
                return []
            response_text = content.strip()

            # Save response to file for debugging
            response_file = save_llm_response(response_text, f"threats_{repo_name}")
            logger.debug(f"Threat extraction response saved to {response_file}")

            # Try to find JSON array in the response
            json_match = re.search(r"\[[\s\S]*\]", response_text)
            if not json_match:
                logger.warning(f"No JSON array found in LLM response for {repo_name}")
                return []

            threats_data = json.loads(json_match.group(0))

            # Convert to SecurityThreat objects
            threats = []
            for threat_data in threats_data:
                threat = SecurityThreat(
                    name=threat_data.get("name", "Unnamed Threat"),
                    description=threat_data.get("description", ""),
                    threat_type=threat_data.get("threat_type", "Unclassified"),
                    severity=threat_data.get("severity", "Medium"),
                    score=threat_data.get("score"),
                    cvss=threat_data.get("cvss"),
                    cwe_id=threat_data.get("cwe_id"),
                    mitigation=threat_data.get("mitigation"),
                    affected_components=threat_data.get("affected_components"),
                    status="Open",
                )
                threats.append(threat)

            logger.info(f"Extracted {len(threats)} threats from {repo_name}")
            return threats

        except Exception as e:
            logger.error(f"Failed to extract threats from analysis: {e}")
            return []

    def threats_from_findings(
        self,
        findings: List[Dict[str, Any]],
        repo_name: str,
    ) -> List[SecurityThreat]:
        """
        Convert structured security findings (from Phase 3 JSON) into SecurityThreat objects.

        This skips the LLM call since the findings are already structured.

        Args:
            findings: List of security finding dicts from Phase 3 analysis
            repo_name: Repository name for logging

        Returns:
            List of SecurityThreat objects
        """
        logger.info(f"Converting {len(findings)} structured findings for {repo_name}")
        threats = []
        for finding in findings:
            threat = SecurityThreat(
                name=finding.get("name", "Unnamed Threat"),
                description=finding.get("description", ""),
                threat_type=finding.get("threat_type", "Unclassified"),
                severity=finding.get("severity", "Medium"),
                score=finding.get("score"),
                cvss=finding.get("cvss"),
                cwe_id=finding.get("cwe_id"),
                mitigation=finding.get("mitigation"),
                affected_components=finding.get("affected_components"),
                status="Open",
            )
            threats.append(threat)
        logger.info(f"Converted {len(threats)} threats from {repo_name}")
        return threats

    def create_threats_in_tmi(
        self,
        threats: List[SecurityThreat],
        threat_model_id: str,
        tmi_client,
        diagram_id: Optional[str] = None,
        metadata: Optional[List[Dict[str, str]]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Create threat objects in TMI threat model.

        Args:
            threats: List of SecurityThreat objects to create
            threat_model_id: TMI threat model UUID
            tmi_client: TMIClientWrapper instance
            diagram_id: Optional diagram UUID to associate threats with
            metadata: Optional list of metadata dicts with 'key' and 'value' keys

        Returns:
            List of created threat dicts
        """
        logger.info(
            f"Creating {len(threats)} threats in threat model {threat_model_id}"
        )

        created_threats = []
        for threat in threats:
            try:
                created_threat = tmi_client.create_threat(
                    threat_model_id=threat_model_id,
                    name=threat.name,
                    threat_type=threat.threat_type,
                    description=threat.description,
                    mitigation=threat.mitigation,
                    severity=threat.severity,
                    score=threat.score,
                    cvss=threat.cvss,
                    cwe_id=threat.cwe_id,
                    status=threat.status,
                    diagram_id=diagram_id,
                    metadata=metadata,
                )
                created_threats.append(created_threat)
                logger.info(f"Created threat: {threat.name}")
            except Exception as e:
                logger.error(f"Failed to create threat '{threat.name}': {e}")
                # Continue with next threat
                continue

        logger.info(
            f"Successfully created {len(created_threats)} out of {len(threats)} threats"
        )
        return created_threats
