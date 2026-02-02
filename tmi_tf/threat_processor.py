"""Threat extraction and processing from security analysis."""

import json
import logging
import os
import re
from typing import List, Dict, Any, Optional, Union

import litellm

from tmi_tf.config import Config

logger = logging.getLogger(__name__)

# Suppress LiteLLM's verbose logging
litellm.suppress_debug_info = True  # type: ignore[assignment]


class SecurityThreat:
    """Represents a security threat extracted from analysis."""

    def __init__(
        self,
        name: str,
        description: str,
        threat_type: Union[str, List[str]],
        severity: str = "Medium",
        mitigation: Optional[str] = None,
        status: str = "Open",
    ):
        """
        Initialize security threat.

        Args:
            name: Threat name/title
            description: Detailed description of the threat
            threat_type: Type/category of threat (STRIDE classification as string or list)
            severity: Severity level (Critical, High, Medium, Low)
            mitigation: Recommended mitigation strategies
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
        self.mitigation = mitigation
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

        # Build prompt for threat extraction
        system_prompt = """You are a security threat modeling expert specializing in the STRIDE framework. Your task is to extract and structure security threats from infrastructure analysis content.

For each security issue or concern mentioned in the analysis:
1. Create a clear, concise threat name (max 100 characters)
2. Provide a detailed description of the threat and risk
3. Classify the threat using the STRIDE framework by evaluating ALL categories and including EVERY applicable one:

   STRIDE Category Evaluation Questions:
   - Spoofing (Authenticity): Could an attacker impersonate a valid user, system, or process?
   - Tampering (Integrity): Could an attacker modify data, code, or configurations without authorization?
   - Repudiation (Non-repudiability): Could a user or system deny having performed a specific action, and would you have proof otherwise (e.g., via logs)?
   - Information Disclosure (Confidentiality): Could an attacker gain unauthorized access to sensitive data?
   - Denial of Service (Availability): Could an attacker disrupt the system's availability or performance for legitimate users?
   - Elevation of Privilege (Authorization): Could an attacker gain higher privileges or permissions than they are entitled to?

   IMPORTANT: A single threat may violate multiple security properties. Include ALL applicable STRIDE categories.
   Examples:
   - Missing authentication AND exposed data → "Spoofing, Information Disclosure"
   - Modifiable config file with admin access → "Tampering, Elevation of Privilege"
   - Unencrypted data that can be modified → "Information Disclosure, Tampering"

4. Assign severity based on risk:
   - Critical: Immediate exploitation risk with severe impact
   - High: Significant security risk requiring urgent attention
   - Medium: Moderate risk that should be addressed
   - Low: Minor risk or defense-in-depth improvement
5. Suggest specific, actionable mitigation strategies

Return your response as a JSON array of threat objects with this structure:
[
  {
    "name": "Brief threat title",
    "description": "Detailed threat description including risk and impact",
    "threat_type": "Comma-separated list of ALL applicable STRIDE categories",
    "severity": "Critical|High|Medium|Low",
    "mitigation": "Recommended mitigation strategies"
  }
]

If no security threats are found, return an empty array: []"""

        user_prompt = f"""Analyze the following infrastructure security analysis for repository "{repo_name}" and extract all security threats.

Focus on the Security Observations section and any other security concerns mentioned in the analysis.

Analysis Content:
---
{analysis_content}
---

Extract and structure all security threats found in this analysis."""

        try:
            response = litellm.completion(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                max_tokens=4096,
                temperature=0.3,
                timeout=180.0,
            )

            # Extract token usage from response and accumulate
            if hasattr(response, "usage") and response.usage:
                self.input_tokens += getattr(response.usage, "prompt_tokens", 0) or 0
                self.output_tokens += (
                    getattr(response.usage, "completion_tokens", 0) or 0
                )
                # Calculate cost using litellm's cost calculator
                try:
                    call_cost = litellm.completion_cost(completion_response=response)
                    self.total_cost += call_cost
                except Exception:
                    pass
                logger.info(
                    f"Threat extraction for {repo_name}: "
                    f"{getattr(response.usage, 'prompt_tokens', 0)} input tokens, "
                    f"{getattr(response.usage, 'completion_tokens', 0)} output tokens"
                )

            # Extract JSON from response
            # LiteLLM returns ModelResponse with choices attribute at runtime
            content = response.choices[0].message.content  # type: ignore[union-attr]
            if not content:
                logger.warning(f"Empty response from LLM for {repo_name}")
                return []
            response_text = content.strip()

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
                    mitigation=threat_data.get("mitigation"),
                    status="Open",
                )
                threats.append(threat)

            logger.info(f"Extracted {len(threats)} threats from {repo_name}")
            return threats

        except Exception as e:
            logger.error(f"Failed to extract threats from analysis: {e}")
            return []

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
