"""Threat extraction and processing from security analysis."""

import logging
import re
from typing import List, Dict, Any, Union

from anthropic import Anthropic

from tmi_tf.config import Config

logger = logging.getLogger(__name__)


class SecurityThreat:
    """Represents a security threat extracted from analysis."""

    def __init__(
        self,
        name: str,
        description: str,
        threat_type: Union[str, List[str]],
        severity: str = "Medium",
        mitigation: str = None,
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
            self.threat_type = [t.strip() for t in threat_type.split(',') if t.strip()]
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

    def __init__(self, config: Config):
        """
        Initialize threat processor.

        Args:
            config: Application configuration
        """
        self.config = config
        self.client = Anthropic(
            api_key=config.anthropic_api_key,
            timeout=180.0,  # 3 minute timeout for threat extraction
        )
        self.model = "claude-sonnet-4-5"

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
3. Classify the threat using the STRIDE framework. Choose the most appropriate category (or multiple if applicable):
   - Spoofing: Identity impersonation, authentication bypass, credential theft
   - Tampering: Unauthorized modification of data, code, or configuration
   - Repudiation: Inability to prove actions occurred (lack of logging/auditing)
   - Information Disclosure: Unauthorized access to sensitive data, data leakage
   - Denial of Service: Service disruption, resource exhaustion, availability issues
   - Elevation of Privilege: Unauthorized access escalation, privilege abuse
4. Assign severity based on risk:
   - Critical: Immediate exploitation risk with severe impact
   - High: Significant security risk requiring urgent attention
   - Medium: Moderate risk that should be addressed
   - Low: Minor risk or defense-in-depth improvement
5. Suggest specific, actionable mitigation strategies

IMPORTANT: The threat_type field must contain one or more STRIDE categories separated by commas.
Examples: "Information Disclosure", "Tampering, Elevation of Privilege", "Denial of Service"

Return your response as a JSON array of threat objects with this structure:
[
  {
    "name": "Brief threat title",
    "description": "Detailed threat description including risk and impact",
    "threat_type": "One or more STRIDE categories (comma-separated)",
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
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=system_prompt,
                messages=[
                    {
                        "role": "user",
                        "content": user_prompt,
                    }
                ],
            )

            # Extract JSON from response
            response_text = response.content[0].text.strip()

            # Try to find JSON array in the response
            json_match = re.search(r"\[[\s\S]*\]", response_text)
            if not json_match:
                logger.warning(
                    f"No JSON array found in Claude response for {repo_name}"
                )
                return []

            import json

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
        diagram_id: str = None,
    ) -> List[Dict[str, Any]]:
        """
        Create threat objects in TMI threat model.

        Args:
            threats: List of SecurityThreat objects to create
            threat_model_id: TMI threat model UUID
            tmi_client: TMIClientWrapper instance
            diagram_id: Optional diagram UUID to associate threats with

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
