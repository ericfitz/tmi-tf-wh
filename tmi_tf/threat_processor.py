"""Threat extraction and processing from security analysis."""

import logging
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Union

from tmi_tf.cwe_699 import CWE_699_IDS
from tmi_tf.json_extract import extract_json_array
from tmi_tf.providers import LLMProvider
from tmi_tf.retry import retry_transient_llm_call

logger = logging.getLogger(__name__)

_CWE_RE = re.compile(r"^CWE-(\d+)$")


def filter_valid_cwe_ids(cwe_ids: List[str]) -> List[str]:
    """Filter CWE IDs to only those in the CWE-699 (non-category) view.

    Invalid or unrecognised IDs are logged and dropped.
    """
    valid: List[str] = []
    for cid in cwe_ids:
        m = _CWE_RE.match(cid)
        if not m:
            logger.warning("Dropping malformed CWE identifier: %s", cid)
            continue
        num = int(m.group(1))
        if num not in CWE_699_IDS:
            logger.warning("Dropping CWE-%d: not in CWE-699 view", num)
            continue
        valid.append(cid)
    return valid


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
        self.cwe_id = filter_valid_cwe_ids(cwe_id) if cwe_id else []
        self.mitigation = mitigation
        self.affected_components = affected_components or []
        self.status = status

    def __repr__(self) -> str:
        """Return string representation."""
        return f"SecurityThreat(name={self.name}, severity={self.severity}, type={self.threat_type})"


class ThreatProcessor:
    """Processes analysis content to extract and structure security threats."""

    def __init__(self, llm_provider: LLMProvider):
        """
        Initialize threat processor.

        Args:
            llm_provider: LLM provider instance
        """
        self.llm_provider = llm_provider
        self._load_prompts()

        # Token and cost tracking for threat extraction
        self.input_tokens = 0
        self.output_tokens = 0
        self.total_cost = 0.0

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

    def extract_threats_from_analysis(
        self, analysis_content: str, repo_name: str
    ) -> List[SecurityThreat]:
        """
        Extract structured threats from analysis markdown content using LLM.

        Args:
            analysis_content: Markdown content from Terraform analysis
            repo_name: Repository name for context

        Returns:
            List of SecurityThreat objects
        """
        logger.info(f"Extracting threats from analysis for {repo_name}")
        system_prompt = self.system_prompt
        user_prompt = self.user_prompt_template.format(
            repo_name=repo_name, analysis_content=analysis_content
        )
        try:
            response = retry_transient_llm_call(
                lambda: self.llm_provider.complete(
                    system_prompt, user_prompt, max_tokens=16000, timeout=180.0
                ),
                description=f"Threat extraction for {repo_name}",
            )
            self.input_tokens += response.input_tokens
            self.output_tokens += response.output_tokens
            self.total_cost += response.cost
            logger.info(
                "Threat extraction for %s: %d input tokens, %d output tokens",
                repo_name,
                response.input_tokens,
                response.output_tokens,
            )
            if not response.text:
                logger.warning("Empty response from LLM for %s", repo_name)
                return []
            threats_data = extract_json_array(response.text)
            if not threats_data:
                logger.warning("No JSON array found in LLM response for %s", repo_name)
                return []
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
            logger.info("Extracted %d threats from %s", len(threats), repo_name)
            return threats
        except Exception as e:
            logger.error("Failed to extract threats from analysis: %s", e)
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
