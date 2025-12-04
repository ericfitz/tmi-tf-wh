"""
LLM-based DFD Generator.

This module uses Claude to generate structured component and flow data
from Terraform analysis markdown.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from anthropic import Anthropic

logger = logging.getLogger(__name__)


class DFDLLMGenerator:
    """Generates structured DFD data using Claude LLM."""

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-5"):
        """
        Initialize the DFD LLM generator.

        Args:
            api_key: Anthropic API key
            model: Claude model to use (default: Claude Sonnet 4.5)
        """
        self.client = Anthropic(api_key=api_key)
        self.model = model
        self._load_prompt_template()

    def _load_prompt_template(self):
        """Load the DFD generation prompt template."""
        prompt_path = (
            Path(__file__).parent.parent / "prompts" / "terraform_dfd_generation.txt"
        )

        try:
            with open(prompt_path, "r", encoding="utf-8") as f:
                self.prompt_template = f.read()
            logger.info("Loaded DFD generation prompt template from %s", prompt_path)
        except Exception as e:
            logger.error("Failed to load DFD generation prompt template: %s", e)
            raise

    def generate_structured_components(
        self, analysis_markdown: str
    ) -> Optional[Dict[str, List[Dict[str, Any]]]]:
        """
        Generate structured component and flow data from analysis markdown.

        Args:
            analysis_markdown: The Terraform analysis markdown content

        Returns:
            Dictionary with "components" and "flows" keys, or None on error
        """
        logger.info("Generating structured DFD data from analysis using %s", self.model)

        try:
            # Build the full prompt
            full_prompt = f"{self.prompt_template}\n\n# Infrastructure Analysis\n\n{analysis_markdown}"

            # Call Claude API
            response = self.client.messages.create(
                model=self.model,
                max_tokens=16000,
                temperature=0,  # Deterministic output for structured data
                messages=[{"role": "user", "content": full_prompt}],
            )

            # Extract the response content
            if not response.content or len(response.content) == 0:
                logger.error("Empty response from Claude API")
                return None

            response_text = response.content[0].text

            # Parse JSON from response
            structured_data = self._extract_json(response_text)

            if not structured_data:
                logger.error("Failed to extract JSON from Claude response")
                return None

            # Validate structure
            if not self._validate_structure(structured_data):
                logger.error("Invalid structure in generated data")
                return None

            logger.info(
                "Successfully generated %d components and %d flows",
                len(structured_data.get("components", [])),
                len(structured_data.get("flows", [])),
            )

            return structured_data

        except Exception as e:
            logger.error("Error generating structured DFD data: %s", e)
            return None

    def _extract_json(self, text: str) -> Optional[Dict[str, Any]]:
        """
        Extract JSON from Claude's response.

        Handles both plain JSON and JSON within markdown code blocks.

        Args:
            text: Response text from Claude

        Returns:
            Parsed JSON dictionary or None
        """
        # Try parsing directly first
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try extracting from code block
        import re

        # Look for JSON in code blocks (```json or ```)
        code_block_pattern = r"```(?:json)?\s*\n(.*?)\n```"
        matches = re.findall(code_block_pattern, text, re.DOTALL)

        for match in matches:
            try:
                return json.loads(match)
            except json.JSONDecodeError:
                continue

        # Try finding JSON object in text
        json_pattern = r"\{[\s\S]*\}"
        matches = re.findall(json_pattern, text)

        for match in matches:
            try:
                return json.loads(match)
            except json.JSONDecodeError:
                continue

        return None

    def _validate_structure(self, data: Dict[str, Any]) -> bool:
        """
        Validate the structure of generated data.

        Args:
            data: Parsed JSON data

        Returns:
            True if valid, False otherwise
        """
        # Check top-level structure
        if not isinstance(data, dict):
            logger.error("Data is not a dictionary")
            return False

        if "components" not in data or "flows" not in data:
            logger.error("Missing required keys: components and/or flows")
            return False

        components = data["components"]
        flows = data["flows"]

        if not isinstance(components, list) or not isinstance(flows, list):
            logger.error("components and flows must be lists")
            return False

        # Validate components
        component_ids = set()
        for i, component in enumerate(components):
            if not self._validate_component(component, i):
                return False
            component_ids.add(component["id"])

        # Validate flows
        for i, flow in enumerate(flows):
            if not self._validate_flow(flow, i, component_ids):
                return False

        return True

    def _validate_component(self, component: Dict[str, Any], index: int) -> bool:
        """
        Validate a single component.

        Args:
            component: Component dictionary
            index: Index in the components list (for error messages)

        Returns:
            True if valid, False otherwise
        """
        required_fields = ["id", "name", "type"]

        for field in required_fields:
            if field not in component:
                logger.error("Component %d missing required field: %s", index, field)
                return False

        valid_types = [
            "tenancy",
            "container",
            "network",
            "gateway",
            "compute",
            "storage",
            "actor",
        ]
        if component["type"] not in valid_types:
            logger.error("Component %d has invalid type: %s", index, component["type"])
            return False

        return True

    def _validate_flow(
        self, flow: Dict[str, Any], index: int, component_ids: set
    ) -> bool:
        """
        Validate a single flow.

        Args:
            flow: Flow dictionary
            index: Index in the flows list (for error messages)
            component_ids: Set of valid component IDs

        Returns:
            True if valid, False otherwise
        """
        required_fields = ["id", "source_id", "target_id"]

        for field in required_fields:
            if field not in flow:
                logger.error("Flow %d missing required field: %s", index, field)
                return False

        # Validate source and target exist
        if flow["source_id"] not in component_ids:
            logger.error(
                "Flow %d references non-existent source: %s", index, flow["source_id"]
            )
            return False

        if flow["target_id"] not in component_ids:
            logger.error(
                "Flow %d references non-existent target: %s", index, flow["target_id"]
            )
            return False

        return True
