"""
LLM-based DFD Generator.

This module uses LLMProvider to generate structured component and flow data
from Terraform analysis structured JSON.
"""

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from tmi_tf.json_extract import extract_json_object
from tmi_tf.providers import LLMProvider
from tmi_tf.retry import retry_transient_llm_call

logger = logging.getLogger(__name__)


class DFDLLMGenerator:
    """Generates structured DFD data using LLM."""

    def __init__(self, llm_provider: LLMProvider):
        """
        Initialize the DFD LLM generator.

        Args:
            llm_provider: LLMProvider instance to use for completions.
        """
        self.llm_provider = llm_provider
        self.provider = llm_provider.provider
        self.model = llm_provider.model
        self.input_tokens = 0
        self.output_tokens = 0
        self.total_cost = 0.0
        self._load_prompt_template()

    def _load_prompt_template(self):
        """Load the DFD generation prompt templates."""
        prompts_dir = Path(__file__).parent.parent / "prompts"
        system_path = prompts_dir / "dfd_generation_system.txt"
        user_path = prompts_dir / "dfd_generation_user.txt"

        try:
            with open(system_path, "r", encoding="utf-8") as f:
                self.system_prompt = f.read()
            with open(user_path, "r", encoding="utf-8") as f:
                self.user_prompt_template = f.read()
            logger.info("Loaded DFD generation prompt templates from %s", prompts_dir)
        except Exception as e:
            logger.error("Failed to load DFD generation prompt templates: %s", e)
            raise

    def generate_structured_components(
        self,
        inventory: Dict[str, Any],
        infrastructure: Dict[str, Any],
    ) -> Optional[Dict[str, List[Dict[str, Any]]]]:
        """
        Generate structured component and flow data from analysis JSON.

        Args:
            inventory: Phase 1 inventory JSON (components, services)
            infrastructure: Phase 2 infrastructure JSON (relationships, flows, boundaries)

        Returns:
            Dictionary with "components" and "flows" keys, or None on error
        """
        logger.info("Generating structured DFD data from analysis using %s", self.model)

        try:
            # Build the user prompt from template with JSON data
            user_prompt = self.user_prompt_template.format(
                inventory_json=json.dumps(inventory, indent=2),
                infrastructure_json=json.dumps(infrastructure, indent=2),
            )

            response = retry_transient_llm_call(
                lambda: self.llm_provider.complete(self.system_prompt, user_prompt, max_tokens=16000, timeout=180.0),
                description="DFD generation",
            )
            self.input_tokens = response.input_tokens
            self.output_tokens = response.output_tokens
            self.total_cost = response.cost
            logger.info("DFD generation: %d input tokens, %d output tokens, $%.4f", self.input_tokens, self.output_tokens, self.total_cost)
            if not response.text:
                logger.error("Empty content in LLM response")
                return None
            response_text = response.text

            # Parse JSON from response
            structured_data = extract_json_object(response_text)

            if not structured_data:
                logger.error("Failed to extract JSON from Claude response")
                return None

            # Strip any markup from all string values
            self._strip_markup(structured_data)

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

    @staticmethod
    def _strip_markup_string(text: str) -> str:
        """Strip markdown and HTML markup from a string.

        Removes: HTML tags, markdown bold/italic (*** / ** / * / __ ),
        backticks, and markdown header prefixes (# ).
        """
        # HTML tags
        text = re.sub(r"<[^>]+>", "", text)
        # Markdown bold/italic markers (*** ** * __ )
        text = re.sub(r"\*{1,3}|_{2}", "", text)
        # Backticks
        text = text.replace("`", "")
        # Markdown header prefixes
        text = re.sub(r"^#{1,6}\s+", "", text)
        return text.strip()

    def _strip_markup(self, data: Any) -> None:
        """Recursively strip markup from all string values in a data structure."""
        if isinstance(data, dict):
            for key in data:
                if isinstance(data[key], str):
                    data[key] = self._strip_markup_string(data[key])
                else:
                    self._strip_markup(data[key])
        elif isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, str):
                    data[i] = self._strip_markup_string(item)
                else:
                    self._strip_markup(item)

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
            "tenant",
            "container",
            "network",
            "gateway",
            "compute",
            "service",
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
