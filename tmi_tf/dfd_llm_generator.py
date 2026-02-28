"""
LLM-based DFD Generator.

This module uses LiteLLM to generate structured component and flow data
from Terraform analysis markdown.
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import litellm

from tmi_tf.config import get_effective_temperature

logger = logging.getLogger(__name__)

# Suppress LiteLLM's verbose logging
litellm.suppress_debug_info = True  # type: ignore[assignment]
litellm.drop_params = True  # type: ignore[assignment]


class DFDLLMGenerator:
    """Generates structured DFD data using LLM."""

    # LiteLLM model prefixes for each provider
    MODEL_PREFIXES = {
        "anthropic": "anthropic/",
        "openai": "openai/",
        "xai": "xai/",
        "gemini": "gemini/",
    }

    def __init__(
        self, config=None, api_key: Optional[str] = None, model: Optional[str] = None
    ):
        """
        Initialize the DFD LLM generator.

        Args:
            config: Application configuration (preferred). If provided, api_key and model are ignored.
            api_key: API key (deprecated, for backwards compatibility)
            model: Model to use (deprecated, for backwards compatibility)
        """
        # Token and cost tracking for this generation
        self.input_tokens = 0
        self.output_tokens = 0
        self.total_cost = 0.0

        if config:
            # New-style initialization with config
            self.provider = getattr(config, "llm_provider", "anthropic")
            from tmi_tf.config import Config

            model_name = config.llm_model or Config.DEFAULT_MODELS.get(
                self.provider, Config.DEFAULT_MODELS["anthropic"]
            )
            self.model = self._normalize_model_name(model_name)
            self._configure_api_keys_from_config(config)
        else:
            # Backwards compatibility: direct api_key and model
            self.provider = "anthropic"
            self.model = model or "anthropic/claude-opus-4-5-20251101"
            if api_key:
                os.environ["ANTHROPIC_API_KEY"] = api_key

        self._load_prompt_template()

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

    def _configure_api_keys_from_config(self, config):
        """Configure API keys for LiteLLM based on the config."""
        if self.provider == "anthropic":
            if hasattr(config, "anthropic_api_key") and config.anthropic_api_key:
                os.environ["ANTHROPIC_API_KEY"] = config.anthropic_api_key
        elif self.provider == "openai":
            if hasattr(config, "openai_api_key") and config.openai_api_key:
                os.environ["OPENAI_API_KEY"] = config.openai_api_key
        elif self.provider == "xai":
            if hasattr(config, "xai_api_key") and config.xai_api_key:
                os.environ["XAI_API_KEY"] = config.xai_api_key
        elif self.provider == "gemini":
            if hasattr(config, "gemini_api_key") and config.gemini_api_key:
                os.environ["GEMINI_API_KEY"] = config.gemini_api_key

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

            # Call LLM API via LiteLLM
            response = litellm.completion(
                model=self.model,
                messages=[{"role": "user", "content": full_prompt}],
                max_tokens=16000,
                temperature=get_effective_temperature(self.model, 0),
                timeout=180.0,
            )

            # Extract token usage from response
            if hasattr(response, "usage") and response.usage:
                self.input_tokens = getattr(response.usage, "prompt_tokens", 0) or 0
                self.output_tokens = (
                    getattr(response.usage, "completion_tokens", 0) or 0
                )
                # Calculate cost using litellm's cost calculator
                try:
                    self.total_cost = litellm.completion_cost(
                        completion_response=response
                    )
                except Exception:
                    self.total_cost = 0.0
                logger.info(
                    f"DFD generation: {self.input_tokens} input tokens, "
                    f"{self.output_tokens} output tokens, ${self.total_cost:.4f}"
                )

            # Extract the response content
            # LiteLLM returns ModelResponse with choices attribute at runtime
            if not getattr(response, "choices", None) or len(response.choices) == 0:  # type: ignore[union-attr]
                logger.error("Empty response from LLM API")
                return None

            response_text = response.choices[0].message.content  # type: ignore[union-attr]
            if not response_text:
                logger.error("Empty content in LLM response")
                return None

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
            "tenant",
            "container",
            "network",
            "network_access_control",
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
