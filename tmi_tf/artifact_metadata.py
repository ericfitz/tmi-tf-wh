"""Artifact metadata generation for TMI resources.

This module provides utilities for generating consistent metadata
for all artifacts created by tmi-tf (notes, diagrams, threats).
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List


# Version identifier for tmi-tf
TMI_TF_VERSION = "0.1.0"


@dataclass
class ArtifactMetadata:
    """Metadata for an artifact created by tmi-tf."""

    creation_agent: str = "tmi-tf"
    creation_timestamp: str = ""
    llm_provider: str = ""
    llm_model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    cost_estimate_usd: float = 0.0

    def __post_init__(self):
        """Set creation timestamp if not provided."""
        if not self.creation_timestamp:
            self.creation_timestamp = get_rfc3339_timestamp()

    def to_metadata_list(self) -> List[dict]:
        """
        Convert to list of metadata key-value dicts for TMI API.

        Returns:
            List of dicts with 'key' and 'value' keys
        """
        return [
            {"key": "creation-agent", "value": self.creation_agent},
            {"key": "creation-timestamp", "value": self.creation_timestamp},
            {"key": "llm-provider", "value": self.llm_provider},
            {"key": "llm-model", "value": self.llm_model},
            {"key": "input-tokens", "value": str(self.input_tokens)},
            {"key": "output-tokens", "value": str(self.output_tokens)},
            {"key": "cost-estimate-usd", "value": f"{self.cost_estimate_usd:.3f}"},
        ]


def get_rfc3339_timestamp() -> str:
    """
    Get current timestamp in RFC3339 format with 0 decimal precision on seconds.

    Returns:
        Timestamp string like '2025-12-29T10:30:45+00:00'
    """
    now = datetime.now(timezone.utc)
    # Format with 0 decimal precision on seconds
    return now.strftime("%Y-%m-%dT%H:%M:%S%z")


def create_artifact_metadata(
    provider: str,
    model: str,
    input_tokens: int = 0,
    output_tokens: int = 0,
    cost_estimate_usd: float = 0.0,
) -> ArtifactMetadata:
    """
    Create artifact metadata with the given LLM information.

    Args:
        provider: LLM provider name (e.g., 'anthropic', 'openai')
        model: LLM model name (e.g., 'claude-opus-4-6')
        input_tokens: Number of input tokens used
        output_tokens: Number of output tokens generated
        cost_estimate_usd: Estimated cost in USD

    Returns:
        ArtifactMetadata instance
    """
    return ArtifactMetadata(
        creation_agent="tmi-tf",
        creation_timestamp=get_rfc3339_timestamp(),
        llm_provider=provider,
        llm_model=model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cost_estimate_usd=cost_estimate_usd,
    )


def aggregate_analysis_metadata(
    analyses: List,
    provider: str,
    model: str,
) -> ArtifactMetadata:
    """
    Create aggregated metadata from multiple analysis results.

    Args:
        analyses: List of TerraformAnalysis objects
        provider: LLM provider name
        model: LLM model name

    Returns:
        ArtifactMetadata with aggregated token counts and costs
    """
    total_input_tokens = sum(
        getattr(a, "input_tokens", 0) for a in analyses if getattr(a, "success", False)
    )
    total_output_tokens = sum(
        getattr(a, "output_tokens", 0) for a in analyses if getattr(a, "success", False)
    )
    total_cost = sum(
        getattr(a, "total_cost", 0.0) for a in analyses if getattr(a, "success", False)
    )

    return ArtifactMetadata(
        creation_agent="tmi-tf",
        creation_timestamp=get_rfc3339_timestamp(),
        llm_provider=provider,
        llm_model=model,
        input_tokens=total_input_tokens,
        output_tokens=total_output_tokens,
        cost_estimate_usd=total_cost,
    )
