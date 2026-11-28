"""Artifact metadata generation for TMI resources.

This module provides utilities for generating consistent metadata
for all artifacts created by tmi-tf (notes, diagrams, threats).
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from tmi_tf.cell_schema import clean_metadata

# Version identifier for tmi-tf
TMI_TF_VERSION = "0.1.0"

# Metadata key carrying the creating job's run id (#115)
RUN_ID_KEY = "run_id"


@dataclass
class ArtifactMetadata:
    """Metadata for an artifact created by tmi-tf.

    ``run_id`` identifies the analysis job that created the artifact; model,
    token and cost details live in the report note text, not in metadata.
    """

    run_id: str
    creation_agent: str = "tmi-tf"
    creation_timestamp: str = ""

    def __post_init__(self):
        """Validate the run id and set the creation timestamp if not provided."""
        validate_run_id(self.run_id)
        if not self.creation_timestamp:
            self.creation_timestamp = get_rfc3339_timestamp()

    def to_metadata_list(self) -> list[dict]:
        """Convert to a list of metadata key-value dicts for the TMI API."""
        return clean_metadata(
            [
                ("creation-agent", self.creation_agent),
                ("creation-timestamp", self.creation_timestamp),
                (RUN_ID_KEY, self.run_id),
            ]
        )


def new_run_id() -> str:
    """A globally unique id for one analysis job (TMI supplies none per job)."""
    return str(uuid.uuid4())


def validate_run_id(run_id: object) -> str:
    """Return ``run_id`` if it is a canonical UUID string, else raise ValueError."""
    if not isinstance(run_id, str):
        raise ValueError(f"run_id must be a UUID string, got {type(run_id).__name__}")  # noqa: TRY004
    try:
        canonical = str(uuid.UUID(run_id))
    except ValueError:
        raise ValueError(f"run_id is not a UUID: {run_id!r}") from None
    if canonical != run_id:
        raise ValueError(f"run_id is not a canonical UUID: {run_id!r}")
    return run_id


def get_rfc3339_timestamp() -> str:
    """
    Get current timestamp in RFC3339 format with 0 decimal precision on seconds.

    Returns:
        Timestamp string like '2025-12-29T10:30:45+00:00'
    """
    now = datetime.now(UTC)
    # Format with 0 decimal precision on seconds
    return now.strftime("%Y-%m-%dT%H:%M:%S%z")


def create_artifact_metadata(run_id: str) -> ArtifactMetadata:
    """Create artifact metadata stamped with the creating job's run id."""
    return ArtifactMetadata(run_id=run_id)
