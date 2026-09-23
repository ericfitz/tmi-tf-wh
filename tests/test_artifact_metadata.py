"""Tests for artifact metadata."""

from tmi_tf.artifact_metadata import (
    aggregate_analysis_metadata,
    create_artifact_metadata,
)


def test_profile_key_emitted():
    md = create_artifact_metadata(provider="openai", model="m", profile="gpt56cyber")
    assert {"key": "llm-profile", "value": "gpt56cyber"} in md.to_metadata_list()


def test_aggregate_carries_profile():
    assert (
        aggregate_analysis_metadata([], "openai", "m", profile="p").llm_profile == "p"
    )
