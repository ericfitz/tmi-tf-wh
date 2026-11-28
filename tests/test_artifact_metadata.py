"""Tests for artifact metadata (#115)."""

import uuid

import pytest

from tmi_tf import artifact_metadata as am
from tmi_tf.artifact_metadata import ArtifactMetadata, create_artifact_metadata

RUN_A = "11111111-1111-4111-8111-111111111111"

FORBIDDEN_FRAGMENTS = ("llm", "model", "provider", "profile", "token", "cost")


def _as_dict(md: ArtifactMetadata) -> dict[str, str]:
    return {m["key"]: m["value"] for m in md.to_metadata_list()}


def test_metadata_has_exactly_agent_timestamp_and_run_id():
    meta = _as_dict(create_artifact_metadata(RUN_A))
    assert set(meta) == {"creation-agent", "creation-timestamp", "run_id"}
    assert meta["creation-agent"] == "tmi-tf"
    assert meta["run_id"] == RUN_A


def test_no_model_provider_profile_token_or_cost_keys():
    for key in _as_dict(create_artifact_metadata(RUN_A)):
        assert not any(f in key.lower() for f in FORBIDDEN_FRAGMENTS)


def test_every_value_is_non_empty():
    assert all(m["value"] for m in create_artifact_metadata(RUN_A).to_metadata_list())


@pytest.mark.parametrize("bad", ["", "not-a-uuid", "1234", " ", None, 7])
def test_unknown_run_id_is_rejected(bad):
    with pytest.raises(ValueError):
        create_artifact_metadata(bad)  # pyright: ignore[reportArgumentType]


def test_new_run_id_is_a_fresh_uuid_each_call():
    a, b = am.new_run_id(), am.new_run_id()
    assert a != b
    assert str(uuid.UUID(a)) == a


def test_old_llm_helpers_are_gone():
    assert not hasattr(am, "aggregate_analysis_metadata")
    assert not hasattr(ArtifactMetadata, "llm_model")
