"""Tests for tmi_tf.scope."""

import pytest  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

from tmi_tf.scope import ALL, LATEST, match_environments, normalize_scope

NAMES = ["aws-private", "aws-public", "gcp-public", "oci-public"]


class TestNormalize:
    def test_none_is_latest(self):
        assert normalize_scope(None) == LATEST

    def test_blank_is_latest(self):
        assert normalize_scope("   ") == LATEST

    def test_case_and_whitespace(self):
        assert normalize_scope("  ALL ") == ALL


class TestMatch:
    def test_all(self):
        matched, skipped = match_environments(ALL, NAMES)
        assert matched == NAMES and skipped == []

    def test_latest_raises(self):
        with pytest.raises(ValueError):
            match_environments(LATEST, NAMES)

    def test_glob_and_name(self):
        matched, skipped = match_environments("aws-*, OCI-PUBLIC", NAMES)
        assert matched == ["aws-private", "aws-public", "oci-public"]
        assert skipped == [("gcp-public", "not in scope")]

    def test_unmatched_pattern_reported(self):
        matched, skipped = match_environments("azure-*", NAMES)
        assert matched == []
        assert ("azure-*", "pattern matched no environment") in skipped
        assert ("aws-public", "not in scope") in skipped

    def test_preserves_input_order(self):
        matched, _ = match_environments("oci-public,aws-public", NAMES)
        assert matched == ["aws-public", "oci-public"]
