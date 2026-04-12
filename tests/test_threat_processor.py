"""Tests for CWE validation in tmi_tf.threat_processor."""

from tmi_tf.threat_processor import SecurityThreat, filter_valid_cwe_ids


class TestFilterValidCweIds:
    """Tests for filter_valid_cwe_ids()."""

    def test_valid_ids_pass_through(self):
        result = filter_valid_cwe_ids(["CWE-22", "CWE-78", "CWE-798"])
        assert result == ["CWE-22", "CWE-78", "CWE-798"]

    def test_invalid_ids_are_dropped(self):
        # CWE-284 is a category, not in CWE-699 non-category set
        result = filter_valid_cwe_ids(["CWE-284", "CWE-22"])
        assert result == ["CWE-22"]

    def test_malformed_ids_are_dropped(self):
        result = filter_valid_cwe_ids(["CWE22", "not-a-cwe", "284", "CWE-22"])
        assert result == ["CWE-22"]

    def test_empty_list(self):
        assert filter_valid_cwe_ids([]) == []

    def test_all_invalid(self):
        result = filter_valid_cwe_ids(["CWE-284", "CWE-693", "CWE-9999"])
        assert result == []

    def test_category_cwe_ids_rejected(self):
        # These are category-level CWEs that were in the old prompts
        categories = ["CWE-284", "CWE-311", "CWE-269", "CWE-200", "CWE-693"]
        result = filter_valid_cwe_ids(categories)
        assert result == []


class TestSecurityThreatCweValidation:
    """Tests that SecurityThreat filters CWE IDs on construction."""

    def test_valid_cwe_ids_kept(self):
        threat = SecurityThreat(
            name="Test",
            description="desc",
            threat_type="Spoofing",
            cwe_id=["CWE-22", "CWE-78"],
        )
        assert threat.cwe_id == ["CWE-22", "CWE-78"]

    def test_invalid_cwe_ids_filtered(self):
        threat = SecurityThreat(
            name="Test",
            description="desc",
            threat_type="Spoofing",
            cwe_id=["CWE-284", "CWE-22", "CWE-9999"],
        )
        assert threat.cwe_id == ["CWE-22"]

    def test_none_cwe_id_defaults_to_empty(self):
        threat = SecurityThreat(
            name="Test",
            description="desc",
            threat_type="Spoofing",
            cwe_id=None,
        )
        assert threat.cwe_id == []
