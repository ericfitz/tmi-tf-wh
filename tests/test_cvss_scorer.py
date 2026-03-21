"""Tests for tmi_tf.cvss_scorer module."""

from tmi_tf.cvss_scorer import score_cvss4_vector


class TestScoreCvss4Vector:
    """Tests for score_cvss4_vector function."""

    def test_valid_critical_vector(self):
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        score, severity, error = score_cvss4_vector(vector)
        assert error is None
        assert score is not None
        assert isinstance(score, float)
        assert score >= 9.0
        assert severity == "Critical"

    def test_valid_low_vector(self):
        vector = "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
        score, severity, error = score_cvss4_vector(vector)
        assert error is None
        assert score is not None
        assert isinstance(score, float)
        assert severity in ("Low", "Medium", "High", "Critical")

    def test_invalid_vector_returns_error(self):
        score, severity, error = score_cvss4_vector("not-a-vector")
        assert score is None
        assert severity is None
        assert error is not None

    def test_empty_string_returns_error(self):
        score, severity, error = score_cvss4_vector("")
        assert score is None
        assert severity is None
        assert error is not None

    def test_cvss31_vector_returns_error(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        score, severity, error = score_cvss4_vector(vector)
        assert score is None
        assert severity is None
        assert error is not None

    def test_missing_metrics_returns_error(self):
        vector = "CVSS:4.0/AV:N/AC:L"
        score, severity, error = score_cvss4_vector(vector)
        assert score is None
        assert severity is None
        assert error is not None

    def test_zero_score_maps_none_severity_to_low(self):
        # All impacts None = score 0.0, library returns severity "None"
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
        score, severity, error = score_cvss4_vector(vector)
        assert error is None
        assert score == 0.0
        assert severity == "Low"
