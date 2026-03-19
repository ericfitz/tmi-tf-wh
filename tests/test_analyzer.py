"""Tests for tmi_tf.analyzer module."""

from tmi_tf.analyzer import AnalysisResult


class TestAnalysisResult:
    """Smoke tests for the AnalysisResult dataclass."""

    def test_returns_analysis_result(self):
        result = AnalysisResult(success=True, analyses=[], errors=[])
        assert result.success is True
        assert result.analyses == []
        assert result.errors == []

    def test_defaults(self):
        result = AnalysisResult(success=False)
        assert result.success is False
        assert result.analyses == []
        assert result.errors == []
        assert result.inventory_content == ""
        assert result.analysis_content == ""

    def test_with_content(self):
        result = AnalysisResult(
            success=True,
            analyses=[],
            errors=[],
            inventory_content="<h1>Inventory</h1>",
            analysis_content="<h1>Analysis</h1>",
        )
        assert result.inventory_content == "<h1>Inventory</h1>"
        assert result.analysis_content == "<h1>Analysis</h1>"

    def test_with_errors(self):
        result = AnalysisResult(
            success=False,
            errors=["repo not found", "auth failed"],
        )
        assert len(result.errors) == 2
        assert "repo not found" in result.errors
