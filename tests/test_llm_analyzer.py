"""Tests for Phase 3a/3b flow in tmi_tf.llm_analyzer."""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from tmi_tf.llm_analyzer import LLMAnalyzer


def _make_config(**overrides):
    """Create a minimal mock config for LLMAnalyzer."""
    defaults = {
        "llm_provider": "anthropic",
        "llm_model": "anthropic/test-model",
        "anthropic_api_key": "test-key",
        "get_oci_completion_kwargs": lambda: {},
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_llm_response(content: str, tokens_in: int = 100, tokens_out: int = 50):
    """Create a mock LiteLLM response."""
    message = MagicMock()
    message.content = content
    choice = MagicMock()
    choice.message = message
    choice.finish_reason = "stop"
    usage = MagicMock()
    usage.prompt_tokens = tokens_in
    usage.completion_tokens = tokens_out
    response = MagicMock()
    response.choices = [choice]
    response.usage = usage
    return response


def _make_tf_repo(name="test-repo", url="https://github.com/test/repo"):
    """Create a minimal mock TerraformRepository."""
    repo = MagicMock()
    repo.name = name
    repo.url = url
    repo.get_terraform_content.return_value = {
        "main.tf": 'resource "aws_s3_bucket" "b" {}'
    }
    return repo


class TestPhase3Decomposition:
    """Tests for the Phase 3a + 3b decomposition in analyze_repository."""

    @patch("tmi_tf.llm_analyzer.litellm")
    @patch("tmi_tf.llm_analyzer.retry_transient_llm_call")
    @patch("tmi_tf.llm_analyzer.save_llm_response")
    def test_phase3a_and_3b_produce_merged_findings(
        self, mock_save, mock_retry, mock_litellm
    ):
        """Phase 3a identifies threats, Phase 3b enriches each one."""
        inventory = {"components": [{"id": "aws_s3_bucket.b"}], "services": []}
        infrastructure = {"relationships": [], "data_flows": [], "trust_boundaries": []}
        raw_threats = [
            {
                "name": "Public S3 Bucket",
                "description": "S3 bucket is publicly accessible",
                "affected_components": ["aws_s3_bucket.b"],
            }
        ]
        threat_analysis = {
            "threat_type": "Information Disclosure",
            "severity": "High",
            "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            "cwe_id": ["CWE-284"],
            "mitigation": "Enable S3 Block Public Access",
            "category": "Public Exposure",
        }

        responses = [
            _make_llm_response(json.dumps(inventory)),
            _make_llm_response(json.dumps(infrastructure)),
            _make_llm_response(json.dumps(raw_threats)),
            _make_llm_response(json.dumps(threat_analysis)),
        ]
        mock_retry.side_effect = responses
        mock_litellm.completion_cost.return_value = 0.01
        mock_save.return_value = "/tmp/test"

        config = _make_config()
        analyzer = LLMAnalyzer(config)
        result = analyzer.analyze_repository(_make_tf_repo())

        assert result.success is True
        assert len(result.security_findings) == 1

        finding = result.security_findings[0]
        assert finding["name"] == "Public S3 Bucket"
        assert finding["threat_type"] == "Information Disclosure"
        assert finding["cwe_id"] == ["CWE-284"]
        assert finding["mitigation"] == "Enable S3 Block Public Access"
        assert finding["score"] is not None
        assert len(finding["cvss"]) == 1
        assert finding["cvss"][0]["vector"].startswith("CVSS:4.0/")

    @patch("tmi_tf.llm_analyzer.litellm")
    @patch("tmi_tf.llm_analyzer.retry_transient_llm_call")
    @patch("tmi_tf.llm_analyzer.save_llm_response")
    def test_phase3a_empty_produces_no_findings(
        self, mock_save, mock_retry, mock_litellm
    ):
        """When Phase 3a finds no threats, result has empty security_findings."""
        inventory = {"components": [], "services": []}
        infrastructure = {"relationships": [], "data_flows": []}

        responses = [
            _make_llm_response(json.dumps(inventory)),
            _make_llm_response(json.dumps(infrastructure)),
            _make_llm_response(json.dumps([])),
        ]
        mock_retry.side_effect = responses
        mock_litellm.completion_cost.return_value = 0.0
        mock_save.return_value = "/tmp/test"

        config = _make_config()
        analyzer = LLMAnalyzer(config)
        result = analyzer.analyze_repository(_make_tf_repo())

        assert result.success is True
        assert result.security_findings == []

    @patch("tmi_tf.llm_analyzer.litellm")
    @patch("tmi_tf.llm_analyzer.retry_transient_llm_call")
    @patch("tmi_tf.llm_analyzer.save_llm_response")
    def test_phase3b_failure_skips_threat(self, mock_save, mock_retry, mock_litellm):
        """When Phase 3b fails for one threat, it's skipped but others succeed."""
        inventory = {"components": [], "services": []}
        infrastructure = {"relationships": [], "data_flows": []}
        raw_threats = [
            {"name": "Threat A", "description": "desc A", "affected_components": []},
            {"name": "Threat B", "description": "desc B", "affected_components": []},
        ]
        threat_b_analysis = {
            "threat_type": "Tampering",
            "severity": "Medium",
            "cvss_vector": "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
            "cwe_id": ["CWE-345"],
            "mitigation": "Add integrity checks",
            "category": "Best Practices",
        }

        responses = [
            _make_llm_response(json.dumps(inventory)),
            _make_llm_response(json.dumps(infrastructure)),
            _make_llm_response(json.dumps(raw_threats)),
            _make_llm_response("not valid json"),
            _make_llm_response(json.dumps(threat_b_analysis)),
        ]
        mock_retry.side_effect = responses
        mock_litellm.completion_cost.return_value = 0.0
        mock_save.return_value = "/tmp/test"

        config = _make_config()
        analyzer = LLMAnalyzer(config)
        result = analyzer.analyze_repository(_make_tf_repo())

        assert result.success is True
        assert len(result.security_findings) == 1
        assert result.security_findings[0]["name"] == "Threat B"

    @patch("tmi_tf.llm_analyzer.litellm")
    @patch("tmi_tf.llm_analyzer.retry_transient_llm_call")
    @patch("tmi_tf.llm_analyzer.save_llm_response")
    def test_invalid_cvss_vector_keeps_threat_without_score(
        self, mock_save, mock_retry, mock_litellm
    ):
        """Invalid CVSS vector: threat kept with score=None, severity from LLM."""
        inventory = {"components": [], "services": []}
        infrastructure = {"relationships": [], "data_flows": []}
        raw_threats = [
            {"name": "Threat X", "description": "desc", "affected_components": []},
        ]
        threat_analysis = {
            "threat_type": "Spoofing",
            "severity": "High",
            "cvss_vector": "CVSS:4.0/AV:INVALID",
            "cwe_id": ["CWE-287"],
            "mitigation": "Fix auth",
            "category": "Authentication/Authorization",
        }

        responses = [
            _make_llm_response(json.dumps(inventory)),
            _make_llm_response(json.dumps(infrastructure)),
            _make_llm_response(json.dumps(raw_threats)),
            _make_llm_response(json.dumps(threat_analysis)),
        ]
        mock_retry.side_effect = responses
        mock_litellm.completion_cost.return_value = 0.0
        mock_save.return_value = "/tmp/test"

        config = _make_config()
        analyzer = LLMAnalyzer(config)
        result = analyzer.analyze_repository(_make_tf_repo())

        assert result.success is True
        assert len(result.security_findings) == 1

        finding = result.security_findings[0]
        assert finding["score"] is None
        assert finding["cvss"] == []
        assert finding["severity"] == "High"

    @patch("tmi_tf.llm_analyzer.litellm")
    @patch("tmi_tf.llm_analyzer.retry_transient_llm_call")
    @patch("tmi_tf.llm_analyzer.save_llm_response")
    def test_all_phase3b_calls_fail_produces_empty_findings(
        self, mock_save, mock_retry, mock_litellm
    ):
        """When all Phase 3b calls fail, result succeeds with empty findings."""
        inventory = {"components": [], "services": []}
        infrastructure = {"relationships": [], "data_flows": []}
        raw_threats = [
            {"name": "Threat A", "description": "desc A", "affected_components": []},
            {"name": "Threat B", "description": "desc B", "affected_components": []},
        ]

        responses = [
            _make_llm_response(json.dumps(inventory)),
            _make_llm_response(json.dumps(infrastructure)),
            _make_llm_response(json.dumps(raw_threats)),
            _make_llm_response("not valid json"),
            _make_llm_response("also not json"),
        ]
        mock_retry.side_effect = responses
        mock_litellm.completion_cost.return_value = 0.0
        mock_save.return_value = "/tmp/test"

        config = _make_config()
        analyzer = LLMAnalyzer(config)
        result = analyzer.analyze_repository(_make_tf_repo())

        assert result.success is True
        assert result.security_findings == []
