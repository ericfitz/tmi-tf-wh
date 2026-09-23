"""Tests for Phase 3a/3b flow in tmi_tf.llm_analyzer."""

import json
from unittest.mock import MagicMock

from tmi_tf.llm_analyzer import LLMAnalyzer
from tmi_tf.providers import LLMResponse


def _make_provider(model: str = "anthropic/test-model") -> MagicMock:
    provider = MagicMock()
    provider.model = model
    provider.provider = "anthropic"
    return provider


def _make_llm_response(
    content: str, tokens_in: int = 100, tokens_out: int = 50
) -> LLMResponse:
    return LLMResponse(
        text=content,
        input_tokens=tokens_in,
        output_tokens=tokens_out,
        cost=0.01,
        finish_reason="stop",
    )


def _make_tf_repo(name="test-repo", url="https://github.com/test/repo"):
    repo = MagicMock()
    repo.name = name
    repo.url = url
    repo.get_terraform_content.return_value = {
        "main.tf": 'resource "aws_s3_bucket" "b" {}'
    }
    return repo


class TestPhase3Decomposition:
    def test_phase3a_and_3b_produce_merged_findings(self):
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
            "cwe_id": ["CWE-276"],
            "mitigation": "Enable S3 Block Public Access",
            "category": "Public Exposure",
        }

        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response(json.dumps(inventory)),
            _make_llm_response(json.dumps(infrastructure)),
            _make_llm_response(json.dumps(raw_threats)),
            _make_llm_response(json.dumps(threat_analysis)),
        ]

        analyzer = LLMAnalyzer(provider)
        result = analyzer.analyze_repository(_make_tf_repo())

        assert result.success is True
        assert len(result.security_findings) == 1
        finding = result.security_findings[0]
        assert finding["name"] == "Public S3 Bucket"
        assert finding["threat_type"] == "Information Disclosure"
        assert finding["cwe_id"] == ["CWE-276"]
        assert finding["score"] is not None
        assert len(finding["cvss"]) == 1

    def test_phase3a_empty_produces_no_findings(self):
        inventory = {"components": [], "services": []}
        infrastructure = {"relationships": [], "data_flows": []}

        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response(json.dumps(inventory)),
            _make_llm_response(json.dumps(infrastructure)),
            _make_llm_response(json.dumps([])),
        ]

        analyzer = LLMAnalyzer(provider)
        result = analyzer.analyze_repository(_make_tf_repo())
        assert result.success is True
        assert result.security_findings == []

    def test_phase3b_failure_skips_threat(self):
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
            "cwe_id": ["CWE-353"],
            "mitigation": "Add integrity checks",
            "category": "Best Practices",
        }

        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response(json.dumps(inventory)),
            _make_llm_response(json.dumps(infrastructure)),
            _make_llm_response(json.dumps(raw_threats)),
            _make_llm_response("not valid json"),
            _make_llm_response(json.dumps(threat_b_analysis)),
        ]

        analyzer = LLMAnalyzer(provider)
        result = analyzer.analyze_repository(_make_tf_repo())
        assert result.success is True
        assert len(result.security_findings) == 1
        assert result.security_findings[0]["name"] == "Threat B"

    def test_invalid_cvss_vector_keeps_threat_without_score(self):
        inventory = {"components": [], "services": []}
        infrastructure = {"relationships": [], "data_flows": []}
        raw_threats = [
            {"name": "Threat X", "description": "desc", "affected_components": []}
        ]
        threat_analysis = {
            "threat_type": "Spoofing",
            "severity": "High",
            "cvss_vector": "CVSS:4.0/AV:INVALID",
            "cwe_id": ["CWE-306"],
            "mitigation": "Fix auth",
            "category": "Authentication/Authorization",
        }

        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response(json.dumps(inventory)),
            _make_llm_response(json.dumps(infrastructure)),
            _make_llm_response(json.dumps(raw_threats)),
            _make_llm_response(json.dumps(threat_analysis)),
        ]

        analyzer = LLMAnalyzer(provider)
        result = analyzer.analyze_repository(_make_tf_repo())
        assert result.success is True
        assert len(result.security_findings) == 1
        finding = result.security_findings[0]
        assert finding["score"] is None
        assert finding["cvss"] == []
        assert finding["severity"] == "High"

    def test_all_phase3b_calls_fail_produces_empty_findings(self):
        inventory = {"components": [], "services": []}
        infrastructure = {"relationships": [], "data_flows": []}
        raw_threats = [
            {"name": "Threat A", "description": "desc A", "affected_components": []},
            {"name": "Threat B", "description": "desc B", "affected_components": []},
        ]

        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response(json.dumps(inventory)),
            _make_llm_response(json.dumps(infrastructure)),
            _make_llm_response(json.dumps(raw_threats)),
            _make_llm_response("not valid json"),
            _make_llm_response("also not json"),
        ]

        analyzer = LLMAnalyzer(provider)
        result = analyzer.analyze_repository(_make_tf_repo())
        assert result.success is True
        assert result.security_findings == []


class TestPhase1Retry:
    """#53: phase 1 retries once on truncated/malformed JSON, then fails loudly."""

    def _inventory_calls(self, provider):
        return [c for c in provider.complete.call_args_list]

    def test_retries_once_on_length_then_succeeds(self):
        inventory = {"components": [{"id": "x"}], "services": []}
        provider = _make_provider()
        truncated = _make_llm_response('{"components": [{"id": "x"')
        truncated.finish_reason = "length"
        provider.complete.side_effect = [
            truncated,
            _make_llm_response(json.dumps(inventory)),
            _make_llm_response(json.dumps({"relationships": []})),
            _make_llm_response("[]"),
        ]
        result = LLMAnalyzer(provider).analyze_repository(_make_tf_repo())
        assert result.success is True
        assert provider.complete.call_count == 4
        # tokens from both phase-1 attempts are counted
        assert result.input_tokens >= 400

    def test_retries_once_on_parse_failure_then_fails_loudly(self):
        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response("not json"),
            _make_llm_response("still not json"),
        ]
        result = LLMAnalyzer(provider).analyze_repository(_make_tf_repo())
        assert result.success is False
        assert provider.complete.call_count == 2
        assert "Phase 1" in result.error_message
        assert "2 attempts" in result.error_message


class TestCweRedirect:
    """#79: one corrective turn when phase 3b maps to a disallowed CWE."""

    def _run(self, *analyses):
        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response(json.dumps({"components": [], "services": []})),
            _make_llm_response(json.dumps({"relationships": []})),
            _make_llm_response(
                json.dumps(
                    [{"name": "T", "description": "d", "affected_components": []}]
                )
            ),
            *(_make_llm_response(json.dumps(a)) for a in analyses),
        ]
        return provider, LLMAnalyzer(provider).analyze_repository(_make_tf_repo())

    def test_allowed_cwe_needs_no_retry(self):
        provider, result = self._run({"cwe_id": ["CWE-306"]})
        assert provider.complete.call_count == 4
        assert result.security_findings[0]["cwe_id"] == ["CWE-306"]

    def test_disallowed_cwe_triggers_redirect(self):
        provider, result = self._run(
            {"cwe_id": ["CWE-862", "CWE-306"]}, {"cwe_id": ["CWE-306"]}
        )
        assert provider.complete.call_count == 5
        retry_user = provider.complete.call_args_list[4].args[1]
        assert "CWE-862 not allowed" in retry_user
        assert "CWE-699 or CWE-1446" in retry_user
        assert result.security_findings[0]["cwe_id"] == ["CWE-306"]

    def test_unparseable_redirect_keeps_first_answer(self):
        provider, result = self._run({"cwe_id": ["CWE-862"]}, "not json")
        assert provider.complete.call_count == 5
        assert result.security_findings[0]["cwe_id"] == ["CWE-862"]
