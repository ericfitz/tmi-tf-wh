# pyright: reportPrivateImportUsage=false
"""Tests for Phase 3a/3b flow in tmi_tf.llm_analyzer."""

import json
from unittest.mock import MagicMock

import pytest
from llm_errors import FakeClock, rate_limit_error

from tmi_tf.llm_analyzer import (
    LLMAnalyzer,
    TerraformAnalysis,
    ThreatGaps,
    call_llm_checked,
)
from tmi_tf.providers import LLMResponse
from tmi_tf.retry import DeadlineReached, RetryBudget


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

    def _one_threat_responses(self, *threat_analysis_responses):
        inventory = {"components": [{"id": "aws_s3_bucket.b"}], "services": []}
        infrastructure = {"relationships": [], "data_flows": [], "trust_boundaries": []}
        raw_threats = [
            {
                "name": "Public S3 Bucket",
                "description": "S3 bucket is publicly accessible",
                "affected_components": ["aws_s3_bucket.b"],
            }
        ]
        return [
            _make_llm_response(json.dumps(inventory)),
            _make_llm_response(json.dumps(infrastructure)),
            _make_llm_response(json.dumps(raw_threats)),
            *threat_analysis_responses,
        ]

    def test_empty_response_is_retried_once_and_tokens_summed(self):
        analysis = {"threat_type": "Tampering", "severity": "High", "cwe_id": []}
        empty = LLMResponse(
            text=None,
            input_tokens=100,
            output_tokens=0,
            cost=0.01,
            finish_reason="stop",
        )
        provider = _make_provider()
        provider.complete.side_effect = self._one_threat_responses(
            empty, _make_llm_response(json.dumps(analysis))
        )

        result = LLMAnalyzer(provider).analyze_repository(_make_tf_repo())

        assert provider.complete.call_count == 5
        assert [f["name"] for f in result.security_findings] == ["Public S3 Bucket"]
        # 3 phases + both 3b calls: 5 x 100 input tokens.
        assert result.input_tokens == 500

    def test_content_filter_empty_response_is_not_retried(self):
        refused = LLMResponse(
            text=None,
            input_tokens=100,
            output_tokens=0,
            cost=0.01,
            finish_reason="content_filter",
        )
        provider = _make_provider()
        provider.complete.side_effect = self._one_threat_responses(refused)

        result = LLMAnalyzer(provider).analyze_repository(_make_tf_repo())

        assert provider.complete.call_count == 4
        assert result.security_findings == []

    def test_phase2_refusal_fails_the_run_without_retry(self):
        refused = LLMResponse(
            text=None,
            input_tokens=100,
            output_tokens=0,
            cost=0.01,
            finish_reason="content_filter",
        )
        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response(json.dumps({"components": [], "services": []})),
            refused,
        ]

        result = LLMAnalyzer(provider).analyze_repository(_make_tf_repo())

        assert result.success is False
        assert provider.complete.call_count == 2
        assert "refused" in result.error_message
        assert "content_filter" in result.error_message

    def test_phase3b_refusal_is_counted_and_run_continues(self):
        refused = LLMResponse(
            text=None,
            input_tokens=100,
            output_tokens=0,
            cost=0.01,
            finish_reason="content_filter",
        )
        provider = _make_provider()
        provider.complete.side_effect = self._one_threat_responses(refused)

        result = LLMAnalyzer(provider).analyze_repository(_make_tf_repo())

        assert result.success is True
        assert result.security_findings == []
        assert result.refusals == "phase 3b: 1 threat(s)"

    def test_content_filter_with_text_is_still_a_refusal(self):
        refused = LLMResponse(
            text="I can't help analyze this.",
            input_tokens=100,
            output_tokens=8,
            cost=0.01,
            finish_reason="content_filter",
        )
        provider = _make_provider()
        provider.complete.side_effect = self._one_threat_responses(refused)

        result = LLMAnalyzer(provider).analyze_repository(_make_tf_repo())

        assert result.refusals == "phase 3b: 1 threat(s)"

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


AWS_TF = (
    'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n  tags = { a = "b" }\n}\n'
    'resource "aws_instance" "web" {\n  ami = "ami-1"\n  instance_type = "t3.micro"\n'
    "  subnet_id = aws_subnet.private.id\n}\n"
)


def _make_static_repo(files: dict[str, str]):
    repo = MagicMock()
    repo.name = "test-repo"
    repo.url = "https://github.com/test/repo"
    repo.get_terraform_content.return_value = files
    return repo


def _tail_responses():
    """Phase 2, 3a responses so analyze_repository runs to completion."""
    return [
        _make_llm_response(json.dumps({"relationships": [], "data_flows": []})),
        _make_llm_response("[]"),
    ]


class TestPhase1Static:
    def test_static_path_sends_prebuilt_inventory_and_filtered_hcl(self):
        semantic = {
            "components": [
                {"id": "aws_vpc.main", "name": "Main VPC", "purpose": "Network"},
                {"id": "aws_instance.web", "name": "Web", "purpose": "Serves"},
            ],
            "services": [],
            "dependencies": [
                {
                    "type": "cloud",
                    "provider": "AWS",
                    "service": "EC2",
                    "dependent_components": ["aws_instance.web"],
                }
            ],
        }
        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response(json.dumps(semantic)),
            *_tail_responses(),
        ]
        result = LLMAnalyzer(provider).analyze_repository(
            _make_static_repo({"main.tf": AWS_TF})
        )
        assert result.success is True

        system_prompt, user_prompt = provider.complete.call_args_list[0].args[:2]
        assert "semantic inference only" in system_prompt
        assert "Pre-extracted inventory" in user_prompt
        assert '"id":"aws_instance.web"' in user_prompt
        assert '"type":"compute"' in user_prompt
        assert '"configuration"' not in user_prompt  # no longer duplicated in JSON
        assert "instance_type" not in user_prompt  # filtered out of the HCL
        assert "### File: main.tf" in user_prompt

        comps = {c["id"]: c for c in result.inventory["components"]}
        assert comps["aws_instance.web"]["name"] == "Web"
        assert comps["aws_instance.web"]["type"] == "compute"
        assert comps["aws_instance.web"]["resource_type"] == "aws_instance"
        assert comps["aws_instance.web"]["configuration"]["ami"] == "ami-1"
        assert comps["aws_instance.web"]["dependencies"] == [
            {"type": "cloud", "provider": "AWS", "service": "EC2"}
        ]
        assert result.inventory["dependencies"] == semantic["dependencies"]

        # phase 2 still receives the full raw Terraform text
        phase2_user = provider.complete.call_args_list[1].args[1]
        assert "instance_type" in phase2_user

    def test_phase1_partial_parse_sends_unparsed_raw(self):
        broken = 'resource "aws_instance" "broken" {\n  ami =\n}\n'
        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response(json.dumps({"components": []})),
            *_tail_responses(),
        ]
        result = LLMAnalyzer(provider).analyze_repository(
            _make_static_repo({"main.tf": AWS_TF, "broken.tf": broken})
        )
        assert result.success is True
        user_prompt = provider.complete.call_args_list[0].args[1]
        assert "Pre-extracted inventory" in user_prompt
        assert '"unparsed_files":["broken.tf"]' in user_prompt
        assert "ami =\n}" in user_prompt  # raw broken file passed through
        assert [c["id"] for c in result.inventory["components"]] == [
            "aws_vpc.main",
            "aws_instance.web",
        ]

    def test_falls_back_to_full_llm_when_nothing_parses(self, caplog):
        broken = 'resource "aws_instance" "broken" {\n  ami =\n}\n'
        inventory = {"components": [{"id": "aws_instance.broken"}], "services": []}
        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response(json.dumps(inventory)),
            *_tail_responses(),
        ]
        with caplog.at_level("WARNING"):
            result = LLMAnalyzer(provider).analyze_repository(
                _make_static_repo({"broken.tf": broken})
            )
        assert result.success is True
        system_prompt, user_prompt = provider.complete.call_args_list[0].args[:2]
        assert "semantic inference only" not in system_prompt
        assert "## Terraform Configuration Files" in user_prompt
        assert result.inventory == inventory  # untouched full-LLM answer
        assert "full-LLM phase 1" in caplog.text

    def test_falls_back_when_static_analysis_raises(self, monkeypatch, caplog):
        import tmi_tf.llm_analyzer as mod

        def boom(_contents):
            raise RuntimeError("registry exploded")

        monkeypatch.setattr(mod, "parse_terraform", boom)
        inventory = {"components": [], "services": []}
        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response(json.dumps(inventory)),
            *_tail_responses(),
        ]
        with caplog.at_level("WARNING"):
            result = LLMAnalyzer(provider).analyze_repository(
                _make_static_repo({"main.tf": AWS_TF})
            )
        assert result.success is True
        assert "registry exploded" in caplog.text
        assert (
            "## Terraform Configuration Files"
            in provider.complete.call_args_list[0].args[1]
        )

    def test_static_path_keeps_retry_once_then_fail_loudly(self):
        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response("not json"),
            _make_llm_response("still not json"),
        ]
        result = LLMAnalyzer(provider).analyze_repository(
            _make_static_repo({"main.tf": AWS_TF})
        )
        assert result.success is False
        assert provider.complete.call_count == 2
        assert (
            "Phase 1" in result.error_message and "2 attempts" in result.error_message
        )

    def test_static_path_counts_tokens_from_both_attempts(self):
        semantic = {"components": []}
        truncated = _make_llm_response('{"components": [')
        truncated.finish_reason = "length"
        provider = _make_provider()
        provider.complete.side_effect = [
            truncated,
            _make_llm_response(json.dumps(semantic)),
            *_tail_responses(),
        ]
        result = LLMAnalyzer(provider).analyze_repository(
            _make_static_repo({"main.tf": AWS_TF})
        )
        assert result.success is True
        assert provider.complete.call_count == 4
        assert result.input_tokens >= 400


def test_format_terraform_contents_is_module_level():
    from tmi_tf.llm_analyzer import format_terraform_contents

    assert format_terraform_contents({}) == "(No Terraform files found)"
    text = format_terraform_contents({"b.tf": "x", "a.tf": "y"})
    assert text.index("### File: a.tf") < text.index("### File: b.tf")
    assert "```hcl\ny\n```" in text


INVENTORY = {
    "components": [{"id": "aws_s3_bucket.b"}],
    "services": [],
}
INFRASTRUCTURE = {"relationships": [], "data_flows": [], "trust_boundaries": []}
THREAT_ANALYSIS = {"threat_type": "Tampering", "severity": "High", "cwe_id": []}
THREE = [
    {
        "name": f"T{i}",
        "description": f"threat {i}",
        "affected_components": ["aws_s3_bucket.b"],
    }
    for i in (1, 2, 3)
]


class TestPhase3bRateLimit:
    def test_rate_limited_calls_are_retried_and_no_threat_is_dropped(self, monkeypatch):
        sleeps: list[float] = []
        monkeypatch.setattr("tmi_tf.retry.time.sleep", sleeps.append)
        monkeypatch.setattr("tmi_tf.retry.random.random", lambda: 0.0)
        limited = rate_limit_error({"retry-after": "30"})
        ok = _make_llm_response(json.dumps(THREAT_ANALYSIS))
        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response(json.dumps(INVENTORY)),
            _make_llm_response(json.dumps(INFRASTRUCTURE)),
            _make_llm_response(json.dumps(THREE)),
            limited,
            limited,
            limited,
            ok,  # T1: three 429s, then an answer
            ok,  # T2
            limited,
            ok,  # T3: one 429
        ]
        rows: list[str] = []
        analyzer = LLMAnalyzer(provider)
        result = analyzer.analyze_repository(
            _make_tf_repo(), status_callback=rows.append
        )
        assert [f["name"] for f in result.security_findings] == ["T1", "T2", "T3"]
        gaps = result.threat_gaps
        assert gaps.identified == len(result.security_findings) + gaps.not_analyzed
        assert sleeps == [30.0, 30.0, 30.0, 30.0]
        waits = [r for r in rows if "rate limited (HTTP 429), waiting 30s" in r]
        assert len(waits) == 4
        assert waits[0].endswith("(attempt 1 of 8)")
        # The callback is released once the run ends.
        assert analyzer._on_wait is None

    def test_budget_exhaustion_keeps_findings_and_records_the_rest_as_gaps(
        self, monkeypatch
    ):
        clock = FakeClock()
        monkeypatch.setattr("tmi_tf.retry.time.sleep", clock.sleep)
        monkeypatch.setattr("tmi_tf.retry.random.random", lambda: 0.0)
        limited = rate_limit_error({"retry-after": "40"})
        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response(json.dumps(INVENTORY)),
            _make_llm_response(json.dumps(INFRASTRUCTURE)),
            _make_llm_response(json.dumps(THREE)),
            _make_llm_response(json.dumps(THREAT_ANALYSIS)),  # T1
            limited,
            limited,
            limited,  # T2: waits 40, 40, then no room
        ]
        analyzer = LLMAnalyzer(provider, retry_budget=RetryBudget(100.0, clock))
        result = analyzer.analyze_repository(_make_tf_repo())
        assert result.success is True
        assert [f["name"] for f in result.security_findings] == ["T1"]
        gaps = result.threat_gaps
        assert gaps == ThreatGaps(
            identified=3,
            failed=1,
            refused=0,
            skipped=1,
            hints=("HTTP 429 rate_limit_error",),
        )
        assert gaps.identified == len(result.security_findings) + gaps.not_analyzed
        assert provider.complete.call_count == 7  # T3 was never sent
        assert clock.t == 80.0

    def test_unparseable_answer_is_a_counted_gap(self):
        two = THREE[:2]
        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response(json.dumps(INVENTORY)),
            _make_llm_response(json.dumps(INFRASTRUCTURE)),
            _make_llm_response(json.dumps(two)),
            _make_llm_response("not json"),  # T1
            _make_llm_response(json.dumps(THREAT_ANALYSIS)),  # T2
        ]
        result = LLMAnalyzer(provider).analyze_repository(_make_tf_repo())
        gaps = result.threat_gaps
        assert gaps == ThreatGaps(
            identified=2, failed=1, hints=("unparseable response",)
        )
        assert [f["name"] for f in result.security_findings] == ["T2"]
        assert gaps.identified == len(result.security_findings) + gaps.not_analyzed

    def test_refusal_is_counted_separately_from_errors(self):
        refused = LLMResponse(
            text=None,
            input_tokens=100,
            output_tokens=0,
            cost=0.01,
            finish_reason="content_filter",
        )
        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response(json.dumps(INVENTORY)),
            _make_llm_response(json.dumps(INFRASTRUCTURE)),
            _make_llm_response(json.dumps(THREE)),
            refused,  # T1
            RuntimeError("x"),  # T2
            _make_llm_response(json.dumps(THREAT_ANALYSIS)),  # T3
        ]
        result = LLMAnalyzer(provider).analyze_repository(_make_tf_repo())
        gaps = result.threat_gaps
        assert gaps == ThreatGaps(
            identified=3, failed=1, refused=1, hints=("RuntimeError",)
        )
        assert result.refusals == "phase 3b: 1 threat(s)"
        assert gaps.identified == len(result.security_findings) + gaps.not_analyzed

    def test_clean_run_has_no_gaps(self):
        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response(json.dumps(INVENTORY)),
            _make_llm_response(json.dumps(INFRASTRUCTURE)),
            _make_llm_response(json.dumps(THREE[:1])),
            _make_llm_response(json.dumps(THREAT_ANALYSIS)),
        ]
        result = LLMAnalyzer(provider).analyze_repository(_make_tf_repo())
        gaps = result.threat_gaps
        assert gaps == ThreatGaps(identified=1)
        assert gaps.summary() == ""
        assert gaps.identified == len(result.security_findings) + gaps.not_analyzed


class TestThreatGapsSummary:
    def test_summary_lists_causes_in_order(self):
        gaps = ThreatGaps(
            identified=28,
            failed=22,
            refused=1,
            skipped=2,
            hints=("HTTP 429 rate_limit_error", "unparseable response"),
        )
        assert gaps.not_analyzed == 25
        assert gaps.summary() == (
            "25 of 28 threats not analyzed "
            "(HTTP 429 rate_limit_error, unparseable response, refused, "
            "deadline reached)"
        )

    def test_summary_omits_absent_causes(self):
        gaps = ThreatGaps(identified=3, refused=1)
        assert gaps.summary() == "1 of 3 threats not analyzed (refused)"
        assert ThreatGaps(identified=3, skipped=1).summary() == (
            "1 of 3 threats not analyzed (deadline reached)"
        )

    def test_failed_analysis_defaults_to_empty_gaps(self):
        assert TerraformAnalysis("r", "u", success=False).threat_gaps == ThreatGaps()
        gaps = ThreatGaps(identified=2, failed=1)
        assert TerraformAnalysis("r", "u", threat_gaps=gaps).threat_gaps is gaps


class TestTimeoutFn:
    def _ok(self):
        return _make_llm_response("fine")

    def test_timeout_fn_is_called_once_per_attempt(self, monkeypatch):
        monkeypatch.setattr("tmi_tf.retry.time.sleep", lambda s: None)
        monkeypatch.setattr("tmi_tf.retry.random.random", lambda: 0.0)
        provider = _make_provider()
        provider.complete.side_effect = [
            rate_limit_error({"retry-after": "1"}),
            self._ok(),
        ]
        values = iter([900.0, 400.0])
        calls: list[int] = []

        def timeout_fn() -> float | None:
            calls.append(1)
            return next(values)

        call_llm_checked(provider, "s", "u", "DFD", timeout_fn=timeout_fn)
        assert len(calls) == 2
        timeouts = [c.args[3] for c in provider.complete.call_args_list]
        assert timeouts == [900.0, 400.0]

    def test_none_on_a_later_attempt_raises_deadline_reached_without_a_call(
        self, monkeypatch
    ):
        monkeypatch.setattr("tmi_tf.retry.time.sleep", lambda s: None)
        monkeypatch.setattr("tmi_tf.retry.random.random", lambda: 0.0)
        provider = _make_provider()
        provider.complete.side_effect = [
            rate_limit_error({"retry-after": "1"}),
            self._ok(),
        ]
        values = iter([900.0, None])
        with pytest.raises(DeadlineReached):
            call_llm_checked(provider, "s", "u", "DFD", timeout_fn=lambda: next(values))
        assert provider.complete.call_count == 1

    def test_timeout_fn_is_consulted_for_the_empty_response_retry(self):
        provider = _make_provider()
        empty = LLMResponse(
            text=None, input_tokens=1, output_tokens=0, cost=0.0, finish_reason="stop"
        )
        provider.complete.side_effect = [empty, self._ok()]
        values = iter([100.0, 50.0])
        call_llm_checked(provider, "s", "u", "DFD", timeout_fn=lambda: next(values))
        assert [c.args[3] for c in provider.complete.call_args_list] == [100.0, 50.0]

    def test_without_timeout_fn_the_float_is_used(self):
        provider = _make_provider()
        provider.complete.side_effect = [self._ok()]
        call_llm_checked(provider, "s", "u", "x", timeout=77.0)
        assert provider.complete.call_args.args[3] == 77.0
