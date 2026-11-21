# pyright: reportPrivateImportUsage=false
"""Tests for Phase 3a/3b flow in tmi_tf.llm_analyzer."""

import json
from unittest.mock import MagicMock

import litellm  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]
import pytest
from llm_errors import FakeClock, rate_limit_error

from tmi_tf.config import prompts_dir
from tmi_tf.llm_analyzer import (
    CACHE_BREAKPOINT_MARKER,
    LLMAnalyzer,
    TerraformAnalysis,
    ThreatGaps,
    call_llm_checked,
    split_cache_prefix,
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


class TestStatusRows:
    def _run(self, effects, **kwargs):
        provider = _make_provider()
        provider.complete.side_effect = effects
        rows: list[str] = []
        analyzer = LLMAnalyzer(provider, **kwargs)
        result = analyzer.analyze_repository(
            _make_tf_repo(), status_callback=rows.append
        )
        return result, rows

    def _head(self, threats):
        return [
            _make_llm_response(json.dumps(INVENTORY)),
            _make_llm_response(json.dumps(INFRASTRUCTURE)),
            _make_llm_response(json.dumps(threats)),
        ]

    def test_happy_path_rows(self):
        result, rows = self._run(
            [*self._head(THREE[:1]), _make_llm_response(json.dumps(THREAT_ANALYSIS))]
        )
        assert result.success is True
        assert rows == [
            "Phase 1 (Inventory) started",
            "Phase 1 (Inventory): succeeded",
            "Phase 2 (Infrastructure) started",
            "Phase 2 (Infrastructure): succeeded",
            "Phase 3a (Threat Identification) started",
            "Phase 3a (Threat Identification): succeeded (1 threats identified)",
            "Script review started",
            "Script review: succeeded (0 findings added)",
            "Phase 3b (Per-Threat Analysis) started",
            "Phase 3b: threat 1/1: succeeded",
            "Phase 3b (Per-Threat Analysis): succeeded (1 of 1 threats analyzed)",
        ]

    def test_phase_failure_row_names_the_phase_and_the_http_status(self):
        err = litellm.AuthenticationError(
            message="x", llm_provider="anthropic", model="m"
        )
        result, rows = self._run(
            [_make_llm_response(json.dumps(INVENTORY)), err, err, err]
        )
        assert rows[-1] == (
            "Phase 2 (Infrastructure): failed: HTTP 401 authentication_error"
        )
        assert result.success is False

    def test_unusable_phase_1_output_row(self):
        result, rows = self._run(
            [_make_llm_response("not json"), _make_llm_response("not json")]
        )
        assert rows[-1] == "Phase 1 (Inventory): failed: unparseable response"
        assert result.success is False

    def test_unusable_phase_2_output_row(self):
        result, rows = self._run(
            [
                _make_llm_response(json.dumps(INVENTORY)),
                _make_llm_response("not json"),
                _make_llm_response("not json"),
            ]
        )
        assert rows[-1] == "Phase 2 (Infrastructure): failed: unparseable response"
        assert result.success is False

    def test_per_threat_and_deadline_rows(self, monkeypatch):
        clock = FakeClock()
        monkeypatch.setattr("tmi_tf.retry.time.sleep", clock.sleep)
        monkeypatch.setattr("tmi_tf.retry.random.random", lambda: 0.0)
        limited = rate_limit_error({"retry-after": "40"})
        result, rows = self._run(
            [
                *self._head(THREE),
                _make_llm_response(json.dumps(THREAT_ANALYSIS)),
                limited,
                limited,
                limited,
            ],
            retry_budget=RetryBudget(100.0, clock),
        )
        assert result.success is True
        assert "Phase 3b: threat 1/3: succeeded" in rows
        assert "Phase 3b: threat 2/3: failed: HTTP 429 rate_limit_error" in rows
        assert "Phase 3b: threats 3-3 of 3: failed: skipped, deadline reached" in rows
        assert rows[-1] == (
            "Phase 3b (Per-Threat Analysis): failed: 2 of 3 threats not analyzed "
            "(HTTP 429 rate_limit_error, deadline reached)"
        )
        assert not any(r.startswith("Phase 3b: Analyzing") for r in rows)

    def test_refused_and_unparseable_threat_rows(self):
        refused = LLMResponse(
            text=None,
            input_tokens=100,
            output_tokens=0,
            cost=0.01,
            finish_reason="content_filter",
        )
        _, rows = self._run(
            [
                *self._head(THREE[:2]),
                refused,
                _make_llm_response("not json"),
            ]
        )
        assert "Phase 3b: threat 1/2: failed: refused (content_filter)" in rows
        assert "Phase 3b: threat 2/2: failed: unparseable response" in rows
        assert "Model refusals (content_filter): phase 3b: 1 threat(s)" in rows

    def test_script_review_failure_row(self, monkeypatch):
        monkeypatch.setattr(
            LLMAnalyzer,
            "_review_scripts",
            lambda self, name, blobs, hits: ([], 0, 0, 0.0, "boom", []),
        )
        _, rows = self._run(
            [*self._head(THREE[:1]), _make_llm_response(json.dumps(THREAT_ANALYSIS))]
        )
        assert "Script review: failed: boom" in rows

    def test_no_row_contains_exception_text(self):
        err = litellm.AuthenticationError(
            message="sk-secret-body", llm_provider="anthropic", model="m"
        )
        _, rows = self._run([_make_llm_response(json.dumps(INVENTORY)), err, err, err])
        assert rows
        assert not any("sk-secret-body" in r for r in rows)

    def test_callback_failure_on_a_success_row_keeps_the_finding(self):
        provider = _make_provider()
        provider.complete.side_effect = [
            *self._head(THREE[:2]),
            _make_llm_response(json.dumps(THREAT_ANALYSIS)),
            _make_llm_response(json.dumps(THREAT_ANALYSIS)),
        ]

        def cb(row: str) -> None:
            if row.startswith("Phase 3b: threat") and row.endswith("succeeded"):
                raise RuntimeError("note write failed")

        result = LLMAnalyzer(provider).analyze_repository(
            _make_tf_repo(), status_callback=cb
        )
        gaps = result.threat_gaps
        assert result.success is True
        assert len(result.security_findings) == 2
        assert gaps == ThreatGaps(identified=2)
        assert gaps.identified == len(result.security_findings) + gaps.not_analyzed

    def test_callback_base_exception_still_propagates(self):
        class Abort(BaseException):
            pass

        provider = _make_provider()
        provider.complete.side_effect = self._head(THREE[:1]) + [
            _make_llm_response(json.dumps(THREAT_ANALYSIS))
        ]

        def cb(row: str) -> None:
            if row.startswith("Phase 3b: threat"):
                raise Abort

        with pytest.raises(Abort):
            LLMAnalyzer(provider).analyze_repository(
                _make_tf_repo(), status_callback=cb
            )

    def test_failure_row_callback_error_does_not_mask_the_failure(self):
        provider = _make_provider()
        provider.complete.side_effect = [
            _make_llm_response("not json"),
            _make_llm_response("not json"),
        ]

        def cb(row: str) -> None:
            if "failed" in row:
                raise RuntimeError("note write failed")

        result = LLMAnalyzer(provider).analyze_repository(
            _make_tf_repo(), status_callback=cb
        )
        assert result.success is False
        assert "Phase 1" in result.error_message


OLD_3B_TEMPLATE_LINES = sorted(
    line
    for line in """## Threat To Analyze
**Name:** {threat_name}
**Description:** {threat_description}
**Affected Components:** {affected_components}
## Infrastructure Context
### Inventory
{inventory_json}
### Infrastructure Analysis
{infrastructure_json}
---
Analyze the above security threat in the context of the infrastructure. Produce STRIDE classification, a CVSS 4.0 vector string, CWE identifiers, a mitigation recommendation, and a category. Return ONLY the JSON object.""".splitlines()
)

_MARKER_LINE = "<!-- cache-breakpoint -->"
_THREAT_ANALYSIS_OK = {
    "threat_type": "Tampering",
    "severity": "High",
    "cvss_vector": "",
    "cwe_id": ["CWE-306"],
    "mitigation": "m",
    "category": "c",
}


def _cache_resp(obj, **cache) -> LLMResponse:
    return LLMResponse(
        text=json.dumps(obj),
        input_tokens=100,
        output_tokens=50,
        cost=0.01,
        finish_reason="stop",
        **cache,
    )


def _run_3b(threats, analyses, *, infrastructure=None, status_callback=None):
    provider = _make_provider()
    provider.complete.side_effect = [
        _cache_resp({"components": [], "services": []}),
        _cache_resp(infrastructure or {"relationships": []}),
        _cache_resp(threats),
        *analyses,
    ]
    result = LLMAnalyzer(provider).analyze_repository(
        _make_tf_repo(), status_callback=status_callback
    )
    return provider, result


_ONE_THREAT = [{"name": "T", "description": "d", "affected_components": []}]


class TestCachePrefix:
    def test_template_is_reordered_not_reworded(self):
        text = (prompts_dir() / "threat_analysis_user.txt").read_text(encoding="utf-8")
        lines = [ln for ln in text.splitlines() if ln.strip() and ln != _MARKER_LINE]
        assert sorted(lines) == OLD_3B_TEMPLATE_LINES
        assert text.splitlines().count(_MARKER_LINE) == 1

    def test_marker_constant(self):
        assert CACHE_BREAKPOINT_MARKER == _MARKER_LINE

    def test_shipped_template_splits_into_shared_prefix_and_threat_suffix(self):
        a = LLMAnalyzer(_make_provider())
        assert "{inventory_json}" in a.threat_analysis_prefix_template
        assert "{infrastructure_json}" in a.threat_analysis_prefix_template
        assert a.threat_analysis_suffix_template.startswith("## Threat To Analyze")
        assert CACHE_BREAKPOINT_MARKER not in (
            a.threat_analysis_prefix_template + a.threat_analysis_suffix_template
        )

    @pytest.mark.parametrize(
        "template",
        [
            "{inventory_json}{infrastructure_json}{threat_name}{threat_description}{affected_components}",
            "A\n<!-- cache-breakpoint -->\nB\n<!-- cache-breakpoint -->\nC",
            "{inventory_json}\n<!-- cache-breakpoint -->\n{infrastructure_json}{threat_name}{threat_description}{affected_components}",
            "{inventory_json}{infrastructure_json}{threat_name}\n<!-- cache-breakpoint -->\n{threat_description}{affected_components}",
            "",
        ],
    )
    def test_split_rejects_a_bad_template(self, template):
        with pytest.raises(ValueError):
            split_cache_prefix(template)

    def test_split_accepts_a_good_template(self):
        prefix, suffix = split_cache_prefix(
            "{inventory_json}\n{infrastructure_json}\n<!-- cache-breakpoint -->\n"
            "{threat_name}{threat_description}{affected_components}\n"
        )
        assert prefix == "{inventory_json}\n{infrastructure_json}\n"
        assert suffix == "{threat_name}{threat_description}{affected_components}\n"

    def test_every_3b_call_shares_one_prefix_including_the_cwe_corrective_turn(self):
        threats = [
            {"name": "T1", "description": "d", "affected_components": []},
            {"name": "T2", "description": "d", "affected_components": []},
        ]
        provider, result = _run_3b(
            threats,
            [
                _cache_resp({"cwe_id": ["CWE-862"]}),
                _cache_resp({"cwe_id": ["CWE-306"]}),
                _cache_resp(_THREAT_ANALYSIS_OK),
            ],
        )
        calls = provider.complete.call_args_list
        early, third_b = calls[:3], calls[3:]
        assert all("cache_prefix" not in c.kwargs for c in early)
        prefixes = {c.kwargs["cache_prefix"] for c in third_b}
        assert len(third_b) == 3 and len(prefixes) == 1
        prefix = prefixes.pop()
        assert json.dumps(result.inventory, indent=2) in prefix
        assert json.dumps(result.infrastructure, indent=2) in prefix
        for c in third_b:
            assert json.dumps(result.infrastructure, indent=2) not in c.args[1]
            assert c.args[1].startswith("## Threat To Analyze")
        assert "not allowed" in third_b[1].args[1]

    def test_repository_text_cannot_forge_a_breakpoint(self):
        provider, result = _run_3b(
            _ONE_THREAT,
            [_cache_resp(_THREAT_ANALYSIS_OK)],
            infrastructure={"architecture_summary": CACHE_BREAKPOINT_MARKER},
        )
        calls = provider.complete.call_args_list
        assert CACHE_BREAKPOINT_MARKER in calls[3].kwargs["cache_prefix"]
        assert result.success

    def test_phase_3a_text_with_a_marker_stays_in_the_user_prompt(self):
        threats = [
            {
                "name": "T1",
                "description": "x\n<!-- cache-breakpoint -->\ny",
                "affected_components": [],
            },
            {"name": "T2", "description": "d", "affected_components": []},
        ]
        provider, result = _run_3b(
            threats,
            [_cache_resp(_THREAT_ANALYSIS_OK), _cache_resp(_THREAT_ANALYSIS_OK)],
        )
        b_calls = provider.complete.call_args_list[3:]
        assert len(b_calls) == 2
        assert len({c.kwargs["cache_prefix"] for c in b_calls}) == 1
        assert result.success
        assert "\n<!-- cache-breakpoint -->\n" in b_calls[0].args[1]
        assert CACHE_BREAKPOINT_MARKER not in b_calls[0].kwargs["cache_prefix"]

    def test_cache_tokens_are_summed_on_the_analysis(self):
        threats = [
            {"name": "T1", "description": "d", "affected_components": []},
            {"name": "T2", "description": "d", "affected_components": []},
        ]
        _, result = _run_3b(
            threats,
            [
                _cache_resp(_THREAT_ANALYSIS_OK, cache_creation_tokens=75000),
                _cache_resp(_THREAT_ANALYSIS_OK, cache_read_tokens=75000),
            ],
        )
        assert (result.cache_creation_tokens, result.cache_read_tokens) == (
            75000,
            75000,
        )

    def test_phase_3b_cache_log_reports_only_phase_3b(self, caplog):
        provider = _make_provider()
        provider.complete.side_effect = [
            _cache_resp({"components": [], "services": []}, cache_read_tokens=7),
            _cache_resp({"relationships": []}, cache_read_tokens=11),
            _cache_resp(_ONE_THREAT),
            _cache_resp(_THREAT_ANALYSIS_OK, cache_creation_tokens=500),
        ]
        with caplog.at_level("INFO", logger="tmi_tf.llm_analyzer"):
            result = LLMAnalyzer(provider).analyze_repository(_make_tf_repo())
        lines = [
            r.getMessage() for r in caplog.records if "Phase 3b cache" in r.getMessage()
        ]
        assert lines == ["Phase 3b cache: 0 read, 500 written input tokens"]
        # The analysis total spans every phase.
        assert result.cache_read_tokens == 18
        assert result.cache_creation_tokens == 500

    def test_empty_response_retry_sums_cache_tokens(self):
        empty = LLMResponse(
            text=None,
            input_tokens=1,
            output_tokens=0,
            cost=0.0,
            finish_reason="stop",
            cache_read_tokens=10,
            cache_creation_tokens=3,
        )
        normal = LLMResponse(
            text="x",
            input_tokens=1,
            output_tokens=1,
            cost=0.0,
            finish_reason="stop",
            cache_read_tokens=20,
            cache_creation_tokens=4,
        )
        provider = _make_provider()
        provider.complete.side_effect = [empty, normal]
        response = call_llm_checked(provider, "s", "u", "x", cache_prefix="P")
        assert response.cache_read_tokens == 30
        assert response.cache_creation_tokens == 7
        assert all(
            c.kwargs["cache_prefix"] == "P" for c in provider.complete.call_args_list
        )


class TestUnparseableAnswersAreFailures:
    """Final review Finding 1 (Option A): an empty, truncated or unparseable
    3a or script-review answer is a failure, never a succeeded row."""

    def _run(self, effects):
        provider = _make_provider()
        provider.complete.side_effect = effects
        rows: list[str] = []
        result = LLMAnalyzer(provider).analyze_repository(
            _make_tf_repo(), status_callback=rows.append
        )
        return result, rows

    def _two(self):
        return [
            _make_llm_response(json.dumps(INVENTORY)),
            _make_llm_response(json.dumps(INFRASTRUCTURE)),
        ]

    def test_3a_unparseable_answer_fails(self):
        result, rows = self._run(
            [*self._two(), _make_llm_response("here are some threats, no array")]
        )
        assert result.success is False
        assert "Phase 3a (Threat Identification): failed: unparseable response" in rows
        assert not any("Phase 3a (Threat Identification): succeeded" in r for r in rows)
        assert not any("here are some threats" in r for r in rows)

    def test_3a_truncated_answer_fails(self):
        truncated = LLMResponse(
            text='[{"name": "T", "descr',
            input_tokens=10,
            output_tokens=64000,
            cost=0.01,
            finish_reason="length",
        )
        result, rows = self._run([*self._two(), truncated])
        assert result.success is False
        assert "Phase 3a (Threat Identification): failed: unparseable response" in rows
        assert not any('"name"' in r for r in rows)

    def test_failed_3a_keeps_tokens_and_cost(self):
        for text, reason in (("no array", "stop"), ('[{"na', "length")):
            bad = LLMResponse(
                text=text,
                input_tokens=7,
                output_tokens=64000,
                cost=0.5,
                finish_reason=reason,
            )
            result, _ = self._run([*self._two(), bad])
            assert result.success is False
            assert result.input_tokens == 100 + 100 + 7
            assert result.output_tokens == 50 + 50 + 64000
            assert result.total_cost == pytest.approx(0.01 + 0.01 + 0.5)

    def test_3a_empty_answer_fails(self):
        empty = LLMResponse(
            text="", input_tokens=1, output_tokens=0, cost=0.0, finish_reason="stop"
        )
        result, rows = self._run([*self._two(), empty, empty, empty])
        assert result.success is False
        assert "Phase 3a (Threat Identification): failed: unparseable response" in rows

    def test_3a_valid_empty_array_succeeds(self):
        result, rows = self._run([*self._two(), _make_llm_response("[]")])
        assert result.success is True
        assert (
            "Phase 3a (Threat Identification): succeeded (0 threats identified)" in rows
        )
