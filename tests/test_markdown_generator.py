"""Tests for markdown report generation."""

from typing import ClassVar

from tmi_tf.llm_analyzer import TerraformAnalysis
from tmi_tf.markdown_generator import (
    MarkdownGenerator,
    _config_cell,
    _flatten,
    _leaf_text,
    _md_cell,
    _md_table,
)
from tmi_tf.tf_filter import Registry


def _make_analysis() -> TerraformAnalysis:
    """Create a sample TerraformAnalysis for testing."""
    return TerraformAnalysis(
        repo_name="test-repo",
        repo_url="https://github.com/org/test-repo",
        inventory={
            "components": [
                {
                    "name": "web-server",
                    "type": "compute",
                    "resource_type": "aws_instance",
                    "purpose": "Web server",
                    "configuration": {"instance_type": "t3.micro"},
                },
            ],
            "services": [
                {
                    "name": "web-service",
                    "criteria": ["serves HTTP"],
                    "compute_units": ["web-server"],
                    "associated_resources": [],
                },
            ],
            "dependencies": [
                {
                    "type": "cloud",
                    "provider": "AWS",
                    "service": "EC2",
                    "dependent_components": ["web-server"],
                },
            ],
        },
        infrastructure={
            "architecture_summary": "A simple web app",
            "mermaid_diagram": "graph TD\n  A-->B",
            "relationships": [
                {
                    "source_id": "web",
                    "target_id": "db",
                    "relationship_type": "connects_to",
                    "description": "Web connects to DB",
                },
            ],
            "data_flows": [
                {
                    "name": "HTTP",
                    "source_id": "user",
                    "target_id": "web",
                    "protocol": "HTTPS",
                    "port": "443",
                    "data_type": "requests",
                },
            ],
            "trust_boundaries": [],
        },
        security_findings=[
            {
                "name": "Open port",
                "severity": "Medium",
                "score": 5.0,
                "threat_type": "Information Disclosure",
                "category": "Network",
                "description": "Port open",
                "mitigation": "Close it",
                "cwe_id": [],
                "affected_components": ["web"],
            },
        ],
        success=True,
        elapsed_time=10.0,
        input_tokens=1000,
        output_tokens=500,
        model="anthropic/claude-opus-4-6",
        provider="anthropic",
        total_cost=0.05,
    )


class TestMarkdownGeneratorInventory:
    """Test inventory section generation."""

    def test_empty_components(self):
        gen = MarkdownGenerator(_fake_registry())
        result = gen._format_inventory_section({"components": []})
        assert "No infrastructure components identified" in result

    def test_components_table_filters_configuration(self):
        gen = MarkdownGenerator(_fake_registry())
        inventory = {
            "components": [
                {
                    "type": "compute",
                    "name": "Web Server",
                    "resource_type": "aws_instance",
                    "purpose": "Serves web traffic",
                    "configuration": {"instance_type": "t3.micro", "ami": "ami-123"},
                }
            ]
        }
        result = gen._format_inventory_section(inventory)
        assert "#### Compute" in result
        assert "| Name | Resource Type | Purpose | Configuration |" in result
        assert "|---|---|---|---|" in result
        assert (
            "| Web Server | `aws_instance` | Serves web traffic | `ami = ami-123` |"
            in result
        )
        assert "t3.micro" not in result
        assert "<table" not in result

    def test_unknown_resource_type_config_is_dash(self):
        gen = MarkdownGenerator(_fake_registry())
        inventory = {
            "components": [
                {
                    "type": "other",
                    "name": "thing",
                    "resource_type": "vendor_widget",
                    "purpose": "p",
                    "configuration": {"secret": "x"},
                }
            ]
        }
        result = gen._format_inventory_section(inventory)
        assert "| thing | `vendor_widget` | p | — |" in result
        assert "secret" not in result

    def test_resource_type_escapes_pipe(self):
        gen = MarkdownGenerator(_fake_registry())
        inventory = {
            "components": [
                {
                    "type": "other",
                    "name": "thing",
                    "resource_type": "vendor|widget",
                    "purpose": "p",
                    "configuration": {},
                }
            ]
        }
        result = gen._format_inventory_section(inventory)
        assert "| thing | `vendor\\|widget` | p | — |" in result

    def test_name_falls_back_to_id(self):
        gen = MarkdownGenerator(_fake_registry())
        inventory = {
            "components": [
                {
                    "id": "aws_instance.web",
                    "name": None,
                    "type": "compute",
                    "resource_type": "aws_instance",
                    "purpose": None,
                    "configuration": {},
                }
            ]
        }
        result = gen._format_inventory_section(inventory)
        assert "| aws_instance.web | `aws_instance` | — | — |" in result
        assert "None" not in result

    def test_services_table(self):
        gen = MarkdownGenerator(_fake_registry())
        inventory = {
            "components": [
                {
                    "type": "compute",
                    "name": "web-1",
                    "resource_type": "aws_instance",
                    "purpose": "Web server",
                }
            ],
            "services": [
                {
                    "name": "web-frontend",
                    "criteria": ["shared VPC", "naming pattern"],
                    "compute_units": ["web-1", "web-2"],
                    "associated_resources": ["alb-1"],
                }
            ],
        }
        result = gen._format_inventory_section(inventory)
        assert "#### Services (Logical Groupings)" in result
        assert (
            "| web-frontend | shared VPC<br>naming pattern | web-1<br>web-2 | alb-1 |"
            in result
        )
        assert "<ul>" not in result


class TestMarkdownGeneratorRelationships:
    """Test component relationships section generation."""

    def test_empty(self):
        gen = MarkdownGenerator(_fake_registry())
        assert gen._format_relationships_section({"relationships": []}) == ""

    def test_grouped_table(self):
        gen = MarkdownGenerator(_fake_registry())
        infra = {
            "relationships": [
                {
                    "source_id": "web",
                    "target_id": "db",
                    "relationship_type": "connects_to",
                    "description": "Web | DB",
                },
            ]
        }
        result = gen._format_relationships_section(infra)
        assert "### Component Relationships" in result
        assert "#### Connects To" in result
        assert "| Source | Target | Description |" in result
        assert "| web | db | Web \\| DB |" in result


class TestMarkdownGeneratorDataFlows:
    """Test data flows section generation."""

    def test_empty_flows(self):
        gen = MarkdownGenerator(_fake_registry())
        assert gen._format_data_flows_section({"data_flows": []}) == ""

    def test_flows_table(self):
        gen = MarkdownGenerator(_fake_registry())
        infra = {
            "data_flows": [
                {
                    "name": "Web Traffic",
                    "source_id": "lb-1",
                    "target_id": "web-1",
                    "protocol": "HTTPS",
                    "port": 443,
                    "data_type": "API requests",
                }
            ]
        }
        result = gen._format_data_flows_section(infra)
        assert "### Data Flows" in result
        assert "| Flow | Source | Target | Protocol | Port | Data Type |" in result
        assert "| Web Traffic | lb-1 | web-1 | HTTPS | 443 | API requests |" in result
        assert "Trust Boundaries" not in result


class TestMarkdownGeneratorTrustBoundaries:
    """Test trust boundaries section generation."""

    def test_empty(self):
        gen = MarkdownGenerator(_fake_registry())
        assert gen._format_trust_boundaries_section({}) == ""

    def test_trust_boundaries_without_flows(self):
        gen = MarkdownGenerator(_fake_registry())
        infra = {
            "data_flows": [],
            "trust_boundaries": [
                {
                    "name": "Public Zone",
                    "boundary_type": "network",
                    "component_ids": ["lb-1", "web-1"],
                }
            ],
        }
        result = gen._format_trust_boundaries_section(infra)
        assert "### Trust Boundaries" in result
        assert "| Boundary | Type | Components |" in result
        assert "| Public Zone | network | lb-1<br>web-1 |" in result


class TestMarkdownGeneratorSecurity:
    """Test security section generation."""

    def test_no_findings(self):
        gen = MarkdownGenerator(_fake_registry())
        assert "No security findings identified" in gen._format_security_section([])

    def test_findings_table(self):
        gen = MarkdownGenerator(_fake_registry())
        findings = [
            {
                "name": "SQL Injection",
                "severity": "High",
                "score": 8.5,
                "description": "desc",
                "threat_type": "Tampering",
                "category": "Input Validation",
                "mitigation": "Use parameterized queries",
                "cwe_id": ["CWE-89", "CWE-564"],
                "affected_components": ["db-1", "api-1"],
            }
        ]
        result = gen._format_security_section(findings)
        assert "### Security Observations" in result
        assert (
            "| Finding | Severity | STRIDE | Category | Description | Mitigation "
            "| Affected Components |"
        ) in result
        assert (
            "| SQL Injection<br>`CWE-89` `CWE-564` | High (8.5) | Tampering "
            "| Input Validation | desc | Use parameterized queries | db-1<br>api-1 |"
        ) in result
        assert "<table" not in result

    def test_severity_without_score(self):
        gen = MarkdownGenerator(_fake_registry())
        findings = [
            {"name": "F", "severity": "Low", "cwe_id": [], "affected_components": []}
        ]
        result = gen._format_security_section(findings)
        assert "| F | Low | — | — | — | — | — |" in result


class TestMarkdownGeneratorMetrics:
    """Test per-repository metrics table."""

    def test_metrics_table_structure(self):
        gen = MarkdownGenerator(_fake_registry())

        analysis = TerraformAnalysis(
            repo_name="test-repo",
            repo_url="https://github.com/test/repo",
            success=True,
            elapsed_time=10.5,
            input_tokens=1000,
            output_tokens=500,
            total_cost=0.05,
            model="test-model",
            provider="test-provider",
        )

        result = gen._generate_analysis_job_info("tm-123", [analysis])
        assert "| Repository | Time | Input Tokens | Output Tokens | Cost |" in result
        assert "| test-repo | 10.50s | 1,000 | 500 | $0.0500 |" in result
        assert (
            "| **Total** | **10.50s** | **1,000** | **500** | **$0.0500** |" in result
        )
        assert "<table" not in result


INFRA_HEADINGS = (
    "### Component Relationships",
    "### Data Flows",
    "### Trust Boundaries",
    "### External Dependencies",
)


class TestGenerateInventoryReport:
    def test_contains_all_tables(self):
        gen = MarkdownGenerator(_fake_registry())
        analysis = _make_analysis()
        analysis.infrastructure["trust_boundaries"] = [
            {"name": "Edge", "boundary_type": "network", "component_ids": ["web"]}
        ]
        report = gen.generate_inventory_report("TM", "tm-1", [analysis])
        assert "### Infrastructure Inventory" in report
        assert "web-server" in report
        assert "web-service" in report
        for heading in INFRA_HEADINGS:
            assert heading in report
        assert "Edge" in report
        assert "EC2" in report
        assert "## Analysis Job Information" in report

    def test_section_order(self):
        gen = MarkdownGenerator(_fake_registry())
        analysis = _make_analysis()
        analysis.infrastructure["trust_boundaries"] = [
            {"name": "Edge", "boundary_type": "network", "component_ids": ["web"]}
        ]
        report = gen.generate_inventory_report("TM", "tm-1", [analysis])
        positions = [
            report.index(h) for h in ("### Infrastructure Inventory", *INFRA_HEADINGS)
        ]
        assert positions == sorted(positions)

    def test_excludes_analysis_sections(self):
        gen = MarkdownGenerator(_fake_registry())
        report = gen.generate_inventory_report("TM", "tm-1", [_make_analysis()])
        assert "Security Observations" not in report
        assert "Open port" not in report
        assert "Architecture Summary" not in report
        assert "Consolidated Findings" not in report

    def test_environment_name_in_title(self):
        gen = MarkdownGenerator(_fake_registry())
        report = gen.generate_inventory_report(
            "TM", "tm-1", [_make_analysis()], environment_name="oci-private"
        )
        assert "# Terraform Infrastructure Inventory - oci-private" in report

    def test_failed_analysis(self):
        gen = MarkdownGenerator(_fake_registry())
        failed = TerraformAnalysis(
            repo_name="bad",
            repo_url="https://x/bad",
            success=False,
            error_message="boom",
        )
        report = gen.generate_inventory_report("TM", "tm-1", [failed])
        assert "*Analysis failed: boom*" in report


class TestGenerateAnalysisReport:
    def test_contains_narrative_and_findings(self):
        gen = MarkdownGenerator(_fake_registry())
        report = gen.generate_analysis_report("TM", "tm-1", [_make_analysis()])
        assert "### Architecture Summary" in report
        assert "simple web app" in report
        assert "```mermaid" in report
        assert "### Security Observations" in report
        assert "Open port" in report
        assert "## Consolidated Findings" in report
        assert "## Analysis Job Information" in report

    def test_excludes_inventory_tables(self):
        gen = MarkdownGenerator(_fake_registry())
        report = gen.generate_analysis_report("TM", "tm-1", [_make_analysis()])
        assert "Infrastructure Inventory" not in report
        for heading in INFRA_HEADINGS:
            assert heading not in report
        assert "EC2" not in report

    def test_pointer_line(self):
        gen = MarkdownGenerator(_fake_registry())
        report = gen.generate_analysis_report(
            "TM",
            "tm-1",
            [_make_analysis()],
            inventory_note_name="Terraform Inventory (m, 2026-09-26 00:00:00 UTC)",
        )
        assert (
            "Inventory, relationships, data flows, trust boundaries and dependencies: "
            "see note *Terraform Inventory (m, 2026-09-26 00:00:00 UTC)*."
        ) in report
        assert report.index("see note *") < report.index("### Security Observations")

    def test_no_pointer_without_name(self):
        gen = MarkdownGenerator(_fake_registry())
        report = gen.generate_analysis_report("TM", "tm-1", [_make_analysis()])
        assert "see note *" not in report

    def test_environment_name_in_title(self):
        gen = MarkdownGenerator(_fake_registry())
        report = gen.generate_analysis_report(
            "TM", "tm-1", [_make_analysis()], environment_name="aws-public"
        )
        assert "# Terraform Infrastructure Analysis - aws-public" in report

    def test_combined_report_removed(self):
        assert not hasattr(MarkdownGenerator, "generate_report")


class TestMdCell:
    def test_plain_text(self):
        assert _md_cell("hello") == "hello"

    def test_md_cell_escapes_pipe_html_and_newline(self):
        assert _md_cell("a|b") == "a\\|b"
        assert _md_cell("<script>") == "&lt;script&gt;"
        assert _md_cell("line1\nline2") == "line1<br>line2"

    def test_list_joins_with_br(self):
        assert _md_cell(["a", "b|c", "<d>"]) == "a<br>b\\|c<br>&lt;d&gt;"

    def test_empty_is_dash(self):
        assert _md_cell("") == "—"
        assert _md_cell(None) == "—"
        assert _md_cell([]) == "—"
        assert _md_cell(["", None]) == "—"

    def test_non_string_scalars(self):
        assert _md_cell(443) == "443"
        assert _md_cell(5.0) == "5.0"


class TestMdTable:
    def test_basic_table(self):
        assert _md_table(["A", "B"], [["1", "2"], ["3", "4"]]) == (
            "| A | B |\n|---|---|\n| 1 | 2 |\n| 3 | 4 |"
        )

    def test_empty_rows_still_has_header_and_separator(self):
        assert _md_table(["A"], []) == "| A |\n|---|"


def _fake_registry() -> Registry:
    return Registry(
        providers={},
        resources={
            "aws_instance": {
                "category": "compute",
                "security_attrs": [
                    "ami",
                    "root_block_device.encrypted",
                    "metadata_options",
                ],
            }
        },
        hash_only_attrs=frozenset(),
        data_hash_only_attrs=frozenset(),
    )


class TestFlatten:
    def test_scalar(self):
        assert _flatten({"a": 1}) == [("a", 1)]

    def test_nested_dict_dot_path(self):
        assert _flatten({"a": {"b": {"c": "x"}}}) == [("a.b.c", "x")]

    def test_single_element_list_omits_index(self):
        assert _flatten({"blk": [{"enc": True}]}) == [("blk.enc", True)]

    def test_multi_element_list_indexes(self):
        assert _flatten({"ids": ["x", "y"]}) == [("ids[0]", "x"), ("ids[1]", "y")]

    def test_empty_containers_are_leaves(self):
        assert _flatten({"a": {}, "b": []}) == [("a", {}), ("b", [])]

    def test_bookkeeping_keys_skipped(self):
        assert _flatten({"__is_block__": True, "a": 1}) == [("a", 1)]


class TestLeafText:
    def test_bool_and_none_are_json(self):
        assert _leaf_text(True) == "true"
        assert _leaf_text(None) == "null"

    def test_truncates_at_120(self):
        text = _leaf_text("x" * 200)
        assert text == "x" * 120 + "…"

    def test_leaf_text_escapes_pipe_backtick_newline(self):
        assert _leaf_text("a|b") == "a\\|b"
        assert _leaf_text("a`b") == "a'b"
        assert _leaf_text("a\n  b") == "a b"


class TestConfigCell:
    ATTRS: ClassVar[list[str]] = [
        "ami",
        "root_block_device.encrypted",
        "metadata_options",
    ]

    def test_drops_non_security_attr(self):
        cell = _config_cell({"ami": "ami-1", "instance_type": "t3.micro"}, self.ATTRS)
        assert cell == "`ami = ami-1`"

    def test_unknown_type_is_dash(self):
        assert _config_cell({"ami": "ami-1"}, None) == "—"

    def test_non_dict_config_is_dash(self):
        assert _config_cell(None, self.ATTRS) == "—"
        assert _config_cell("t3.micro", self.ATTRS) == "—"

    def test_nothing_kept_is_dash(self):
        assert _config_cell({"instance_type": "t3.micro"}, self.ATTRS) == "—"

    def test_nested_block_flattens_to_dot_path(self):
        cfg = {"root_block_device": [{"encrypted": True, "volume_size": 10}]}
        assert _config_cell(cfg, self.ATTRS) == "`root_block_device.encrypted = true`"

    def test_whole_subtree_kept_and_joined_with_br(self):
        cfg = {
            "ami": "ami-1",
            "metadata_options": [{"http_tokens": "required", "hop": 1}],
        }
        assert _config_cell(cfg, self.ATTRS) == (
            "`ami = ami-1`<br>`metadata_options.http_tokens = required`"
            "<br>`metadata_options.hop = 1`"
        )

    def test_llm_fallback_shaped_config_is_filtered(self):
        # Fallback path: arbitrary LLM dict, no registry filtering upstream.
        cfg = {"instance_type": "t3.micro", "ami": "ami-1", "tags": {"Name": "web"}}
        assert _config_cell(cfg, self.ATTRS) == "`ami = ami-1`"

    def test_long_value_truncates(self):
        cell = _config_cell({"ami": "a" * 200}, self.ATTRS)
        assert cell == "`ami = " + "a" * 120 + "…`"


class TestGeneratorRegistry:
    def test_default_registry_is_loaded(self):
        gen = MarkdownGenerator()
        assert gen._registry.security_attrs("aws_instance") is not None

    def test_injected_registry(self):
        reg = _fake_registry()
        assert MarkdownGenerator(reg)._registry is reg


class TestMarkdownGeneratorDependencies:
    """Test external dependencies section generation."""

    def test_empty_dependencies(self):
        gen = MarkdownGenerator(_fake_registry())
        assert gen._format_dependencies_section({"dependencies": []}) == ""
        assert gen._format_dependencies_section({}) == ""

    def test_dependencies_table(self):
        gen = MarkdownGenerator(_fake_registry())
        inventory = {
            "dependencies": [
                {
                    "type": "cloud",
                    "provider": "AWS",
                    "service": "S3",
                    "dependent_components": [
                        "aws_s3_bucket.logs",
                        "aws_s3_bucket.data",
                    ],
                },
                {
                    "type": "saas",
                    "provider": "Google",
                    "service": "Sign-In",
                    "dependent_components": ["aws_lambda.auth"],
                },
            ]
        }
        result = gen._format_dependencies_section(inventory)
        assert "### External Dependencies" in result
        assert "| Type | Provider | Service | Dependent Components |" in result
        assert (
            "| cloud | AWS | S3 | aws_s3_bucket.logs<br>aws_s3_bucket.data |" in result
        )
        assert "| saas | Google | Sign-In | aws_lambda.auth |" in result
