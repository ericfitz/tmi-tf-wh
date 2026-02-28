"""Tests for the HTML table generation in MarkdownGenerator."""

from tmi_tf.markdown_generator import (
    MarkdownGenerator,
    _config_nested_table,
    _esc,
    _html_list,
    _html_table,
)


class TestEsc:
    """Test HTML escaping helper."""

    def test_plain_text(self):
        assert _esc("hello") == "hello"

    def test_html_entities(self):
        assert _esc("<script>") == "&lt;script&gt;"
        assert _esc('"quoted"') == "&quot;quoted&quot;"
        assert _esc("a & b") == "a &amp; b"

    def test_empty_string(self):
        assert _esc("") == ""


class TestHtmlList:
    """Test HTML list helper."""

    def test_empty_list(self):
        assert _html_list([]) == ""

    def test_single_item(self):
        result = _html_list(["item1"])
        assert result == "<ul><li>item1</li></ul>"

    def test_multiple_items(self):
        result = _html_list(["a", "b", "c"])
        assert "<ul>" in result
        assert "<li>a</li>" in result
        assert "<li>b</li>" in result
        assert "<li>c</li>" in result

    def test_escapes_content(self):
        result = _html_list(["<script>"])
        assert "<script>" not in result
        assert "&lt;script&gt;" in result


class TestHtmlTable:
    """Test HTML table builder."""

    def test_basic_table(self):
        result = _html_table(["A", "B"], [["1", "2"], ["3", "4"]])
        assert "<table" in result
        assert "<thead>" in result
        assert "<tbody>" in result
        assert "<th>A</th>" in result
        assert "<th>B</th>" in result
        assert "<td>1</td>" in result
        assert "<td>4</td>" in result

    def test_col_widths(self):
        result = _html_table(["A", "B"], [["1", "2"]], col_widths=["30%", "70%"])
        assert "<colgroup>" in result
        assert 'style="width:30%"' in result
        assert 'style="width:70%"' in result

    def test_col_aligns(self):
        result = _html_table(
            ["A", "B"],
            [["1", "2"]],
            col_aligns=["left", "right"],
        )
        assert "text-align:left" in result
        assert "text-align:right" in result

    def test_bold_last_row(self):
        result = _html_table(["A"], [["normal"], ["total"]], bold_last_row=True)
        assert "<strong>total</strong>" in result
        # First row should NOT be bold
        assert "<strong>normal</strong>" not in result

    def test_no_colgroup_without_widths(self):
        result = _html_table(["A"], [["1"]])
        assert "<colgroup>" not in result

    def test_empty_rows(self):
        result = _html_table(["A", "B"], [])
        assert "<thead>" in result
        assert "<tbody></tbody>" in result


class TestConfigNestedTable:
    """Test nested configuration table builder."""

    def test_empty_config(self):
        assert _config_nested_table({}) == ""

    def test_single_entry(self):
        result = _config_nested_table({"key": "val"})
        assert "<table" in result
        assert "<strong>key</strong>" in result
        assert "<code>val</code>" in result

    def test_max_five_entries(self):
        config = {f"k{i}": f"v{i}" for i in range(10)}
        result = _config_nested_table(config)
        # Should only include 5 rows
        assert result.count("<tr>") == 5

    def test_escapes_content(self):
        result = _config_nested_table({"<key>": "<val>"})
        assert "&lt;key&gt;" in result
        assert "&lt;val&gt;" in result


class TestMarkdownGeneratorInventory:
    """Test inventory section generation."""

    def test_empty_components(self):
        gen = MarkdownGenerator()
        result = gen._format_inventory_section({"components": []})
        assert "No infrastructure components identified" in result

    def test_components_table(self):
        gen = MarkdownGenerator()
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
        assert "<table" in result
        assert "Web Server" in result
        assert "aws_instance" in result
        assert "Serves web traffic" in result
        # Configuration should be a nested table
        assert "instance_type" in result
        assert "t3.micro" in result

    def test_services_table(self):
        gen = MarkdownGenerator()
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
        assert "web-frontend" in result
        # Criteria should be a list, not comma-separated
        assert "<ul>" in result
        assert "<li>shared VPC</li>" in result
        assert "<li>naming pattern</li>" in result
        assert "<li>web-1</li>" in result


class TestMarkdownGeneratorDataFlows:
    """Test data flows section generation."""

    def test_empty_flows(self):
        gen = MarkdownGenerator()
        result = gen._format_data_flows_section({"data_flows": []})
        assert result == ""

    def test_flows_table(self):
        gen = MarkdownGenerator()
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
        assert "<table" in result
        assert "Web Traffic" in result
        assert "HTTPS" in result

    def test_trust_boundaries_uses_list(self):
        gen = MarkdownGenerator()
        infra = {
            "data_flows": [
                {
                    "name": "f",
                    "source_id": "a",
                    "target_id": "b",
                    "protocol": "TCP",
                    "port": 80,
                    "data_type": "data",
                }
            ],
            "trust_boundaries": [
                {
                    "name": "Public Zone",
                    "boundary_type": "network",
                    "component_ids": ["lb-1", "web-1", "web-2"],
                }
            ],
        }
        result = gen._format_data_flows_section(infra)
        assert "Public Zone" in result
        # Component IDs should be a list, not comma-separated
        assert "<ul>" in result
        assert "<li>lb-1</li>" in result
        assert "<li>web-1</li>" in result


class TestMarkdownGeneratorSecurity:
    """Test security section generation."""

    def test_no_findings(self):
        gen = MarkdownGenerator()
        result = gen._format_security_section([])
        assert "No security findings identified" in result

    def test_cwe_ids_as_code(self):
        gen = MarkdownGenerator()
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
                "affected_components": ["db-1"],
            }
        ]
        result = gen._format_security_section(findings)
        assert "<code>CWE-89</code>" in result
        assert "<code>CWE-564</code>" in result

    def test_affected_components_as_list(self):
        gen = MarkdownGenerator()
        findings = [
            {
                "name": "Finding",
                "severity": "Medium",
                "description": "desc",
                "threat_type": "Spoofing",
                "category": "Auth",
                "mitigation": "Fix it",
                "cwe_id": [],
                "affected_components": ["comp-a", "comp-b", "comp-c"],
            }
        ]
        result = gen._format_security_section(findings)
        assert "<ul>" in result
        assert "<li>comp-a</li>" in result
        assert "<li>comp-b</li>" in result
        assert "<li>comp-c</li>" in result


class TestMarkdownGeneratorMetrics:
    """Test per-repository metrics table."""

    def test_metrics_table_structure(self):
        from tmi_tf.llm_analyzer import TerraformAnalysis

        gen = MarkdownGenerator()

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
        assert "<table" in result
        assert "test-repo" in result
        assert "10.50s" in result
        assert "1,000" in result
        # Totals row should be bold
        assert "<strong>" in result
