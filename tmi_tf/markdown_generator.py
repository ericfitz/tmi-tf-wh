"""Markdown report generation from structured analysis JSON."""

import json
import logging
from datetime import datetime, timezone
from html import escape as html_escape
from typing import Any

from tmi_tf.llm_analyzer import TerraformAnalysis
from tmi_tf.tf_filter import Registry, _attr_tree, _select, load_registry

logger = logging.getLogger(__name__)


def _md_cell(value: Any) -> str:
    """One markdown table cell: HTML-escaped, ``|`` escaped, newlines as <br>.

    A list joins its items with <br>; anything empty renders as an em dash.
    """
    items = value if isinstance(value, list) else [value]
    lines = [
        html_escape(str(v), quote=True).replace("|", "\\|").replace("\n", "<br>")
        for v in items
        if v is not None and str(v) != ""
    ]
    return "<br>".join(lines) or "—"


def _md_table(headers: list[str], rows: list[list[str]]) -> str:
    """Markdown pipe table; ``rows`` are pre-rendered cell strings."""
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(lines)


_VALUE_MAX = 120


def _flatten(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    """(dot.path, leaf) pairs. Single-element lists drop their index (hcl2
    renders nested blocks as one-element lists); longer lists use ``path[i]``."""
    if isinstance(value, dict) and value:
        return [
            leaf
            for k, v in value.items()
            if not k.startswith("__")
            for leaf in _flatten(v, f"{prefix}.{k}" if prefix else k)
        ]
    if isinstance(value, list) and value:
        if len(value) == 1:
            return _flatten(value[0], prefix)
        return [
            leaf for i, v in enumerate(value) for leaf in _flatten(v, f"{prefix}[{i}]")
        ]
    return [(prefix, value)]


def _leaf_text(value: Any) -> str:
    """Config leaf value rendered as escaped prose (NOT inside a code span):
    whitespace collapsed, truncated at ``_VALUE_MAX`` raw chars, then
    HTML-escaped and ``|``-escaped. A raw ``<``/``>``/``&`` inside a
    backtick span is not safe -- the whole-note sanitizer parses the note
    as HTML before markdown is ever rendered, so a code span does not stop
    it from reading e.g. a heredoc's ``<<EOF > file`` as a tag and eating
    it. An empty value renders as a literal ``""`` so the line doesn't
    trail off with nothing after ``=``."""
    text = value if isinstance(value, str) else json.dumps(value)
    text = " ".join(text.split())
    if len(text) > _VALUE_MAX:
        text = text[:_VALUE_MAX] + "…"
    if text == "":
        return '""'
    return html_escape(text, quote=True).replace("|", "\\|")


def _config_cell(config: Any, attrs: list[str] | None) -> str:
    """Configuration column: registry security_attrs re-applied at render
    time (so the full-LLM fallback path is filtered too), one
    `` `path` = value `` per leaf (path in a code span, value escaped
    prose -- see ``_leaf_text``), joined with <br>."""
    if attrs is None or not isinstance(config, dict):
        return "—"
    selected = _select(config, _attr_tree(attrs))
    if not selected:
        return "—"
    lines = [f"`{path}` = {_leaf_text(v)}" for path, v in _flatten(selected)]
    return "<br>".join(lines) or "—"


class MarkdownGenerator:
    """Generates markdown reports from structured analysis results."""

    def __init__(self, registry: Registry | None = None) -> None:
        self._registry = registry or load_registry()

    def _format_inventory_section(self, inventory: dict[str, Any]) -> str:
        """Format inventory JSON into a markdown section of pipe tables."""
        parts = ["### Infrastructure Inventory"]

        components = inventory.get("components", [])
        if not components:
            parts.append("No infrastructure components identified.")
            return "\n\n".join(parts)

        type_order = [
            "compute",
            "storage",
            "network",
            "gateway",
            "security_control",
            "identity",
            "monitoring",
            "dns",
            "cdn",
            "other",
        ]

        # Group components by type; anything outside the fixed order above
        # (e.g. the full-LLM fallback emitting "database") folds into
        # "other" instead of being silently dropped.
        by_type: dict[str, list[dict[str, Any]]] = {}
        for comp in components:
            comp_type = comp.get("type") or "other"
            if comp_type not in type_order:
                comp_type = "other"
            by_type.setdefault(comp_type, []).append(comp)

        for comp_type in type_order:
            group = by_type.get(comp_type, [])
            if not group:
                continue

            parts.append(f"#### {comp_type.replace('_', ' ').title()}")

            rows: list[list[str]] = []
            for comp in group:
                resource_type = comp.get("resource_type") or ""
                resource_type_cell = (
                    "`"
                    + html_escape(resource_type, quote=True).replace("|", "\\|")
                    + "`"
                    if resource_type
                    else "—"
                )
                rows.append(
                    [
                        _md_cell(comp.get("name") or comp.get("id") or "Unknown"),
                        resource_type_cell,
                        _md_cell(comp.get("purpose")),
                        _config_cell(
                            comp.get("configuration"),
                            self._registry.security_attrs(resource_type),
                        ),
                    ]
                )
            parts.append(
                _md_table(["Name", "Resource Type", "Purpose", "Configuration"], rows)
            )

        # Services
        services = inventory.get("services", [])
        if services:
            parts.append("#### Services (Logical Groupings)")

            rows = [
                [
                    _md_cell(svc.get("name") or "Unknown"),
                    _md_cell(svc.get("criteria", [])),
                    _md_cell(svc.get("compute_units", [])),
                    _md_cell(svc.get("associated_resources", [])),
                ]
                for svc in services
            ]
            parts.append(
                _md_table(
                    ["Service", "Criteria", "Compute Units", "Associated Resources"],
                    rows,
                )
            )

        return "\n\n".join(parts)

    def _format_relationships_section(self, infrastructure: dict[str, Any]) -> str:
        """Format relationships JSON into a markdown section, grouped by type."""
        relationships = infrastructure.get("relationships", [])
        if not relationships:
            return ""
        by_type: dict[str, list[dict[str, Any]]] = {}
        for rel in relationships:
            by_type.setdefault(rel.get("relationship_type", "other"), []).append(rel)
        parts = ["### Component Relationships"]
        for rel_type, rels in by_type.items():
            parts.append(f"#### {rel_type.replace('_', ' ').title()}")
            rows = [
                [
                    _md_cell(rel.get("source_id", "?")),
                    _md_cell(rel.get("target_id", "?")),
                    _md_cell(rel.get("description")),
                ]
                for rel in rels
            ]
            parts.append(_md_table(["Source", "Target", "Description"], rows))
        return "\n\n".join(parts)

    def _format_data_flows_section(self, infrastructure: dict[str, Any]) -> str:
        """Format data flows JSON into a markdown table section."""
        flows = infrastructure.get("data_flows", [])
        if not flows:
            return ""
        keys = ("name", "source_id", "target_id", "protocol", "port", "data_type")
        rows = [[_md_cell(flow.get(k)) for k in keys] for flow in flows]
        return "### Data Flows\n\n" + _md_table(
            ["Flow", "Source", "Target", "Protocol", "Port", "Data Type"], rows
        )

    def _format_trust_boundaries_section(self, infrastructure: dict[str, Any]) -> str:
        """Format trust boundaries JSON into a markdown table section."""
        boundaries = infrastructure.get("trust_boundaries", [])
        if not boundaries:
            return ""
        rows = [
            [
                _md_cell(b.get("name")),
                _md_cell(b.get("boundary_type")),
                _md_cell(b.get("component_ids", [])),
            ]
            for b in boundaries
        ]
        return "### Trust Boundaries\n\n" + _md_table(
            ["Boundary", "Type", "Components"], rows
        )

    def _format_dependencies_section(self, inventory: dict[str, Any]) -> str:
        """Format external dependencies into a markdown table section."""
        dependencies = inventory.get("dependencies", [])
        if not dependencies:
            return ""
        rows = [
            [
                _md_cell(dep.get("type")),
                _md_cell(dep.get("provider")),
                _md_cell(dep.get("service")),
                _md_cell(dep.get("dependent_components", [])),
            ]
            for dep in dependencies
        ]
        return "### External Dependencies\n\n" + _md_table(
            ["Type", "Provider", "Service", "Dependent Components"], rows
        )

    def _format_security_section(self, security_findings: list[dict[str, Any]]) -> str:
        """Format security findings JSON into a markdown table section."""
        if not security_findings:
            return "### Security Observations\n\nNo security findings identified."
        rows: list[list[str]] = []
        for finding in security_findings:
            name = _md_cell(finding.get("name", "Unknown"))
            cwe_ids = finding.get("cwe_id", [])
            if isinstance(cwe_ids, str):
                cwe_ids = [cwe_ids]  # LLM sometimes emits a bare string, not a list
            if cwe_ids:
                name += "<br>" + " ".join(f"`{_md_cell(c)}`" for c in cwe_ids)
            severity = _md_cell(finding.get("severity", "Medium"))
            score = finding.get("score")
            if score is not None:
                severity += f" ({_md_cell(score)})"
            rows.append(
                [
                    name,
                    severity,
                    _md_cell(finding.get("threat_type")),
                    _md_cell(finding.get("category")),
                    _md_cell(finding.get("description")),
                    _md_cell(finding.get("mitigation")),
                    _md_cell(finding.get("affected_components", [])),
                ]
            )
        return "### Security Observations\n\n" + _md_table(
            [
                "Finding",
                "Severity",
                "STRIDE",
                "Category",
                "Description",
                "Mitigation",
                "Affected Components",
            ],
            rows,
        )

    def _format_scripts_section(self, analysis: TerraformAnalysis) -> str:
        """Hits only (source, rule, component, file, digest, severity): never script text."""
        parts = ["### Scripts and Metadata"]
        if analysis.script_review_error:
            parts.append(
                f"*LLM script review unavailable: {_md_cell(analysis.script_review_error)}*"
            )
        if not analysis.script_findings:
            parts.append("No script or metadata findings.")
            return "\n\n".join(parts)
        rows = [
            [
                _md_cell(r.get(k, ""))
                for k in ("source", "rule", "component", "file", "digest", "severity")
            ]
            for r in analysis.script_findings
        ]
        parts.append(
            _md_table(
                [
                    "Source",
                    "Rule / Category",
                    "Component",
                    "File",
                    "Digest",
                    "Severity",
                ],
                rows,
            )
        )
        return "\n\n".join(parts)

    def _generate_consolidated_findings(self, analyses: list[TerraformAnalysis]) -> str:
        """Generate consolidated findings section."""
        successful = [a for a in analyses if a.success]

        if not successful:
            return """## Consolidated Findings

No successful analyses to consolidate."""

        return f"""## Consolidated Findings

This section provides a high-level view across all {len(successful)} analyzed repositories.

### Threat Modeling Recommendations

Based on the analyzed infrastructure, consider focusing threat modeling efforts on:

1. **Authentication and Authorization**: Review access controls, IAM policies, and service-to-service authentication mechanisms
2. **Data Protection**: Examine data at rest and in transit, encryption configurations, and data flow paths
3. **Network Security**: Analyze network segmentation, firewall rules, security groups, and exposure to public networks
4. **Secrets Management**: Verify proper handling of credentials, API keys, and sensitive configuration
5. **Logging and Monitoring**: Ensure adequate logging, monitoring, and alerting for security events
6. **Compliance and Configuration**: Check for compliance with security standards and best practice configurations

### Next Steps

1. Review the detailed findings for each repository above
2. Identify high-risk components and data flows
3. Create threat diagrams for critical infrastructure components
4. Document identified threats using the TMI threat modeling framework
5. Prioritize remediation based on risk assessment
6. Update security controls and verify effectiveness

### Additional Resources

- Use the mermaid diagrams provided in each repository section to visualize architecture
- Cross-reference with your organization's security policies and compliance requirements
- Consider running automated security scanning tools (e.g., tfsec, checkov) for additional validation"""

    def _generate_analysis_job_info(
        self,
        threat_model_id: str,
        analyses: list[TerraformAnalysis],
    ) -> str:
        """Generate Analysis Job Information section combining all metadata."""
        # UTC, explicitly labelled: these reports are read by people in other
        # timezones than the one that generated them.
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        successful = [a for a in analyses if a.success]
        failed = [a for a in analyses if not a.success]

        parts = ["## Analysis Job Information"]

        # Job summary
        parts.append(
            f"**Threat Model ID**: `{threat_model_id}`\n"
            f"**Generated**: {timestamp}\n"
            f"**Repositories Analyzed**: {len(analyses)} "
            f"({len(successful)} successful, {len(failed)} failed)"
        )

        if failed:
            parts.append(
                f"**Failed Repositories**: {', '.join(a.repo_name for a in failed)}"
            )

        # Model & provider (use first successful analysis for model info)
        if successful:
            model = successful[0].model
            provider = successful[0].provider
            if model or provider:
                model_info = []
                if provider:
                    model_info.append(f"**LLM Provider**: {provider}")
                if model:
                    model_info.append(f"**LLM Model**: {model}")
                parts.append("\n".join(model_info))

        jev = next((a.jev_summary for a in successful if a.jev_summary), "")
        if jev:
            parts.append(f"**Jev shadow**: {jev}")

        # Per-repository metrics table
        if successful:
            parts.append("### Per-Repository Metrics")

            rows: list[list[str]] = []
            for a in successful:
                rows.append(
                    [
                        _md_cell(a.repo_name),
                        f"{a.elapsed_time:.2f}s",
                        f"{a.input_tokens:,}",
                        f"{a.output_tokens:,}",
                        f"${a.total_cost:.4f}",
                    ]
                )

            # Totals row
            total_time = sum(a.elapsed_time for a in successful)
            total_input = sum(a.input_tokens for a in successful)
            total_output = sum(a.output_tokens for a in successful)
            total_cost = sum(a.total_cost for a in successful)
            rows.append(
                [
                    f"**{c}**"
                    for c in (
                        "Total",
                        f"{total_time:.2f}s",
                        f"{total_input:,}",
                        f"{total_output:,}",
                        f"${total_cost:.4f}",
                    )
                ]
            )

            parts.append(
                _md_table(
                    ["Repository", "Time", "Input Tokens", "Output Tokens", "Cost"],
                    rows,
                )
            )

        parts.append(
            "*This is an automated analysis. Review findings with your "
            "security and infrastructure teams for validation "
            "and prioritization.*"
        )

        return "\n\n".join(parts)

    def generate_inventory_report(
        self,
        threat_model_name: str,
        threat_model_id: str,
        analyses: list[TerraformAnalysis],
        environment_name: str | None = None,
    ) -> str:
        """Inventory note: every table (components, services, relationships,
        data flows, trust boundaries, dependencies) plus job info."""
        sections = []
        title = "Terraform Infrastructure Inventory"
        if environment_name:
            title += f" - {environment_name}"
        sections.append(f"# {title}\n\n**Threat Model**: {threat_model_name}")

        for i, analysis in enumerate(analyses, 1):
            header = f"## Repository {i}: {analysis.repo_name}\n\n**URL**: [{analysis.repo_url}]({analysis.repo_url})"
            if not analysis.success:
                sections.append(
                    f"{header}\n\n*Analysis failed: {analysis.error_message}*"
                )
                continue
            parts = [
                header,
                self._format_inventory_section(analysis.inventory),
                self._format_relationships_section(analysis.infrastructure),
                self._format_data_flows_section(analysis.infrastructure),
                self._format_trust_boundaries_section(analysis.infrastructure),
                self._format_dependencies_section(analysis.inventory),
            ]
            sections.append("\n\n".join(part for part in parts if part))

        sections.append(self._generate_analysis_job_info(threat_model_id, analyses))
        return "\n\n---\n\n".join(sections)

    def generate_analysis_report(
        self,
        threat_model_name: str,
        threat_model_id: str,
        analyses: list[TerraformAnalysis],
        environment_name: str | None = None,
        inventory_note_name: str | None = None,
    ) -> str:
        """Analysis note: architecture narrative, diagram, pointer to the
        inventory note, security findings, consolidated findings, job info."""
        sections = []
        title = "Terraform Infrastructure Analysis"
        if environment_name:
            title += f" - {environment_name}"
        sections.append(f"# {title}\n\n**Threat Model**: {threat_model_name}")

        for i, analysis in enumerate(analyses, 1):
            header = f"## Repository {i}: {analysis.repo_name}\n\n**URL**: [{analysis.repo_url}]({analysis.repo_url})"
            if not analysis.success:
                sections.append(
                    f"{header}\n\n*Analysis failed: {analysis.error_message}*"
                )
                continue
            parts = [header]
            arch_summary = analysis.infrastructure.get("architecture_summary", "")
            if arch_summary:
                parts.append(f"### Architecture Summary\n\n{arch_summary}")
            mermaid = analysis.infrastructure.get("mermaid_diagram", "")
            if mermaid:
                if not mermaid.strip().startswith("```"):
                    mermaid = f"```mermaid\n{mermaid}\n```"
                parts.append(f"### Architecture Diagram\n\n{mermaid}")
            if inventory_note_name:
                parts.append(
                    "Inventory, relationships, data flows, trust boundaries and "
                    f"dependencies: see note *{inventory_note_name}*."
                )
            parts.append(self._format_security_section(analysis.security_findings))
            parts.append(self._format_scripts_section(analysis))
            sections.append("\n\n".join(part for part in parts if part))

        sections.append(self._generate_consolidated_findings(analyses))
        sections.append(self._generate_analysis_job_info(threat_model_id, analyses))
        return "\n\n---\n\n".join(sections)

    def save_to_file(self, content: str, filepath: str) -> None:
        """
        Save markdown content to file.

        Args:
            content: Markdown content
            filepath: Output file path
        """
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
            logger.info(f"Report saved to {filepath}")
        except Exception as e:
            logger.error(f"Failed to save report to {filepath}: {e}")
            raise
