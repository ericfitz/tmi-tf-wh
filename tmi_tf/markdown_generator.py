"""Markdown report generation from structured analysis JSON."""

import logging
from datetime import datetime
from html import escape as html_escape
from typing import Any, Dict, List, Optional, Sequence

from tmi_tf.llm_analyzer import TerraformAnalysis

logger = logging.getLogger(__name__)


def _esc(value: str) -> str:
    """HTML-escape a string for safe embedding in table cells."""
    return html_escape(str(value), quote=True)


def _html_list(items: Sequence[str]) -> str:
    """Render a list of items as an HTML <ul> list, or empty string if empty."""
    if not items:
        return ""
    li = "".join(f"<li>{_esc(item)}</li>" for item in items)
    return f"<ul>{li}</ul>"


def _html_table(
    headers: List[str],
    rows: List[List[str]],
    col_widths: Optional[List[str]] = None,
    col_aligns: Optional[List[str]] = None,
    bold_last_row: bool = False,
) -> str:
    """Build an HTML table with optional colgroup widths and alignment.

    Args:
        headers: Column header labels.
        rows: List of rows, each row is a list of cell HTML content strings
              (already escaped or containing nested HTML).
        col_widths: Optional list of CSS width values (e.g. "20%", "150px").
        col_aligns: Optional list of CSS text-align values per column.
        bold_last_row: If True, wrap last row cells in <strong>.
    """
    parts: list[str] = ['<table style="width:100%">']

    # Column widths via colgroup
    if col_widths:
        parts.append("<colgroup>")
        for w in col_widths:
            parts.append(f'<col style="width:{w}">')
        parts.append("</colgroup>")

    # Header
    parts.append("<thead><tr>")
    for i, h in enumerate(headers):
        style = f' style="text-align:{col_aligns[i]}"' if col_aligns else ""
        parts.append(f"<th{style}>{_esc(h)}</th>")
    parts.append("</tr></thead>")

    # Body
    parts.append("<tbody>")
    for row_idx, row in enumerate(rows):
        parts.append("<tr>")
        is_bold = bold_last_row and row_idx == len(rows) - 1
        for i, cell in enumerate(row):
            style = f' style="text-align:{col_aligns[i]}"' if col_aligns else ""
            content = f"<strong>{cell}</strong>" if is_bold else cell
            parts.append(f"<td{style}>{content}</td>")
        parts.append("</tr>")
    parts.append("</tbody>")

    parts.append("</table>")
    return "".join(parts)


def _config_nested_table(config: Dict[str, Any]) -> str:
    """Render a configuration dict as a nested table inside a cell."""
    if not config:
        return ""
    parts = ['<table style="width:100%">']
    for k, v in list(config.items())[:5]:
        parts.append(
            f"<tr><td><strong>{_esc(str(k))}</strong></td>"
            f"<td><code>{_esc(str(v))}</code></td></tr>"
        )
    parts.append("</table>")
    return "".join(parts)


class MarkdownGenerator:
    """Generates markdown reports from structured analysis results."""

    def generate_report(
        self,
        threat_model_name: str,
        threat_model_id: str,
        analyses: List[TerraformAnalysis],
    ) -> str:
        """
        Generate comprehensive markdown report from analysis results.

        Args:
            threat_model_name: Name of the threat model
            threat_model_id: UUID of the threat model
            analyses: List of TerraformAnalysis results

        Returns:
            Markdown content
        """
        logger.info(f"Generating markdown report for {len(analyses)} repositories")

        # Build sections
        sections = []

        # Header (just title + threat model name)
        sections.append(self._generate_header(threat_model_name))

        # Individual Repository Analyses
        sections.append(self._generate_repository_sections(analyses))

        # Consolidated Findings
        sections.append(self._generate_consolidated_findings(analyses))

        # Analysis Job Information (all metadata at the end)
        sections.append(self._generate_analysis_job_info(threat_model_id, analyses))

        return "\n\n---\n\n".join(sections)

    def _generate_header(
        self,
        threat_model_name: str,
    ) -> str:
        """Generate report header with just title and threat model name."""
        return f"""# Terraform Infrastructure Analysis

**Threat Model**: {threat_model_name}"""

    def _generate_repository_sections(self, analyses: List[TerraformAnalysis]) -> str:
        """Generate individual repository analysis sections from structured JSON."""
        sections = []

        for i, analysis in enumerate(analyses, 1):
            header = f"""## Repository {i}: {analysis.repo_name}

**URL**: [{analysis.repo_url}]({analysis.repo_url})"""

            if not analysis.success:
                sections.append(
                    f"{header}\n\n*Analysis failed: {analysis.error_message}*"
                )
                continue

            # Assemble markdown from structured JSON outputs
            body_parts = [header]

            # Architecture Summary (from Phase 2)
            arch_summary = analysis.infrastructure.get("architecture_summary", "")
            if arch_summary:
                body_parts.append(f"### Architecture Summary\n\n{arch_summary}")

            # Mermaid Diagram (from Phase 2)
            mermaid = analysis.infrastructure.get("mermaid_diagram", "")
            if mermaid:
                # Ensure it's wrapped in mermaid code fence
                if not mermaid.strip().startswith("```"):
                    mermaid = f"```mermaid\n{mermaid}\n```"
                body_parts.append(f"### Architecture Diagram\n\n{mermaid}")

            # Infrastructure Inventory (from Phase 1)
            body_parts.append(self._format_inventory_section(analysis.inventory))

            # Component Relationships (from Phase 2)
            body_parts.append(
                self._format_relationships_section(analysis.infrastructure)
            )

            # Data Flows (from Phase 2)
            body_parts.append(self._format_data_flows_section(analysis.infrastructure))

            # Security Observations (from Phase 3)
            body_parts.append(self._format_security_section(analysis.security_findings))

            sections.append("\n\n".join(part for part in body_parts if part))

        return "\n\n---\n\n".join(sections)

    def _format_inventory_section(self, inventory: Dict[str, Any]) -> str:
        """Format inventory JSON into markdown section with HTML tables."""
        parts = ["### Infrastructure Inventory"]

        components = inventory.get("components", [])
        if not components:
            parts.append("No infrastructure components identified.")
            return "\n\n".join(parts)

        # Group components by type
        by_type: Dict[str, List[Dict[str, Any]]] = {}
        for comp in components:
            comp_type = comp.get("type", "other")
            if comp_type not in by_type:
                by_type[comp_type] = []
            by_type[comp_type].append(comp)

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

        for comp_type in type_order:
            group = by_type.get(comp_type, [])
            if not group:
                continue

            parts.append(f"#### {comp_type.replace('_', ' ').title()}")

            rows: List[List[str]] = []
            for comp in group:
                name = _esc(comp.get("name", "Unknown"))
                resource_type = comp.get("resource_type", "")
                rt_str = f"<code>{_esc(resource_type)}</code>" if resource_type else ""
                purpose = _esc(comp.get("purpose", ""))
                config = comp.get("configuration", {})
                config_html = (
                    _config_nested_table(config)
                    if isinstance(config, dict) and config
                    else ""
                )
                rows.append([name, rt_str, purpose, config_html])

            parts.append(
                _html_table(
                    ["Name", "Resource Type", "Purpose", "Configuration"],
                    rows,
                    col_widths=["20%", "15%", "30%", "35%"],
                )
            )

        # Services
        services = inventory.get("services", [])
        if services:
            parts.append("#### Services (Logical Groupings)")

            rows = []
            for svc in services:
                svc_name = _esc(svc.get("name", "Unknown"))
                criteria = svc.get("criteria", [])
                compute_units = svc.get("compute_units", [])
                associated = svc.get("associated_resources", [])
                rows.append(
                    [
                        svc_name,
                        _html_list(criteria),
                        _html_list(compute_units),
                        _html_list(associated),
                    ]
                )

            parts.append(
                _html_table(
                    ["Service", "Criteria", "Compute Units", "Associated Resources"],
                    rows,
                    col_widths=["15%", "30%", "25%", "30%"],
                )
            )

        return "\n\n".join(parts)

    def _format_relationships_section(self, infrastructure: Dict[str, Any]) -> str:
        """Format relationships JSON into markdown section with HTML tables."""
        relationships = infrastructure.get("relationships", [])
        if not relationships:
            return ""

        parts = ["### Component Relationships"]

        # Group by relationship type
        by_type: Dict[str, List[Dict[str, Any]]] = {}
        for rel in relationships:
            rel_type = rel.get("relationship_type", "other")
            if rel_type not in by_type:
                by_type[rel_type] = []
            by_type[rel_type].append(rel)

        for rel_type, rels in by_type.items():
            parts.append(f"\n#### {rel_type.replace('_', ' ').title()}")

            rows: List[List[str]] = []
            for rel in rels:
                source = _esc(rel.get("source_id", "?"))
                target = _esc(rel.get("target_id", "?"))
                desc = _esc(rel.get("description", ""))
                rows.append([source, target, desc])

            parts.append(
                _html_table(
                    ["Source", "Target", "Description"],
                    rows,
                    col_widths=["25%", "25%", "50%"],
                )
            )

        return "\n".join(parts)

    def _format_data_flows_section(self, infrastructure: Dict[str, Any]) -> str:
        """Format data flows JSON into markdown section with HTML tables."""
        flows = infrastructure.get("data_flows", [])
        if not flows:
            return ""

        parts = ["### Data Flows"]

        rows: List[List[str]] = []
        for flow in flows:
            rows.append(
                [
                    _esc(flow.get("name", "")),
                    _esc(flow.get("source_id", "")),
                    _esc(flow.get("target_id", "")),
                    _esc(flow.get("protocol", "")),
                    _esc(str(flow.get("port", ""))),
                    _esc(flow.get("data_type", "")),
                ]
            )

        parts.append(
            _html_table(
                ["Flow", "Source", "Target", "Protocol", "Port", "Data Type"],
                rows,
                col_widths=["20%", "15%", "15%", "10%", "10%", "30%"],
            )
        )

        # Trust boundaries
        boundaries = infrastructure.get("trust_boundaries", [])
        if boundaries:
            parts.append("#### Trust Boundaries")

            rows = []
            for boundary in boundaries:
                name = _esc(boundary.get("name", ""))
                btype = _esc(boundary.get("boundary_type", ""))
                component_ids = boundary.get("component_ids", [])
                rows.append([name, btype, _html_list(component_ids)])

            parts.append(
                _html_table(
                    ["Boundary", "Type", "Components"],
                    rows,
                    col_widths=["25%", "20%", "55%"],
                )
            )

        return "\n\n".join(parts)

    def _format_dependencies_section(self, inventory: Dict[str, Any]) -> str:
        """Format external dependencies into markdown section with HTML table."""
        dependencies = inventory.get("dependencies", [])
        if not dependencies:
            return ""

        parts = ["### External Dependencies"]

        rows: List[List[str]] = []
        for dep in dependencies:
            dep_type = _esc(dep.get("type", ""))
            provider = _esc(dep.get("provider", ""))
            service = _esc(dep.get("service", ""))
            components = dep.get("dependent_components", [])
            rows.append([dep_type, provider, service, _html_list(components)])

        parts.append(
            _html_table(
                ["Type", "Provider", "Service", "Dependent Components"],
                rows,
                col_widths=["10%", "15%", "20%", "55%"],
            )
        )

        return "\n\n".join(parts)

    def _format_security_section(self, security_findings: List[Dict[str, Any]]) -> str:
        """Format security findings JSON into markdown section with HTML tables."""
        if not security_findings:
            return "### Security Observations\n\nNo security findings identified."

        parts = ["### Security Observations"]

        rows: List[List[str]] = []
        for finding in security_findings:
            name = _esc(finding.get("name", "Unknown"))
            severity = finding.get("severity", "Medium")
            score = finding.get("score")
            description = _esc(finding.get("description", ""))
            threat_type = _esc(finding.get("threat_type", ""))
            category = _esc(finding.get("category", ""))
            mitigation = _esc(finding.get("mitigation", ""))
            cwe_id = finding.get("cwe_id", [])
            affected = finding.get("affected_components", [])

            severity_str = _esc(severity)
            if score is not None:
                severity_str += f" ({_esc(str(score))})"

            # CWE IDs as separate code elements
            name_html = name
            if cwe_id:
                cwe_html = " ".join(f"<code>{_esc(cid)}</code>" for cid in cwe_id)
                name_html += f"<br>{cwe_html}"

            rows.append(
                [
                    name_html,
                    severity_str,
                    threat_type,
                    category,
                    description,
                    mitigation,
                    _html_list(affected),
                ]
            )

        parts.append(
            _html_table(
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
                col_widths=["15%", "8%", "8%", "10%", "24%", "20%", "15%"],
            )
        )

        return "\n\n".join(parts)

    def _generate_consolidated_findings(self, analyses: List[TerraformAnalysis]) -> str:
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
        analyses: List[TerraformAnalysis],
    ) -> str:
        """Generate Analysis Job Information section combining all metadata."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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

        # Per-repository metrics table
        if successful:
            parts.append("### Per-Repository Metrics")

            rows: List[List[str]] = []
            for a in successful:
                rows.append(
                    [
                        _esc(a.repo_name),
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
                    "Total",
                    f"{total_time:.2f}s",
                    f"{total_input:,}",
                    f"{total_output:,}",
                    f"${total_cost:.4f}",
                ]
            )

            parts.append(
                _html_table(
                    ["Repository", "Time", "Input Tokens", "Output Tokens", "Cost"],
                    rows,
                    col_widths=["30%", "15%", "20%", "20%", "15%"],
                    col_aligns=["left", "right", "right", "right", "right"],
                    bold_last_row=True,
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
        analyses: List[TerraformAnalysis],
        environment_name: Optional[str] = None,
    ) -> str:
        """Generate inventory-only markdown report."""
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
            parts = [header]
            parts.append(self._format_inventory_section(analysis.inventory))
            sections.append("\n\n".join(part for part in parts if part))

        sections.append(self._generate_analysis_job_info(threat_model_id, analyses))
        return "\n\n---\n\n".join(sections)

    def generate_analysis_report(
        self,
        threat_model_name: str,
        threat_model_id: str,
        analyses: List[TerraformAnalysis],
        environment_name: Optional[str] = None,
    ) -> str:
        """Generate analysis markdown report (architecture, relationships, security)."""
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

            parts.append(self._format_relationships_section(analysis.infrastructure))
            parts.append(self._format_data_flows_section(analysis.infrastructure))
            parts.append(self._format_dependencies_section(analysis.inventory))
            parts.append(self._format_security_section(analysis.security_findings))

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
