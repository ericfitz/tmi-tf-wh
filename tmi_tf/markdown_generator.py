"""Markdown report generation from structured analysis JSON."""

import logging
from datetime import datetime
from typing import Any, Dict, List

from tmi_tf.llm_analyzer import TerraformAnalysis

logger = logging.getLogger(__name__)


class MarkdownGenerator:
    """Generates markdown reports from structured analysis results."""

    @staticmethod
    def _table_cell(value: str) -> str:
        """Escape pipe characters in a value for use in a markdown table cell."""
        return str(value).replace("|", "\\|")

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
        """Format inventory JSON into markdown section."""
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

        tc = self._table_cell
        for comp_type in type_order:
            group = by_type.get(comp_type, [])
            if not group:
                continue

            parts.append(f"#### {comp_type.replace('_', ' ').title()}")
            parts.append("")
            parts.append("| Name | Resource Type | Purpose | Configuration |")
            parts.append("|------|---------------|---------|---------------|")
            for comp in group:
                name = comp.get("name", "Unknown")
                resource_type = comp.get("resource_type", "")
                purpose = comp.get("purpose", "")
                config = comp.get("configuration", {})

                config_str = ""
                if isinstance(config, dict) and config:
                    config_items = [f"{k}: `{v}`" for k, v in list(config.items())[:5]]
                    config_str = ", ".join(config_items)

                rt_str = f"`{resource_type}`" if resource_type else ""
                parts.append(
                    f"| {tc(name)} | {rt_str} | {tc(purpose)} | {tc(config_str)} |"
                )

        # Services
        services = inventory.get("services", [])
        if services:
            parts.append("")
            parts.append("#### Services (Logical Groupings)")
            parts.append("")
            parts.append(
                "| Service | Criteria | Compute Units | Associated Resources |"
            )
            parts.append(
                "|---------|----------|---------------|----------------------|"
            )
            for svc in services:
                svc_name = svc.get("name", "Unknown")
                criteria = svc.get("criteria", [])
                compute_units = svc.get("compute_units", [])
                associated = svc.get("associated_resources", [])

                criteria_str = ", ".join(criteria) if criteria else ""
                compute_str = ", ".join(compute_units) if compute_units else ""
                assoc_str = ", ".join(associated) if associated else ""
                parts.append(
                    f"| {tc(svc_name)} | {tc(criteria_str)} "
                    f"| {tc(compute_str)} | {tc(assoc_str)} |"
                )

        return "\n".join(parts)

    def _format_relationships_section(self, infrastructure: Dict[str, Any]) -> str:
        """Format relationships JSON into markdown section."""
        relationships = infrastructure.get("relationships", [])
        if not relationships:
            return ""

        tc = self._table_cell
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
            parts.append("")
            parts.append("| Source | Target | Description |")
            parts.append("|--------|--------|-------------|")
            for rel in rels:
                source = rel.get("source_id", "?")
                target = rel.get("target_id", "?")
                desc = rel.get("description", "")
                parts.append(f"| {tc(source)} | {tc(target)} | {tc(desc)} |")

        return "\n".join(parts)

    def _format_data_flows_section(self, infrastructure: Dict[str, Any]) -> str:
        """Format data flows JSON into markdown section."""
        flows = infrastructure.get("data_flows", [])
        if not flows:
            return ""

        parts = ["### Data Flows", ""]
        parts.append("| Flow | Source | Target | Protocol | Port | Data Type |")
        parts.append("|------|--------|--------|----------|------|-----------|")

        for flow in flows:
            name = flow.get("name", "")
            source = flow.get("source_id", "")
            target = flow.get("target_id", "")
            protocol = flow.get("protocol", "")
            port = flow.get("port", "")
            data_type = flow.get("data_type", "")
            parts.append(
                f"| {name} | {source} | {target} | {protocol} | {port} | {data_type} |"
            )

        # Trust boundaries
        boundaries = infrastructure.get("trust_boundaries", [])
        if boundaries:
            tc = self._table_cell
            parts.append("")
            parts.append("#### Trust Boundaries")
            parts.append("")
            parts.append("| Boundary | Type | Components |")
            parts.append("|----------|------|------------|")
            for boundary in boundaries:
                name = boundary.get("name", "")
                btype = boundary.get("boundary_type", "")
                component_ids = boundary.get("component_ids", [])
                parts.append(
                    f"| {tc(name)} | {tc(btype)} | {tc(', '.join(component_ids))} |"
                )

        return "\n".join(parts)

    def _format_security_section(self, security_findings: List[Dict[str, Any]]) -> str:
        """Format security findings JSON into markdown section."""
        if not security_findings:
            return "### Security Observations\n\nNo security findings identified."

        tc = self._table_cell
        parts = ["### Security Observations", ""]
        parts.append(
            "| Finding | Severity | STRIDE | Category "
            "| Description | Mitigation | Affected Components |"
        )
        parts.append(
            "|---------|----------|--------|----------"
            "|-------------|------------|---------------------|"
        )

        for finding in security_findings:
            name = finding.get("name", "Unknown")
            severity = finding.get("severity", "Medium")
            score = finding.get("score")
            description = finding.get("description", "")
            threat_type = finding.get("threat_type", "")
            category = finding.get("category", "")
            mitigation = finding.get("mitigation", "")
            cwe_id = finding.get("cwe_id", [])
            affected = finding.get("affected_components", [])

            severity_str = severity
            if score is not None:
                severity_str += f" ({score})"

            name_str = name
            if cwe_id:
                name_str += f" [{', '.join(cwe_id)}]"

            affected_str = ", ".join(affected) if affected else ""
            parts.append(
                f"| {tc(name_str)} | {tc(severity_str)} | {tc(threat_type)} "
                f"| {tc(category)} | {tc(description)} | {tc(mitigation)} "
                f"| {tc(affected_str)} |"
            )

        return "\n".join(parts)

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
            tc = self._table_cell
            parts.append("### Per-Repository Metrics")
            parts.append(
                "| Repository | Time | Input Tokens "
                "| Output Tokens | Cost |\n"
                "|------------|------|-------------- "
                "|---------------|------|"
            )
            for a in successful:
                parts.append(
                    f"| {tc(a.repo_name)} | {a.elapsed_time:.2f}s "
                    f"| {a.input_tokens:,} | {a.output_tokens:,} "
                    f"| ${a.total_cost:.4f} |"
                )

            # Totals row
            total_time = sum(a.elapsed_time for a in successful)
            total_input = sum(a.input_tokens for a in successful)
            total_output = sum(a.output_tokens for a in successful)
            total_cost = sum(a.total_cost for a in successful)
            parts.append(
                f"| **Total** | **{total_time:.2f}s** "
                f"| **{total_input:,}** | **{total_output:,}** "
                f"| **${total_cost:.4f}** |"
            )

        parts.append(
            "*This is an automated analysis. Review findings with your "
            "security and infrastructure teams for validation "
            "and prioritization.*"
        )

        return "\n\n".join(parts)

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
