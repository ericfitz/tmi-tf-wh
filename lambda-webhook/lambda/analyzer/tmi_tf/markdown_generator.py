"""Markdown report generation."""

import logging
from datetime import datetime
from typing import List

from tmi_tf.claude_analyzer import TerraformAnalysis

logger = logging.getLogger(__name__)


class MarkdownGenerator:
    """Generates markdown reports from analysis results."""

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

        # Header
        sections.append(
            self._generate_header(threat_model_name, threat_model_id, analyses)
        )

        # Executive Summary
        sections.append(self._generate_executive_summary(analyses))

        # Individual Repository Analyses
        sections.append(self._generate_repository_sections(analyses))

        # Consolidated Findings
        sections.append(self._generate_consolidated_findings(analyses))

        # Footer
        sections.append(self._generate_footer())

        return "\n\n---\n\n".join(sections)

    def _generate_header(
        self,
        threat_model_name: str,
        threat_model_id: str,
        analyses: List[TerraformAnalysis],
    ) -> str:
        """Generate report header."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        successful = sum(1 for a in analyses if a.success)
        failed = len(analyses) - successful

        return f"""# Terraform Infrastructure Analysis

**Threat Model**: {threat_model_name}
**Threat Model ID**: `{threat_model_id}`
**Generated**: {timestamp}
**Repositories Analyzed**: {len(analyses)} ({successful} successful, {failed} failed)

This report provides an automated analysis of Terraform infrastructure code associated with this threat model. The analysis identifies infrastructure components, relationships, data flows, and potential security considerations."""

    def _generate_executive_summary(self, analyses: List[TerraformAnalysis]) -> str:
        """Generate executive summary."""
        successful = [a for a in analyses if a.success]
        failed = [a for a in analyses if not a.success]

        summary_parts = ["## Executive Summary"]

        if successful:
            summary_parts.append(
                f"Successfully analyzed {len(successful)} "
                f"repository/repositories containing Terraform infrastructure code. "
                "Each repository has been examined to identify cloud resources, "
                "component relationships, data flows, and potential security concerns."
            )

        if failed:
            summary_parts.append(
                f"\n⚠️ **Warning**: {len(failed)} repository/repositories failed analysis: "
                f"{', '.join(a.repo_name for a in failed)}"
            )

        summary_parts.append(
            "\nThe detailed analysis for each repository is provided below, "
            "followed by consolidated findings and recommendations for threat modeling focus areas."
        )

        return "\n\n".join(summary_parts)

    def _generate_repository_sections(self, analyses: List[TerraformAnalysis]) -> str:
        """Generate individual repository analysis sections."""
        sections = []

        for i, analysis in enumerate(analyses, 1):
            status_icon = "✅" if analysis.success else "❌"

            section = f"""## Repository {i}: {analysis.repo_name} {status_icon}

**URL**: [{analysis.repo_url}]({analysis.repo_url})
**Status**: {'Analysis Successful' if analysis.success else 'Analysis Failed'}

{analysis.analysis_content}"""

            sections.append(section)

        return "\n\n---\n\n".join(sections)

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

1. **Authentication & Authorization**: Review access controls, IAM policies, and service-to-service authentication mechanisms
2. **Data Protection**: Examine data at rest and in transit, encryption configurations, and data flow paths
3. **Network Security**: Analyze network segmentation, firewall rules, security groups, and exposure to public networks
4. **Secrets Management**: Verify proper handling of credentials, API keys, and sensitive configuration
5. **Logging & Monitoring**: Ensure adequate logging, monitoring, and alerting for security events
6. **Compliance & Configuration**: Check for compliance with security standards and best practice configurations

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

    def _generate_footer(self) -> str:
        """Generate report footer."""
        return """---

**Report Generated By**: TMI Terraform Analysis Tool
**Analysis Engine**: Claude Sonnet 4.5 by Anthropic
**Tool Version**: 0.1.0

*This is an automated analysis. Please review findings with your security and infrastructure teams for validation and prioritization.*"""

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
