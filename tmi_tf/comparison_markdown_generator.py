"""Markdown report generation for comparison results."""

import logging
from datetime import datetime
from typing import List

from tmi_tf.analysis_comparer import ComparisonResult, NormalizedDiscovery

logger = logging.getLogger(__name__)


class ComparisonMarkdownGenerator:
    """Generates markdown comparison reports."""

    def generate_report(
        self,
        comparison: ComparisonResult,
        threat_model_name: str,
        threat_model_id: str,
    ) -> str:
        """
        Generate full comparison markdown report.

        Args:
            comparison: ComparisonResult with all comparison data
            threat_model_name: Name of the threat model
            threat_model_id: UUID of the threat model

        Returns:
            Markdown content
        """
        logger.info(
            f"Generating comparison report for {len(comparison.models_compared)} models"
        )

        sections = []

        # Header
        sections.append(
            self._generate_header(comparison, threat_model_name, threat_model_id)
        )

        # Summary Statistics
        sections.append(self._generate_statistics(comparison))

        # Comparison Tables
        if comparison.infrastructure_comparison:
            sections.append(
                self._generate_comparison_section(
                    "Infrastructure Components",
                    comparison.infrastructure_comparison,
                    comparison.models_compared,
                )
            )

        if comparison.relationships_comparison:
            sections.append(
                self._generate_comparison_section(
                    "Component Relationships",
                    comparison.relationships_comparison,
                    comparison.models_compared,
                )
            )

        if comparison.data_flows_comparison:
            sections.append(
                self._generate_comparison_section(
                    "Data Flows",
                    comparison.data_flows_comparison,
                    comparison.models_compared,
                )
            )

        if comparison.security_comparison:
            sections.append(
                self._generate_comparison_section(
                    "Security Observations",
                    comparison.security_comparison,
                    comparison.models_compared,
                )
            )

        # Analysis Insights
        sections.append(self._generate_insights_section(comparison.summary_insights))

        # Footer
        sections.append(self._generate_footer())

        return "\n\n---\n\n".join(sections)

    def _generate_header(
        self,
        comparison: ComparisonResult,
        threat_model_name: str,
        threat_model_id: str,
    ) -> str:
        """Generate report header."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Format model names for display
        model_display = self._format_model_names(comparison.models_compared)

        return f"""# Terraform Analysis Comparison Report

**Threat Model**: {threat_model_name}
**Threat Model ID**: `{threat_model_id}`
**Generated**: {timestamp}
**Models Compared**: {model_display}

This report compares infrastructure analysis results from multiple AI models to identify areas of agreement and divergence in their threat modeling assessments."""

    def _generate_statistics(self, comparison: ComparisonResult) -> str:
        """Generate summary statistics section."""
        # Count discoveries by agreement level
        all_discoveries = (
            comparison.infrastructure_comparison
            + comparison.relationships_comparison
            + comparison.data_flows_comparison
            + comparison.security_comparison
        )

        total_models = len(comparison.models_compared)
        full_agreement = sum(
            1 for d in all_discoveries if len(d.models_that_found) == total_models
        )
        partial_agreement = sum(
            1 for d in all_discoveries if 1 < len(d.models_that_found) < total_models
        )
        single_model = sum(
            1 for d in all_discoveries if len(d.models_that_found) == 1
        )

        return f"""## Summary Statistics

| Metric | Value |
|--------|-------|
| Total Unique Discoveries | {comparison.total_unique_discoveries} |
| Agreement Rate (all models) | {comparison.agreement_rate:.1f}% |
| Full Agreement | {full_agreement} discoveries |
| Partial Agreement | {partial_agreement} discoveries |
| Single Model Only | {single_model} discoveries |

### Breakdown by Category

| Category | Count |
|----------|-------|
| Infrastructure Components | {len(comparison.infrastructure_comparison)} |
| Component Relationships | {len(comparison.relationships_comparison)} |
| Data Flows | {len(comparison.data_flows_comparison)} |
| Security Observations | {len(comparison.security_comparison)} |"""

    def _generate_comparison_section(
        self,
        section_name: str,
        discoveries: List[NormalizedDiscovery],
        models: List[str],
    ) -> str:
        """Generate a comparison section with table."""
        if not discoveries:
            return f"## {section_name}\n\nNo discoveries in this category."

        lines = [f"## {section_name}"]
        lines.append("")

        # Generate table
        table = self._generate_comparison_table(discoveries, models)
        lines.append(table)

        return "\n".join(lines)

    def _generate_comparison_table(
        self,
        discoveries: List[NormalizedDiscovery],
        models: List[str],
    ) -> str:
        """Generate comparison table for a category."""
        # Create short model names for column headers
        short_names = [self._get_short_model_name(m) for m in models]

        # Header row
        header = "| Discovery | " + " | ".join(short_names) + " | Notes |"
        separator = "|" + "-" * 40 + "|" + "|".join(":---:" for _ in models) + "|" + "-" * 30 + "|"

        rows = [header, separator]

        # Sort discoveries: full agreement first, then by name
        sorted_discoveries = sorted(
            discoveries,
            key=lambda d: (-len(d.models_that_found), d.canonical_name.lower()),
        )

        for discovery in sorted_discoveries:
            # Discovery name (truncate if too long)
            name = discovery.canonical_name
            if len(name) > 38:
                name = name[:35] + "..."

            # Model indicators
            indicators = []
            for model in models:
                if model in discovery.models_that_found:
                    indicators.append("X")
                else:
                    indicators.append("")

            # Notes column
            notes = ""
            if discovery.differences_summary:
                notes = discovery.differences_summary[:28] + "..." if len(discovery.differences_summary) > 30 else discovery.differences_summary
            elif len(discovery.models_that_found) == len(models):
                notes = "All models"
            elif len(discovery.models_that_found) == 1:
                notes = f"Only {self._get_short_model_name(discovery.models_that_found[0])}"

            row = f"| {name} | " + " | ".join(indicators) + f" | {notes} |"
            rows.append(row)

        return "\n".join(rows)

    def _generate_insights_section(self, insights: str) -> str:
        """Generate the LLM insights section."""
        return f"""## Analysis Insights

{insights}"""

    def _generate_footer(self) -> str:
        """Generate report footer."""
        return """---

**Report Generated By**: TMI Terraform Analysis Tool - Compare
**Tool Version**: 0.1.0

*This comparison helps identify areas where different AI models agree or diverge in their infrastructure analysis. Use this information to prioritize threat modeling focus areas and validate findings.*"""

    def _format_model_names(self, models: List[str]) -> str:
        """Format model names for display."""
        short_names = [self._get_short_model_name(m) for m in models]
        return ", ".join(short_names)

    def _get_short_model_name(self, model: str) -> str:
        """Get a short display name for a model."""
        # Handle provider/model format like "anthropic/claude-opus-4-5-20251101"
        if "/" in model:
            parts = model.split("/")
            model = parts[-1]

        # Common model name mappings
        name_map = {
            "claude-opus-4-5-20251101": "Claude",
            "claude-sonnet-4-20250514": "Claude",
            "gpt-5.2": "GPT",
            "gpt-4": "GPT-4",
            "gpt-4-turbo": "GPT-4",
            "grok-4-1-fast-reasoning": "Grok",
            "gemini-3-pro-preview": "Gemini",
            "gemini-pro": "Gemini",
        }

        # Check for exact match first
        if model in name_map:
            return name_map[model]

        # Try prefix matching
        for key, value in name_map.items():
            if model.startswith(key.split("-")[0]):
                return value

        # Fallback: capitalize first part
        if "-" in model:
            return model.split("-")[0].capitalize()

        return model[:10] if len(model) > 10 else model

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
            logger.info(f"Comparison report saved to {filepath}")
        except Exception as e:
            logger.error(f"Failed to save report to {filepath}: {e}")
            raise
