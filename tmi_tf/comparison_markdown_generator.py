"""Markdown report generation for comparison results."""

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional

from tmi_tf.analysis_comparer import (
    ComparisonResult,
    NormalizedDiscovery,
)

logger = logging.getLogger(__name__)


@dataclass
class ModelCostInfo:
    """Cost and token information for a single model's analysis."""

    model_name: str
    provider: str
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0


@dataclass
class ComparisonCostInfo:
    """Cost and token information for the comparison operation itself."""

    provider: str = ""
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0


class ComparisonMarkdownGenerator:
    """Generates markdown comparison reports."""

    def generate_report(
        self,
        comparison: ComparisonResult,
        threat_model_name: str,
        threat_model_id: str,
        model_costs: Optional[List[ModelCostInfo]] = None,
        comparison_cost: Optional[ComparisonCostInfo] = None,
    ) -> str:
        """
        Generate full comparison markdown report.

        Args:
            comparison: ComparisonResult with all comparison data
            threat_model_name: Name of the threat model
            threat_model_id: UUID of the threat model
            model_costs: Optional list of cost info for each model being compared
            comparison_cost: Optional cost info for the comparison operation itself

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

        # Model Cost Comparison Table (if cost info available)
        if model_costs:
            sections.append(self._generate_model_cost_table(model_costs))

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

        # Footer (with comparison cost if available)
        sections.append(self._generate_footer(comparison_cost))

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

    def _generate_model_cost_table(self, model_costs: List[ModelCostInfo]) -> str:
        """Generate a table comparing costs/tokens across models."""
        if not model_costs:
            return ""

        lines = ["## Model Cost Comparison", ""]
        lines.append(
            "The following table shows the token usage and cost for each model's "
            "original analysis:"
        )
        lines.append("")

        # Table header
        lines.append("| Model | Provider | Input Tokens | Output Tokens | Cost (USD) |")
        lines.append("|-------|----------|-------------:|-------------:|----------:|")

        # Calculate totals
        total_input = 0
        total_output = 0
        total_cost = 0.0

        for cost_info in model_costs:
            short_name = self._get_short_model_name(cost_info.model_name)
            lines.append(
                f"| {short_name} | {cost_info.provider} | "
                f"{cost_info.input_tokens:,} | {cost_info.output_tokens:,} | "
                f"${cost_info.cost_usd:.4f} |"
            )
            total_input += cost_info.input_tokens
            total_output += cost_info.output_tokens
            total_cost += cost_info.cost_usd

        # Add totals row
        lines.append(
            f"| **Total** | | **{total_input:,}** | **{total_output:,}** | "
            f"**${total_cost:.4f}** |"
        )

        return "\n".join(lines)

    def _generate_comparison_section(
        self,
        section_name: str,
        discoveries: List[NormalizedDiscovery],
        models: List[str],
    ) -> str:
        """Generate a comparison section with table and narrative."""
        if not discoveries:
            return f"## {section_name}\n\nNo discoveries in this category."

        lines = [f"## {section_name}"]
        lines.append("")

        # Generate table
        table = self._generate_comparison_table(discoveries, models)
        lines.append(table)

        # Generate narrative analysis below the table
        narrative = self._generate_section_narrative(discoveries, models, section_name)
        if narrative:
            lines.append("")
            lines.append(narrative)

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

    def _generate_section_narrative(
        self,
        discoveries: List[NormalizedDiscovery],
        models: List[str],
        section_name: str,
    ) -> str:
        """Generate narrative analysis for a section explaining what each model found."""
        if not discoveries:
            return ""

        lines = ["### Analysis"]
        lines.append("")

        # Group discoveries by coverage pattern
        all_models_found = []
        partial_found = []
        single_model_found: Dict[str, List[NormalizedDiscovery]] = {m: [] for m in models}

        for d in discoveries:
            if len(d.models_that_found) == len(models):
                all_models_found.append(d)
            elif len(d.models_that_found) == 1:
                single_model_found[d.models_that_found[0]].append(d)
            else:
                partial_found.append(d)

        # Narrative about universal findings
        if all_models_found:
            lines.append(f"**Universal Findings ({len(all_models_found)} items)**")
            lines.append("")
            lines.append(
                f"All models identified the following {section_name.lower()}:"
            )
            lines.append("")
            for d in all_models_found[:5]:  # Limit to avoid excessive length
                narrative = self._build_discovery_narrative(d, models)
                lines.append(f"- **{d.canonical_name}**: {narrative}")
            if len(all_models_found) > 5:
                lines.append(f"- *...and {len(all_models_found) - 5} more items*")
            lines.append("")

        # Narrative about partial findings
        if partial_found:
            lines.append(f"**Partial Agreement ({len(partial_found)} items)**")
            lines.append("")
            lines.append(
                "The following items were found by some but not all models:"
            )
            lines.append("")
            for d in partial_found[:5]:
                found_by = ", ".join(
                    self._get_short_model_name(m) for m in d.models_that_found
                )
                missed_by = ", ".join(
                    self._get_short_model_name(m)
                    for m in models
                    if m not in d.models_that_found
                )
                narrative = self._build_discovery_narrative(d, models)
                lines.append(
                    f"- **{d.canonical_name}**: Found by {found_by}, "
                    f"missed by {missed_by}. {narrative}"
                )
            if len(partial_found) > 5:
                lines.append(f"- *...and {len(partial_found) - 5} more items*")
            lines.append("")

        # Narrative about unique findings per model
        unique_models_with_findings = [
            m for m in models if single_model_found[m]
        ]
        if unique_models_with_findings:
            lines.append("**Unique Findings**")
            lines.append("")
            for model in unique_models_with_findings:
                unique_items = single_model_found[model]
                short_name = self._get_short_model_name(model)
                lines.append(
                    f"*{short_name}* uniquely identified {len(unique_items)} item(s):"
                )
                lines.append("")
                for d in unique_items[:3]:
                    narrative = self._build_single_model_narrative(d, model)
                    lines.append(f"- **{d.canonical_name}**: {narrative}")
                if len(unique_items) > 3:
                    lines.append(f"- *...and {len(unique_items) - 3} more items*")
                lines.append("")

        return "\n".join(lines)

    def _build_discovery_narrative(
        self, discovery: NormalizedDiscovery, models: List[str]
    ) -> str:
        """Build a narrative description for a discovery showing how models described it."""
        parts = []

        # Start with semantic summary if available
        if discovery.semantic_summary:
            parts.append(discovery.semantic_summary)

        # Add per-model interpretations if there are differences worth noting
        if (
            discovery.per_model_narratives
            and len(discovery.per_model_narratives) > 1
        ):
            model_descriptions = []
            for model, detail in discovery.per_model_narratives.items():
                short_name = self._get_short_model_name(model)
                if detail.original_name != discovery.canonical_name:
                    model_descriptions.append(
                        f'{short_name} called this "{detail.original_name}"'
                    )
                elif detail.description:
                    # Truncate long descriptions
                    desc = detail.description
                    if len(desc) > 100:
                        desc = desc[:97] + "..."
                    model_descriptions.append(f"{short_name}: {desc}")

            if model_descriptions:
                parts.append(" ".join(model_descriptions))

        # Note if semantically different
        if not discovery.is_semantically_equivalent:
            parts.append("*Note: Models interpreted this item differently.*")

        return " ".join(parts) if parts else "No additional details available."

    def _build_single_model_narrative(
        self, discovery: NormalizedDiscovery, model: str
    ) -> str:
        """Build a narrative for a discovery found by only one model."""
        if model in discovery.per_model_narratives:
            detail = discovery.per_model_narratives[model]
            if detail.description:
                desc = detail.description
                if len(desc) > 150:
                    desc = desc[:147] + "..."
                return desc
            elif detail.semantic_meaning:
                return detail.semantic_meaning

        if discovery.semantic_summary:
            return discovery.semantic_summary

        return "No additional details available."

    def _generate_insights_section(self, insights: str) -> str:
        """Generate the LLM insights section."""
        return f"""## Analysis Insights

{insights}"""

    def _generate_footer(
        self, comparison_cost: Optional[ComparisonCostInfo] = None
    ) -> str:
        """Generate report footer with optional comparison cost info."""
        lines = ["---", ""]
        lines.append("**Report Generated By**: TMI Terraform Analysis Tool - Compare")
        lines.append("**Tool Version**: 0.1.0")

        # Add comparison cost info if available
        if comparison_cost and (
            comparison_cost.input_tokens > 0 or comparison_cost.cost_usd > 0
        ):
            lines.append("")
            lines.append("### Comparison Report Generation")
            lines.append("")
            lines.append("| Metric | Value |")
            lines.append("|--------|-------|")
            if comparison_cost.provider:
                lines.append(f"| Provider | {comparison_cost.provider} |")
            if comparison_cost.model:
                lines.append(f"| Model | {comparison_cost.model} |")
            lines.append(f"| Input Tokens | {comparison_cost.input_tokens:,} |")
            lines.append(f"| Output Tokens | {comparison_cost.output_tokens:,} |")
            lines.append(f"| Cost (USD) | ${comparison_cost.cost_usd:.4f} |")

        lines.append("")
        lines.append(
            "*This comparison helps identify areas where different AI models agree "
            "or diverge in their infrastructure analysis. Use this information to "
            "prioritize threat modeling focus areas and validate findings.*"
        )

        return "\n".join(lines)

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
