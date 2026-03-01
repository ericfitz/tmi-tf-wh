"""Analysis comparison module for comparing LLM analysis notes."""

import json
import logging
import os
import re
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, cast

import litellm  # pyright: ignore[reportMissingImports] # ty:ignore[unresolved-import]
from litellm import ModelResponse  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

from tmi_tf.config import Config, save_llm_response

logger = logging.getLogger(__name__)

litellm.drop_params = True  # type: ignore[assignment]


class DiscoveryCategory(Enum):
    """Categories of discoveries to compare."""

    INFRASTRUCTURE = "infrastructure"
    RELATIONSHIPS = "relationships"
    DATA_FLOWS = "data_flows"
    SECURITY = "security"


@dataclass
class Discovery:
    """Represents a single discovery from an analysis."""

    id: str
    category: DiscoveryCategory
    name: str
    description: str
    source_model: str
    raw_text: str
    normalized_name: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    # Semantic representation: what this discovery represents/means
    semantic_meaning: Optional[str] = None


@dataclass
class ModelDiscoveryDetail:
    """Details about how a specific model described a discovery."""

    model_name: str
    original_name: str
    description: str
    semantic_meaning: Optional[str] = None


@dataclass
class NormalizedDiscovery:
    """A discovery normalized across models."""

    canonical_name: str
    category: DiscoveryCategory
    models_that_found: List[str]
    model_details: Dict[str, Discovery]
    differences_summary: Optional[str] = None
    # Narrative summary of what this discovery represents
    semantic_summary: Optional[str] = None
    # Per-model narratives explaining each model's interpretation
    per_model_narratives: Dict[str, ModelDiscoveryDetail] = field(default_factory=dict)
    # Whether this appears to be semantically equivalent across models that found it
    is_semantically_equivalent: bool = True


@dataclass
class ParsedAnalysis:
    """Parsed content from a single analysis note."""

    model_name: str
    note_id: str
    note_name: str
    infrastructure_items: List[Discovery]
    relationships: List[Discovery]
    data_flows: List[Discovery]
    security_observations: List[Discovery]
    raw_content: str


@dataclass
class ComparisonResult:
    """Complete comparison result across all models."""

    models_compared: List[str]
    infrastructure_comparison: List[NormalizedDiscovery]
    relationships_comparison: List[NormalizedDiscovery]
    data_flows_comparison: List[NormalizedDiscovery]
    security_comparison: List[NormalizedDiscovery]
    summary_insights: str
    total_unique_discoveries: int = 0
    agreement_rate: float = 0.0


class AnalysisParser:
    """Parses analysis markdown notes into structured data."""

    # Pattern to match note names like "Terraform Analysis Report (anthropic/claude-opus-4-5-20251101)"
    NOTE_NAME_PATTERN = re.compile(r"Terraform Analysis Report \(([^)]+)\)")

    # Section header patterns - flexible to handle numbered or unnumbered headers
    SECTION_PATTERNS = {
        DiscoveryCategory.INFRASTRUCTURE: re.compile(
            r"##\s*(?:\d+\.\s*)?Infrastructure Inventory\s*\n(.*?)(?=\n##|\Z)",
            re.DOTALL | re.IGNORECASE,
        ),
        DiscoveryCategory.RELATIONSHIPS: re.compile(
            r"##\s*(?:\d+\.\s*)?Component Relationships\s*\n(.*?)(?=\n##|\Z)",
            re.DOTALL | re.IGNORECASE,
        ),
        DiscoveryCategory.DATA_FLOWS: re.compile(
            r"##\s*(?:\d+\.\s*)?Data Flows\s*\n(.*?)(?=\n##|\Z)",
            re.DOTALL | re.IGNORECASE,
        ),
        DiscoveryCategory.SECURITY: re.compile(
            r"##\s*(?:\d+\.\s*)?Security Observations\s*\n(.*?)(?=\n##|\Z)",
            re.DOTALL | re.IGNORECASE,
        ),
    }

    def extract_model_from_note_name(self, note_name: str) -> Optional[str]:
        """Extract model identifier from note name pattern."""
        match = self.NOTE_NAME_PATTERN.match(note_name)
        if match:
            return match.group(1)
        return None

    def parse_note(
        self, note_content: str, model_name: str, note_id: str, note_name: str
    ) -> ParsedAnalysis:
        """Parse a single analysis note into structured discoveries."""
        logger.info(f"Parsing analysis note for model: {model_name}")

        infrastructure_items = self._parse_section(
            note_content, DiscoveryCategory.INFRASTRUCTURE, model_name
        )
        relationships = self._parse_section(
            note_content, DiscoveryCategory.RELATIONSHIPS, model_name
        )
        data_flows = self._parse_section(
            note_content, DiscoveryCategory.DATA_FLOWS, model_name
        )
        security_observations = self._parse_section(
            note_content, DiscoveryCategory.SECURITY, model_name
        )

        logger.info(
            f"Parsed {len(infrastructure_items)} infrastructure, "
            f"{len(relationships)} relationships, "
            f"{len(data_flows)} data flows, "
            f"{len(security_observations)} security observations"
        )

        return ParsedAnalysis(
            model_name=model_name,
            note_id=note_id,
            note_name=note_name,
            infrastructure_items=infrastructure_items,
            relationships=relationships,
            data_flows=data_flows,
            security_observations=security_observations,
            raw_content=note_content,
        )

    def _extract_section(self, content: str, category: DiscoveryCategory) -> str:
        """Extract a specific section from markdown content."""
        pattern = self.SECTION_PATTERNS.get(category)
        if not pattern:
            return ""

        match = pattern.search(content)
        if match:
            return match.group(1).strip()
        return ""

    def _parse_section(
        self, content: str, category: DiscoveryCategory, model_name: str
    ) -> List[Discovery]:
        """Parse a section into Discovery objects."""
        section_content = self._extract_section(content, category)
        if not section_content:
            return []

        discoveries = []

        # Parse bullet points and list items
        # Match lines starting with -, *, or numbered items
        item_pattern = re.compile(
            r"^[\s]*(?:[-*]|\d+\.)\s*\*?\*?([^*\n]+)\*?\*?:?\s*(.*?)(?=\n[\s]*(?:[-*]|\d+\.)|\n\n|\Z)",
            re.MULTILINE | re.DOTALL,
        )

        for match in item_pattern.finditer(section_content):
            name = match.group(1).strip()
            description = match.group(2).strip() if match.group(2) else ""

            # Clean up the name - remove markdown formatting
            name = re.sub(r"\*+", "", name).strip()
            name = re.sub(r"`+", "", name).strip()

            if name:
                # Build semantic meaning from name and description
                semantic_meaning = self._build_semantic_meaning(
                    name, description, category
                )
                discovery = Discovery(
                    id=str(uuid.uuid4()),
                    category=category,
                    name=name,
                    description=description,
                    source_model=model_name,
                    raw_text=match.group(0).strip(),
                    semantic_meaning=semantic_meaning,
                )
                discoveries.append(discovery)

        # Also try to parse sub-sections (### headers within the section)
        subsection_pattern = re.compile(r"###\s*([^\n]+)\n(.*?)(?=\n###|\Z)", re.DOTALL)
        for match in subsection_pattern.finditer(section_content):
            subsection_name = match.group(1).strip()
            subsection_content = match.group(2).strip()

            # Parse items within subsection
            for item_match in item_pattern.finditer(subsection_content):
                name = item_match.group(1).strip()
                description = item_match.group(2).strip() if item_match.group(2) else ""

                name = re.sub(r"\*+", "", name).strip()
                name = re.sub(r"`+", "", name).strip()

                if name:
                    # Include subsection context in semantic meaning
                    semantic_meaning = self._build_semantic_meaning(
                        name, description, category, subsection_name
                    )
                    discovery = Discovery(
                        id=str(uuid.uuid4()),
                        category=category,
                        name=name,
                        description=description,
                        source_model=model_name,
                        raw_text=item_match.group(0).strip(),
                        metadata={"subsection": subsection_name},
                        semantic_meaning=semantic_meaning,
                    )
                    discoveries.append(discovery)

        return discoveries

    def _build_semantic_meaning(
        self,
        name: str,
        description: str,
        category: DiscoveryCategory,
        subsection: Optional[str] = None,
    ) -> str:
        """Build a semantic meaning string from discovery components."""
        parts = []

        # Add subsection context if present
        if subsection:
            parts.append(f"[{subsection}]")

        # Add the name
        parts.append(name)

        # Add description if substantive
        if description and len(description) > 10:
            # Clean up the description
            clean_desc = description.replace("\n", " ").strip()
            # Truncate if too long, but preserve meaning
            if len(clean_desc) > 200:
                clean_desc = clean_desc[:197] + "..."
            parts.append(f"- {clean_desc}")

        return " ".join(parts)


class AnalysisComparer:
    """Main comparison engine using LLM for semantic matching."""

    def __init__(self, config: Config):
        """Initialize with config for LLM access."""
        self.config = config
        self.parser = AnalysisParser()

        # Token and cost tracking for comparison operations
        self.input_tokens = 0
        self.output_tokens = 0
        self.total_cost = 0.0

        # Load prompts
        prompts_dir = Path(__file__).parent.parent / "prompts"
        self.comparison_system_prompt = self._load_prompt(
            prompts_dir / "comparison_normalization_system.txt"
        )
        self.comparison_user_prompt = self._load_prompt(
            prompts_dir / "comparison_normalization_user.txt"
        )
        self.insights_system_prompt = self._load_prompt(
            prompts_dir / "comparison_insights_system.txt"
        )

        # Configure LiteLLM
        self._configure_litellm()

    def _load_prompt(self, path: Path) -> str:
        """Load a prompt file."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
        except FileNotFoundError:
            logger.warning(f"Prompt file not found: {path}")
            return ""

    def _configure_litellm(self):
        """Configure LiteLLM with API keys via environment variables."""
        if self.config.anthropic_api_key:
            os.environ["ANTHROPIC_API_KEY"] = self.config.anthropic_api_key
        if self.config.openai_api_key:
            os.environ["OPENAI_API_KEY"] = self.config.openai_api_key
        if hasattr(self.config, "xai_api_key") and self.config.xai_api_key:
            os.environ["XAI_API_KEY"] = self.config.xai_api_key
        if hasattr(self.config, "gemini_api_key") and self.config.gemini_api_key:
            os.environ["GEMINI_API_KEY"] = self.config.gemini_api_key

    def _get_llm_model(self) -> str:
        """Get the LLM model to use for comparison."""
        return self.config.get_llm_model()

    def discover_analysis_notes(
        self, tmi_client: Any, threat_model_id: str
    ) -> List[Any]:
        """Find all notes matching 'Terraform Analysis Report (*)'."""
        logger.info("Discovering analysis notes...")
        all_notes = tmi_client.get_threat_model_notes(threat_model_id)

        analysis_notes = []
        for note in all_notes:
            if self.parser.NOTE_NAME_PATTERN.match(note.name):
                analysis_notes.append(note)
                logger.info(f"Found analysis note: {note.name}")

        logger.info(f"Discovered {len(analysis_notes)} analysis notes")
        return analysis_notes

    def compare_analyses(
        self, parsed_analyses: List[ParsedAnalysis]
    ) -> ComparisonResult:
        """Main comparison method."""
        if len(parsed_analyses) < 2:
            raise ValueError("Need at least 2 analyses to compare")

        models = [a.model_name for a in parsed_analyses]
        logger.info(f"Comparing analyses from models: {models}")

        # Collect all discoveries by category
        all_infrastructure = []
        all_relationships = []
        all_data_flows = []
        all_security = []

        for analysis in parsed_analyses:
            all_infrastructure.extend(analysis.infrastructure_items)
            all_relationships.extend(analysis.relationships)
            all_data_flows.extend(analysis.data_flows)
            all_security.extend(analysis.security_observations)

        # Normalize and group discoveries using LLM
        infrastructure_comparison = self._normalize_discoveries(
            all_infrastructure, DiscoveryCategory.INFRASTRUCTURE, models
        )
        relationships_comparison = self._normalize_discoveries(
            all_relationships, DiscoveryCategory.RELATIONSHIPS, models
        )
        data_flows_comparison = self._normalize_discoveries(
            all_data_flows, DiscoveryCategory.DATA_FLOWS, models
        )
        security_comparison = self._normalize_discoveries(
            all_security, DiscoveryCategory.SECURITY, models
        )

        # Calculate statistics
        total_unique = (
            len(infrastructure_comparison)
            + len(relationships_comparison)
            + len(data_flows_comparison)
            + len(security_comparison)
        )

        # Calculate agreement rate (discoveries found by all models)
        all_comparisons = (
            infrastructure_comparison
            + relationships_comparison
            + data_flows_comparison
            + security_comparison
        )
        if all_comparisons:
            agreed = sum(
                1 for d in all_comparisons if len(d.models_that_found) == len(models)
            )
            agreement_rate = agreed / len(all_comparisons) * 100
        else:
            agreement_rate = 0.0

        # Create preliminary result
        result = ComparisonResult(
            models_compared=models,
            infrastructure_comparison=infrastructure_comparison,
            relationships_comparison=relationships_comparison,
            data_flows_comparison=data_flows_comparison,
            security_comparison=security_comparison,
            summary_insights="",
            total_unique_discoveries=total_unique,
            agreement_rate=agreement_rate,
        )

        # Generate insights
        result.summary_insights = self._generate_summary_insights(result)

        return result

    def _normalize_discoveries(
        self,
        discoveries: List[Discovery],
        category: DiscoveryCategory,
        all_models: List[str],
    ) -> List[NormalizedDiscovery]:
        """Use LLM to normalize and group similar discoveries."""
        if not discoveries:
            return []

        logger.info(
            f"Normalizing {len(discoveries)} discoveries in category: {category.value}"
        )

        # Prepare discovery data for LLM with semantic meaning
        discovery_data = []
        for d in discoveries:
            discovery_data.append(
                {
                    "id": d.id,
                    "name": d.name,
                    "description": d.description,
                    "source_model": d.source_model,
                    "semantic_meaning": d.semantic_meaning or d.description,
                }
            )

        # Call LLM for normalization with rich semantic output
        user_prompt = f"""Normalize and group these {category.value} discoveries from different AI models.

Models being compared: {", ".join(all_models)}

Discoveries:
{json.dumps(discovery_data, indent=2)}

Group semantically equivalent discoveries together and create a canonical name for each group.
For each group, provide:
1. A canonical name
2. A semantic summary explaining what this discovery represents
3. Per-model details showing how each model named and interpreted the discovery
4. Whether the models are semantically equivalent in their understanding

Return JSON with this structure:
{{
  "normalized_items": [
    {{
      "canonical_name": "Standardized name",
      "discovery_ids": ["id1", "id2"],
      "semantic_summary": "A narrative description of what this represents",
      "per_model_details": {{
        "model_name": {{
          "original_name": "What the model called it",
          "interpretation": "How the model described it"
        }}
      }},
      "is_semantically_equivalent": true,
      "differences_note": "Any notable differences in treatment"
    }}
  ]
}}"""

        try:
            response = cast(
                ModelResponse,
                litellm.completion(
                    model=self._get_llm_model(),
                    messages=[
                        {"role": "system", "content": self.comparison_system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                ),
            )

            # Track token usage
            usage = getattr(response, "usage", None)
            if usage:
                self.input_tokens += getattr(usage, "prompt_tokens", 0) or 0
                self.output_tokens += getattr(usage, "completion_tokens", 0) or 0
                try:
                    call_cost = litellm.completion_cost(completion_response=response)
                    self.total_cost += call_cost
                except Exception:
                    pass

            response_text = response.choices[0].message.content  # type: ignore[union-attr]

            # Save response to file for debugging
            if response_text:
                response_file = save_llm_response(
                    response_text, f"compare_normalize_{category.value}"
                )
                logger.debug(f"Normalization response saved to {response_file}")

            # Extract JSON from response
            normalized_data = self._extract_json(response_text or "")

            if not normalized_data or "normalized_items" not in normalized_data:
                logger.warning("Failed to parse normalization response, using fallback")
                return self._fallback_normalize(discoveries, all_models)

            # Build NormalizedDiscovery objects with rich semantic data
            discovery_map = {d.id: d for d in discoveries}
            normalized_discoveries = []

            for item in normalized_data["normalized_items"]:
                canonical_name = item.get("canonical_name", "Unknown")
                discovery_ids = item.get("discovery_ids", [])
                differences_note = item.get("differences_note")
                semantic_summary = item.get("semantic_summary")
                per_model_details_raw = item.get("per_model_details", {})
                is_semantically_equivalent = item.get(
                    "is_semantically_equivalent", True
                )

                # Find which models found this discovery
                models_found = set()
                model_details = {}
                per_model_narratives = {}

                for did in discovery_ids:
                    if did in discovery_map:
                        d = discovery_map[did]
                        models_found.add(d.source_model)
                        model_details[d.source_model] = d

                        # Build per-model narrative from LLM response or fallback
                        if d.source_model in per_model_details_raw:
                            pmd = per_model_details_raw[d.source_model]
                            per_model_narratives[d.source_model] = ModelDiscoveryDetail(
                                model_name=d.source_model,
                                original_name=pmd.get("original_name", d.name),
                                description=pmd.get("interpretation", d.description),
                                semantic_meaning=d.semantic_meaning,
                            )
                        else:
                            # Fallback: use discovery data directly
                            per_model_narratives[d.source_model] = ModelDiscoveryDetail(
                                model_name=d.source_model,
                                original_name=d.name,
                                description=d.description,
                                semantic_meaning=d.semantic_meaning,
                            )

                if models_found:
                    normalized_discoveries.append(
                        NormalizedDiscovery(
                            canonical_name=canonical_name,
                            category=category,
                            models_that_found=sorted(models_found),
                            model_details=model_details,
                            differences_summary=differences_note,
                            semantic_summary=semantic_summary,
                            per_model_narratives=per_model_narratives,
                            is_semantically_equivalent=is_semantically_equivalent,
                        )
                    )

            return normalized_discoveries

        except Exception as e:
            logger.error(f"LLM normalization failed: {e}")
            return self._fallback_normalize(discoveries, all_models)

    def _fallback_normalize(
        self, discoveries: List[Discovery], all_models: List[str]
    ) -> List[NormalizedDiscovery]:
        """Fallback normalization using simple string matching."""
        # Group by lowercase name similarity
        groups: Dict[str, List[Discovery]] = {}

        for d in discoveries:
            # Simple normalization: lowercase, remove extra whitespace
            key = " ".join(d.name.lower().split())
            if key not in groups:
                groups[key] = []
            groups[key].append(d)

        normalized = []
        for key, group in groups.items():
            models_found = list(set(d.source_model for d in group))
            model_details = {d.source_model: d for d in group}

            # Use the first discovery's name as canonical
            canonical_name = group[0].name

            # Build per-model narratives from discovery data
            per_model_narratives = {}
            for d in group:
                per_model_narratives[d.source_model] = ModelDiscoveryDetail(
                    model_name=d.source_model,
                    original_name=d.name,
                    description=d.description,
                    semantic_meaning=d.semantic_meaning,
                )

            # Build semantic summary from first discovery
            semantic_summary = group[0].semantic_meaning or group[0].description

            normalized.append(
                NormalizedDiscovery(
                    canonical_name=canonical_name,
                    category=group[0].category,
                    models_that_found=sorted(models_found),
                    model_details=model_details,
                    differences_summary=None,
                    semantic_summary=semantic_summary,
                    per_model_narratives=per_model_narratives,
                    is_semantically_equivalent=True,
                )
            )

        return normalized

    def _generate_summary_insights(self, comparison: ComparisonResult) -> str:
        """Use LLM to generate insights about differences."""
        logger.info("Generating summary insights...")

        # Prepare summary data
        summary_data = {
            "models_compared": comparison.models_compared,
            "total_unique_discoveries": comparison.total_unique_discoveries,
            "agreement_rate": f"{comparison.agreement_rate:.1f}%",
            "infrastructure_count": len(comparison.infrastructure_comparison),
            "relationships_count": len(comparison.relationships_comparison),
            "data_flows_count": len(comparison.data_flows_comparison),
            "security_count": len(comparison.security_comparison),
        }

        # Find discoveries unique to each model
        unique_per_model: Dict[str, List[str]] = {
            m: [] for m in comparison.models_compared
        }
        missed_per_model: Dict[str, List[str]] = {
            m: [] for m in comparison.models_compared
        }

        all_comparisons = (
            comparison.infrastructure_comparison
            + comparison.relationships_comparison
            + comparison.data_flows_comparison
            + comparison.security_comparison
        )

        for nd in all_comparisons:
            if len(nd.models_that_found) == 1:
                unique_per_model[nd.models_that_found[0]].append(nd.canonical_name)
            elif len(nd.models_that_found) < len(comparison.models_compared):
                for model in comparison.models_compared:
                    if model not in nd.models_that_found:
                        missed_per_model[model].append(nd.canonical_name)

        summary_data["unique_per_model"] = unique_per_model
        summary_data["missed_per_model"] = missed_per_model

        user_prompt = f"""Analyze this comparison of infrastructure threat model analyses from different AI models:

{json.dumps(summary_data, indent=2)}

Provide insights about:
1. Overall consistency between models
2. Notable coverage gaps
3. Which model(s) were most thorough
4. Recommendations for threat modeling based on these findings

Keep the summary concise (under 400 words) but insightful."""

        try:
            response = cast(
                ModelResponse,
                litellm.completion(
                    model=self._get_llm_model(),
                    messages=[
                        {"role": "system", "content": self.insights_system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                ),
            )

            # Track token usage
            usage = getattr(response, "usage", None)
            if usage:
                self.input_tokens += getattr(usage, "prompt_tokens", 0) or 0
                self.output_tokens += getattr(usage, "completion_tokens", 0) or 0
                try:
                    call_cost = litellm.completion_cost(completion_response=response)
                    self.total_cost += call_cost
                except Exception:
                    pass

            insights_text = response.choices[0].message.content or ""  # type: ignore[union-attr]

            # Save response to file for debugging
            if insights_text:
                response_file = save_llm_response(insights_text, "compare_insights")
                logger.debug(f"Insights response saved to {response_file}")

            return insights_text

        except Exception as e:
            logger.error(f"Failed to generate insights: {e}")
            return self._fallback_insights(comparison)

    def _fallback_insights(self, comparison: ComparisonResult) -> str:
        """Generate basic insights without LLM."""
        lines = [
            f"Compared {len(comparison.models_compared)} models: {', '.join(comparison.models_compared)}",
            "",
            "**Statistics:**",
            f"- Total unique discoveries: {comparison.total_unique_discoveries}",
            f"- Agreement rate: {comparison.agreement_rate:.1f}%",
            f"- Infrastructure items: {len(comparison.infrastructure_comparison)}",
            f"- Relationships: {len(comparison.relationships_comparison)}",
            f"- Data flows: {len(comparison.data_flows_comparison)}",
            f"- Security observations: {len(comparison.security_comparison)}",
        ]
        return "\n".join(lines)

    def _extract_json(self, text: str) -> Optional[Dict]:
        """Extract JSON from LLM response text."""
        # Try to find JSON in code blocks first
        code_block_pattern = re.compile(r"```(?:json)?\s*\n?(.*?)\n?```", re.DOTALL)
        match = code_block_pattern.search(text)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass

        # Try to parse the whole text as JSON
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try to find JSON object in text
        brace_pattern = re.compile(r"\{.*\}", re.DOTALL)
        match = brace_pattern.search(text)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass

        return None
