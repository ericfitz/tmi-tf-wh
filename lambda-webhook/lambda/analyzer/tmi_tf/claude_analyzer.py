"""Claude AI integration for Terraform analysis."""

import logging
from pathlib import Path

from anthropic import Anthropic

from tmi_tf.config import Config
from tmi_tf.repo_analyzer import TerraformRepository

logger = logging.getLogger(__name__)


class TerraformAnalysis:
    """Result of Terraform analysis."""

    def __init__(
        self, repo_name: str, repo_url: str, analysis_content: str, success: bool = True
    ):
        """
        Initialize analysis result.

        Args:
            repo_name: Repository name
            repo_url: Repository URL
            analysis_content: Analysis markdown content from Claude
            success: Whether analysis was successful
        """
        self.repo_name = repo_name
        self.repo_url = repo_url
        self.analysis_content = analysis_content
        self.success = success

    def __repr__(self) -> str:
        """Return string representation."""
        status = "success" if self.success else "failed"
        return f"TerraformAnalysis(repo={self.repo_name}, status={status})"


class ClaudeAnalyzer:
    """Claude AI analyzer for Terraform files."""

    def __init__(self, config: Config):
        """
        Initialize Claude analyzer.

        Args:
            config: Application configuration
        """
        self.config = config
        self.client = Anthropic(api_key=config.anthropic_api_key)
        self.model = "claude-sonnet-4-5"  # Claude Sonnet 4.5

        # Load prompts
        self.prompts_dir = Path(__file__).parent.parent / "prompts"
        self.system_prompt = self._load_prompt("terraform_analysis_system.txt")
        self.user_prompt_template = self._load_prompt("terraform_analysis_user.txt")

        logger.info(f"Claude analyzer initialized with model: {self.model}")

    def _load_prompt(self, filename: str) -> str:
        """
        Load prompt from file.

        Args:
            filename: Prompt filename

        Returns:
            Prompt content
        """
        prompt_file = self.prompts_dir / filename
        if prompt_file.exists():
            return prompt_file.read_text(encoding="utf-8")
        else:
            logger.warning(f"Prompt file not found: {prompt_file}, using default")
            return self._get_default_prompt(filename)

    def _get_default_prompt(self, filename: str) -> str:
        """
        Get default prompt if file doesn't exist.

        Args:
            filename: Prompt filename

        Returns:
            Default prompt content
        """
        if "system" in filename:
            return """You are an expert infrastructure security analyst specializing in Terraform and cloud architecture.

Your task is to analyze Terraform (.tf) files to:
1. Identify all infrastructure components being provisioned
2. Map relationships and dependencies between components
3. Identify potential security concerns or misconfigurations
4. Create a clear inventory suitable for threat modeling

Provide your analysis in clear, structured markdown format."""

        else:  # user prompt
            return """Repository: {repo_name}
URL: {repo_url}

Terraform Files:
{terraform_contents}

{documentation_summary}

Please analyze these Terraform files and provide:

## Infrastructure Inventory
List all resources by type (compute, storage, network, databases, etc.)

## Component Relationships
How do components connect and depend on each other?

## Data Flows
How does data move between components?

## Security Observations
Potential security concerns or best practices violations

## Architecture Summary
High-level summary of what this infrastructure does

## Mermaid Diagram
Provide a mermaid diagram showing the architecture and relationships between components."""

    def analyze_repository(
        self, terraform_repo: TerraformRepository
    ) -> TerraformAnalysis:
        """
        Analyze Terraform repository using Claude.

        Args:
            terraform_repo: Terraform repository to analyze

        Returns:
            TerraformAnalysis result
        """
        logger.info(f"Analyzing repository: {terraform_repo.name}")

        try:
            # Get Terraform file contents
            tf_contents = terraform_repo.get_terraform_content()
            doc_contents = terraform_repo.get_documentation_content()

            # Format Terraform contents for prompt
            terraform_text = self._format_terraform_contents(tf_contents)

            # Format documentation summary
            doc_summary = self._format_documentation_summary(doc_contents)

            # Build user prompt
            user_prompt = self.user_prompt_template.format(
                repo_name=terraform_repo.name,
                repo_url=terraform_repo.url,
                terraform_contents=terraform_text,
                documentation_summary=doc_summary,
            )

            # Check token estimate (rough estimate: 4 chars per token)
            estimated_tokens = (len(self.system_prompt) + len(user_prompt)) // 4
            logger.info(f"Estimated input tokens: {estimated_tokens}")

            if estimated_tokens > 150000:
                logger.warning(
                    f"Input may be too large ({estimated_tokens} tokens). "
                    "Consider reducing file count."
                )

            # Call Claude API
            logger.info(f"Sending request to Claude ({self.model})...")
            response = self.client.messages.create(
                model=self.model,
                max_tokens=16000,
                system=self.system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )

            analysis_content = response.content[0].text
            logger.info(
                f"Analysis complete. Output tokens: {response.usage.output_tokens}, "
                f"Input tokens: {response.usage.input_tokens}"
            )

            return TerraformAnalysis(
                repo_name=terraform_repo.name,
                repo_url=terraform_repo.url,
                analysis_content=analysis_content,
                success=True,
            )

        except Exception as e:
            logger.error(f"Failed to analyze {terraform_repo.name}: {e}")
            error_message = f"**Analysis Failed**: {str(e)}"
            return TerraformAnalysis(
                repo_name=terraform_repo.name,
                repo_url=terraform_repo.url,
                analysis_content=error_message,
                success=False,
            )

    def _format_terraform_contents(self, tf_contents: dict[str, str]) -> str:
        """
        Format Terraform contents for prompt.

        Args:
            tf_contents: Dictionary of file paths to contents

        Returns:
            Formatted string
        """
        if not tf_contents:
            return "(No Terraform files found)"

        sections = []
        for filepath, content in sorted(tf_contents.items()):
            sections.append(f"### File: {filepath}\n```hcl\n{content}\n```\n")

        return "\n".join(sections)

    def _format_documentation_summary(self, doc_contents: dict[str, str]) -> str:
        """
        Format documentation summary for prompt.

        Args:
            doc_contents: Dictionary of file paths to contents

        Returns:
            Formatted string
        """
        if not doc_contents:
            return ""

        sections = ["Documentation Files:"]
        for filepath, content in sorted(doc_contents.items()):
            # Truncate very long docs
            truncated = content[:2000] + "..." if len(content) > 2000 else content
            sections.append(f"### {filepath}\n{truncated}\n")

        return "\n".join(sections)

    def estimate_tokens(self, text: str) -> int:
        """
        Rough estimate of token count.

        Args:
            text: Text to estimate

        Returns:
            Estimated token count
        """
        # Rough estimate: ~4 characters per token
        return len(text) // 4
