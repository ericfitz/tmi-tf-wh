"""Unified LLM analyzer for Terraform analysis using LiteLLM (Lambda version).

This module provides a single analyzer class that supports multiple LLM providers
(Anthropic, OpenAI, x.ai, Google Gemini, etc.) through the LiteLLM library.
"""

import logging
import os
import time
from pathlib import Path
from typing import Dict, Any

import litellm

logger = logging.getLogger(__name__)

# Suppress LiteLLM's verbose logging
litellm.suppress_debug_info = True


class LLMAnalyzer:
    """Unified LLM analyzer for Terraform files using LiteLLM."""

    # Default models for each provider (LiteLLM format)
    DEFAULT_MODELS = {
        "anthropic": "claude-opus-4-5-20251101",
        "openai": "gpt-5.2",
        "xai": "xai/grok-4-1-fast-reasoning",
        "gemini": "gemini/gemini-3-pro-preview",
    }

    # LiteLLM model prefixes for each provider
    MODEL_PREFIXES = {
        "anthropic": "",  # LiteLLM auto-detects anthropic models
        "openai": "",  # LiteLLM auto-detects openai models
        "xai": "xai/",  # x.ai uses xai/ prefix
        "gemini": "gemini/",  # Google uses gemini/ prefix
    }

    def __init__(self, config):
        """
        Initialize LLM analyzer.

        Args:
            config: Lambda configuration with LLM provider settings
        """
        self.config = config
        self.provider = getattr(config, "llm_provider", "anthropic")

        # Determine the model to use
        if hasattr(config, "llm_model") and config.llm_model:
            self.model = self._normalize_model_name(config.llm_model)
        else:
            self.model = self.DEFAULT_MODELS.get(self.provider, self.DEFAULT_MODELS["anthropic"])

        # Set up API keys for LiteLLM based on provider
        self._configure_api_keys()

        # Load prompts
        self.prompts_dir = Path(__file__).parent / "prompts"
        self.system_prompt = self._load_prompt("terraform_analysis_system.txt")
        self.user_prompt_template = self._load_prompt("terraform_analysis_user.txt")

        logger.info(f"LLM analyzer initialized: provider={self.provider}, model={self.model}")

    def _normalize_model_name(self, model: str) -> str:
        """
        Normalize model name to include proper LiteLLM prefix.

        Args:
            model: Model name from config

        Returns:
            Normalized model name with appropriate prefix
        """
        # If model already has a prefix, return as-is
        if "/" in model:
            return model

        # Add prefix based on provider
        prefix = self.MODEL_PREFIXES.get(self.provider, "")
        if prefix and not model.startswith(prefix):
            return f"{prefix}{model}"
        return model

    def _configure_api_keys(self):
        """Configure API keys for LiteLLM based on the selected provider."""
        if self.provider == "anthropic":
            if hasattr(self.config, "anthropic_api_key") and self.config.anthropic_api_key:
                os.environ["ANTHROPIC_API_KEY"] = self.config.anthropic_api_key
        elif self.provider == "openai":
            if hasattr(self.config, "openai_api_key") and self.config.openai_api_key:
                os.environ["OPENAI_API_KEY"] = self.config.openai_api_key
        elif self.provider == "xai":
            if hasattr(self.config, "xai_api_key") and self.config.xai_api_key:
                os.environ["XAI_API_KEY"] = self.config.xai_api_key
        elif self.provider == "gemini":
            if hasattr(self.config, "gemini_api_key") and self.config.gemini_api_key:
                os.environ["GEMINI_API_KEY"] = self.config.gemini_api_key

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

    def analyze_repository(self, terraform_repo) -> Dict[str, Any]:
        """
        Analyze Terraform repository using LLM.

        Args:
            terraform_repo: Terraform repository to analyze

        Returns:
            Dictionary with analysis results (Lambda-compatible format)
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

            # Call LLM API via LiteLLM
            logger.info(f"Sending request to {self.provider} ({self.model})...")
            start_time = time.time()

            response = litellm.completion(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                max_tokens=16000,
                temperature=0.3,
                timeout=300.0,
            )

            elapsed_time = time.time() - start_time

            analysis_content = response.choices[0].message.content
            input_tokens = response.usage.prompt_tokens
            output_tokens = response.usage.completion_tokens

            # Calculate cost using LiteLLM's cost tracking
            try:
                total_cost = litellm.completion_cost(completion_response=response)
            except Exception:
                total_cost = 0.0

            logger.info(
                f"Analysis complete in {elapsed_time:.2f}s. "
                f"Input tokens: {input_tokens}, Output tokens: {output_tokens}, "
                f"Cost: ${total_cost:.4f}"
            )

            # Return Lambda-compatible dict format
            return {
                "analysis": analysis_content,
                "model": self.model,
                "provider": self.provider,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_cost": total_cost,
                "elapsed_time": elapsed_time,
            }

        except Exception as e:
            logger.error(f"Failed to analyze {terraform_repo.name}: {e}")
            return {
                "analysis": f"**Analysis Failed**: {str(e)}",
                "model": self.model,
                "provider": self.provider,
                "input_tokens": 0,
                "output_tokens": 0,
                "total_cost": 0.0,
                "error": str(e),
            }

    def _format_terraform_contents(self, tf_contents: dict) -> str:
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

    def _format_documentation_summary(self, doc_contents: dict) -> str:
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
