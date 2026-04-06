"""Shared analysis pipeline for TMI Terraform Analysis Tool.

Extracts the core analysis logic from cli.py so it can be reused by
both the CLI command and the webhook worker.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional, Protocol

from tmi_tf.artifact_metadata import (
    aggregate_analysis_metadata,
    create_artifact_metadata,
)
from tmi_tf.config import Config
from tmi_tf.dfd_llm_generator import DFDLLMGenerator
from tmi_tf.diagram_builder import DFDBuilder
from tmi_tf.github_client import GitHubClient
from tmi_tf.llm_analyzer import LLMAnalyzer, TerraformAnalysis
from tmi_tf.markdown_generator import MarkdownGenerator
from tmi_tf.providers import get_llm_provider
from tmi_tf.repo_analyzer import RepositoryAnalyzer
from tmi_tf.tf_validator import validate_and_sanitize
from tmi_tf.threat_processor import ThreatProcessor
from tmi_tf.tmi_client_wrapper import TMIClient

logger = logging.getLogger(__name__)


class StatusCallback(Protocol):
    """Protocol for status callback objects (e.g. AddonCallback)."""

    def send_status(self, status: str, message: str = "") -> None: ...


@dataclass
class AnalysisResult:
    """Result of the full analysis pipeline."""

    success: bool
    analyses: List[TerraformAnalysis] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    inventory_content: str = ""
    analysis_content: str = ""


def _analyze_single_environment(
    tf_repo: Any,
    selected: Any,
    repo_analyzer: RepositoryAnalyzer,
    llm_analyzer: LLMAnalyzer,
    tmi_client: TMIClient,
    threat_model_id: str,
    repo_name: str,
) -> TerraformAnalysis:
    """Resolve modules for an environment and run LLM analysis."""
    tf_repo.environment_name = selected.name
    logger.info(f"Selected environment: {selected.name}")
    tmi_client.update_status_note(
        threat_model_id,
        f"Selected environment: {selected.name}",
    )
    tmi_client.update_status_note(
        threat_model_id,
        f"Resolving modules for environment: {selected.name}",
    )
    tf_repo.terraform_files = RepositoryAnalyzer.resolve_modules(
        selected, tf_repo.clone_path
    )

    # Validate and sanitize resolved files before LLM analysis
    validation_result = validate_and_sanitize(
        tf_repo.terraform_files, tf_repo.clone_path
    )
    tf_repo.terraform_files = validation_result.valid_files
    for msg in validation_result.sanitization_log:
        logger.info(msg)

    def _status_cb(msg: str) -> None:
        tmi_client.update_status_note(threat_model_id, msg)

    return llm_analyzer.analyze_repository(tf_repo, status_callback=_status_cb)


def run_analysis(
    config: Config,
    threat_model_id: str,
    tmi_client: TMIClient,
    repo_id: Optional[str] = None,
    temp_dir: Optional[Path] = None,
    callback: Optional[StatusCallback] = None,
    skip_diagram: bool = False,
    skip_threats: bool = False,
    environment: Optional[str] = None,
) -> AnalysisResult:
    """Run the full Terraform analysis pipeline.

    This is the core analysis logic extracted from cli.py's ``analyze()``
    command.  It is synchronous; the webhook worker wraps it in
    ``asyncio.to_thread``.

    Args:
        config: Application configuration.
        threat_model_id: UUID of the threat model in TMI.
        tmi_client: Authenticated TMI client.
        repo_id: If given, only analyse the repository with this ID.
        temp_dir: Base temporary directory for clones.
        callback: Optional status callback (e.g. AddonCallback).
        skip_diagram: Skip diagram generation.
        skip_threats: Skip threat creation.
        environment: If given, filter to this Terraform environment name.

    Returns:
        AnalysisResult with success flag, analyses, and generated content.
    """
    errors: List[str] = []

    try:
        logger.info("=" * 80)
        logger.info("TMI Terraform Analysis Tool")
        logger.info("=" * 80)

        logger.info(f"Threat Model ID: {threat_model_id}")
        logger.info(f"Max Repositories: {config.max_repos}")
        logger.info(f"TMI Server: {config.tmi_server_url}")

        # Initialize helpers
        logger.info("\n[1/7] Initializing clients...")
        github_client = GitHubClient(config)
        repo_analyzer = RepositoryAnalyzer(config)
        llm_provider = get_llm_provider(config)
        llm_analyzer = LLMAnalyzer(llm_provider)
        markdown_gen = MarkdownGenerator()

        tmi_client.update_status_note(threat_model_id, "Analysis started")

        # Get threat model
        logger.info("\n[2/7] Fetching threat model...")
        threat_model = tmi_client.get_threat_model(threat_model_id)
        logger.info(f"Threat Model: {threat_model.name}")

        # Get repositories
        logger.info("\n[3/7] Fetching repositories...")
        repositories = tmi_client.get_threat_model_repositories(threat_model_id)
        logger.info(f"Found {len(repositories)} total repositories")

        # Filter for GitHub repos
        github_repos = [
            repo for repo in repositories if github_client.is_github_url(repo.uri)
        ]
        logger.info(f"GitHub repositories: {len(github_repos)}")

        # Filter to specific repo_id if provided
        if repo_id is not None:
            github_repos = [r for r in github_repos if str(r.id) == repo_id]
            if not github_repos:
                msg = f"Repository {repo_id} not found or not a GitHub repository"
                logger.error(msg)
                return AnalysisResult(success=False, errors=[msg])

        if not github_repos:
            msg = "No GitHub repositories found in threat model"
            logger.error(msg)
            return AnalysisResult(success=False, errors=[msg])

        # Limit number of repos
        repos_to_analyze = github_repos[: config.max_repos]
        if len(github_repos) > config.max_repos:
            logger.warning(
                f"Limiting analysis to {config.max_repos} of {len(github_repos)} repositories"
            )

        # Analyze repositories
        logger.info(f"\n[4/7] Analyzing {len(repos_to_analyze)} repositories...")
        analyses: List[TerraformAnalysis] = []
        selected_env_name: Optional[str] = None

        for i, repo in enumerate(repos_to_analyze, 1):
            logger.info(
                f"\n--- Repository {i}/{len(repos_to_analyze)}: {repo.name} ---"
            )
            logger.info(f"URL: {repo.uri}")

            try:
                repo_name = repo_analyzer.extract_repository_name(repo.uri)
                tmi_client.update_status_note(
                    threat_model_id, f"Cloning repository: {repo.uri}"
                )
                with repo_analyzer.clone_repository_sparse(
                    repo.uri, repo_name, base_temp_dir=temp_dir
                ) as tf_repo:
                    if tf_repo:
                        tmi_client.update_status_note(
                            threat_model_id, f"Clone complete: {repo_name}"
                        )

                        # Detect Terraform environments
                        envs = RepositoryAnalyzer.detect_environments(
                            tf_repo.clone_path
                        )
                        tf_repo.environments_found = [e.name for e in envs]

                        if len(envs) == 0:
                            logger.info(
                                "No Terraform environments detected, analyzing all files"
                            )
                            tmi_client.update_status_note(
                                threat_model_id,
                                f"No environments detected in {repo_name}, analyzing all files",
                            )

                            # Validate and sanitize before LLM analysis
                            validation_result = validate_and_sanitize(
                                tf_repo.terraform_files, tf_repo.clone_path
                            )
                            tf_repo.terraform_files = validation_result.valid_files
                            for msg in validation_result.sanitization_log:
                                logger.info(msg)

                            def _status_cb(msg: str) -> None:
                                tmi_client.update_status_note(threat_model_id, msg)

                            analysis = llm_analyzer.analyze_repository(
                                tf_repo, status_callback=_status_cb
                            )
                            analyses.append(analysis)

                        elif len(envs) == 1:
                            selected = envs[0]
                            selected_env_name = selected.name
                            logger.info(f"Auto-selected environment: {selected.name}")
                            tmi_client.update_status_note(
                                threat_model_id,
                                f"Found 1 Terraform environment: {selected.name}",
                            )
                            analysis = _analyze_single_environment(
                                tf_repo,
                                selected,
                                repo_analyzer,
                                llm_analyzer,
                                tmi_client,
                                threat_model_id,
                                repo_name,
                            )
                            analyses.append(analysis)

                        else:
                            # Multiple environments
                            env_names = ", ".join(e.name for e in envs)
                            tmi_client.update_status_note(
                                threat_model_id,
                                f"Found {len(envs)} Terraform environments: {env_names}",
                            )

                            if environment:
                                # Filter to the requested environment
                                matches = [
                                    e
                                    for e in envs
                                    if e.name.lower() == environment.lower()
                                ]
                                if not matches:
                                    available = ", ".join(e.name for e in envs)
                                    msg = (
                                        f"Environment '{environment}' not found. "
                                        f"Available: {available}"
                                    )
                                    logger.error(msg)
                                    errors.append(msg)
                                    continue
                                selected = matches[0]
                                selected_env_name = selected.name
                                analysis = _analyze_single_environment(
                                    tf_repo,
                                    selected,
                                    repo_analyzer,
                                    llm_analyzer,
                                    tmi_client,
                                    threat_model_id,
                                    repo_name,
                                )
                                analyses.append(analysis)
                            else:
                                # Analyze ALL environments
                                for env in envs:
                                    logger.info(f"Analyzing environment: {env.name}")
                                    selected_env_name = env.name
                                    analysis = _analyze_single_environment(
                                        tf_repo,
                                        env,
                                        repo_analyzer,
                                        llm_analyzer,
                                        tmi_client,
                                        threat_model_id,
                                        repo_name,
                                    )
                                    analyses.append(analysis)
                    else:
                        logger.warning(
                            f"Skipping {repo.name} - no Terraform files found"
                        )

            except Exception as e:
                error_msg = f"Failed to analyze {repo.name}: {e}"
                logger.error(error_msg)
                errors.append(error_msg)
                continue

        if not analyses:
            msg = "No repositories were successfully analyzed"
            logger.error(msg)
            errors.append(msg)
            return AnalysisResult(success=False, errors=errors)

        logger.info(f"\n[5/9] Successfully analyzed {len(analyses)} repositories")

        # Build artifact names (environment-aware)
        model_label = llm_analyzer.model
        ts = config.timestamp
        if selected_env_name:
            inventory_note_name = (
                f"Terraform Inventory - {selected_env_name} ({model_label}, {ts})"
            )
            analysis_note_name = (
                f"Terraform Analysis - {selected_env_name} ({model_label}, {ts})"
            )
            diagram_name = f"Infrastructure Data Flow Diagram - {selected_env_name} ({model_label}, {ts})"
        else:
            inventory_note_name = f"Terraform Inventory ({model_label}, {ts})"
            analysis_note_name = f"Terraform Analysis ({model_label}, {ts})"
            diagram_name = f"Infrastructure Data Flow Diagram ({model_label}, {ts})"

        # Generate reports
        tmi_client.update_status_note(threat_model_id, "Generating inventory report")
        logger.info("\n[6/9] Generating inventory report...")
        inventory_content = markdown_gen.generate_inventory_report(
            threat_model_name=threat_model.name,
            threat_model_id=threat_model_id,
            analyses=analyses,
            environment_name=selected_env_name,
        )

        tmi_client.update_status_note(threat_model_id, "Generating analysis report")
        logger.info("\n[7/9] Generating analysis report...")
        analysis_content = markdown_gen.generate_analysis_report(
            threat_model_name=threat_model.name,
            threat_model_id=threat_model_id,
            analyses=analyses,
            environment_name=selected_env_name,
        )

        # Create notes in TMI
        repo_short_names = [
            a.repo_url.rstrip("/").removesuffix(".git").split("/")[-1] for a in analyses
        ]
        repo_word = "repository" if len(repo_short_names) == 1 else "repositories"
        repo_list = ", ".join(repo_short_names)

        inv_note = tmi_client.create_or_update_note(
            threat_model_id=threat_model_id,
            name=inventory_note_name,
            content=inventory_content,
            description=f"Infrastructure inventory from Terraform templates in {repo_word}: {repo_list}",
        )
        logger.info(f"Inventory note created/updated: {inv_note.id}")

        artifact_metadata = aggregate_analysis_metadata(
            analyses=analyses,
            provider=llm_analyzer.provider,
            model=llm_analyzer.model,
        )
        try:
            tmi_client.set_note_metadata(
                threat_model_id=threat_model_id,
                note_id=inv_note.id,
                metadata=artifact_metadata.to_metadata_list(),
            )
        except Exception as e:
            logger.warning(f"Failed to set inventory note metadata: {e}")

        analysis_note = tmi_client.create_or_update_note(
            threat_model_id=threat_model_id,
            name=analysis_note_name,
            content=analysis_content,
            description=f"Terraform analysis for {repo_word}: {repo_list}",
        )
        logger.info(f"Analysis note created/updated: {analysis_note.id}")

        try:
            tmi_client.set_note_metadata(
                threat_model_id=threat_model_id,
                note_id=analysis_note.id,
                metadata=artifact_metadata.to_metadata_list(),
            )
        except Exception as e:
            logger.warning(f"Failed to set analysis note metadata: {e}")

        # Generate and create data flow diagram
        if not skip_diagram:
            tmi_client.update_status_note(threat_model_id, "Generating DFD diagram")
            logger.info("\n[8/9] Generating data flow diagram...")
            try:
                dfd_generator = DFDLLMGenerator(llm_provider)

                combined_inventory: dict = {"components": [], "services": []}
                combined_infrastructure: dict = {
                    "architecture_summary": "",
                    "relationships": [],
                    "data_flows": [],
                    "trust_boundaries": [],
                }
                for analysis in analyses:
                    if analysis.success:
                        inv = analysis.inventory or {}
                        infra = analysis.infrastructure or {}
                        combined_inventory["components"].extend(
                            inv.get("components", [])
                        )
                        combined_inventory["services"].extend(inv.get("services", []))
                        combined_infrastructure["relationships"].extend(
                            infra.get("relationships", [])
                        )
                        combined_infrastructure["data_flows"].extend(
                            infra.get("data_flows", [])
                        )
                        combined_infrastructure["trust_boundaries"].extend(
                            infra.get("trust_boundaries", [])
                        )
                        arch = infra.get("architecture_summary", "")
                        if arch:
                            if combined_infrastructure["architecture_summary"]:
                                combined_infrastructure["architecture_summary"] += (
                                    f"\n\n{arch}"
                                )
                            else:
                                combined_infrastructure["architecture_summary"] = arch

                structured_data = dfd_generator.generate_structured_components(
                    inventory=combined_inventory,
                    infrastructure=combined_infrastructure,
                )

                if structured_data:
                    builder = DFDBuilder(
                        components=structured_data["components"],
                        flows=structured_data["flows"],
                        services=combined_inventory.get("services"),
                    )
                    cells = builder.build_cells()

                    diagram = tmi_client.create_or_update_diagram(
                        threat_model_id=threat_model_id,
                        name=diagram_name,
                        cells=cells,
                    )
                    diagram_id = (
                        diagram["id"] if isinstance(diagram, dict) else diagram.id
                    )
                    logger.info(f"Diagram created/updated successfully: {diagram_id}")
                    logger.info(f"Diagram contains {len(cells)} cells")

                    diagram_metadata = create_artifact_metadata(
                        provider=dfd_generator.provider,
                        model=dfd_generator.model,
                        input_tokens=dfd_generator.input_tokens,
                        output_tokens=dfd_generator.output_tokens,
                        cost_estimate_usd=dfd_generator.total_cost,
                    )
                    try:
                        tmi_client.set_diagram_metadata(
                            threat_model_id=threat_model_id,
                            diagram_id=diagram_id,
                            metadata=diagram_metadata.to_metadata_list(),
                        )
                        logger.info("Diagram metadata set successfully")
                    except Exception as e:
                        logger.warning(f"Failed to set diagram metadata: {e}")
                else:
                    logger.warning("Failed to generate structured data for diagram")

            except Exception as e:
                logger.error(f"Failed to generate diagram: {e}")
                logger.info("Continuing without diagram...")

        else:
            logger.info("\n[8/9] Skipping diagram generation (skip_diagram)")

        # Create threats from security issues
        if not skip_threats:
            tmi_client.update_status_note(threat_model_id, "Creating threats")
            logger.info(
                "\n[9/9] Extracting and creating threats from security issues..."
            )
            try:
                threat_processor = ThreatProcessor(llm_provider)
                all_threats = []

                for analysis in analyses:
                    if analysis.success and analysis.security_findings:
                        threats = threat_processor.threats_from_findings(
                            analysis.security_findings, analysis.repo_name
                        )
                        all_threats.extend(threats)

                logger.info(f"Extracted {len(all_threats)} total threats from analyses")

                if all_threats:
                    diagram_id_for_threats: Optional[str] = None
                    if not skip_diagram:
                        try:
                            existing_diagram = tmi_client.find_diagram_by_name(
                                threat_model_id, diagram_name
                            )
                            if existing_diagram:
                                raw_id = existing_diagram.id
                                diagram_id_for_threats = str(raw_id) if raw_id else None
                        except Exception as e:
                            logger.warning(f"Could not get diagram ID: {e}")

                    sec_input = sum(
                        a.security_input_tokens for a in analyses if a.success
                    )
                    sec_output = sum(
                        a.security_output_tokens for a in analyses if a.success
                    )
                    sec_cost = sum(a.security_cost for a in analyses if a.success)
                    threat_metadata = create_artifact_metadata(
                        provider=llm_analyzer.provider,
                        model=llm_analyzer.model,
                        input_tokens=sec_input,
                        output_tokens=sec_output,
                        cost_estimate_usd=sec_cost,
                    )
                    created_threats = threat_processor.create_threats_in_tmi(
                        threats=all_threats,
                        threat_model_id=threat_model_id,
                        tmi_client=tmi_client,
                        diagram_id=diagram_id_for_threats,
                        metadata=threat_metadata.to_metadata_list(),
                    )
                    logger.info(
                        f"Successfully created {len(created_threats)} threats in TMI"
                    )
                else:
                    logger.info("No threats extracted from analyses")

            except Exception as e:
                logger.error(f"Failed to create threats: {e}")
                logger.info("Continuing without threat creation...")

        else:
            logger.info("\n[9/9] Skipping threat creation (skip_threats)")

        tmi_client.update_status_note(threat_model_id, "Analysis complete")
        logger.info("\n" + "=" * 80)
        logger.info("Analysis complete!")
        logger.info("=" * 80)

        return AnalysisResult(
            success=True,
            analyses=analyses,
            errors=errors,
            inventory_content=inventory_content,
            analysis_content=analysis_content,
        )

    except Exception as e:
        error_msg = f"Fatal error: {e}"
        logger.error(error_msg, exc_info=True)
        errors.append(error_msg)
        return AnalysisResult(success=False, errors=errors)
