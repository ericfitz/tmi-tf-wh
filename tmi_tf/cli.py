"""Command-line interface for TMI Terraform Analysis Tool."""

import logging
import sys
from typing import Optional

import click

from tmi_tf.analysis_comparer import AnalysisComparer
from tmi_tf.artifact_metadata import aggregate_analysis_metadata
from tmi_tf.comparison_markdown_generator import ComparisonMarkdownGenerator
from tmi_tf.config import get_config
from tmi_tf.llm_analyzer import LLMAnalyzer
from tmi_tf.dfd_llm_generator import DFDLLMGenerator
from tmi_tf.diagram_builder import DFDBuilder
from tmi_tf.github_client import GitHubClient
from tmi_tf.markdown_generator import MarkdownGenerator
from tmi_tf.repo_analyzer import RepositoryAnalyzer
from tmi_tf.threat_processor import ThreatProcessor
from tmi_tf.tmi_client_wrapper import TMIClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)

logger = logging.getLogger(__name__)


def _cli_impl() -> None:
    """TMI Terraform Analysis Tool - Analyze infrastructure code for threat modeling."""
    pass


# Apply Click decorators and cast to Group for proper type hints
cli: click.Group = click.version_option(version="0.1.0")(
    click.group()(_cli_impl)
)


@cli.command()
@click.argument("threat_model_id")
@click.option(
    "--max-repos",
    type=int,
    default=None,
    help="Maximum number of repositories to analyze (default: from config)",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Analyze but don't create note in TMI (save to file instead)",
)
@click.option(
    "--output",
    type=click.Path(),
    default=None,
    help="Save markdown output to file (in addition to or instead of TMI note)",
)
@click.option(
    "--force-auth", is_flag=True, help="Force new authentication (ignore cached token)"
)
@click.option("--verbose", is_flag=True, help="Enable verbose logging")
@click.option(
    "--skip-diagram",
    is_flag=True,
    help="Skip generating data flow diagram",
)
@click.option(
    "--skip-threats",
    is_flag=True,
    help="Skip extracting and creating threat objects from security issues",
)
def analyze(
    threat_model_id: str,
    max_repos: Optional[int],
    dry_run: bool,
    output: Optional[str],
    force_auth: bool,
    verbose: bool,
    skip_diagram: bool,
    skip_threats: bool,
):
    """
    Analyze Terraform repositories for a threat model.

    THREAT_MODEL_ID: UUID of the threat model in TMI
    """
    # Set log level
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        logger.info("=" * 80)
        logger.info("TMI Terraform Analysis Tool")
        logger.info("=" * 80)

        # Load configuration
        config = get_config()
        if max_repos:
            config.max_repos = max_repos

        logger.info(f"Threat Model ID: {threat_model_id}")
        logger.info(f"Max Repositories: {config.max_repos}")
        logger.info(f"TMI Server: {config.tmi_server_url}")

        # Initialize clients
        logger.info("\n[1/7] Initializing clients...")
        tmi_client = TMIClient.create_authenticated(config, force_refresh=force_auth)
        github_client = GitHubClient(config)
        repo_analyzer = RepositoryAnalyzer(config)
        llm_analyzer = LLMAnalyzer(config)
        markdown_gen = MarkdownGenerator()

        # Get threat model
        logger.info("\n[2/7] Fetching threat model...")
        threat_model = tmi_client.get_threat_model(threat_model_id)
        logger.info(f"Threat Model: {threat_model.name}")

        # Get repositories
        logger.info("\n[3/7] Fetching repositories...")
        repositories = tmi_client.get_threat_model_repositories(threat_model_id)
        logger.info(f"Found {len(repositories)} total repositories")

        # Filter for GitHub repos with Terraform
        github_repos = [
            repo for repo in repositories if github_client.is_github_url(repo.uri)
        ]
        logger.info(f"GitHub repositories: {len(github_repos)}")

        if not github_repos:
            logger.error("No GitHub repositories found in threat model")
            sys.exit(1)

        # Limit number of repos
        repos_to_analyze = github_repos[: config.max_repos]
        if len(github_repos) > config.max_repos:
            logger.warning(
                f"Limiting analysis to {config.max_repos} of {len(github_repos)} repositories"
            )

        # Analyze repositories
        logger.info(f"\n[4/7] Analyzing {len(repos_to_analyze)} repositories...")
        analyses = []

        for i, repo in enumerate(repos_to_analyze, 1):
            logger.info(
                f"\n--- Repository {i}/{len(repos_to_analyze)}: {repo.name} ---"
            )
            logger.info(f"URL: {repo.uri}")

            try:
                # Clone repository
                repo_name = repo_analyzer.extract_repository_name(repo.uri)
                with repo_analyzer.clone_repository_sparse(
                    repo.uri, repo_name
                ) as tf_repo:
                    if tf_repo:
                        # Analyze with Claude
                        analysis = llm_analyzer.analyze_repository(tf_repo)
                        analyses.append(analysis)
                    else:
                        logger.warning(
                            f"Skipping {repo.name} - no Terraform files found"
                        )

            except Exception as e:
                logger.error(f"Failed to analyze {repo.name}: {e}")
                # Continue with other repos
                continue

        if not analyses:
            logger.error("No repositories were successfully analyzed")
            sys.exit(1)

        logger.info(f"\n[5/7] Successfully analyzed {len(analyses)} repositories")

        # Generate markdown report
        logger.info("\n[6/7] Generating markdown report...")
        markdown_content = markdown_gen.generate_report(
            threat_model_name=threat_model.name,
            threat_model_id=threat_model_id,
            analyses=analyses,
        )

        # Save to file if requested
        if output:
            markdown_gen.save_to_file(markdown_content, output)
            logger.info(f"Report saved to: {output}")

        # Create note in TMI
        if not dry_run:
            logger.info("\n[7/7] Creating note in TMI...")
            note = tmi_client.create_or_update_note(
                threat_model_id=threat_model_id,
                name=config.analysis_note_name,
                content=markdown_content,
                description=f"Automated analysis of {len(analyses)} Terraform repositories",
            )
            logger.info(f"Note created/updated successfully: {note.id}")
            logger.info(f"Note name: {note.name}")

            # Add metadata to the note
            artifact_metadata = aggregate_analysis_metadata(
                analyses=analyses,
                provider=llm_analyzer.provider,
                model=llm_analyzer.model,
            )
            try:
                tmi_client.set_note_metadata(
                    threat_model_id=threat_model_id,
                    note_id=note.id,
                    metadata=artifact_metadata.to_metadata_list(),
                )
                logger.info("Note metadata set successfully")
            except Exception as e:
                logger.warning(f"Failed to set note metadata: {e}")
        else:
            logger.info("\n[7/7] Dry run - skipping note creation")
            if not output:
                # Print to stdout if no output file specified
                print("\n" + "=" * 80)
                print("GENERATED MARKDOWN REPORT")
                print("=" * 80 + "\n")
                print(markdown_content)

        # Generate and create data flow diagram
        if not skip_diagram and not dry_run:
            logger.info("\n[8/7] Generating data flow diagram...")
            try:
                # Initialize DFD generator
                dfd_generator = DFDLLMGenerator(config=config)

                # Generate structured data from the analysis
                structured_data = dfd_generator.generate_structured_components(
                    markdown_content
                )

                if structured_data:
                    # Build diagram cells
                    builder = DFDBuilder(
                        components=structured_data["components"],
                        flows=structured_data["flows"],
                    )
                    cells = builder.build_cells()

                    # Create or update diagram in TMI
                    diagram = tmi_client.create_or_update_diagram(
                        threat_model_id=threat_model_id,
                        name=config.diagram_name,
                        cells=cells,
                    )
                    # Handle both dict and object responses
                    diagram_id = (
                        diagram["id"] if isinstance(diagram, dict) else diagram.id
                    )
                    logger.info(f"Diagram created/updated successfully: {diagram_id}")
                    logger.info(f"Diagram contains {len(cells)} cells")

                    # Add metadata to the diagram
                    diagram_metadata = aggregate_analysis_metadata(
                        analyses=analyses,
                        provider=dfd_generator.provider,
                        model=dfd_generator.model,
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
                # Don't fail the entire analysis if diagram generation fails
                logger.error(f"Failed to generate diagram: {e}")
                logger.info("Continuing without diagram...")

        elif skip_diagram:
            logger.info("\n[8/7] Skipping diagram generation (--skip-diagram)")

        # Create threats from security issues
        if not skip_threats and not dry_run:
            logger.info(
                "\n[9/7] Extracting and creating threats from security issues..."
            )
            try:
                threat_processor = ThreatProcessor(config)
                all_threats = []

                # Extract threats from each successful analysis
                for analysis in analyses:
                    if analysis.success:
                        threats = threat_processor.extract_threats_from_analysis(
                            analysis.analysis_content, analysis.repo_name
                        )
                        all_threats.extend(threats)

                logger.info(f"Extracted {len(all_threats)} total threats from analyses")

                if all_threats:
                    # Get diagram_id if diagram was created
                    diagram_id = None
                    if not skip_diagram:
                        try:
                            existing_diagram = tmi_client.find_diagram_by_name(
                                threat_model_id, config.diagram_name
                            )
                            if existing_diagram:
                                raw_id = existing_diagram.id if hasattr(existing_diagram, 'id') else existing_diagram.get("id")  # type: ignore[union-attr]
                                diagram_id = str(raw_id) if raw_id else None
                        except Exception as e:
                            logger.warning(f"Could not get diagram ID: {e}")

                    # Create threats in TMI with metadata
                    threat_metadata = aggregate_analysis_metadata(
                        analyses=analyses,
                        provider=threat_processor.provider,
                        model=threat_processor.model,
                    )
                    created_threats = threat_processor.create_threats_in_tmi(
                        threats=all_threats,
                        threat_model_id=threat_model_id,
                        tmi_client=tmi_client,
                        diagram_id=diagram_id,
                        metadata=threat_metadata.to_metadata_list(),
                    )
                    logger.info(
                        f"Successfully created {len(created_threats)} threats in TMI"
                    )
                else:
                    logger.info("No threats extracted from analyses")

            except Exception as e:
                # Don't fail the entire analysis if threat creation fails
                logger.error(f"Failed to create threats: {e}")
                logger.info("Continuing without threat creation...")

        elif skip_threats:
            logger.info("\n[9/7] Skipping threat creation (--skip-threats)")
        elif dry_run:
            logger.info("\n[9/7] Dry run - skipping threat creation")

        logger.info("\n" + "=" * 80)
        logger.info("Analysis complete!")
        logger.info("=" * 80)

    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


@cli.command()
def auth():
    """Authenticate with TMI server (or refresh authentication)."""
    try:
        logger.info("Authenticating with TMI server...")
        config = get_config()
        TMIClient.create_authenticated(config, force_refresh=True)
        logger.info("Authentication successful!")
        logger.info("Token cached for future use.")
    except Exception as e:
        logger.error(f"Authentication failed: {e}")
        sys.exit(1)


@cli.command()
@click.argument("threat_model_id")
def list_repos(threat_model_id: str):
    """List all repositories in a threat model."""
    try:
        config = get_config()
        tmi_client = TMIClient.create_authenticated(config)

        threat_model = tmi_client.get_threat_model(threat_model_id)
        print(f"\nThreat Model: {threat_model.name}")
        print(f"ID: {threat_model_id}\n")

        repositories = tmi_client.get_threat_model_repositories(threat_model_id)
        github_client = GitHubClient(config)

        print(f"Total Repositories: {len(repositories)}")
        print("\nRepositories:")
        print("-" * 80)

        for i, repo in enumerate(repositories, 1):
            is_github = github_client.is_github_url(repo.uri)
            print(f"{i}. {repo.name}")
            print(f"   URL: {repo.uri}")
            print(f"   Type: {repo.type if hasattr(repo, 'type') else 'unknown'}")
            print(f"   GitHub: {'Yes' if is_github else 'No'}")
            print()

    except Exception as e:
        logger.error(f"Failed to list repositories: {e}")
        sys.exit(1)


@cli.command()
def clear_auth():
    """Clear cached authentication token."""
    try:
        config = get_config()
        from tmi_tf.auth import TokenCache

        cache = TokenCache(config.token_cache_file)
        cache.clear_token()
        logger.info("Authentication token cleared")
    except Exception as e:
        logger.error(f"Failed to clear token: {e}")
        sys.exit(1)


@cli.command()
def config_info():
    """Display current configuration."""
    try:
        config = get_config()
        print("\nConfiguration:")
        print("-" * 80)
        print(f"TMI Server URL: {config.tmi_server_url}")
        print(f"OAuth IDP: {config.tmi_oauth_idp}")
        print(f"Max Repositories: {config.max_repos}")
        print(f"Clone Timeout: {config.clone_timeout}s")
        print(f"Note Name: {config.analysis_note_name}")
        print(f"Diagram Name: {config.diagram_name}")
        print(
            f"GitHub Token: {'Configured' if config.github_token else 'Not configured'}"
        )
        print(
            f"Anthropic API Key: {'Configured' if config.anthropic_api_key else 'Not configured'}"
        )
        print(f"Cache Directory: {config.cache_dir}")
        print()
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)


@cli.command()
@click.argument("threat_model_id")
@click.option(
    "--dry-run",
    is_flag=True,
    help="Compare but don't create note in TMI (save to file instead)",
)
@click.option(
    "--output",
    type=click.Path(),
    default=None,
    help="Save markdown output to file (in addition to or instead of TMI note)",
)
@click.option(
    "--force-auth", is_flag=True, help="Force new authentication (ignore cached token)"
)
@click.option("--verbose", is_flag=True, help="Enable verbose logging")
def compare(
    threat_model_id: str,
    dry_run: bool,
    output: Optional[str],
    force_auth: bool,
    verbose: bool,
):
    """
    Compare analysis notes from different LLM models.

    THREAT_MODEL_ID: UUID of the threat model in TMI

    This command discovers all analysis notes matching 'Terraform Analysis Report (*)'
    for the specified threat model and generates a comparison report showing:
    - Infrastructure components discovered by each model
    - Relationships and dependencies
    - Data flows
    - Security observations

    The comparison uses LLM-assisted semantic matching to normalize discoveries
    across different model outputs.
    """
    # Set log level
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        logger.info("=" * 80)
        logger.info("TMI Terraform Analysis Tool - Compare")
        logger.info("=" * 80)

        # Load configuration
        config = get_config()
        logger.info(f"Threat Model ID: {threat_model_id}")
        logger.info(f"TMI Server: {config.tmi_server_url}")

        # Step 1: Initialize clients
        logger.info("\n[1/6] Initializing clients...")
        tmi_client = TMIClient.create_authenticated(config, force_refresh=force_auth)
        comparer = AnalysisComparer(config)
        markdown_gen = ComparisonMarkdownGenerator()

        # Step 2: Fetch threat model
        logger.info("\n[2/6] Fetching threat model...")
        threat_model = tmi_client.get_threat_model(threat_model_id)
        logger.info(f"Threat Model: {threat_model.name}")

        # Step 3: Discover analysis notes
        logger.info("\n[3/6] Discovering analysis notes...")
        analysis_notes = comparer.discover_analysis_notes(tmi_client, threat_model_id)

        if len(analysis_notes) < 2:
            logger.error(
                f"Found {len(analysis_notes)} analysis notes. "
                "Need at least 2 notes to compare."
            )
            logger.info(
                "Run 'tmi-tf analyze' with different LLM providers to create more analysis notes."
            )
            sys.exit(1)

        logger.info(f"Found {len(analysis_notes)} analysis notes to compare")
        for note in analysis_notes:
            logger.info(f"  - {note.name}")

        # Step 4: Parse and compare analyses
        logger.info("\n[4/6] Parsing and comparing analyses...")
        parsed_analyses = []

        for note in analysis_notes:
            model_name = comparer.parser.extract_model_from_note_name(note.name)
            if model_name:
                parsed = comparer.parser.parse_note(
                    note_content=note.content,
                    model_name=model_name,
                    note_id=note.id,
                    note_name=note.name,
                )
                parsed_analyses.append(parsed)
                logger.info(
                    f"  Parsed {model_name}: "
                    f"{len(parsed.infrastructure_items)} infrastructure, "
                    f"{len(parsed.relationships)} relationships, "
                    f"{len(parsed.data_flows)} data flows, "
                    f"{len(parsed.security_observations)} security"
                )

        if len(parsed_analyses) < 2:
            logger.error("Could not parse enough analysis notes for comparison")
            sys.exit(1)

        # Run comparison
        logger.info("\n[5/6] Running comparison with LLM normalization...")
        comparison_result = comparer.compare_analyses(parsed_analyses)

        logger.info("Comparison complete:")
        logger.info(f"  - Total unique discoveries: {comparison_result.total_unique_discoveries}")
        logger.info(f"  - Agreement rate: {comparison_result.agreement_rate:.1f}%")

        # Step 5: Generate markdown report
        logger.info("\n[6/6] Generating comparison report...")
        markdown_content = markdown_gen.generate_report(
            comparison=comparison_result,
            threat_model_name=threat_model.name,
            threat_model_id=threat_model_id,
        )

        # Save to file if requested
        if output:
            markdown_gen.save_to_file(markdown_content, output)
            logger.info(f"Report saved to: {output}")

        # Create note in TMI
        if not dry_run:
            from datetime import datetime

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
            note_name = f"Terraform Analysis Comparison ({timestamp})"

            note = tmi_client.create_or_update_note(
                threat_model_id=threat_model_id,
                name=note_name,
                content=markdown_content,
                description=f"Comparison of {len(parsed_analyses)} analysis notes from different LLM models",
            )
            logger.info(f"Comparison note created: {note.id}")
            logger.info(f"Note name: {note.name}")
        else:
            logger.info("Dry run - skipping note creation")
            if not output:
                # Print to stdout if no output file specified
                print("\n" + "=" * 80)
                print("COMPARISON REPORT")
                print("=" * 80 + "\n")
                print(markdown_content)

        logger.info("\n" + "=" * 80)
        logger.info("Comparison complete!")
        logger.info("=" * 80)

    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
