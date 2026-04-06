"""Command-line interface for TMI Terraform Analysis Tool."""

import logging
import sys
from typing import Optional

import click  # pyright: ignore[reportMissingImports]  # ty:ignore[unresolved-import]

from tmi_tf.analyzer import AnalysisResult, run_analysis
from tmi_tf.config import get_config
from tmi_tf.markdown_generator import MarkdownGenerator
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
cli: click.Group = click.version_option(version="0.1.0")(click.group()(_cli_impl))


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
@click.option(
    "--environment",
    "-e",
    type=str,
    default=None,
    help="Pre-select a Terraform environment by name (skip interactive prompt)",
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
    environment: Optional[str],
):
    """
    Analyze Terraform repositories for a threat model.

    THREAT_MODEL_ID: UUID of the threat model in TMI
    """
    # Set log level
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        # Load configuration
        config = get_config()
        if max_repos:
            config.max_repos = max_repos

        # Initialize TMI client (CLI handles auth concerns)
        tmi_client = TMIClient.create_authenticated(config, force_refresh=force_auth)

        # In CLI mode with multiple environments and no --environment flag,
        # the user gets an interactive prompt.  We handle that here before
        # delegating to run_analysis which would analyse ALL environments.
        # If --environment is given we pass it through; if not, we need to
        # detect the interactive case ourselves.
        cli_environment = environment  # may be None

        if not environment and not dry_run:
            # Peek at environments to decide if we need an interactive prompt.
            # run_analysis will handle the actual analysis; we just need to
            # resolve the environment selection in the CLI layer.
            from tmi_tf.github_client import GitHubClient
            from tmi_tf.repo_analyzer import RepositoryAnalyzer

            _github_client = GitHubClient(config)
            _repo_analyzer = RepositoryAnalyzer(config)

            repositories = tmi_client.get_threat_model_repositories(threat_model_id)
            github_repos = [
                repo for repo in repositories if _github_client.is_github_url(repo.uri)
            ]
            for repo in github_repos[: config.max_repos]:
                repo_name = _repo_analyzer.extract_repository_name(repo.uri)
                with _repo_analyzer.clone_repository_sparse(
                    repo.uri, repo_name
                ) as tf_repo:
                    if tf_repo:
                        envs = RepositoryAnalyzer.detect_environments(
                            tf_repo.clone_path
                        )
                        if len(envs) > 1:
                            click.echo(f"\nFound {len(envs)} Terraform environments:")
                            for idx, env in enumerate(envs, 1):
                                click.echo(f"  {idx}. {env.name}")
                            choice = click.prompt(
                                "Select environment to analyze",
                                type=click.IntRange(1, len(envs)),
                            )
                            cli_environment = envs[choice - 1].name
                            break  # Only prompt once

        # Delegate to the shared analysis pipeline
        result: AnalysisResult = run_analysis(
            config=config,
            threat_model_id=threat_model_id,
            tmi_client=tmi_client,
            environment=cli_environment,
            skip_diagram=skip_diagram or dry_run,
            skip_threats=skip_threats or dry_run,
        )

        if not result.success:
            for err in result.errors:
                logger.error(err)
            sys.exit(1)

        # Save to files if requested
        if output:
            from pathlib import Path as _Path

            markdown_gen = MarkdownGenerator()
            out_path = _Path(output)
            stem = out_path.stem
            suffix = out_path.suffix or ".md"
            parent = out_path.parent
            inv_path = parent / f"{stem}-inventory{suffix}"
            analysis_path = parent / f"{stem}-analysis{suffix}"
            markdown_gen.save_to_file(result.inventory_content, str(inv_path))
            markdown_gen.save_to_file(result.analysis_content, str(analysis_path))
            logger.info(f"Inventory report saved to: {inv_path}")
            logger.info(f"Analysis report saved to: {analysis_path}")

        # Dry run: print reports to stdout
        if dry_run:
            if not output:
                print("\n" + "=" * 80)
                print("INVENTORY REPORT")
                print("=" * 80 + "\n")
                print(result.inventory_content)
                print("\n" + "=" * 80)
                print("ANALYSIS REPORT")
                print("=" * 80 + "\n")
                print(result.analysis_content)

    except click.Abort:
        logger.info("Analysis cancelled by user")
        sys.exit(0)
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
        from tmi_tf.github_client import GitHubClient

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
        print(f"LLM Provider: {config.llm_provider}")
        print(f"LLM Model: {config.llm_model or '(default)'}")
        print(f"Timestamp: {config.timestamp}")
        print(
            f"GitHub Token: {'Configured' if config.github_token else 'Not configured'}"
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
def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
