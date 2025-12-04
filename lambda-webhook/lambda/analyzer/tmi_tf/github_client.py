"""GitHub API client for repository metadata."""

import logging
from typing import Optional
from urllib.parse import urlparse

from github import Auth, Github, GithubException
from github.Repository import Repository

from tmi_tf.config import Config

logger = logging.getLogger(__name__)


class GitHubClient:
    """GitHub API client wrapper."""

    def __init__(self, config: Config):
        """
        Initialize GitHub client.

        Args:
            config: Application configuration
        """
        self.config = config

        # Initialize GitHub client
        if config.github_token:
            auth = Auth.Token(config.github_token)
            self.github = Github(auth=auth)
            logger.info("GitHub client initialized with authentication")
        else:
            self.github = Github()
            logger.warning(
                "GitHub client initialized without authentication - rate limits apply"
            )

    def get_repository_info(self, repo_url: str) -> Optional[Repository]:
        """
        Get repository information from GitHub API.

        Args:
            repo_url: GitHub repository URL

        Returns:
            GitHub Repository object, or None if not found/error
        """
        owner, repo_name = self._parse_github_url(repo_url)
        if not owner or not repo_name:
            logger.warning(f"Could not parse GitHub URL: {repo_url}")
            return None

        try:
            repo = self.github.get_repo(f"{owner}/{repo_name}")
            logger.info(
                f"Retrieved GitHub repo info: {repo.full_name} "
                f"(size: {repo.size}KB, stars: {repo.stargazers_count})"
            )
            return repo
        except GithubException as e:
            logger.error(f"Failed to get GitHub repo {owner}/{repo_name}: {e}")
            return None

    def check_has_terraform_files(self, repo_url: str) -> bool:
        """
        Check if repository contains Terraform files.

        Args:
            repo_url: GitHub repository URL

        Returns:
            True if repo likely contains .tf files
        """
        repo = self.get_repository_info(repo_url)
        if not repo:
            return False

        try:
            # Search for .tf files in the repo
            # Note: This requires authentication for private repos
            results = self.github.search_code(
                query=f"extension:tf repo:{repo.full_name}", per_page=1
            )
            has_tf_files = results.totalCount > 0
            logger.info(
                f"Terraform files in {repo.full_name}: "
                f"{'found' if has_tf_files else 'not found'}"
            )
            return has_tf_files
        except GithubException as e:
            logger.warning(
                f"Could not search for .tf files in {repo.full_name}: {e}. "
                f"Will attempt clone anyway."
            )
            # If search fails (e.g., rate limit, permissions), assume true
            # and let the clone operation determine
            return True

    def get_repository_size(self, repo_url: str) -> Optional[int]:
        """
        Get repository size in KB.

        Args:
            repo_url: GitHub repository URL

        Returns:
            Repository size in KB, or None if not available
        """
        repo = self.get_repository_info(repo_url)
        return repo.size if repo else None

    def is_github_url(self, url: str) -> bool:
        """
        Check if URL is a GitHub repository URL.

        Args:
            url: Repository URL

        Returns:
            True if URL is a GitHub URL
        """
        try:
            parsed = urlparse(url)
            return parsed.hostname in ["github.com", "www.github.com"]
        except Exception:
            return False

    @staticmethod
    def _parse_github_url(url: str) -> tuple[Optional[str], Optional[str]]:
        """
        Parse GitHub URL to extract owner and repository name.

        Args:
            url: GitHub repository URL

        Returns:
            Tuple of (owner, repo_name), or (None, None) if invalid
        """
        try:
            parsed = urlparse(url)
            path_parts = parsed.path.strip("/").split("/")

            if len(path_parts) >= 2:
                owner = path_parts[0]
                repo_name = path_parts[1].replace(".git", "")
                return owner, repo_name
            else:
                return None, None
        except Exception as e:
            logger.error(f"Failed to parse GitHub URL {url}: {e}")
            return None, None

    def get_rate_limit_info(self) -> dict:
        """
        Get current GitHub API rate limit information.

        Returns:
            Dictionary with rate limit info
        """
        try:
            rate_limit = self.github.get_rate_limit()
            core = rate_limit.core
            return {
                "limit": core.limit,
                "remaining": core.remaining,
                "reset": core.reset.isoformat(),
            }
        except GithubException as e:
            logger.error(f"Failed to get rate limit info: {e}")
            return {"limit": 0, "remaining": 0, "reset": "unknown"}
