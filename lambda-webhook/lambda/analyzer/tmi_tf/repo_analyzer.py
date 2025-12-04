"""Repository cloning and Terraform file extraction."""

import logging
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import List, Optional


from tmi_tf.config import Config

logger = logging.getLogger(__name__)


class TerraformRepository:
    """Represents a cloned repository with Terraform files."""

    def __init__(
        self,
        name: str,
        url: str,
        clone_path: Path,
        terraform_files: List[Path],
        documentation_files: List[Path],
    ):
        """
        Initialize Terraform repository.

        Args:
            name: Repository name
            url: Repository URL
            clone_path: Local clone path
            terraform_files: List of .tf file paths
            documentation_files: List of documentation file paths
        """
        self.name = name
        self.url = url
        self.clone_path = clone_path
        self.terraform_files = terraform_files
        self.documentation_files = documentation_files

    def get_terraform_content(self) -> dict[str, str]:
        """
        Get content of all Terraform files.

        Returns:
            Dictionary mapping relative file paths to content
        """
        content = {}
        for tf_file in self.terraform_files:
            try:
                relative_path = tf_file.relative_to(self.clone_path)
                content[str(relative_path)] = tf_file.read_text(encoding="utf-8")
            except Exception as e:
                logger.warning(f"Failed to read {tf_file}: {e}")
        return content

    def get_documentation_content(self) -> dict[str, str]:
        """
        Get content of all documentation files.

        Returns:
            Dictionary mapping relative file paths to content
        """
        content = {}
        for doc_file in self.documentation_files:
            try:
                relative_path = doc_file.relative_to(self.clone_path)
                content[str(relative_path)] = doc_file.read_text(encoding="utf-8")
            except Exception as e:
                logger.warning(f"Failed to read {doc_file}: {e}")
        return content

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"TerraformRepository(name={self.name}, "
            f"tf_files={len(self.terraform_files)}, "
            f"docs={len(self.documentation_files)})"
        )


class RepositoryAnalyzer:
    """Handles cloning and analysis of repositories."""

    def __init__(self, config: Config):
        """
        Initialize repository analyzer.

        Args:
            config: Application configuration
        """
        self.config = config

    @contextmanager
    def clone_repository_sparse(self, repo_url: str, repo_name: str):
        """
        Clone repository with sparse checkout for Terraform and documentation files.

        Args:
            repo_url: Repository URL
            repo_name: Repository name (for logging)

        Yields:
            TerraformRepository object or None if no Terraform files found

        Raises:
            Exception: If clone fails
        """
        temp_dir = Path(tempfile.mkdtemp(prefix=f"tmi-tf-{repo_name}-"))
        logger.info(f"Cloning {repo_name} to {temp_dir}")

        try:
            # Clone with sparse checkout
            terraform_repo = self._sparse_clone(repo_url, temp_dir, repo_name)

            if terraform_repo and len(terraform_repo.terraform_files) > 0:
                logger.info(
                    f"Successfully cloned {repo_name} with "
                    f"{len(terraform_repo.terraform_files)} Terraform files"
                )
                yield terraform_repo
            else:
                logger.warning(f"No Terraform files found in {repo_name}")
                yield None

        except Exception as e:
            logger.error(f"Failed to clone {repo_name}: {e}")
            raise

        finally:
            # Cleanup
            try:
                shutil.rmtree(temp_dir)
                logger.debug(f"Cleaned up temp directory: {temp_dir}")
            except Exception as e:
                logger.warning(f"Failed to cleanup {temp_dir}: {e}")

    def _sparse_clone(
        self, repo_url: str, clone_path: Path, repo_name: str
    ) -> Optional[TerraformRepository]:
        """
        Perform sparse clone to get only Terraform and documentation files.

        Args:
            repo_url: Repository URL
            clone_path: Local path to clone to
            repo_name: Repository name

        Returns:
            TerraformRepository object or None if no files found
        """
        try:
            # Initialize repo
            subprocess.run(
                ["git", "init"],
                cwd=clone_path,
                check=True,
                capture_output=True,
                timeout=30,
            )

            # Add remote
            subprocess.run(
                ["git", "remote", "add", "origin", repo_url],
                cwd=clone_path,
                check=True,
                capture_output=True,
                timeout=30,
            )

            # Enable sparse checkout
            subprocess.run(
                ["git", "config", "core.sparseCheckout", "true"],
                cwd=clone_path,
                check=True,
                capture_output=True,
                timeout=30,
            )

            # Set sparse checkout patterns
            sparse_checkout_file = clone_path / ".git" / "info" / "sparse-checkout"
            patterns = [
                "*.tf",
                "*.tfvars",
                "*.md",
                "README*",
                "LICENSE*",
                "*.txt",
            ]
            sparse_checkout_file.write_text("\n".join(patterns))

            # Pull with timeout
            logger.info(
                f"Pulling repository content (timeout: {self.config.clone_timeout}s)"
            )
            subprocess.run(
                ["git", "pull", "--depth=1", "origin", "HEAD"],
                cwd=clone_path,
                check=True,
                capture_output=True,
                timeout=self.config.clone_timeout,
            )

            # Find Terraform files
            terraform_files = list(clone_path.rglob("*.tf"))
            terraform_files.extend(clone_path.rglob("*.tfvars"))

            # Find documentation files
            doc_files = list(clone_path.rglob("*.md"))
            doc_files.extend(clone_path.rglob("README*"))
            doc_files.extend(clone_path.rglob("LICENSE*"))

            if not terraform_files:
                logger.warning(f"No Terraform files found in {repo_name}")
                return None

            return TerraformRepository(
                name=repo_name,
                url=repo_url,
                clone_path=clone_path,
                terraform_files=terraform_files,
                documentation_files=doc_files,
            )

        except subprocess.TimeoutExpired:
            logger.error(
                f"Clone timeout for {repo_name} after {self.config.clone_timeout}s"
            )
            raise
        except subprocess.CalledProcessError as e:
            logger.error(f"Git command failed for {repo_name}: {e.stderr.decode()}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error cloning {repo_name}: {e}")
            raise

    def extract_repository_name(self, repo_url: str) -> str:
        """
        Extract repository name from URL.

        Args:
            repo_url: Repository URL

        Returns:
            Repository name
        """
        # Extract from URL like https://github.com/owner/repo.git
        parts = repo_url.rstrip("/").rstrip(".git").split("/")
        if len(parts) >= 2:
            return f"{parts[-2]}_{parts[-1]}"
        return "unknown_repo"

    def should_analyze_repository(
        self, repo_url: str, max_size_kb: int = 500000
    ) -> tuple[bool, str]:
        """
        Determine if repository should be analyzed based on size and other criteria.

        Args:
            repo_url: Repository URL
            max_size_kb: Maximum repository size in KB

        Returns:
            Tuple of (should_analyze: bool, reason: str)
        """
        # For PoC, we'll be optimistic and analyze most repos
        # In production, you could query GitHub API for size first

        if not repo_url:
            return False, "Empty URL"

        if not repo_url.startswith(("http://", "https://", "git@")):
            return False, "Invalid URL format"

        return True, "OK"
