"""
Repository clone helpers.

Provides utilities for parsing GitHub URLs, extracting repo names,
removing .git directories, and cloning a single repository.
"""

import re
import shutil
import subprocess
from pathlib import Path


def parse_github_url(url: str) -> tuple[str, str] | None:
    """
    Extract owner and repository name from a GitHub URL.

    Args:
        url: GitHub repository URL.

    Returns:
        Tuple of (owner, repo_name), or None if the URL is not a GitHub URL
        or cannot be parsed.
    """
    match = re.search(r"github\.com/([^/]+)/([^/]+?)(?:\.git)?$", url)
    if match:
        owner, repo = match.groups()
        return owner, repo
    return None


def get_repo_name_from_url(url: str) -> str:
    """
    Extract the repository name from a URL.

    Args:
        url: Repository URL.

    Returns:
        Repository name (trailing .git suffix stripped if present).
    """
    return url.split("/")[-1].replace(".git", "")


def remove_git_directory(repo_path: Path) -> None:
    """
    Remove the .git directory from a cloned repository.

    Args:
        repo_path: Path to the cloned repository root.
    """
    git_dir = repo_path / ".git"
    if git_dir.exists():
        try:
            shutil.rmtree(git_dir)
            print(f"   Removed: {git_dir}")
        except OSError as e:
            print(f"   Error removing {git_dir}: {e}")


def clone_single_repository(url: str, clone_dir: Path) -> bool:
    """
    Clone a single repository into the given directory.

    If the target path already exists it is removed before cloning so that
    every run starts from a clean state.  After a successful clone the .git
    directory is also removed so that the working tree can be scanned without
    git metadata.

    Args:
        url: Repository URL to clone.
        clone_dir: Directory into which the repository will be cloned.

    Returns:
        True on success, False on failure.
    """
    repo_name = get_repo_name_from_url(url)
    repo_path = clone_dir / repo_name

    # Always remove any pre-existing target so every run starts fresh.
    if repo_path.exists():
        try:
            if repo_path.is_dir():
                shutil.rmtree(repo_path)
            else:
                repo_path.unlink()
            print(f"Removed existing path: {repo_path}")
        except OSError as e:
            print(f"Error removing existing path '{repo_path}': {e}")
            return False

    print(f"Cloning: {url}")

    try:
        process = subprocess.Popen(
            ["git", "clone", "--progress", url, repo_name],
            cwd=clone_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        # Stream stderr so the caller can see clone progress in real time.
        while process.poll() is None:
            if process.stderr is not None:
                line = process.stderr.readline()
                if line:
                    print(f"   {line.strip()}", end="\r")

        print(" " * 80, end="\r")  # Clear the progress line.

        if process.returncode == 0:
            print("Clone successful.")

            # Remove .git so the tree can be scanned cleanly.
            print(f"   Removing .git directory from '{repo_name}'...")
            remove_git_directory(repo_path)
            print("   .git directory removed.")
            return True
        else:
            stdout_err, stderr_err = process.communicate()
            error_message = stderr_err if stderr_err else stdout_err
            print(f"Error cloning. Reason: {error_message.strip()}")
            return False

    except FileNotFoundError:
        print("Error: 'git' command not found. Please install Git.")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False
