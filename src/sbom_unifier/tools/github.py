"""SBOM retrieval using the GitHub Dependency Graph API."""

import json
from pathlib import Path

import requests  # type: ignore[import-untyped]

from .registry import REGISTRY, ToolEntry

GITHUB_SBOM_FILENAME = "dependency-graph-sbom.json"
GITHUB_API_BASE = "https://api.github.com"
GITHUB_API_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


def fetch_sbom_for_repo(
    owner: str,
    repo_name: str,
    output_dir: Path,
    github_token: str | None = None,
) -> bool:
    """Fetch an SBOM from the GitHub Dependency Graph API for a single repository.

    Args:
        owner: Repository owner (user or organisation).
        repo_name: Repository name.
        output_dir: Destination directory for the retrieved SBOM file.
        github_token: GitHub personal access token.  Optional — public repos
            work without a token but are subject to the lower unauthenticated
            rate limit (60 req/hour).

    Returns:
        True on success, False on failure.
    """
    print(f"Fetching SBOM for: {owner}/{repo_name}")

    api_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}/dependency-graph/sbom"
    headers = GITHUB_API_HEADERS.copy()

    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    try:
        response = requests.get(api_url, headers=headers)

        if response.status_code == 200:
            print("API request successful.")
            sbom_data = response.json().get("sbom")

            if not sbom_data:
                print("Error: 'sbom' key not found in the API response.")
                return False

            output_dir.mkdir(parents=True, exist_ok=True)
            final_sbom_path = output_dir / GITHUB_SBOM_FILENAME
            print(f"   Writing SBOM to: {final_sbom_path}")

            with open(final_sbom_path, "w", encoding="utf-8") as f:
                json.dump(sbom_data, f, ensure_ascii=False, indent=2)

            print("SBOM file saved.")
            return True

        elif response.status_code == 404:
            print("Warning: Could not fetch SBOM. (Status: 404)")
            print("   The repository may not exist, or the Dependency Graph may not be enabled.")
            return False
        else:
            print(f"Error: Failed to fetch SBOM. Status code: {response.status_code}")
            print(f"   Response: {response.text}")
            return False

    except requests.exceptions.RequestException as e:
        print("Error: A network error occurred.")
        print(f"   Details: {e}")
        return False


def generate(
    *,
    output_dir: Path,
    owner: str,
    repo_name: str,
    github_token: str | None,
    **_: object,
) -> bool:
    """Fetch SBOM from GitHub Dependency Graph API."""
    if not github_token:
        print(
            "[github] GITHUB_TOKEN not set; proceeding without authentication. "
            "Public repos are accessible but rate limits apply (60 req/hour). "
            "Private repos will not be accessible."
        )
    return fetch_sbom_for_repo(
        owner=owner,
        repo_name=repo_name,
        output_dir=output_dir,
        github_token=github_token,
    )


TOOL = ToolEntry(
    name="github",
    label="GitHub Dependency Graph",
    output_filename="dependency-graph-sbom.json",
    generate=generate,
    can_be_base=True,
    default_merge_position=15,
    requires_token=True,
    description=(
        "GitHub REST dependency-graph SBOM. Works without a token for public "
        "repos (rate-limited); a read-scoped token enables private repos and "
        "raises the rate limit."
    ),
)

REGISTRY.register(TOOL)
