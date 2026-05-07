"""Paths and immutable constants. Single source of truth.

The set of available SBOM source tools and their filenames lives in
sbom_unifier.tools.registry, not here.
"""

from __future__ import annotations

from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_OUTPUT_DIR = PACKAGE_DIR / "output"

# Output filename of the final unified SBOM.
UNIFIED_SBOM_FILENAME = "unified_sbom.json"

# SPDX target version stamped on the unified output.
TARGET_SPDX_VERSION = "SPDX-2.3"

# Identity string used in creationInfo.creators and annotation annotators.
# Downstream tooling that filters unified SBOMs by this value must update accordingly.
SCRIPT_CREATOR = "Tool: SBOM unifier"


def get_project_paths(project_name: str, output_root: Path | None = None) -> dict[str, Path]:
    """Return all standard output paths for a single project run."""
    root = output_root or DEFAULT_OUTPUT_DIR
    project_dir = root / project_name
    return {
        "project_dir": project_dir,
        "clone_dir": project_dir / "cloned",
        "repo_path": project_dir / "cloned" / project_name,
        "sbom_dir": project_dir,
        "analysis_dir": project_dir / "analysis",
    }
