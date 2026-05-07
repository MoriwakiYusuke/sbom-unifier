"""Post-merge SBOM enrichment.

High-level entry point: ``enrich_sbom``.
Granular APIs: ``enrich_with_file_types`` and ``enrich_with_ninka``.
"""

from __future__ import annotations

from .file_types import enrich_with_file_types
from .ninka import enrich_with_ninka

__all__ = ["enrich_sbom", "enrich_with_file_types", "enrich_with_ninka"]


def enrich_sbom(base_data: dict, repo_root: str | None = None) -> dict:
    """Run all enrichment passes.

    - file_types: always run (only needs SBOM data)
    - ninka: run only when repo_root is provided (needs source files)
    """
    results: dict = {"file_types_added": enrich_with_file_types(base_data)}
    if repo_root:
        results.update(enrich_with_ninka(base_data, repo_root))
    return results
