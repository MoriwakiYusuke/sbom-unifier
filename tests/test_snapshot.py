"""Snapshot test: full pipeline merge+enrich vs ground-truth unified SBOM."""

import shutil
from pathlib import Path
from unittest.mock import patch

import pytest

from sbom_unifier.config import UNIFIED_SBOM_FILENAME
from sbom_unifier.enrichment import enrich_sbom
from sbom_unifier.merge.merger import finalize_sbom, merge_sbom
from sbom_unifier.merge.utils import load_sbom_json, save_sbom_json
from sbom_unifier.tools.registry import REGISTRY

from .conftest import assert_snapshot

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "tiny-project"
INPUTS = FIXTURE_DIR / "inputs"
EXPECTED = FIXTURE_DIR / "expected" / "unified_sbom.json"


@pytest.fixture
def project_dir(tmp_path: Path) -> Path:
    """Lay out fixture inputs in the canonical project directory shape."""
    project = tmp_path / "tiny-project"
    project.mkdir()
    # sbom-tool base
    sub = project / "_manifest" / "spdx_2.2"
    sub.mkdir(parents=True)
    shutil.copy(INPUTS / "manifest.spdx.json", sub / "manifest.spdx.json")
    # other tools
    for fname in (
        "syft-sbom.json",
        "trivy-sbom.json",
        "dependency-graph-sbom.json",
        "custom-sbom.json",
    ):
        shutil.copy(INPUTS / fname, project / fname)
    return project


def _run_merge_pipeline(project_dir: Path) -> dict:
    """Invoke the merge+finalize+enrich path against the fixture."""
    base_path = project_dir / "_manifest" / "spdx_2.2" / "manifest.spdx.json"
    base = load_sbom_json(str(base_path))

    merge_order = [t.name for t in REGISTRY.default_merge_order()]
    for name in merge_order:
        if name == "sbom-tool":
            continue
        entry = REGISTRY.get(name)
        src_path = project_dir / entry.output_filename
        if not src_path.exists():
            continue
        merge_sbom(base, load_sbom_json(str(src_path)), name)

    finalize_sbom(base)

    # ninka unavailable in tests; only file_types runs
    with patch("sbom_unifier.enrichment.ninka.subprocess.run") as run:
        run.return_value.returncode = 1
        enrich_sbom(base, repo_root=None)

    return base


def test_unify_matches_ground_truth(project_dir):
    unified = _run_merge_pipeline(project_dir)
    save_sbom_json(unified, str(project_dir / UNIFIED_SBOM_FILENAME))
    assert_snapshot(unified, EXPECTED)
