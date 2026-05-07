"""Tests for the orchestration pipeline (with mocks for external commands)."""

import json
from unittest.mock import patch

import pytest

from sbom_unifier.config import UNIFIED_SBOM_FILENAME
from sbom_unifier.pipeline import run_pipeline


def _minimal_sbom(name: str, packages: list[dict] | None = None) -> dict:
    return {
        "spdxVersion": "SPDX-2.2",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": name,
        "creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": [f"Tool: {name}"]},
        "packages": packages or [],
        "files": [],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": packages[0]["SPDXID"] if packages else "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
            }
        ],
    }


@pytest.fixture
def mock_pipeline_externals(tmp_path):
    """Stub out clone and every tool's generate() so no external commands run."""
    output_root = tmp_path / "out"

    pkg = {
        "SPDXID": "SPDXRef-Pkg-A",
        "name": "a",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": "pkg:pypi/a@1.0",
            }
        ],
    }

    def fake_clone(url, clone_dir):
        repo = clone_dir / "repo"
        repo.mkdir(parents=True, exist_ok=True)
        (repo / "main.py").write_text("# nothing\n")
        return True

    def fake_sbom_tool(*, repo_path, output_dir, owner, repo_name, **_):
        sub = output_dir / "_manifest" / "spdx_2.2"
        sub.mkdir(parents=True, exist_ok=True)
        (sub / "manifest.spdx.json").write_text(json.dumps(_minimal_sbom("sbom-tool", [pkg])))
        return True

    def fake_syft(*, repo_path, output_dir, **_):
        (output_dir / "syft-sbom.json").write_text(json.dumps(_minimal_sbom("syft", [pkg])))
        return True

    def fake_trivy(*, repo_path, output_dir, **_):
        (output_dir / "trivy-sbom.json").write_text(json.dumps(_minimal_sbom("trivy", [pkg])))
        return True

    def fake_github(*, output_dir, owner, repo_name, github_token, **_):
        return False  # no token in test

    with (
        patch("sbom_unifier.pipeline.clone_single_repository", side_effect=fake_clone),
        patch("sbom_unifier.tools.sbom_tool.generate", side_effect=fake_sbom_tool),
        patch("sbom_unifier.tools.syft.generate", side_effect=fake_syft),
        patch("sbom_unifier.tools.trivy.generate", side_effect=fake_trivy),
        patch("sbom_unifier.tools.github.generate", side_effect=fake_github),
        patch("sbom_unifier.enrichment.ninka.subprocess.run") as mock_ninka,
    ):
        mock_ninka.return_value.returncode = 1  # ninka unavailable -> NOASSERTION
        yield {"output_root": output_root, "url": "https://github.com/test/repo"}


def test_run_pipeline_writes_unified_sbom(mock_pipeline_externals):
    success = run_pipeline(
        url=mock_pipeline_externals["url"],
        output_root=mock_pipeline_externals["output_root"],
    )
    assert success is True
    out = mock_pipeline_externals["output_root"] / "repo" / UNIFIED_SBOM_FILENAME
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["spdxVersion"] == "SPDX-2.3"


def test_run_pipeline_handles_invalid_url(tmp_path):
    success = run_pipeline(url="not-a-url", output_root=tmp_path)
    assert success is False


def test_run_pipeline_manual_as_base(mock_pipeline_externals, tmp_path):
    """Pipeline should not crash when manual (custom SBOM) is chosen as base."""
    import json as _json

    pkg = {
        "SPDXID": "SPDXRef-Custom-Pkg",
        "name": "custom",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": "pkg:pypi/custom@2.0",
            }
        ],
    }
    custom_sbom = {
        "spdxVersion": "SPDX-2.2",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "custom-base",
        "creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: manual"]},
        "packages": [pkg],
        "files": [],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": "SPDXRef-Custom-Pkg",
                "relationshipType": "DESCRIBES",
            }
        ],
    }
    custom_path = tmp_path / "custom-sbom.json"
    custom_path.write_text(_json.dumps(custom_sbom))

    success = run_pipeline(
        url=mock_pipeline_externals["url"],
        base_tool="manual",
        custom_sbom_path=str(custom_path),
        output_root=mock_pipeline_externals["output_root"],
    )
    assert success is True
    out = mock_pipeline_externals["output_root"] / "repo" / UNIFIED_SBOM_FILENAME
    assert out.exists()
    data = _json.loads(out.read_text())
    assert data["spdxVersion"] == "SPDX-2.3"
