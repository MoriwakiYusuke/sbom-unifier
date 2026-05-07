"""Tests for analyzer."""

import json
from pathlib import Path

from sbom_unifier.analyze import analyze_project


def _minimal_sbom() -> dict:
    return {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "x",
        "creationInfo": {"created": "2024-01-01T00:00:00Z", "creators": ["Tool: test"]},
        "packages": [
            {
                "SPDXID": "SPDXRef-Pkg-A",
                "name": "a",
                "versionInfo": "1.0",
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": "MIT",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "filesAnalyzed": False,
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:pypi/a@1.0",
                    }
                ],
            }
        ],
        "files": [],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": "SPDXRef-Pkg-A",
                "relationshipType": "DESCRIBES",
            }
        ],
    }


def test_analyze_project_writes_csv(tmp_path: Path):
    sbom_dir = tmp_path / "p"
    sbom_dir.mkdir()
    # syft and trivy and the unified output go into project dir
    (sbom_dir / "syft-sbom.json").write_text(json.dumps(_minimal_sbom()))
    (sbom_dir / "unified_sbom.json").write_text(json.dumps(_minimal_sbom()))

    output_csv = tmp_path / "out.csv"
    result = analyze_project(project_path=str(sbom_dir), output_path=str(output_csv))
    assert output_csv.exists()
    assert result is not None
