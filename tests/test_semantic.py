"""Semantic invariant tests for the unified SBOM (B-type ground-truth checks)."""

import json
from pathlib import Path

import pytest

from sbom_unifier.config import SCRIPT_CREATOR, TARGET_SPDX_VERSION
from sbom_unifier.merge.utils import get_purl_from_package

FIXTURE_EXPECTED = (
    Path(__file__).parent / "fixtures" / "tiny-project" / "expected" / "unified_sbom.json"
)


@pytest.fixture
def unified() -> dict:
    return json.loads(FIXTURE_EXPECTED.read_text())


def test_spdx_version_is_target(unified):
    assert unified["spdxVersion"] == TARGET_SPDX_VERSION


def test_creators_includes_script_creator(unified):
    assert SCRIPT_CREATOR in unified["creationInfo"]["creators"]


def test_every_package_has_required_fields(unified):
    for pkg in unified["packages"]:
        assert pkg.get("SPDXID")
        assert pkg.get("name")
        assert "downloadLocation" in pkg


def test_no_duplicate_purls(unified):
    purls = []
    for pkg in unified["packages"]:
        purl = get_purl_from_package(pkg)
        if purl:
            purls.append(purl)
    assert len(purls) == len(set(purls)), "Duplicate PURLs detected"


def test_packages_added_from_other_tools(unified):
    purls = {get_purl_from_package(p) for p in unified["packages"] if get_purl_from_package(p)}
    assert "pkg:pypi/urllib3@2.2.0" in purls  # added by syft/trivy
    assert "pkg:pypi/certifi@2024.7.4" in purls  # added by dep-graph


def test_requests_license_was_supplemented(unified):
    requests = next(
        p for p in unified["packages"] if get_purl_from_package(p) == "pkg:pypi/requests@2.32.0"
    )
    assert requests["licenseConcluded"] == "Apache-2.0"


def test_requests_copyright_was_supplemented(unified):
    requests = next(
        p for p in unified["packages"] if get_purl_from_package(p) == "pkg:pypi/requests@2.32.0"
    )
    assert "Kenneth Reitz" in requests["copyrightText"]


def test_every_file_entry_has_filetypes(unified):
    for file in unified.get("files", []):
        assert "fileTypes" in file
        assert isinstance(file["fileTypes"], list) and len(file["fileTypes"]) >= 1


def test_relationships_describe_root_package(unified):
    described = [r for r in unified["relationships"] if r["relationshipType"] == "DESCRIBES"]
    assert any(r["spdxElementId"] == "SPDXRef-DOCUMENT" for r in described)


def test_supplementation_annotations_recorded(unified):
    found = False
    for pkg in unified["packages"]:
        for ann in pkg.get("annotations", []):
            if "supplemented" in (ann.get("comment") or "").lower():
                found = True
                break
    assert found, "Expected at least one 'supplemented by' annotation"
