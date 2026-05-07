"""Tests for sbom_unifier.merge utilities and merger."""

import json
from pathlib import Path

from sbom_unifier.merge.merger import (
    finalize_sbom,
    merge_package_info,
    merge_sbom,
)
from sbom_unifier.merge.utils import (
    EXTENSION_TO_FILE_TYPE,
    KEY_ORDER,
    get_file_type,
    get_purl_from_package,
    save_sbom_json,
)


def test_get_purl_from_package_returns_purl():
    pkg = {
        "externalRefs": [
            {"referenceType": "purl", "referenceLocator": "pkg:pypi/flask@2.0"},
            {"referenceType": "cpe23Type", "referenceLocator": "cpe:..."},
        ]
    }
    assert get_purl_from_package(pkg) == "pkg:pypi/flask@2.0"


def test_get_purl_from_package_returns_none_when_absent():
    assert get_purl_from_package({}) is None
    assert get_purl_from_package({"externalRefs": []}) is None
    assert get_purl_from_package({"externalRefs": [{"referenceType": "cpe23Type"}]}) is None


def test_get_file_type_uses_extension_mapping():
    assert get_file_type("./src/main.py") == "SOURCE"
    assert get_file_type("./README.md") == "DOCUMENTATION"
    assert get_file_type("./bin/app") == "OTHER"


def test_get_file_type_recognises_spdx_json_suffix():
    assert get_file_type("manifest.spdx.json") == "SPDX"


def test_load_and_save_sbom_round_trip(tmp_path: Path):
    data = {"SPDXID": "SPDXRef-DOCUMENT", "spdxVersion": "SPDX-2.3", "name": "x"}
    path = tmp_path / "out.json"
    save_sbom_json(data, str(path))
    assert json.loads(path.read_text()) == data


def test_save_sbom_json_orders_known_keys_first(tmp_path: Path):
    data = {
        "extraKey": 1,
        "name": "x",
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.3",
    }
    path = tmp_path / "out.json"
    save_sbom_json(data, str(path))
    keys = list(json.loads(path.read_text()).keys())
    assert keys.index("SPDXID") < keys.index("extraKey")
    assert keys.index("spdxVersion") < keys.index("extraKey")


def test_extension_mapping_covers_common_source_types():
    for ext in (".py", ".java", ".js", ".ts", ".go", ".rs"):
        assert EXTENSION_TO_FILE_TYPE[ext] == "SOURCE"


def test_key_order_starts_with_spdxid():
    assert KEY_ORDER[0] == "SPDXID"


def test_get_project_paths_uses_output_root(tmp_path: Path):
    from sbom_unifier.config import get_project_paths

    paths = get_project_paths("flask", output_root=tmp_path)
    assert paths["project_dir"] == tmp_path / "flask"
    assert paths["clone_dir"] == tmp_path / "flask" / "cloned"
    assert paths["repo_path"] == tmp_path / "flask" / "cloned" / "flask"
    assert paths["sbom_dir"] == tmp_path / "flask"
    assert paths["analysis_dir"] == tmp_path / "flask" / "analysis"


def test_fields_module_exposes_invalid_values():
    from sbom_unifier.merge.fields import INVALID_VALUES, PACKAGE_SIMPLE_FIELDS

    assert "" in INVALID_VALUES
    assert "NOASSERTION" in INVALID_VALUES
    assert "name" in PACKAGE_SIMPLE_FIELDS
    assert "licenseConcluded" in PACKAGE_SIMPLE_FIELDS


def _pkg(spdxid: str, *, name: str = "lib", purl: str | None = None, **fields):
    pkg = {"SPDXID": spdxid, "name": name}
    if purl is not None:
        pkg["externalRefs"] = [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }
        ]
    pkg.update(fields)
    return pkg


def _doc(*, packages=(), relationships=(), creation_info=None, **extra):
    base = {
        "spdxVersion": "SPDX-2.2",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "test",
        "creationInfo": creation_info or {"created": "2024-01-01T00:00:00Z", "creators": []},
        "packages": list(packages),
        "relationships": list(relationships),
    }
    base.update(extra)
    return base


def test_merge_package_info_fills_missing_fields():
    base_pkg = _pkg(
        "SPDXRef-A", purl="pkg:pypi/a@1", licenseConcluded="NOASSERTION", copyrightText=""
    )
    src_pkg = _pkg(
        "SPDXRef-A", purl="pkg:pypi/a@1", licenseConcluded="MIT", copyrightText="Copyright 2024"
    )
    result = merge_package_info(base_pkg, src_pkg, "syft")
    assert base_pkg["licenseConcluded"] == "MIT"
    assert base_pkg["copyrightText"] == "Copyright 2024"
    assert result["fields_updated"] >= 2


def test_merge_package_info_records_conflicts():
    base_pkg = _pkg("SPDXRef-A", purl="pkg:pypi/a@1", licenseConcluded="MIT")
    src_pkg = _pkg("SPDXRef-A", purl="pkg:pypi/a@1", licenseConcluded="Apache-2.0")
    result = merge_package_info(base_pkg, src_pkg, "trivy")
    assert base_pkg["licenseConcluded"] == "MIT"
    assert result["fields_conflict"] == 1
    assert any("Conflict" in (a.get("comment") or "") for a in base_pkg["annotations"])


def test_merge_sbom_adds_missing_package_with_relationship():
    base = _doc(
        packages=[_pkg("SPDXRef-Root", name="root", purl="pkg:generic/root@1")],
        relationships=[
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": "SPDXRef-Root",
                "relationshipType": "DESCRIBES",
            }
        ],
    )
    src = _doc(
        packages=[
            _pkg("SPDXRef-Root", name="root", purl="pkg:generic/root@1"),
            _pkg("SPDXRef-NewLib", name="newlib", purl="pkg:pypi/newlib@2"),
        ],
        relationships=[
            {
                "spdxElementId": "SPDXRef-Root",
                "relatedSpdxElement": "SPDXRef-NewLib",
                "relationshipType": "DEPENDS_ON",
            },
        ],
    )
    result = merge_sbom(base, src, "syft")
    purls = [get_purl_from_package(p) for p in base["packages"]]
    assert "pkg:pypi/newlib@2" in purls
    assert result["packages_added"] == 1
    assert result["relationships_added"] >= 1


def test_merge_sbom_skip_missing_packages_when_disabled():
    base = _doc(packages=[_pkg("SPDXRef-Root", purl="pkg:generic/root@1")])
    src = _doc(
        packages=[
            _pkg("SPDXRef-Root", purl="pkg:generic/root@1"),
            _pkg("SPDXRef-X", purl="pkg:pypi/x@1"),
        ],
    )
    merge_sbom(base, src, "syft", add_missing_packages=False)
    purls = [get_purl_from_package(p) for p in base["packages"]]
    assert "pkg:pypi/x@1" not in purls


def test_finalize_sbom_sets_spdx_version_and_creator():
    from sbom_unifier.config import SCRIPT_CREATOR, TARGET_SPDX_VERSION

    data = _doc()
    finalize_sbom(data)
    assert data["spdxVersion"] == TARGET_SPDX_VERSION
    assert SCRIPT_CREATOR in data["creationInfo"]["creators"]
