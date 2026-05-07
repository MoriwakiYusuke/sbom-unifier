"""Tests for the enrichment package."""

from pathlib import Path
from unittest.mock import patch

from sbom_unifier.enrichment import enrich_sbom
from sbom_unifier.enrichment.file_types import (
    add_file_type,
    enrich_with_file_types,
)
from sbom_unifier.enrichment.ninka import (
    NINKA_LICENSE_MAP,
    add_ninka_info,
    enrich_with_ninka,
)


def test_add_file_type_sets_python_source():
    entry = {"SPDXID": "SPDXRef-File-1", "fileName": "./src/main.py"}
    changed = add_file_type(entry)
    assert changed is True
    assert entry["fileTypes"] == ["SOURCE"]
    assert any("fileTypes" in (a.get("comment") or "") for a in entry["annotations"])


def test_add_file_type_returns_false_when_already_correct():
    entry = {"SPDXID": "SPDXRef-File-2", "fileName": "./src/main.py", "fileTypes": ["SOURCE"]}
    assert add_file_type(entry) is False
    assert "annotations" not in entry


def test_enrich_with_file_types_returns_count():
    base = {
        "files": [
            {"SPDXID": "SPDXRef-File-1", "fileName": "./a.py"},
            {"SPDXID": "SPDXRef-File-2", "fileName": "./b.md"},
            {"SPDXID": "SPDXRef-File-3", "fileName": "./c.py", "fileTypes": ["SOURCE"]},
        ],
    }
    assert enrich_with_file_types(base) == 2
    assert base["files"][0]["fileTypes"] == ["SOURCE"]
    assert base["files"][1]["fileTypes"] == ["DOCUMENTATION"]


class _FakeCompleted:
    def __init__(self, stdout: str = "", returncode: int = 0):
        self.stdout = stdout
        self.returncode = returncode


def _write_repo_file(tmp_path: Path, rel: str, content: str = "x") -> Path:
    full = tmp_path / rel
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(content)
    return full


def test_add_ninka_info_skips_when_file_missing(tmp_path: Path):
    entry = {"SPDXID": "SPDXRef-F1", "fileName": "./missing.py"}
    result = add_ninka_info(entry, str(tmp_path))
    assert result == (False, False, False, False)


def test_add_ninka_info_sets_license_when_ninka_succeeds(tmp_path: Path):
    _write_repo_file(tmp_path, "src/a.py", "# Apache-2 License header\n")
    entry = {
        "SPDXID": "SPDXRef-F1",
        "fileName": "./src/a.py",
        "licenseConcluded": "NOASSERTION",
        "copyrightText": "NOASSERTION",
    }

    def fake_run(cmd, capture_output, text, timeout):
        # Format expected: "<filepath>;<license>;..."
        return _FakeCompleted(stdout="/tmp/x/a.py;Apache-2;...;...;\n", returncode=0)

    with patch("sbom_unifier.enrichment.ninka.subprocess.run", side_effect=fake_run):
        lic, cp, info, comment = add_ninka_info(entry, str(tmp_path))

    assert lic is True
    assert entry["licenseConcluded"] == "Apache-2.0"


def test_add_ninka_info_when_ninka_fails_sets_noassertion(tmp_path: Path):
    _write_repo_file(tmp_path, "src/b.py")
    entry = {"SPDXID": "SPDXRef-F1", "fileName": "./src/b.py", "licenseConcluded": ""}

    def fake_run(*args, **kwargs):
        return _FakeCompleted(stdout="", returncode=1)

    with patch("sbom_unifier.enrichment.ninka.subprocess.run", side_effect=fake_run):
        add_ninka_info(entry, str(tmp_path))

    assert entry["licenseConcluded"] == "NOASSERTION"


def test_enrich_with_ninka_returns_summary(tmp_path: Path):
    _write_repo_file(tmp_path, "a.py")
    _write_repo_file(tmp_path, "b.py")
    base = {
        "files": [
            {"SPDXID": "SPDXRef-1", "fileName": "./a.py", "licenseConcluded": "NOASSERTION"},
            {"SPDXID": "SPDXRef-2", "fileName": "./b.py", "licenseConcluded": "NOASSERTION"},
        ]
    }

    def fake_run(*args, **kwargs):
        return _FakeCompleted(stdout="/tmp/x/a.py;MIT;...;...;\n", returncode=0)

    with patch("sbom_unifier.enrichment.ninka.subprocess.run", side_effect=fake_run):
        summary = enrich_with_ninka(base, str(tmp_path))

    assert summary["ninka_files_scanned"] == 2
    assert summary["ninka_license_updated"] == 2


def test_ninka_license_map_known_keys():
    assert NINKA_LICENSE_MAP["MIT"] == "MIT"
    assert NINKA_LICENSE_MAP["Apache-2"] == "Apache-2.0"
    assert NINKA_LICENSE_MAP["GPL-3+"] == "GPL-3.0-or-later"


def test_enrich_sbom_runs_file_types_only_when_no_repo_root():
    base = {"files": [{"SPDXID": "SPDXRef-1", "fileName": "./a.py"}]}
    result = enrich_sbom(base, repo_root=None)
    assert result["file_types_added"] == 1
    assert "ninka_files_scanned" not in result


def test_enrich_sbom_runs_both_when_repo_root_given(tmp_path: Path):
    _write_repo_file(tmp_path, "a.py")
    base = {
        "files": [{"SPDXID": "SPDXRef-1", "fileName": "./a.py", "licenseConcluded": "NOASSERTION"}]
    }

    def fake_run(*args, **kwargs):
        return _FakeCompleted(stdout="/tmp/x/a.py;MIT;...\n", returncode=0)

    with patch("sbom_unifier.enrichment.ninka.subprocess.run", side_effect=fake_run):
        result = enrich_sbom(base, repo_root=str(tmp_path))

    assert result["file_types_added"] == 1
    assert result["ninka_files_scanned"] == 1
