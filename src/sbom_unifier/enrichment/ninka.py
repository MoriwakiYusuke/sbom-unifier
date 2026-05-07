"""Post-merge enrichment via ninka: file-level license and copyright."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

from ..merge.fields import INVALID_VALUES
from .file_types import _make_annotation

# ninka raw license name -> SPDX identifier
NINKA_LICENSE_MAP: dict[str, str] = {
    "Apache-2": "Apache-2.0",
    "GPL-2": "GPL-2.0-only",
    "GPL-2+": "GPL-2.0-or-later",
    "GPL-3": "GPL-3.0-only",
    "GPL-3+": "GPL-3.0-or-later",
    "LGPL-2": "LGPL-2.0-only",
    "LGPL-2+": "LGPL-2.0-or-later",
    "LGPL-2.1": "LGPL-2.1-only",
    "LGPL-2.1+": "LGPL-2.1-or-later",
    "LGPL-3": "LGPL-3.0-only",
    "LGPL-3+": "LGPL-3.0-or-later",
    "MIT": "MIT",
    "BSD-2": "BSD-2-Clause",
    "BSD-3": "BSD-3-Clause",
    "ISC": "ISC",
    "MPL-1.1": "MPL-1.1",
    "MPL-2": "MPL-2.0",
    "CDDL-1": "CDDL-1.0",
    "EPL-1": "EPL-1.0",
    "EPL-2": "EPL-2.0",
    "AGPL-3": "AGPL-3.0-only",
    "AGPL-3+": "AGPL-3.0-or-later",
    "Artistic": "Artistic-2.0",
    "Artistic-2": "Artistic-2.0",
    "CC0-1.0": "CC0-1.0",
    "Zlib": "Zlib",
    "PSF": "Python-2.0",
    "Python": "Python-2.0",
    "Unlicense": "Unlicense",
    "unlicense": "Unlicense",
    "spdxMIT": "MIT",
    "spdxBSD2": "BSD-2-Clause",
    "spdxBSD3": "BSD-3-Clause",
    "spdxBSD4": "BSD-4-Clause",
    "spdxSleepyCat": "Sleepycat",
}


def _run_ninka(filepath: str) -> tuple[str | None, str | None, str | None]:
    """Run ninka on a single file and parse SPDX license, copyright, and comment.

    Returns (license_spdx, copyright_text, license_comment) where each may be:
        - a string SPDX identifier / "NONE" / a copyright text
        - None on failure (caller maps to NOASSERTION)
    """
    tmpdir = tempfile.mkdtemp()
    try:
        fname = os.path.basename(filepath)
        tmp_file = os.path.join(tmpdir, fname)
        shutil.copy2(filepath, tmp_file)

        result = subprocess.run(
            ["ninka", "-i", tmp_file],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return None, None, None

        stdout = result.stdout.strip()
        parts = stdout.split(";")
        if len(parts) < 2:
            return None, None, None

        raw = parts[1]
        if raw in ("UNKNOWN", "NONE"):
            license_spdx = "NONE"
        elif raw in NINKA_LICENSE_MAP:
            license_spdx = NINKA_LICENSE_MAP[raw]
        else:
            license_spdx = f"LicenseRef-ninka-{raw}"

        # .senttok parsing
        senttok = tmp_file + ".senttok"
        copyright_lines: list[str] = []
        if os.path.exists(senttok):
            with open(senttok, encoding="utf-8", errors="replace") as f:
                for line in f:
                    if not line.startswith("Copyright;"):
                        continue
                    fields = line.split(";", 4)
                    if len(fields) == 5 and ":" in fields[4]:
                        original = fields[4].split(":", 1)[1].strip()
                        if original and original not in copyright_lines:
                            copyright_lines.append(original)
        copyright_text = "\n".join(copyright_lines) if copyright_lines else "NONE"

        # .goodsent parsing
        goodsent = tmp_file + ".goodsent"
        license_comment: str | None = None
        if os.path.exists(goodsent):
            with open(goodsent, encoding="utf-8", errors="replace") as f:
                content = f.read().strip()
            if content:
                license_comment = f"[Detected by ninka] {content}"

        return license_spdx, copyright_text, license_comment

    except subprocess.TimeoutExpired:
        return None, None, None
    except Exception:
        return None, None, None
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def add_ninka_info(file_entry: dict, repo_root: str) -> tuple[bool, bool, bool, bool]:
    """Run ninka on a single file entry and update fields when missing."""
    filename = file_entry.get("fileName", "")
    if filename.startswith("./"):
        rel = filename[2:]
    else:
        rel = filename.lstrip("/")
    full = os.path.join(repo_root, rel)

    if not os.path.isfile(full):
        return False, False, False, False

    license_spdx, copyright_text, license_comment = _run_ninka(full)
    ninka_succeeded = license_spdx is not None

    if license_spdx is None:
        license_spdx = "NOASSERTION"
    if copyright_text is None:
        copyright_text = "NOASSERTION"

    license_concluded_updated = False
    copyright_updated = False
    license_info_updated = False
    comment_added = False
    spdx_id = file_entry.get("SPDXID")

    if file_entry.get("licenseConcluded") in INVALID_VALUES:
        file_entry["licenseConcluded"] = license_spdx
        file_entry.setdefault("annotations", []).append(
            _make_annotation(
                f"Field (licenseConcluded) was set to '{license_spdx}' by ninka.",
                spdx_id,
            )
        )
        license_concluded_updated = True

    current_info = file_entry.get("licenseInfoInFiles", [])
    if ninka_succeeded and all(v in INVALID_VALUES for v in current_info):
        file_entry["licenseInfoInFiles"] = [license_spdx]
        file_entry.setdefault("annotations", []).append(
            _make_annotation(
                f"Field (licenseInfoInFiles) was set to '{license_spdx}' by ninka.",
                spdx_id,
            )
        )
        license_info_updated = True

    if license_comment and not file_entry.get("licenseComment"):
        file_entry["licenseComment"] = license_comment
        comment_added = True

    if file_entry.get("copyrightText") in INVALID_VALUES:
        file_entry["copyrightText"] = copyright_text
        file_entry.setdefault("annotations", []).append(
            _make_annotation("Field (copyrightText) was set by ninka.", spdx_id)
        )
        copyright_updated = True

    return license_concluded_updated, copyright_updated, license_info_updated, comment_added


def enrich_with_ninka(base_data: dict, repo_root: str) -> dict[str, int]:
    """Run ninka against every file entry. Return summary counts."""
    summary = {
        "ninka_files_scanned": 0,
        "ninka_license_updated": 0,
        "ninka_copyright_updated": 0,
        "ninka_license_info_updated": 0,
        "ninka_comment_added": 0,
        "ninka_errors": 0,
    }

    for entry in base_data.get("files", []):
        summary["ninka_files_scanned"] += 1
        try:
            lic, cp, info, comment = add_ninka_info(entry, repo_root)
            if lic:
                summary["ninka_license_updated"] += 1
            if cp:
                summary["ninka_copyright_updated"] += 1
            if info:
                summary["ninka_license_info_updated"] += 1
            if comment:
                summary["ninka_comment_added"] += 1
        except Exception:
            summary["ninka_errors"] += 1

    return summary
