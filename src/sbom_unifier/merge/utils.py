"""Merge-side utilities: PURL extraction, JSON I/O, file-type lookup, key order."""

from __future__ import annotations

import json
import os
from typing import Any

# Canonical key order for the unified SPDX JSON document.
KEY_ORDER: list[str] = [
    "SPDXID",
    "spdxVersion",
    "creationInfo",
    "name",
    "dataLicense",
    "documentNamespace",
    "comment",
    "documentDescribes",
    "externalDocumentRefs",
    "packages",
    "files",
    "relationships",
]


# Extension to SPDX fileType mapping.
EXTENSION_TO_FILE_TYPE: dict[str, str] = {
    # SOURCE
    ".c": "SOURCE",
    ".cpp": "SOURCE",
    ".h": "SOURCE",
    ".cs": "SOURCE",
    ".java": "SOURCE",
    ".py": "SOURCE",
    ".js": "SOURCE",
    ".ts": "SOURCE",
    ".go": "SOURCE",
    ".rs": "SOURCE",
    ".rb": "SOURCE",
    ".sh": "SOURCE",
    ".html": "SOURCE",
    ".css": "SOURCE",
    ".php": "SOURCE",
    ".swift": "SOURCE",
    # BINARY
    ".o": "BINARY",
    ".a": "BINARY",
    ".exe": "BINARY",
    ".dll": "BINARY",
    ".so": "BINARY",
    ".bin": "BINARY",
    # ARCHIVE
    ".tar": "ARCHIVE",
    ".jar": "ARCHIVE",
    ".zip": "ARCHIVE",
    ".gz": "ARCHIVE",
    ".whl": "ARCHIVE",
    # IMAGE
    ".jpg": "IMAGE",
    ".jpeg": "IMAGE",
    ".png": "IMAGE",
    ".gif": "IMAGE",
    ".svg": "IMAGE",
    # TEXT
    ".txt": "TEXT",
    # AUDIO
    ".mp3": "AUDIO",
    ".wav": "AUDIO",
    ".ogg": "AUDIO",
    ".flac": "AUDIO",
    # VIDEO
    ".mp4": "VIDEO",
    ".mov": "VIDEO",
    ".avi": "VIDEO",
    ".mkv": "VIDEO",
    # DOCUMENTATION
    ".md": "DOCUMENTATION",
    ".rst": "DOCUMENTATION",
    ".pdf": "DOCUMENTATION",
    ".doc": "DOCUMENTATION",
    ".docx": "DOCUMENTATION",
}


def get_purl_from_package(pkg: dict) -> str | None:
    """Return the Package URL from a package's externalRefs, or None."""
    for ref in pkg.get("externalRefs", []):
        if ref.get("referenceType") == "purl":
            return ref.get("referenceLocator")
    return None


def load_sbom_json(file_path: str) -> dict[str, Any]:
    """Load an SBOM JSON file."""
    with open(file_path, encoding="utf-8") as f:
        return json.load(f)


def save_sbom_json(sbom_data: dict, file_path: str) -> None:
    """Save SBOM data with canonical key order and stable indentation."""
    ordered = {k: sbom_data[k] for k in KEY_ORDER if k in sbom_data}
    ordered.update({k: v for k, v in sbom_data.items() if k not in ordered})
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(ordered, f, indent=2, ensure_ascii=False)
    print(f"   Saved: {os.path.basename(file_path)}")


def get_file_type(filename: str) -> str:
    """Map a filename to an SPDX fileType, with .spdx.json as a special case."""
    if filename.lower().endswith(".spdx.json"):
        return "SPDX"
    _, ext = os.path.splitext(filename)
    return EXTENSION_TO_FILE_TYPE.get(ext.lower(), "OTHER")
