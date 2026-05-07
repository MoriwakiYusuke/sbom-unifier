"""Post-merge enrichment: derive SPDX fileTypes from filename extensions."""

from __future__ import annotations

from datetime import UTC, datetime

from ..config import SCRIPT_CREATOR
from ..merge.utils import get_file_type


def _make_annotation(comment: str, spdx_element_id: str | None = None) -> dict:
    annotation = {
        "annotationDate": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "annotationType": "OTHER",
        "annotator": SCRIPT_CREATOR,
        "comment": comment,
    }
    if spdx_element_id:
        annotation["spdxElementId"] = spdx_element_id
    return annotation


def add_file_type(file_entry: dict) -> bool:
    """Set fileTypes on a single file entry. Return True if updated."""
    filename = file_entry.get("fileName")
    if not filename:
        return False

    file_type = get_file_type(filename)
    if file_entry.get("fileTypes") == [file_type]:
        return False

    file_entry["fileTypes"] = [file_type]
    annotation = _make_annotation(
        "Field (fileTypes) was added/updated based on file extension.",
        file_entry.get("SPDXID"),
    )
    file_entry.setdefault("annotations", []).append(annotation)
    return True


def enrich_with_file_types(base_data: dict) -> int:
    """Apply add_file_type to every file entry. Return count of updates."""
    count = 0
    for entry in base_data.get("files", []):
        if add_file_type(entry):
            count += 1
    return count
