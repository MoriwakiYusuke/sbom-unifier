"""Shared pytest fixtures and helpers."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

FIXTURE_TIMESTAMP = "2026-01-01T00:00:00Z"


def normalize_for_snapshot(data: Any) -> Any:
    """Replace volatile fields with deterministic placeholders."""
    if isinstance(data, dict):
        out: dict = {}
        for k, v in data.items():
            if k in ("created", "annotationDate"):
                out[k] = FIXTURE_TIMESTAMP
            elif k == "documentNamespace" and isinstance(v, str):
                # strip uuid suffix
                out[k] = v.split("?", 1)[0].rsplit("/", 1)[0] + "/<uuid>"
            else:
                out[k] = normalize_for_snapshot(v)
        return out
    if isinstance(data, list):
        return [normalize_for_snapshot(x) for x in data]
    return data


def assert_snapshot(actual: dict, expected_path: Path) -> None:
    """Compare an SBOM dict to a frozen expected JSON file."""
    actual_norm = normalize_for_snapshot(copy.deepcopy(actual))
    if not expected_path.exists():
        expected_path.parent.mkdir(parents=True, exist_ok=True)
        expected_path.write_text(json.dumps(actual_norm, indent=2, ensure_ascii=False))
        raise AssertionError(
            f"Snapshot did not exist; wrote initial value to {expected_path}. Re-run."
        )
    expected = json.loads(expected_path.read_text())
    if expected != actual_norm:
        # Write actual to .actual for diffing
        diff_path = expected_path.with_suffix(".actual.json")
        diff_path.write_text(json.dumps(actual_norm, indent=2, ensure_ascii=False))
        raise AssertionError(f"Snapshot mismatch.\nExpected: {expected_path}\nActual: {diff_path}")
