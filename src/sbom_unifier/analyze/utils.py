"""
Utility functions for SPDX field analysis.
"""

import json
from typing import Any

# SPDX field coverage thresholds (was sbom_analyzer/config.py).
FULL_RATIO = 1.0
PARTIAL_RATIO = 0.0


def is_noassertion_or_empty(value: Any) -> bool:
    """Return True if value is NOASSERTION, NONE, or empty.

    Args:
        value: The value to check.

    Returns:
        True if NOASSERTION, NONE, or empty.
    """
    if value is None:
        return True
    if isinstance(value, str):
        return value.upper() in ["NOASSERTION", "NONE", ""] or value.strip() == ""
    if isinstance(value, list):
        if len(value) == 0:
            return True
        # Check if all list elements are NOASSERTION
        return all(is_noassertion_or_empty(v) for v in value)
    if isinstance(value, dict):
        return len(value) == 0
    return False


def is_noassertion(value: Any) -> bool:
    """Return True if value is NOASSERTION (does not include NONE).

    Args:
        value: The value to check.

    Returns:
        True if NOASSERTION.
    """
    if value is None:
        return False
    if isinstance(value, str):
        return value.upper() == "NOASSERTION"
    if isinstance(value, list):
        if len(value) == 0:
            return False
        return all(is_noassertion(v) for v in value)
    return False


def is_none_value(value: Any) -> bool:
    """Return True if value is NONE (a valid SPDX declaration of absence).

    Args:
        value: The value to check.

    Returns:
        True if NONE.
    """
    if value is None:
        return False
    if isinstance(value, str):
        return value.upper() == "NONE"
    if isinstance(value, list):
        if len(value) == 0:
            return False
        return all(is_none_value(v) for v in value)
    return False


def is_empty_value(value: Any) -> bool:
    """Return True if value is empty (None, empty string, empty list, or empty dict).

    Args:
        value: The value to check.

    Returns:
        True if empty.
    """
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == ""
    if isinstance(value, list):
        return len(value) == 0
    if isinstance(value, dict):
        return len(value) == 0
    return False


def has_real_value(value: Any) -> bool:
    """Return True if there is a meaningful real value.

    NONE is treated as a valid value (an explicit SPDX declaration of absence).

    Args:
        value: The value to check.

    Returns:
        True if there is a meaningful value (including NONE).
    """
    if value is None:
        return False
    if isinstance(value, bool):
        return True
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, str):
        # Exclude only NOASSERTION and empty. NONE is a valid value.
        return value.upper() not in ["NOASSERTION", ""] and value.strip() != ""
    if isinstance(value, list):
        if len(value) == 0:
            return False
        # At least one meaningful value in the list
        return any(has_real_value(v) for v in value)
    if isinstance(value, dict):
        return len(value) > 0
    return False


def get_nested_value(obj: dict, key_path: str) -> tuple[bool, Any]:
    """Retrieve a value from a nested key path.

    Args:
        obj: The dictionary to search.
        key_path: Dot-separated key path (e.g. "creationInfo.creators").

    Returns:
        (key_exists, value): Whether the key exists and its value.
    """
    keys = key_path.split(".")
    current = obj

    for key in keys:
        if isinstance(current, dict):
            if key in current:
                current = current[key]
            else:
                return (False, None)
        elif isinstance(current, list) and len(current) > 0:
            # For lists, check the first element
            if isinstance(current[0], dict) and key in current[0]:
                current = current[0][key]
            else:
                return (False, None)
        else:
            return (False, None)

    return (True, current)


def analyze_items(items: list[dict], field_key: str) -> str:
    """Analyze the field status across multiple items (packages, files, etc.).

    Result values:
        full: all items have a real value (including NONE)
        part: some items have a real value (including NONE)
        miss: key does not exist (0%)
        NOASSERTION: key exists but all values are NOASSERTION

    Threshold settings:
        FULL_RATIO: ratio at or above this is full
        PARTIAL_RATIO: ratio at or above this is part

    Args:
        items: List of items to analyze.
        field_key: Field key to check.

    Returns:
        full/part/miss/NOASSERTION
    """
    if not items or len(items) == 0:
        return "miss"

    key_exists_count = 0
    real_value_count = 0
    noassertion_count = 0
    empty_count = 0

    for item in items:
        key_exists, value = get_nested_value(item, field_key)

        if key_exists:
            key_exists_count += 1
            if has_real_value(value):
                real_value_count += 1
            elif is_noassertion(value):
                noassertion_count += 1
            elif is_empty_value(value):
                empty_count += 1

    total = len(items)

    # No key exists at all
    if key_exists_count == 0:
        return "miss"

    # Evaluate against thresholds
    ratio = real_value_count / total

    # At or above FULL_RATIO -> full
    if ratio >= FULL_RATIO:
        return "full"

    # Real values and NOASSERTION mixed -> part
    if ratio > PARTIAL_RATIO:
        return "part"

    # No real values
    if real_value_count == 0:
        # All NOASSERTION
        if noassertion_count > 0:
            return "NOASSERTION"

    return "miss"


def analyze_document_field(sbom: dict, field_key: str) -> str:
    """Analyze a document-level field.

    Args:
        sbom: Parsed SBOM data.
        field_key: Field key to check.

    Returns:
        full/miss/NOASSERTION
    """
    key_exists, value = get_nested_value(sbom, field_key)

    if not key_exists:
        return "miss"

    if has_real_value(value):
        return "full"

    if is_noassertion(value):
        return "NOASSERTION"

    # Empty value (None, empty string, empty list, etc.)
    return "miss"


def load_sbom(filepath: str) -> dict:
    """Load an SBOM file.

    Args:
        filepath: Path to the SBOM file.

    Returns:
        Parsed SBOM data.
    """
    with open(filepath, encoding="utf-8") as f:
        return json.load(f)


def analyze_items_with_ratio(items: list[dict], field_key: str) -> tuple[str, float]:
    """Analyze field status across multiple items and return a percentage.

    Args:
        items: List of items to analyze.
        field_key: Field key to check.

    Returns:
        (result, percentage):
            result is full/part/miss/NOASSERTION
            percentage is the ratio of items with real values (0.0-100.0)
    """
    if not items or len(items) == 0:
        return ("miss", 0.0)

    key_exists_count = 0
    real_value_count = 0
    noassertion_count = 0
    empty_count = 0

    for item in items:
        key_exists, value = get_nested_value(item, field_key)

        if key_exists:
            key_exists_count += 1
            if has_real_value(value):
                real_value_count += 1
            elif is_noassertion(value):
                noassertion_count += 1
            elif is_empty_value(value):
                empty_count += 1

    total = len(items)

    # Calculate percentage
    ratio = real_value_count / total if total > 0 else 0.0
    percentage = ratio * 100

    # No key exists at all
    if key_exists_count == 0:
        return ("miss", 0.0)

    # Evaluate against thresholds
    if ratio >= FULL_RATIO:
        return ("full", percentage)

    if ratio > PARTIAL_RATIO:
        return ("part", percentage)

    # No real values
    if real_value_count == 0:
        if noassertion_count > 0:
            return ("NOASSERTION", 0.0)

    return ("miss", 0.0)


def analyze_document_field_with_ratio(sbom: dict, field_key: str) -> tuple[str, float]:
    """Analyze a document-level field and return a percentage.

    Args:
        sbom: Parsed SBOM data.
        field_key: Field key to check.

    Returns:
        (result, percentage):
            result is full/miss/NOASSERTION
            percentage is 100.0 (value present) or 0.0
    """
    key_exists, value = get_nested_value(sbom, field_key)

    if not key_exists:
        return ("miss", 0.0)

    if has_real_value(value):
        return ("full", 100.0)

    if is_noassertion(value):
        return ("NOASSERTION", 0.0)

    return ("miss", 0.0)
