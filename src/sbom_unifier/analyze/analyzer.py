#!/usr/bin/env python3
"""
SPDX Field Analyzer.

Analyzes SPDX field coverage from each SBOM tool's output and generates a
comparison table.

Result values (5 categories):
- full: all items have a real value
- part: some items have a real value
- miss: key does not exist / empty
- NOASSERTION: all values are NOASSERTION
- NONE: all values are NONE

Attributes (one per field, taken directly from SPDX_FIELDS static attribute):
- required: mandatory field
- optional: optional field
- deprecated: deprecated field
- omission: omitted section (Snippet, Other Licensing, Annotation) or conditional item
"""

import csv
from pathlib import Path

from .spdx_fields import SPDX_FIELDS
from .utils import (
    FULL_RATIO,
    PARTIAL_RATIO,
    analyze_document_field,
    analyze_document_field_with_ratio,
    analyze_items,
    analyze_items_with_ratio,
    load_sbom,
)

# SBOM filenames
SYFT_SBOM_FILENAME = "syft-sbom.json"
TRIVY_SBOM_FILENAME = "trivy-sbom.json"
GITHUB_SBOM_FILENAME = "dependency-graph-sbom.json"
SBOM_TOOL_MANIFEST_RELPATH = "_manifest/spdx_2.2/manifest.spdx.json"
UNIFIED_SBOM_FILENAME = "unified_sbom.json"


def _resolve_attribute(static_attr: str) -> str:
    """Return the field attribute (static attribute from SPDX_FIELDS passed through).

    Args:
        static_attr: Attribute defined in SPDX_FIELDS (required/optional/deprecated/omission).

    Returns:
        Attribute string.
    """
    return static_attr


def analyze_sbom(sbom: dict) -> dict[str, str]:
    """Analyze an SBOM and return the field coverage status.

    Args:
        sbom: Parsed SBOM data.

    Returns:
        Dict mapping field name to result (full/part/miss/NOASSERTION).
    """
    results = {}

    for category, field_name, field_key, field_type, *_ in SPDX_FIELDS:
        full_name = f"{category}|{field_name}"

        if field_type == "document":
            results[full_name] = analyze_document_field(sbom, field_key)

        elif field_type == "package":
            packages = sbom.get("packages", [])
            results[full_name] = analyze_items(packages, field_key)

        elif field_type == "file":
            files = sbom.get("files", [])
            if not files:
                results[full_name] = "miss"
            else:
                results[full_name] = analyze_items(files, field_key)

        elif field_type == "snippet":
            snippets = sbom.get("snippets", [])
            if not snippets:
                results[full_name] = "miss"
            else:
                results[full_name] = analyze_items(snippets, field_key)

        elif field_type == "extractedLicensingInfo":
            licensing_info = sbom.get("hasExtractedLicensingInfos", [])
            if not licensing_info:
                results[full_name] = "miss"
            else:
                results[full_name] = analyze_items(licensing_info, field_key)

        elif field_type == "relationship":
            relationships = sbom.get("relationships", [])
            if not relationships:
                results[full_name] = "miss"
            else:
                results[full_name] = analyze_items(relationships, field_key)

        elif field_type == "annotation":
            annotations = sbom.get("annotations", [])
            for pkg in sbom.get("packages", []):
                annotations.extend(pkg.get("annotations", []))

            if not annotations:
                results[full_name] = "miss"
            else:
                results[full_name] = analyze_items(annotations, field_key)

        elif field_type == "review":
            reviews = sbom.get("revieweds", [])
            if not reviews:
                results[full_name] = "miss"
            else:
                results[full_name] = analyze_items(reviews, field_key)

    return results


def analyze_sbom_attributes(sbom: dict) -> dict[str, str]:
    """Analyze an SBOM and return the runtime attributes for each field.

    Args:
        sbom: Parsed SBOM data.

    Returns:
        Dict mapping field name to attribute string.
    """
    attributes = {}

    for category, field_name, _field_key, _field_type, static_attr in SPDX_FIELDS:
        full_name = f"{category}|{field_name}"
        attributes[full_name] = _resolve_attribute(static_attr)

    return attributes


def analyze_sbom_with_ratio(sbom: dict) -> dict[str, tuple[str, float]]:
    """Analyze an SBOM and return field coverage status with percentages.

    Args:
        sbom: Parsed SBOM data.

    Returns:
        Dict mapping field name to (result, percentage) tuple.
    """
    results = {}

    for category, field_name, field_key, field_type, *_ in SPDX_FIELDS:
        full_name = f"{category}|{field_name}"

        if field_type == "document":
            results[full_name] = analyze_document_field_with_ratio(sbom, field_key)

        elif field_type == "package":
            packages = sbom.get("packages", [])
            results[full_name] = analyze_items_with_ratio(packages, field_key)

        elif field_type == "file":
            files = sbom.get("files", [])
            if not files:
                results[full_name] = ("miss", 0.0)
            else:
                results[full_name] = analyze_items_with_ratio(files, field_key)

        elif field_type == "snippet":
            snippets = sbom.get("snippets", [])
            if not snippets:
                results[full_name] = ("miss", 0.0)
            else:
                results[full_name] = analyze_items_with_ratio(snippets, field_key)

        elif field_type == "extractedLicensingInfo":
            licensing_info = sbom.get("hasExtractedLicensingInfos", [])
            if not licensing_info:
                results[full_name] = ("miss", 0.0)
            else:
                results[full_name] = analyze_items_with_ratio(licensing_info, field_key)

        elif field_type == "relationship":
            relationships = sbom.get("relationships", [])
            if not relationships:
                results[full_name] = ("miss", 0.0)
            else:
                results[full_name] = analyze_items_with_ratio(relationships, field_key)

        elif field_type == "annotation":
            annotations = sbom.get("annotations", [])
            for pkg in sbom.get("packages", []):
                annotations.extend(pkg.get("annotations", []))

            if not annotations:
                results[full_name] = ("miss", 0.0)
            else:
                results[full_name] = analyze_items_with_ratio(annotations, field_key)

        elif field_type == "review":
            reviews = sbom.get("revieweds", [])
            if not reviews:
                results[full_name] = ("miss", 0.0)
            else:
                results[full_name] = analyze_items_with_ratio(reviews, field_key)

    return results


def analyze_project(
    project_path: str | None = None, output_path: str | None = None
) -> dict[str, dict[str, str]]:
    """Analyze all SBOMs in a project directory.

    Args:
        project_path: Path to the project directory containing SBOM files.
        output_path: Output CSV file path (auto-generated if omitted).

    Returns:
        Per-tool analysis results.
    """
    if project_path is None:
        print("No project_path specified.")
        return {}

    project_dir = Path(project_path)
    project_name = project_dir.name

    # SBOM file mapping
    sbom_files = {
        "Unified": project_dir / UNIFIED_SBOM_FILENAME,
        "MS SBOM Tool": project_dir / SBOM_TOOL_MANIFEST_RELPATH,
        "Syft": project_dir / SYFT_SBOM_FILENAME,
        "Trivy": project_dir / TRIVY_SBOM_FILENAME,
        "Dependency Graph": project_dir / GITHUB_SBOM_FILENAME,
    }

    results = {}
    results_with_ratio = {}
    attributes = {}

    for tool_name, filepath in sbom_files.items():
        if filepath.exists():
            print(f"Analyzing {tool_name}: {filepath}")
            try:
                sbom = load_sbom(str(filepath))
                results[tool_name] = analyze_sbom(sbom)
                results_with_ratio[tool_name] = analyze_sbom_with_ratio(sbom)
                attributes[tool_name] = analyze_sbom_attributes(sbom)
            except Exception as e:
                print(f"  Error loading {tool_name}: {e}")
                results[tool_name] = {}
                results_with_ratio[tool_name] = {}
                attributes[tool_name] = {}
        else:
            print(f"  File not found: {filepath}")
            results[tool_name] = {}
            results_with_ratio[tool_name] = {}
            attributes[tool_name] = {}

    # Write CSV output
    if output_path is None:
        output_dir = project_dir / "analysis_results"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = str(output_dir / f"{project_name}_spdx_comparison.csv")

    write_comparison_csv(results, str(output_path), attributes=attributes)
    print(f"\nOutput: {output_path}")

    # Also write percentage CSV
    percent_output_path = str(output_path).replace(
        "_spdx_comparison.csv", "_spdx_comparison_percent.csv"
    )
    write_comparison_percent_csv(results_with_ratio, percent_output_path, attributes=attributes)
    print(f"Output (percent): {percent_output_path}")

    return results


def write_comparison_csv(
    results: dict[str, dict[str, str]],
    output_path: str,
    attributes: dict[str, dict[str, str]] | None = None,
):
    """Write comparison results to CSV.

    Args:
        results: Per-tool analysis results.
        output_path: Output CSV file path.
        attributes: Per-tool attribute information (no attribute column if None).
    """
    tools = ["Unified", "MS SBOM Tool", "Syft", "Trivy", "Dependency Graph"]
    available_tools = [t for t in tools if t in results and results[t]]

    # Use attributes from the first tool that has them
    attr_map = None
    if attributes:
        for tool in available_tools:
            if tool in attributes and attributes[tool]:
                attr_map = attributes[tool]
                break

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)

        # Header
        header = ["Category", "SPDX Field"]
        if attr_map is not None:
            header.append("Attribute")
        header += available_tools
        writer.writerow(header)

        # Data rows
        for category, field_name, _, _, *_ in SPDX_FIELDS:
            full_name = f"{category}|{field_name}"
            row = [category, field_name]

            if attr_map is not None:
                row.append(attr_map.get(full_name, ""))

            for tool in available_tools:
                if tool in results and full_name in results[tool]:
                    row.append(results[tool][full_name])
                else:
                    row.append("miss")

            writer.writerow(row)


def write_comparison_percent_csv(
    results_with_ratio: dict[str, dict[str, tuple]],
    output_path: str,
    attributes: dict[str, dict[str, str]] | None = None,
):
    """Write comparison results with percentages to CSV.

    Args:
        results_with_ratio: Per-tool analysis results as (result, percentage) tuples.
        output_path: Output CSV file path.
        attributes: Per-tool attribute information (no attribute column if None).
    """
    tools = [
        "Unified",
        "MS SBOM Tool",
        "Syft",
        "Trivy",
        "Dependency Graph",
    ]
    available_tools = [t for t in tools if t in results_with_ratio and results_with_ratio[t]]

    attr_map = None
    if attributes:
        for tool in available_tools:
            if tool in attributes and attributes[tool]:
                attr_map = attributes[tool]
                break

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)

        # Header
        header = ["Category", "SPDX Field"]
        if attr_map is not None:
            header.append("Attribute")
        header += available_tools
        writer.writerow(header)

        # Data rows
        for category, field_name, _, _, *_ in SPDX_FIELDS:
            full_name = f"{category}|{field_name}"
            row = [category, field_name]

            if attr_map is not None:
                row.append(attr_map.get(full_name, ""))

            for tool in available_tools:
                if tool in results_with_ratio and full_name in results_with_ratio[tool]:
                    _, percentage = results_with_ratio[tool][full_name]
                    row.append(f"{percentage:.1f}%")
                else:
                    row.append("0.0%")

            writer.writerow(row)


def print_summary(results: dict[str, dict[str, str]]):
    """Print an analysis summary to stdout.

    Args:
        results: Per-tool analysis results.
    """
    tools = [
        "Unified",
        "MS SBOM Tool",
        "Syft",
        "Trivy",
        "Dependency Graph",
    ]
    available_tools = [t for t in tools if t in results and results[t]]

    print("\n" + "=" * 80)
    print("SPDX Field Analysis Summary")
    print(f"Thresholds: FULL={FULL_RATIO * 100:.0f}%, PARTIAL={PARTIAL_RATIO * 100:.0f}%")
    print("=" * 80)

    for tool in available_tools:
        if tool not in results:
            continue

        tool_results = results[tool]
        counts = {
            "full": 0,
            "part": 0,
            "miss": 0,
            "NOASSERTION": 0,
        }

        for value in tool_results.values():
            if value == "NONE":
                value = "full"
            if value in counts:
                counts[value] += 1

        total = sum(counts.values())
        print(f"\n{tool}:")
        if total > 0:
            pct = {k: v / total * 100 for k, v in counts.items()}
            print(f"  full        all real values:    {counts['full']:3d} ({pct['full']:.1f}%)")
            print(f"  part        some real values:   {counts['part']:3d} ({pct['part']:.1f}%)")
            print(f"  miss        key absent:         {counts['miss']:3d} ({pct['miss']:.1f}%)")
            print(
                f"  NOASSERTION all NOASSERTION:    "
                f"{counts['NOASSERTION']:3d} ({pct['NOASSERTION']:.1f}%)"
            )


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="SPDX Field Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a specific project directory
  python -m sbom_unifier.analyze.analyzer path/to/project

  # Change thresholds (80% or above = full, 20% or above = part)
  python -m sbom_unifier.analyze.analyzer --full 0.8 --partial 0.2
        """,
    )
    parser.add_argument("project_path", nargs="?", help="Path to the project SBOM directory")
    parser.add_argument("-o", "--output", help="Output CSV file path")
    parser.add_argument(
        "--full",
        type=float,
        default=1.0,
        help="Threshold for full (default: 1.0 = 100%%)",
    )
    parser.add_argument(
        "--partial",
        type=float,
        default=0.0,
        help="Threshold for part (default: 0.0 = any)",
    )

    args = parser.parse_args()

    results = analyze_project(args.project_path, args.output)
    print_summary(results)


if __name__ == "__main__":
    main()
