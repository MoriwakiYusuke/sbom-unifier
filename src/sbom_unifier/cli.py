"""Command-line entry point for sbom-unifier."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .pipeline import run_pipeline
from .tools import REGISTRY  # imports tools, triggering registration


def build_parser() -> argparse.ArgumentParser:
    generator_names = sorted(t.name for t in REGISTRY.generators())
    base_names = sorted(t.name for t in REGISTRY.base_candidates())

    parser = argparse.ArgumentParser(
        prog="sbom-unifier",
        description="Generate, merge, enrich, and analyze SPDX SBOMs from a GitHub URL.",
    )
    parser.add_argument(
        "url",
        nargs="?",
        help="GitHub repository URL (https://github.com/<owner>/<repo>).",
    )
    parser.add_argument(
        "--tools",
        "-t",
        nargs="+",
        choices=generator_names,
        help="SBOM source tools to run (default: all generators).",
    )
    parser.add_argument(
        "--base-tool",
        choices=base_names,
        help="Base SBOM tool name (default: first base candidate by default order).",
    )
    parser.add_argument(
        "--custom-sbom",
        type=str,
        help="Path to a user-supplied SBOM merged at the end.",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        help="Output root directory (default: <package>/output).",
    )
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="Print the registered tool list and exit.",
    )
    return parser


def _print_tools() -> None:
    print(f"{'name':<14} {'base':<5} {'pos':<4} {'description'}")
    print("-" * 80)
    for tool in REGISTRY.default_merge_order():
        is_base = "yes" if tool.can_be_base else "no"
        print(f"{tool.name:<14} {is_base:<5} {tool.default_merge_position:<4} {tool.description}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_tools:
        _print_tools()
        return 0

    if not args.url:
        parser.error("url is required (or use --list-tools)")

    output_root = Path(args.output) if args.output else None
    success = run_pipeline(
        url=args.url,
        enabled_tools=args.tools,
        base_tool=args.base_tool,
        custom_sbom_path=args.custom_sbom,
        output_root=output_root,
    )
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
