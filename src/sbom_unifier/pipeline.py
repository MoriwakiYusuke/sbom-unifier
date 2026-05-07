"""Pipeline orchestration: clone -> generate -> merge -> enrich -> analyze."""

from __future__ import annotations

import importlib
import os
import shutil
import sys
from pathlib import Path

from dotenv import load_dotenv

from .analyze import analyze_project
from .clone import clone_single_repository, parse_github_url
from .config import UNIFIED_SBOM_FILENAME, get_project_paths
from .enrichment import enrich_sbom
from .merge.merger import finalize_sbom, merge_sbom
from .merge.utils import load_sbom_json, save_sbom_json
from .tools import REGISTRY  # noqa: F401 – triggers self-registration of all tools

load_dotenv()


def _resolve_generate(tool_name: str):
    """Resolve a tool's generate() at call time so that tests can patch
    `sbom_unifier.tools.<module_name>.generate`. Module convention: tool name
    with hyphens replaced by underscores. Returns None if no generate found
    (e.g. for the manual upload slot)."""
    module_name = f"sbom_unifier.tools.{tool_name.replace('-', '_')}"
    try:
        mod = importlib.import_module(module_name)
    except ImportError:
        return None
    return getattr(mod, "generate", None)


def _default_base_tool() -> str:
    """Return the highest-priority base candidate name."""
    candidates = sorted(
        REGISTRY.base_candidates(),
        key=lambda t: t.default_merge_position,
    )
    if not candidates:
        raise RuntimeError("No base candidates registered")
    return candidates[0].name


def _resolve_base_path(sbom_dir: Path, base_tool: str) -> Path:
    """Return the path of the base SBOM file for the given tool name."""
    return sbom_dir / REGISTRY.filename_for(base_tool)


def _find_existing_base(sbom_dir: Path) -> Path | None:
    """Fall back to the first existing base candidate by default order."""
    for entry in sorted(REGISTRY.base_candidates(), key=lambda t: t.default_merge_position):
        path = sbom_dir / REGISTRY.filename_for(entry.name)
        if path.exists():
            return path
    return None


def _apply_custom_sbom(sbom_dir: Path, custom_sbom_path: str | None) -> None:
    """Copy user-provided custom SBOM into place; clean up stale ones."""
    manual = REGISTRY.get("manual")
    dest = sbom_dir / manual.output_filename
    if custom_sbom_path:
        src = Path(custom_sbom_path)
        if src.exists():
            if dest.exists():
                dest.unlink()
            shutil.copy(str(src), str(dest))
            print(f"[pipeline] Applied custom SBOM: {src.name} -> {dest.name}")
        else:
            print(f"[pipeline] Warning: custom SBOM not found: {custom_sbom_path}")
    else:
        if dest.exists():
            dest.unlink()
            print("[pipeline] Removed stale custom SBOM from a previous run")


def run_pipeline(
    url: str,
    enabled_tools: list[str] | None = None,
    base_tool: str | None = None,
    merge_order: list[str] | None = None,
    custom_sbom_path: str | None = None,
    output_root: Path | None = None,
) -> bool:
    """Run the full pipeline. Return True on success."""
    parsed = parse_github_url(url)
    if not parsed:
        print(f"[pipeline] Error: not a GitHub URL: {url}", file=sys.stderr)
        return False
    owner, repo_name = parsed
    print(f"=== sbom-unifier: {owner}/{repo_name} ===")

    paths = get_project_paths(repo_name, output_root)
    for d in (paths["clone_dir"], paths["sbom_dir"], paths["analysis_dir"]):
        d.mkdir(parents=True, exist_ok=True)

    # Step 1: clone
    if not clone_single_repository(url, paths["clone_dir"]):
        print("[pipeline] Error: clone failed", file=sys.stderr)
        return False
    repo_path = paths["repo_path"]
    if not repo_path.is_dir():
        print(f"[pipeline] Error: cloned repo missing: {repo_path}", file=sys.stderr)
        return False

    # Step 2: generate via every enabled tool in registry
    generators = REGISTRY.generators()
    if enabled_tools is not None:
        wanted = set(enabled_tools)
        generators = [g for g in generators if g.name in wanted]

    generated: list[str] = []
    github_token = os.environ.get("GITHUB_TOKEN")
    for tool in generators:
        print(f"--- generate: {tool.name} ---")
        # Resolve generate() at call time via module lookup so that tests can
        # patch the module-level symbol. Falls back to the registered callable.
        generate_fn = _resolve_generate(tool.name) or tool.generate
        if generate_fn is None:
            continue
        ok = generate_fn(
            repo_path=repo_path,
            output_dir=paths["sbom_dir"],
            owner=owner,
            repo_name=repo_name,
            github_token=github_token,
        )
        if ok:
            generated.append(tool.name)

    if not generated:
        print("[pipeline] Error: no generators succeeded", file=sys.stderr)
        return False
    print(f"[pipeline] generated: {', '.join(generated)}")

    # Step 3: handle custom SBOM
    _apply_custom_sbom(paths["sbom_dir"], custom_sbom_path)

    # Step 4: resolve base
    chosen_base = base_tool or _default_base_tool()
    base_path = _resolve_base_path(paths["sbom_dir"], chosen_base)
    if not base_path.exists():
        fallback = _find_existing_base(paths["sbom_dir"])
        if fallback is None:
            print("[pipeline] Error: no base SBOM available", file=sys.stderr)
            return False
        print(f"[pipeline] Base {chosen_base!r} missing; fell back to {fallback.name}")
        base_path = fallback

    base_data = load_sbom_json(str(base_path))

    # Step 5: merge
    order = merge_order or [t.name for t in REGISTRY.default_merge_order()]
    for tool_name in order:
        if tool_name == chosen_base:
            continue
        try:
            src_path = paths["sbom_dir"] / REGISTRY.filename_for(tool_name)
        except KeyError:
            print(f"[pipeline] skip unknown tool in merge order: {tool_name}")
            continue
        if not src_path.exists():
            print(f"[pipeline] skip {tool_name}: file missing")
            continue
        if src_path.resolve() == base_path.resolve():
            continue
        src_data = load_sbom_json(str(src_path))
        result = merge_sbom(base_data, src_data, tool_name)
        print(
            f"[pipeline] merged {tool_name}: "
            f"merged={result['packages_merged']} "
            f"added={result['packages_added']} "
            f"fields={result['fields_updated']}"
        )

    finalize_sbom(base_data)

    # Step 6: enrich
    enrich_sbom(base_data, repo_root=str(repo_path))

    # Step 7: save unified SBOM
    out_path = paths["sbom_dir"] / UNIFIED_SBOM_FILENAME
    save_sbom_json(base_data, str(out_path))

    # Step 8: analyze (best effort)
    try:
        analyze_project(
            project_path=str(paths["sbom_dir"]),
            output_path=str(paths["analysis_dir"] / f"{repo_name}_spdx_comparison.csv"),
        )
    except Exception as exc:
        print(f"[pipeline] Warning: analysis failed: {exc}")

    print(f"[pipeline] Done. Output: {out_path}")
    return True
