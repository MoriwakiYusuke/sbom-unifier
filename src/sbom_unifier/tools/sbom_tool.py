"""SBOM generation using Microsoft sbom-tool (.NET)."""

import shutil
import subprocess
from pathlib import Path

from .registry import REGISTRY, ToolEntry


def generate_sbom_for_repo(
    repo_path: Path,
    output_dir: Path,
    package_name: str,
    package_supplier: str = "Unknown",
    package_version: str = "latest",
) -> bool:
    """Run sbom-tool against a single repository and move the output into output_dir.

    Args:
        repo_path: Path to the repository root.
        output_dir: Destination directory for the generated SBOM manifest.
        package_name: Name of the package / repository.
        package_supplier: Supplier / owner of the package.
        package_version: Package version string passed to sbom-tool.

    Returns:
        True on success, False on failure.
    """
    final_manifest_path = output_dir / "_manifest"

    print(f"Processing: {package_name}")
    print(f"   Package Name: {package_name}")
    print(f"   Package Supplier: {package_supplier}")

    # Remove any stale _manifest directory left inside the repo itself.
    manifest_in_repo = repo_path / "_manifest"
    if manifest_in_repo.is_dir():
        print("   Found existing '_manifest' directory. Removing it.")
        shutil.rmtree(manifest_in_repo)

    # Build the sbom-tool command.
    command = [
        "sbom-tool",
        "generate",
        "-bc",
        str(repo_path),
        "-b",
        str(repo_path),
        "-pn",
        package_name,
        "-ps",
        package_supplier,
        "-m",
        str(repo_path),
        "-pv",
        package_version,
    ]

    print(f"   Executing: {' '.join(command)}")

    try:
        # Run with check=False: sbom-tool exits 1 on warnings but still produces
        # the manifest, so we determine success by file existence.
        result = subprocess.run(command, capture_output=True, text=True)

        if manifest_in_repo.is_dir():
            output_dir.mkdir(parents=True, exist_ok=True)

            if result.returncode != 0:
                print("sbom-tool completed with warnings (exit code 1), but SBOM was generated.")
            else:
                print("SBOM generation successful.")

            # When re-generating, replace any pre-existing output manifest.
            if final_manifest_path.exists():
                print(f"   Removing existing output: {final_manifest_path}")
                if final_manifest_path.is_dir():
                    shutil.rmtree(final_manifest_path)
                else:
                    final_manifest_path.unlink()

            print(f"   Moving '{manifest_in_repo}' into: {output_dir}")
            shutil.move(str(manifest_in_repo), str(final_manifest_path))
            print("Move successful.")
            return True
        else:
            print(f"Error: Could not find generated manifest directory at '{manifest_in_repo}'")
            if result.stderr:
                print(f"   [stderr]:\n{result.stderr.strip()[:500]}")
            return False

    except FileNotFoundError:
        print("Error: The command 'sbom-tool' was not found.")
        return False


def generate(
    *,
    repo_path: Path,
    output_dir: Path,
    owner: str,
    repo_name: str,
    **_: object,
) -> bool:
    """Run Microsoft sbom-tool against repo_path; output goes under output_dir."""
    return generate_sbom_for_repo(
        repo_path=repo_path,
        output_dir=output_dir,
        package_name=repo_name,
        package_supplier=owner,
    )


TOOL = ToolEntry(
    name="sbom-tool",
    label="Microsoft SBOM Tool",
    output_filename="manifest.spdx.json",
    output_subpath="_manifest/spdx_2.2/manifest.spdx.json",
    generate=generate,
    can_be_base=True,
    default_merge_position=10,
    description="Microsoft sbom-tool (.NET) — used as the default base SBOM.",
)

REGISTRY.register(TOOL)
