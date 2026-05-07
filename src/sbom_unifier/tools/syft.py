"""SBOM generation using Anchore Syft."""

import os
import shutil
import subprocess
from pathlib import Path

from .registry import REGISTRY, ToolEntry

SYFT_SBOM_FILENAME = "syft-sbom.json"


def generate_sbom_for_repo(
    repo_path: Path,
    output_dir: Path,
) -> bool:
    """Run Syft against a single repository and write the SBOM to output_dir.

    Args:
        repo_path: Path to the repository root.
        output_dir: Destination directory for the generated SBOM file.

    Returns:
        True on success, False on failure.
    """
    repo_name = repo_path.name
    final_sbom_path = output_dir / SYFT_SBOM_FILENAME

    print(f"Processing: {repo_name}")

    # Save the original working directory before changing into the repo.
    original_dir = os.getcwd()

    try:
        os.chdir(repo_path)

        temp_sbom_filename = "syft-sbom.json"
        command = ["syft", "dir:./", "-o", "spdx-json"]
        print(f"   Executing: {' '.join(command)} > {temp_sbom_filename}")

        result = subprocess.run(command, check=True, capture_output=True, text=True)
        print("Syft execution successful.")

        # Write stdout to a temporary file in the repo directory.
        with open(temp_sbom_filename, "w", encoding="utf-8") as f:
            f.write(result.stdout)

        # Move the temporary file to the final output location.
        output_dir.mkdir(parents=True, exist_ok=True)
        print(f"   Moving SBOM to: {final_sbom_path}")
        shutil.move(temp_sbom_filename, str(final_sbom_path))
        print("SBOM file saved.")

        return True

    except FileNotFoundError:
        print("Error: The command 'syft' was not found.")
        return False
    except subprocess.CalledProcessError as e:
        print("Error executing command.")
        if e.stdout:
            print(f"   [stdout]:\n{e.stdout.strip()}")
        if e.stderr:
            print(f"   [stderr]:\n{e.stderr.strip()}")
        return False
    finally:
        os.chdir(original_dir)


def generate(
    *,
    repo_path: Path,
    output_dir: Path,
    **_: object,
) -> bool:
    """Run Syft against repo_path; output goes to output_dir/syft-sbom.json."""
    return generate_sbom_for_repo(
        repo_path=repo_path,
        output_dir=output_dir,
    )


TOOL = ToolEntry(
    name="syft",
    label="Syft",
    output_filename="syft-sbom.json",
    generate=generate,
    can_be_base=True,
    default_merge_position=20,
    description="Anchore Syft SBOM generator (native CLI on PATH).",
)

REGISTRY.register(TOOL)
