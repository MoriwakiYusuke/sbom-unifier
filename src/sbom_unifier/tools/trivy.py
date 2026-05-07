"""SBOM generation using Aqua Security Trivy."""

import os
import shutil
import subprocess
from pathlib import Path

from .registry import REGISTRY, ToolEntry

TRIVY_SBOM_FILENAME = "trivy-sbom.json"


def generate_sbom_for_repo(
    repo_path: Path,
    output_dir: Path,
) -> bool:
    """Run Trivy against a single repository and write the SBOM to output_dir.

    Args:
        repo_path: Path to the repository root.
        output_dir: Destination directory for the generated SBOM file.

    Returns:
        True on success, False on failure.
    """
    repo_name = repo_path.name
    final_sbom_path = output_dir / TRIVY_SBOM_FILENAME

    print(f"Processing: {repo_name}")

    # Save the original working directory before changing into the repo.
    original_dir = os.getcwd()

    try:
        os.chdir(repo_path)

        temp_sbom_filename = "spdx-json-by-trivy.json"
        command = ["trivy", "fs", ".", "--format", "spdx-json", "--output", temp_sbom_filename]
        print(f"   Executing: {' '.join(command)}")

        subprocess.run(command, check=True, capture_output=True, text=True)
        print("Trivy execution successful.")

        # Move the output file to the final output location.
        output_dir.mkdir(parents=True, exist_ok=True)
        print(f"   Moving SBOM to: {final_sbom_path}")
        shutil.move(temp_sbom_filename, str(final_sbom_path))
        print("SBOM file saved.")

        return True

    except FileNotFoundError:
        print("Error: The command 'trivy' was not found.")
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
    """Run Trivy against repo_path; output goes to output_dir/trivy-sbom.json."""
    return generate_sbom_for_repo(
        repo_path=repo_path,
        output_dir=output_dir,
    )


TOOL = ToolEntry(
    name="trivy",
    label="Trivy",
    output_filename="trivy-sbom.json",
    generate=generate,
    can_be_base=True,
    default_merge_position=30,
    description="Aqua Security Trivy SBOM generator (native CLI on PATH).",
)

REGISTRY.register(TOOL)
