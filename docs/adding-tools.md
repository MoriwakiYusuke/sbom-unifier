# Adding a New SBOM Generator

How to plug a new SBOM generator (e.g. `cyclonedx-python`) into `sbom-unifier`.

## Big picture

Every generator in `sbom-unifier` lives under `src/sbom_unifier/tools/` and self-registers. Three steps:

1. Create `src/sbom_unifier/tools/<name>.py`
2. Add one line `from . import <name>` to the `# === ADD NEW TOOL HERE ===` block of `src/sbom_unifier/tools/__init__.py`
3. Add a test and run `pytest`

That's enough to surface the new tool in the CLI's `--tools` choices, the Web UI checkboxes, the default merge order, and the base SBOM selector.

## Step-by-step

### 1. Create the tool file

Example: `src/sbom_unifier/tools/cyclonedx.py`

```python
"""CycloneDX (Python) SBOM generator integration."""
from __future__ import annotations

from pathlib import Path
import subprocess

from .registry import REGISTRY, ToolEntry


def generate(
    *,
    repo_path: Path,
    output_dir: Path,
    skip_existing: bool,
    **_: object,
) -> bool:
    """Run cyclonedx-py against repo_path; output goes to output_dir."""
    out = output_dir / "cyclonedx-sbom.json"
    if skip_existing and out.exists():
        return True
    try:
        subprocess.run(
            ["cyclonedx-py", "environment", "-o", str(out)],
            cwd=repo_path,
            check=True,
        )
        return out.exists()
    except subprocess.CalledProcessError as exc:
        print(f"[cyclonedx] failed: {exc}")
        return False


TOOL = ToolEntry(
    name="cyclonedx",
    label="CycloneDX (Python)",
    output_filename="cyclonedx-sbom.json",
    generate=generate,
    can_be_base=True,
    default_merge_position=25,    # after syft (20), before trivy (30)
    description="CycloneDX-Python: SBOM generation from a pip environment.",
)

REGISTRY.register(TOOL)
```

### 2. Wire it into the central `__init__.py`

Add one line to the ADD HERE block in `src/sbom_unifier/tools/__init__.py`:

```python
# === ADD NEW TOOL HERE ===
from . import sbom_tool   # noqa: F401
from . import syft        # noqa: F401
from . import trivy       # noqa: F401
from . import github      # noqa: F401
from . import cyclonedx   # noqa: F401  ← added
from . import manual      # noqa: F401
# === END ADD NEW TOOL HERE ===
```

### 3. Add a registration test

In `tests/test_registry.py`:

```python
def test_cyclonedx_registered():
    import sbom_unifier.tools  # noqa: F401
    from sbom_unifier.tools.registry import REGISTRY

    entry = REGISTRY.get("cyclonedx")
    assert entry.output_filename == "cyclonedx-sbom.json"
    assert entry.default_merge_position == 25
```

### 4. Add a fixture (recommended)

To exercise the new tool in snapshot / semantic tests, hand-write `tests/fixtures/tiny-project/inputs/cyclonedx-sbom.json` and regenerate the expected output:

```bash
rm tests/fixtures/tiny-project/expected/unified_sbom.json
pytest tests/test_snapshot.py    # regenerates the expected snapshot
# eyeball the result, then commit
```

## ToolEntry fields

| Field | Required | Meaning |
|---|---|---|
| `name` | ✓ | CLI / Web UI ID. Must be unique. e.g. `"syft"` |
| `label` | ✓ | Display name. e.g. `"Syft"` |
| `output_filename` | ✓ | Output filename directly under the project directory |
| `output_subpath` | | Use when output goes into a subdirectory (e.g. sbom-tool: `_manifest/spdx_2.2/manifest.spdx.json`) |
| `generate` | | Generator function. `None` means a non-generating slot (e.g. user upload) |
| `can_be_base` | | Whether this tool can serve as the base SBOM (default `True`) |
| `default_merge_position` | | Priority in the default merge order. Lower = processed earlier |
| `requires_token` | | Whether this tool needs `GITHUB_TOKEN` (or another env var) |
| `description` | | One-line description (used by `--list-tools` and the Web UI) |

## generate() signature contract

Every `generate()` accepts these **shared kwargs** (use `**_` to ignore the ones you don't need):

```python
def generate(
    *,
    repo_path: Path,            # path to the cloned repo
    output_dir: Path,           # SBOM output directory (the project directory)
    skip_existing: bool,        # whether to skip if the output already exists
    owner: str,                 # GitHub owner
    repo_name: str,             # repository name
    github_token: str | None,   # API token
    **_: object,
) -> bool:
    ...
```

Return value: **`True` on successful generation, `False` otherwise**.

## default_merge_position guidance

Assign `default_merge_position` by this convention:

| Range | Use |
|---|---|
| 0–9 | Reserved |
| 10 | Highest-priority base candidate (sbom-tool) |
| 11–19 | Fallback base candidates |
| 20–29 | Primary generators (syft, etc.) |
| 30–49 | Secondary generators (trivy, etc.) |
| 50–998 | Sub-tools |
| 999 | manual (final slot) |

## Checklist

- [ ] Created `src/sbom_unifier/tools/<name>.py` and called `REGISTRY.register(TOOL)`
- [ ] Added `from . import <name>` to the ADD HERE block in `tools/__init__.py`
- [ ] Added a registration test in `tests/test_registry.py`
- [ ] CLI: `sbom-unifier --list-tools` shows the new tool
- [ ] Web UI: the new tool appears in the `/` checkboxes and base selector
- [ ] `pytest --cov=sbom_unifier --cov-fail-under=55` is still green
