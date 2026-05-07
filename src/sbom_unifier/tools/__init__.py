"""Tool registry: import every tool module here so it self-registers."""

# === ADD NEW TOOL HERE ===
# 1. Create tools/<name>.py with a `generate()` function and a
#    `TOOL = ToolEntry(...)` declaration plus REGISTRY.register(TOOL)
#    at module load time.
# 2. Add `from . import <name>` below.
# 3. See docs/adding-tools.md for the full guide.
from . import (
    github,  # noqa: F401
    manual,  # noqa: F401
    sbom_tool,  # noqa: F401
    syft,  # noqa: F401
    trivy,  # noqa: F401
)
from .registry import REGISTRY, ToolEntry  # noqa: F401
# === END ADD NEW TOOL HERE ===
