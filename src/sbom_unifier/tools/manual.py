"""User-uploaded SBOM slot. Not a generator; merged at the end of the order."""

from .registry import REGISTRY, ToolEntry

TOOL = ToolEntry(
    name="manual",
    label="Manual upload",
    output_filename="custom-sbom.json",
    generate=None,
    can_be_base=True,
    default_merge_position=999,
    description="User-uploaded supplemental SBOM merged at the end (or used as base if selected).",
)

REGISTRY.register(TOOL)
