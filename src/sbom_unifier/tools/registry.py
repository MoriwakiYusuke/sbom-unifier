"""Tool registry: single source of truth for SBOM source tools."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class ToolEntry:
    """Declarative metadata for an SBOM source tool.

    A tool either generates an SBOM by running a command (generate is a callable),
    or represents a non-generating slot (e.g. user-uploaded SBOM, generate=None).
    """

    name: str
    label: str
    output_filename: str
    output_subpath: str | None = None
    generate: Callable[..., bool] | None = None
    can_be_base: bool = True
    default_merge_position: int = 100
    requires_token: bool = False
    description: str = ""


class ToolRegistry:
    """Mutable in-memory registry of ToolEntry objects keyed by name."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolEntry] = {}

    def register(self, entry: ToolEntry) -> None:
        if entry.name in self._tools:
            raise ValueError(f"Tool {entry.name!r} is already registered")
        self._tools[entry.name] = entry

    def get(self, name: str) -> ToolEntry:
        return self._tools[name]

    def all(self) -> list[ToolEntry]:
        return list(self._tools.values())

    def generators(self) -> list[ToolEntry]:
        return [t for t in self._tools.values() if t.generate is not None]

    def base_candidates(self) -> list[ToolEntry]:
        return [t for t in self._tools.values() if t.can_be_base]

    def default_merge_order(self) -> list[ToolEntry]:
        return sorted(self._tools.values(), key=lambda t: t.default_merge_position)

    def filename_for(self, name: str) -> str:
        entry = self._tools[name]
        return entry.output_subpath or entry.output_filename


REGISTRY = ToolRegistry()
