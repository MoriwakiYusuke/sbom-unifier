"""Tests for tool registry."""

from dataclasses import FrozenInstanceError

import pytest

from sbom_unifier.tools.registry import REGISTRY, ToolEntry, ToolRegistry


def test_tool_entry_minimal_fields():
    entry = ToolEntry(
        name="dummy",
        label="Dummy",
        output_filename="dummy.json",
    )
    assert entry.name == "dummy"
    assert entry.label == "Dummy"
    assert entry.output_filename == "dummy.json"
    assert entry.output_subpath is None
    assert entry.generate is None
    assert entry.can_be_base is True
    assert entry.default_merge_position == 100
    assert entry.requires_token is False
    assert entry.description == ""


def test_tool_entry_is_frozen():
    entry = ToolEntry(name="x", label="X", output_filename="x.json")
    with pytest.raises((FrozenInstanceError, AttributeError)):
        entry.name = "y"  # type: ignore[misc]


@pytest.fixture
def fresh_registry():
    return ToolRegistry()


def _make_entry(
    name, *, generate=lambda **_: True, position=100, can_be_base=True, output="x.json"
):
    return ToolEntry(
        name=name,
        label=name.title(),
        output_filename=output,
        generate=generate,
        can_be_base=can_be_base,
        default_merge_position=position,
    )


def test_registry_register_and_get(fresh_registry):
    entry = _make_entry("syft", position=20)
    fresh_registry.register(entry)
    assert fresh_registry.get("syft") is entry


def test_registry_rejects_duplicate(fresh_registry):
    fresh_registry.register(_make_entry("syft"))
    with pytest.raises(ValueError, match="already registered"):
        fresh_registry.register(_make_entry("syft"))


def test_registry_get_unknown_raises(fresh_registry):
    with pytest.raises(KeyError):
        fresh_registry.get("nope")


def test_registry_generators_excludes_non_generators(fresh_registry):
    fresh_registry.register(_make_entry("syft"))
    fresh_registry.register(_make_entry("manual", generate=None, can_be_base=False))
    names = [t.name for t in fresh_registry.generators()]
    assert names == ["syft"]


def test_registry_base_candidates(fresh_registry):
    fresh_registry.register(_make_entry("syft", can_be_base=True))
    fresh_registry.register(_make_entry("manual", generate=None, can_be_base=False))
    names = [t.name for t in fresh_registry.base_candidates()]
    assert names == ["syft"]


def test_registry_default_merge_order_sorted(fresh_registry):
    fresh_registry.register(_make_entry("trivy", position=30))
    fresh_registry.register(_make_entry("syft", position=20))
    fresh_registry.register(_make_entry("manual", generate=None, position=999, can_be_base=False))
    names = [t.name for t in fresh_registry.default_merge_order()]
    assert names == ["syft", "trivy", "manual"]


def test_registry_filename_for_uses_subpath(fresh_registry):
    entry = ToolEntry(
        name="sbom-tool",
        label="Microsoft SBOM Tool",
        output_filename="manifest.spdx.json",
        output_subpath="_manifest/spdx_2.2/manifest.spdx.json",
        generate=lambda **_: True,
    )
    fresh_registry.register(entry)
    assert fresh_registry.filename_for("sbom-tool") == "_manifest/spdx_2.2/manifest.spdx.json"


def test_registry_filename_for_falls_back_to_filename(fresh_registry):
    fresh_registry.register(_make_entry("syft", output="syft-sbom.json"))
    assert fresh_registry.filename_for("syft") == "syft-sbom.json"


def test_module_level_registry_singleton_exists():
    assert isinstance(REGISTRY, ToolRegistry)


def test_manual_tool_is_registered_on_package_import():
    # Importing sbom_unifier.tools triggers tools/__init__.py which imports manual.
    import sbom_unifier.tools  # noqa: F401
    from sbom_unifier.tools.registry import REGISTRY

    entry = REGISTRY.get("manual")
    assert entry.generate is None
    assert entry.can_be_base is True
    assert entry.default_merge_position == 999
    assert entry.output_filename == "custom-sbom.json"


def test_sbom_tool_registered_with_subpath():
    import sbom_unifier.tools  # noqa: F401
    from sbom_unifier.tools.registry import REGISTRY

    entry = REGISTRY.get("sbom-tool")
    assert entry.output_subpath == "_manifest/spdx_2.2/manifest.spdx.json"
    assert entry.can_be_base is True
    assert entry.generate is not None


def test_full_registry_has_all_expected_tools():
    import sbom_unifier.tools  # noqa: F401
    from sbom_unifier.tools.registry import REGISTRY

    names = {t.name for t in REGISTRY.all()}
    assert names == {"sbom-tool", "syft", "trivy", "github", "manual"}


def test_full_registry_default_merge_order_position():
    import sbom_unifier.tools  # noqa: F401
    from sbom_unifier.tools.registry import REGISTRY

    order = [t.name for t in REGISTRY.default_merge_order()]
    # sbom-tool(10) < github(15) < syft(20) < trivy(30) < manual(999)
    assert order == ["sbom-tool", "github", "syft", "trivy", "manual"]


def test_full_registry_generators_excludes_manual():
    import sbom_unifier.tools  # noqa: F401
    from sbom_unifier.tools.registry import REGISTRY

    names = {t.name for t in REGISTRY.generators()}
    assert names == {"sbom-tool", "syft", "trivy", "github"}


def test_full_registry_base_candidates_includes_manual():
    import sbom_unifier.tools  # noqa: F401
    from sbom_unifier.tools.registry import REGISTRY

    names = {t.name for t in REGISTRY.base_candidates()}
    assert names == {"sbom-tool", "syft", "trivy", "github", "manual"}
