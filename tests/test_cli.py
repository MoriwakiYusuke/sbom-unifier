"""Tests for the CLI entry point."""

from unittest.mock import patch

import pytest

from sbom_unifier.cli import build_parser, main


def test_build_parser_choices_from_registry():
    parser = build_parser()
    actions = {a.dest: a for a in parser._actions}
    assert set(actions["tools"].choices) == {"sbom-tool", "syft", "trivy", "github"}
    assert set(actions["base_tool"].choices) == {"sbom-tool", "syft", "trivy", "github", "manual"}


def test_main_list_tools_prints_registry(capsys):
    rc = main(["--list-tools"])
    out = capsys.readouterr().out
    assert "sbom-tool" in out
    assert "syft" in out
    assert "trivy" in out
    assert "github" in out
    assert "manual" in out
    assert rc == 0


def test_main_invokes_run_pipeline_with_url():
    with patch("sbom_unifier.cli.run_pipeline", return_value=True) as mock_run:
        rc = main(["https://github.com/x/y"])
    assert rc == 0
    args, kwargs = mock_run.call_args
    assert kwargs["url"] == "https://github.com/x/y"


def test_main_returns_nonzero_on_pipeline_failure():
    with patch("sbom_unifier.cli.run_pipeline", return_value=False):
        rc = main(["https://github.com/x/y"])
    assert rc == 1


def test_main_requires_url_or_list_tools():
    with pytest.raises(SystemExit):
        main([])
