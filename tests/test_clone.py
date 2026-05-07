"""Tests for clone helpers."""

from sbom_unifier.clone import get_repo_name_from_url, parse_github_url


def test_parse_github_url_basic():
    assert parse_github_url("https://github.com/pallets/flask") == ("pallets", "flask")


def test_parse_github_url_with_dot_git():
    assert parse_github_url("https://github.com/pallets/flask.git") == ("pallets", "flask")


def test_parse_github_url_returns_none_for_non_github():
    assert parse_github_url("https://gitlab.com/x/y") is None


def test_get_repo_name_from_url_strips_git_suffix():
    assert get_repo_name_from_url("https://github.com/pallets/flask.git") == "flask"
