"""Tests for benchmarks/sources.py (C7-C10)."""

from __future__ import annotations

import importlib.util
import sys
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "marketplace_sources", "benchmarks/sources.py"
)
assert spec is not None and spec.loader is not None
sources = importlib.util.module_from_spec(spec)
sys.modules["marketplace_sources"] = sources
spec.loader.exec_module(sources)


def test_server_entry_defaults() -> None:
    e = sources.ServerEntry(source="x", repo="a/b", name="a/b")
    assert e.url == ""
    assert e.category == ""
    assert e.extra == {}


def test_anthropic_official_handles_404() -> None:
    with patch.object(sources, "_fetch_json", return_value=None):
        entries = sources.anthropic_official()
    assert entries == []


def test_anthropic_official_parses_dir_listing() -> None:
    fake = [
        {"type": "dir", "name": "example-plugin", "html_url": "https://github.com/x/example-plugin"},
        {"type": "file", "name": "README.md"},  # ignored
        {"type": "dir", "name": "another", "html_url": "https://github.com/x/another"},
    ]
    with patch.object(sources, "_fetch_json", return_value=fake):
        entries = sources.anthropic_official(limit=10)
    assert len(entries) == 2
    assert entries[0].source == "anthropic-official"
    assert entries[0].name == "example-plugin"
    assert "raw.githubusercontent.com" in entries[0].raw_config_url


def test_cmps_parses_repo_links() -> None:
    html = '''<html>
<a href="https://github.com/acme/helpers">helpers</a>
<a href="https://github.com/docs.site/repo">dotted</a>
<a href="https://github.com/other/mcp-tools">mcp-tools</a>
<a href="https://github.com/acme/helpers">dup</a>
</html>'''
    with patch.object(sources, "_fetch_text", return_value=html):
        entries = sources.claudemarketplaces()
    repos = {e.repo for e in entries}
    assert "acme/helpers" in repos
    assert "other/mcp-tools" in repos
    # duplicates are collapsed
    assert sum(1 for e in entries if e.repo == "acme/helpers") == 1
    # owners with a dot are filtered (looks like a GH org with a dot-name, which
    # is invalid — usually the site shipped a stray link to docs.site/<something>).
    assert not any(e.repo.startswith("docs.site/") for e in entries)


def test_cmps_handles_network_failure() -> None:
    with patch.object(sources, "_fetch_text", return_value=None):
        assert sources.claudemarketplaces() == []


def test_aitmpl_parses_github_urls() -> None:
    html = 'before https://github.com/acme/tool middle https://github.com/x/y end'
    with patch.object(sources, "_fetch_text", return_value=html):
        entries = sources.aitmpl()
    repos = {e.repo for e in entries}
    assert "acme/tool" in repos
    assert "x/y" in repos


def test_buildwithclaude_parses_github_urls() -> None:
    html = '<a href="https://github.com/my-org/myrepo">project</a>'
    with patch.object(sources, "_fetch_text", return_value=html):
        entries = sources.buildwithclaude()
    assert entries
    assert entries[0].source == "bwc"


def test_collect_all_merges_and_dedups() -> None:
    def fake_a(_limit: int) -> list:
        return [sources.ServerEntry(source="s1", repo="x/y", name="x/y")]

    def fake_b(_limit: int) -> list:
        return [
            sources.ServerEntry(source="s2", repo="x/y", name="x/y"),  # dup
            sources.ServerEntry(source="s2", repo="u/v", name="u/v"),
        ]

    with patch.dict(sources.SOURCES, {"a": fake_a, "b": fake_b}, clear=True):
        entries = sources.collect_all()
    assert len(entries) == 2
    repos = sorted(e.repo for e in entries)
    assert repos == ["u/v", "x/y"]


def test_collect_all_survives_crashy_source() -> None:
    def bad(_limit: int) -> list:
        raise RuntimeError("boom")

    def good(_limit: int) -> list:
        return [sources.ServerEntry(source="g", repo="g/ok", name="g/ok")]

    with patch.dict(sources.SOURCES, {"bad": bad, "good": good}, clear=True):
        entries = sources.collect_all()
    assert len(entries) == 1
    assert entries[0].repo == "g/ok"
