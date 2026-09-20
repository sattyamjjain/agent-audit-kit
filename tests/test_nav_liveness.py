"""`scripts/nav_liveness.py` — the parsing half, offline.

The network half runs in CI (`link-check.yml`, job `nav-liveness`). What is
worth testing here is everything that decides *which* URLs get requested,
because a parser that silently stops matching turns a green check into a check
of nothing. That is the failure this script exists to prevent, so it would be a
poor joke to reintroduce it one level down.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _module():
    spec = importlib.util.spec_from_file_location(
        "nav_liveness", REPO_ROOT / "scripts" / "nav_liveness.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["nav_liveness"] = module
    spec.loader.exec_module(module)
    return module


nav = _module()

_SAMPLE = """site_name: X
site_url: https://example.test/agent-audit-kit/docs/

nav:
  - Home: index.md
  - Group:
      - One: one.md
      - Nested: a/b/c.md
  - Last: last.md

markdown_extensions:
  - tables
"""


def test_nav_parsing_stops_at_the_end_of_the_block() -> None:
    """`markdown_extensions` must not be read as nav entries."""
    assert nav.nav_sources(_SAMPLE) == ["index.md", "one.md", "a/b/c.md", "last.md"]


def test_index_maps_to_the_directory_root() -> None:
    base = "https://example.test/agent-audit-kit/docs/"
    assert nav.source_to_url("index.md", base) == base


def test_nested_pages_keep_their_path() -> None:
    base = "https://example.test/agent-audit-kit/docs/"
    assert (
        nav.source_to_url("research/state-of-mcp-2026/REPORT.md", base)
        == base + "research/state-of-mcp-2026/REPORT/"
    )


def test_directory_urls_disabled_yields_html_files() -> None:
    base = "https://example.test/docs/"
    assert nav.source_to_url("cli.md", base, directory_urls=False) == base + "cli.html"


def test_site_url_comes_from_mkdocs_not_a_hardcoded_string() -> None:
    assert nav.site_url(_SAMPLE) == "https://example.test/agent-audit-kit/docs/"


def test_real_mkdocs_nav_is_parsed_and_non_empty() -> None:
    """The live config must yield URLs, or CI checks nothing."""
    urls = nav.nav_urls()
    assert len(urls) >= 20, f"only {len(urls)} nav URLs parsed from mkdocs.yml"
    assert all(u.startswith("https://") for u in urls)


def test_every_nav_entry_resolves_to_a_page_the_build_can_produce() -> None:
    """A nav entry is either a file in docs/ or one the MkDocs hook publishes.

    This is the offline half of the liveness check: it catches a renamed or
    deleted page at test time, before the deployed site is the thing that
    reports it.
    """
    docs = REPO_ROOT / "docs"
    published = set()
    hooks_path = REPO_ROOT / "scripts" / "mkdocs_hooks.py"
    if hooks_path.is_file():
        spec = importlib.util.spec_from_file_location("mkdocs_hooks_probe", hooks_path)
        assert spec is not None and spec.loader is not None
        try:
            module = importlib.util.module_from_spec(spec)
            sys.modules["mkdocs_hooks_probe"] = module
            spec.loader.exec_module(module)
            published = {f"{module.RESEARCH_DIR}/{n}" for n in module.PUBLISHED_FILES}
        except ImportError:  # mkdocs absent; fall back to the path convention
            published = set()

    missing = [
        src
        for src in nav.nav_sources()
        if not (docs / src).is_file()
        and src not in published
        and not (REPO_ROOT / src).is_file()
    ]
    assert not missing, (
        f"nav entries with no source page: {missing}. Either the file was "
        f"renamed without updating mkdocs.yml, or it needs adding to "
        f"PUBLISHED_FILES in scripts/mkdocs_hooks.py."
    )


def test_published_assets_are_checked_too() -> None:
    """The PDF, results.json and the abstracts are not nav pages.

    link-check.yml excludes this site's `/docs/` subtree from lychee on the
    grounds that nav-liveness covers it. That is only true if the assets are
    covered as well as the pages, so an empty list here would quietly break the
    promise made in that exclusion's comment.

    It was empty once already: `PUBLISHED_FILES` carries a type annotation, so
    it parses as `AnnAssign` and a walk looking only for `Assign` found nothing.
    """
    assets = nav.published_asset_urls()
    assert assets, (
        "no published assets resolved from scripts/mkdocs_hooks.py — the AST "
        "walk has stopped matching PUBLISHED_FILES, which makes this half of "
        "the liveness check vacuous"
    )
    joined = " ".join(assets)
    assert "state-of-mcp-security-2026.pdf" in joined
    assert "results.json" in joined
    assert all(u.startswith("https://") for u in assets)


def test_published_assets_do_not_duplicate_nav_pages() -> None:
    """REPORT.md and PREVALENCE.md are in the nav; they must not be probed twice."""
    overlap = set(nav.nav_urls()) & set(nav.published_asset_urls())
    assert not overlap, f"probed twice: {sorted(overlap)}"
