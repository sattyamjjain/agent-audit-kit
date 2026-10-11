"""`scripts/nav_liveness.py` — the parsing half, offline.

The network half runs in CI (`link-check.yml`, job `nav-liveness`). What is
worth testing here is everything that decides *which* URLs get requested,
because a parser that silently stops matching turns a green check into a check
of nothing. That is the failure this script exists to prevent, so it would be a
poor joke to reintroduce it one level down.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import urllib.error
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


def test_no_two_nav_entries_land_on_the_same_url() -> None:
    """The nav listed `rules.md` and `rules/index.md`, which MkDocs publishes at one address
    (`.../docs/rules/`), so one of the two entries was a second link to a page it was not."""
    urls = nav.nav_urls()
    duplicated = sorted({url for url in urls if urls.count(url) > 1})
    assert not duplicated, f"nav entries that land on the same URL: {duplicated}"


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


# --------------------------------------------------------------------------
# Rule help pages: the SARIF helpUri targets
# --------------------------------------------------------------------------


def test_every_rule_page_is_probed_and_none_is_probed_twice() -> None:
    """`rules.json` lists every rule; each rule's page is a helpUri target.

    A rule can exist in the registry before its page exists on the site (the docs
    only redeploy on certain pushes), so a liveness check that skipped these would
    be silent about exactly the state it was added to catch.
    """
    bundle = json.loads((REPO_ROOT / "rules.json").read_text(encoding="utf-8"))["rules"]
    urls = nav.rule_page_urls()
    assert len(urls) == len({r["rule_id"] for r in bundle}) > 300
    assert all(u.startswith("https://") and u.endswith("/") for u in urls)
    assert any(u.endswith("/docs/rules/AAK-MCP-003/") for u in urls)
    assert not set(urls) & set(nav.nav_urls()), "a nav page is also swept as a rule page"
    assert not set(urls) & set(nav.published_asset_urls())


def test_rule_page_urls_follow_the_site_layout(tmp_path: Path) -> None:
    bundle = tmp_path / "rules.json"
    bundle.write_text(json.dumps({"rules": [{"rule_id": "AAK-X-001"}, {"rule_id": "AAK-A-001"}]}))
    base = "https://example.test/docs/"
    assert nav.rule_page_urls(base, bundle, True) == [
        "https://example.test/docs/rules/AAK-A-001/",
        "https://example.test/docs/rules/AAK-X-001/",
    ]
    # use_directory_urls: false publishes <id>.html, and the sweep must follow it.
    assert nav.rule_page_urls(base, bundle, False)[0] == "https://example.test/docs/rules/AAK-A-001.html"


def test_a_missing_rule_bundle_yields_no_rule_pages(tmp_path: Path) -> None:
    assert nav.rule_page_urls("https://example.test/docs/", tmp_path / "none.json", True) == []


class _Ok:
    status = 200

    def __enter__(self) -> "_Ok":
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def _server(statuses: list[int]):
    """A urlopen stand-in answering with `statuses` in turn (the last one repeats)."""
    calls: list[int] = []

    def urlopen(request, timeout):  # noqa: ARG001
        calls.append(1)
        code = statuses[min(len(calls), len(statuses)) - 1]
        if code == 200:
            return _Ok()
        raise urllib.error.HTTPError(request.full_url, code, "reason", {}, None)  # type: ignore[arg-type]

    return urlopen, calls


def test_a_transient_cdn_status_is_retried_but_a_404_is_not(monkeypatch) -> None:
    """Several hundred requests will meet a 429 or a 503 sooner or later; that must not
    turn the daily check red. A 404 is the answer the check exists to give."""
    monkeypatch.setattr(nav.time, "sleep", lambda _seconds: None)

    urlopen, calls = _server([503, 429, 200])
    monkeypatch.setattr(nav.urllib.request, "urlopen", urlopen)
    assert nav.probe("https://example.test/a/") == (200, "")
    assert len(calls) == 3

    urlopen, calls = _server([404])
    monkeypatch.setattr(nav.urllib.request, "urlopen", urlopen)
    assert nav.probe("https://example.test/b/")[0] == 404
    assert len(calls) == 1

    urlopen, calls = _server([503])
    monkeypatch.setattr(nav.urllib.request, "urlopen", urlopen)
    assert nav.probe("https://example.test/c/")[0] == 503  # gives up after the retries
    assert len(calls) == nav._RETRIES
