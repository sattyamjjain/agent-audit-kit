"""The README is machine-written in places. This is the contract.

Several daily jobs write into README.md: `sync_rule_count.py`,
`sync_scanner_count.py`, `sync_fp_badge.py`, `gen_owasp_coverage.py` and
`index_cadence.py`. Each looks for a specific HTML-comment marker. A prose edit
that drops one takes the corresponding number out of automation.

Most of those writers fail loudly on a missing marker. **`gen_owasp_coverage.py`
does not** — `scripts/gen_owasp_coverage.py` returns False and writes nothing if
its markers are absent, it has no `--check` mode, and its tests only assert the
module exits 0. Losing that marker would freeze the OWASP coverage table with
nothing to notice, which is the same failure class as the release-time latency
guard fixed in 0.5.2.

So the markers are asserted here rather than trusted to care.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).parent.parent
README = REPO / "README.md"


def _text() -> str:
    return README.read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# Markers the daily jobs write into
# --------------------------------------------------------------------------

# (open marker, closing family). The writer for each is named in the docstring.
_SCALAR_MARKERS = [
    "rule-count:total",
    "scanner-count:total",
    "test-count:total",
    "fix-recipe-coverage:count",
    "fix-recipe-coverage:pct",
    "report:corpus",
    "report:noauth-pct",
    "report:noauth-n",
    "report:inline-auth-pct",
    "report:inline-auth-n",
    "report:inline-auth-d",
]


@pytest.mark.parametrize("marker", _SCALAR_MARKERS)
def test_scalar_marker_is_present_and_well_formed(marker: str) -> None:
    family = marker.split(":")[0]
    pattern = re.escape(f"<!-- {marker} -->") + r".*?" + re.escape(f"<!-- /{family} -->")
    assert re.search(pattern, _text(), re.S), (
        f"README lost the {marker!r} marker. `scripts/sync_rule_count.py` writes "
        "that number; without the marker the figure stops updating."
    )


@pytest.mark.parametrize(
    "block_open,block_close,writer",
    [
        ("<!-- owasp-coverage:start -->", "<!-- owasp-coverage:end -->", "gen_owasp_coverage.py"),
        ("<!-- fp-badge -->", "<!-- /fp-badge -->", "sync_fp_badge.py"),
        ("<!-- index-cadence -->", "<!-- /index-cadence -->", "index_cadence.py"),
    ],
)
def test_block_marker_is_present(block_open: str, block_close: str, writer: str) -> None:
    text = _text()
    assert block_open in text and block_close in text, (
        f"README lost {block_open}. `scripts/{writer}` writes that block."
    )


def test_owasp_coverage_marker_specifically() -> None:
    """Called out on its own because this is the one that fails silently.

    `gen_owasp_coverage.py` returns False and writes nothing when the marker is
    absent, and has no --check mode to catch it afterwards.
    """
    text = _text()
    assert "<!-- owasp-coverage:start -->" in text
    assert "<!-- owasp-coverage:end -->" in text
    body = text.split("<!-- owasp-coverage:start -->")[1].split("<!-- owasp-coverage:end -->")[0]
    assert "ASI01" in body, "the OWASP block is present but empty"


def test_every_category_has_a_count_marker() -> None:
    """One marker per Category enum member, or a category silently stops counting."""
    from agent_audit_kit.models import Category

    found = set(re.findall(r"<!-- category-count:([A-Z0-9_]+) -->", _text()))
    expected = {c.name for c in Category}
    assert expected <= found, f"README has no count marker for: {sorted(expected - found)}"


# --------------------------------------------------------------------------
# Counts stated in prose must be stated in a phrasing the guard matches
# --------------------------------------------------------------------------


def test_stated_counts_use_a_guarded_phrasing() -> None:
    """`check_counts.py` only checks counts written one of its known ways.

    A count phrased any other way is never looked at and rots while the guard
    reports clean — the documented `registered scanners` failure. So any count
    key the README talks about has to be matched by at least one pattern.
    """
    import scripts.check_counts as cc

    text = _text()
    matched = {key for pat, key in cc.PATTERNS for _ in pat.finditer(text)}
    # Rules and scanners are stated only inside generated markers, which are a
    # stronger guarantee than a prose pattern, so they are not required here.
    for key in ("commands", "frameworks", "categories", "platforms"):
        assert key in matched, (
            f"README states no {key!r} count in a phrasing check_counts.py "
            "matches. Reuse a guarded phrasing or add one to its PATTERNS."
        )


# --------------------------------------------------------------------------
# The README is also the PyPI long_description
# --------------------------------------------------------------------------


def test_readme_has_no_relative_links() -> None:
    """`pyproject.toml` sets `readme = "README.md"`.

    PyPI renders it verbatim and does not resolve repository-relative paths, so
    a relative link is a broken link on the page where people decide whether to
    install. There were 42 of them before 0.6.3.
    """
    relative = re.findall(r"\]\((?!https?://|#)([^)]+)\)", _text())
    assert not relative, f"relative links break on PyPI: {sorted(set(relative))[:10]}"


def test_pyproject_still_points_at_this_readme() -> None:
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    assert 'readme = "README.md"' in text


# --------------------------------------------------------------------------
# Length budget
# --------------------------------------------------------------------------


def test_readme_stays_scannable() -> None:
    """A budget, not a style rule.

    The README reached 7,056 words, against a 2026 median of 800-1,500 and a
    reader who decides in under thirty seconds. The cap is deliberately well
    above the target so ordinary additions are fine; crossing it means content
    belongs in `docs/`, which the nav now reaches.
    """
    words = len(_text().split())
    assert words <= 2500, (
        f"README is {words} words. Move a section to docs/ and link it rather "
        "than trimming meaning out of the front page."
    )


def test_quick_start_is_near_the_top() -> None:
    """A reader decides in seconds; runnable code has to be in the first screen."""
    lines = _text().splitlines()
    idx = next((i for i, line in enumerate(lines) if line.startswith("## Quick start")), None)
    assert idx is not None, "README lost its Quick start section"
    assert idx < 40, f"Quick start is at line {idx + 1}; it was at line 69 before 0.6.3"


# --------------------------------------------------------------------------
# Docs the README links to must exist
# --------------------------------------------------------------------------


def test_every_docs_site_link_has_a_source_page() -> None:
    """A 404 from the front page is worse than a missing link."""
    # Docs are linked as GitHub blob URLs, not mkdocs-site URLs. The GitHub
    # Pages origin serves the MCP Security Index, and no workflow runs mkdocs,
    # so `…github.io/agent-audit-kit/getting-started/` is a 404 today -- as the
    # link check proved when this README first used that form.
    blob = "https://github.com/sattyamjjain/agent-audit-kit/blob/main/docs/"
    pages = set(re.findall(re.escape(blob) + r"([A-Za-z0-9_./-]+\.md)", _text()))
    assert pages, "README links to no docs page at all"
    for page in pages:
        assert (REPO / "docs" / page).is_file(), (
            f"README links to docs/{page} which does not exist"
        )


def test_readme_does_not_link_to_the_unpublished_docs_site() -> None:
    """`sattyamjjain.github.io/agent-audit-kit/` is the MCP Security Index.

    No workflow runs mkdocs, so every `…/<page>/` URL under that origin 404s.
    The Index root and its `/data/` files are fine.
    """
    bad = re.findall(
        r"https://sattyamjjain\.github\.io/agent-audit-kit/([a-z0-9-]+)/(?=[)\s\]])",
        _text(),
    )
    assert not bad, f"these link to the unpublished mkdocs site: {sorted(set(bad))}"


def test_every_mkdocs_nav_target_exists() -> None:
    text = (REPO / "mkdocs.yml").read_text(encoding="utf-8")
    nav = text[text.index("nav:"):text.index("markdown_extensions:")]
    targets = re.findall(r":\s*([A-Za-z0-9_./-]+\.md)\s*$", nav, re.M)
    assert targets, "mkdocs nav has no page targets"
    missing = [t for t in targets if not (REPO / "docs" / t).is_file()]
    assert not missing, f"mkdocs nav points at missing pages: {missing}"
