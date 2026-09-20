"""The research artifacts are published to the docs site, from one source.

`research/state-of-mcp-2026/` sits outside `docs/`, so MkDocs could not serve it
and the corpus study — cited by CITATION.cff, both Black Hat abstracts, the OWASP
outreach note and the awesome-list entries — had no https address. The link from
`docs/STATE-OF-MCP-SECURITY-2026.md` answered 404 on the deployed site.

`scripts/mkdocs_hooks.py` adds those files to the build in place. These tests
hold the two properties that makes safe: the files are never copied into `docs/`
(so `make report` and the figure guards keep their single path), and every link
that escapes the research directory has an explicit rewrite (so a new one fails
here rather than becoming a 404 nobody sees).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
RESEARCH = REPO_ROOT / "research/state-of-mcp-2026"


def _hooks():
    spec = importlib.util.spec_from_file_location(
        "mkdocs_hooks", REPO_ROOT / "scripts" / "mkdocs_hooks.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["mkdocs_hooks"] = module
    spec.loader.exec_module(module)
    return module


hooks = pytest.importorskip(
    "mkdocs.structure.files", reason="mkdocs is not installed"
) and _hooks()


def test_every_published_file_exists_on_disk() -> None:
    """The site advertises these URLs; a missing source is a 404 we published."""
    missing = [n for n in hooks.PUBLISHED_FILES if not (RESEARCH / n).is_file()]
    assert not missing, f"PUBLISHED_FILES names files that do not exist: {missing}"


def test_published_files_are_not_duplicated_into_docs() -> None:
    """One source of truth.

    A copy under docs/ would be a second file to keep in step with
    `make report`, and `scripts/check_report_figures.py` asserts prose against
    results.json at the research path only — so a forked copy could disagree
    with the numbers while every guard stayed green.
    """
    for name in hooks.PUBLISHED_FILES:
        copied = REPO_ROOT / "docs" / hooks.RESEARCH_DIR / name
        assert not copied.exists(), (
            f"docs/{hooks.RESEARCH_DIR}/{name} exists. The MkDocs hook publishes "
            f"these from research/ at build time; a committed copy forks the text."
        )


@pytest.mark.parametrize(
    "name", [n for n in ("REPORT.md", "PREVALENCE.md") if (RESEARCH / n).is_file()]
)
def test_no_escaping_link_is_left_unrewritten(name: str) -> None:
    """A relative link climbing out of research/ must have a rewrite rule.

    Inside the built site the docs directory is the root, so `../../docs/x`
    climbs above it. These resolve to nothing and render as a dead link.
    """
    text = (RESEARCH / name).read_text(encoding="utf-8")
    uncovered = hooks.uncovered_links(text)
    assert not uncovered, (
        f"{name} has relative link(s) that escape the research directory with no "
        f"entry in _LINK_REWRITES: {sorted(uncovered)}. Add each to that table in "
        f"scripts/mkdocs_hooks.py, mapping it to a path that resolves in the "
        f"built site or to an absolute repository URL."
    )


def test_rewrite_maps_docs_targets_inside_the_site() -> None:
    out = hooks.rewrite_links("see [coverage](../../docs/coverage.json) now")
    assert "](../../coverage.json)" in out


def test_rewrite_sends_non_site_targets_to_the_repository() -> None:
    out = hooks.rewrite_links("cite [this](../../CITATION.cff)")
    assert "https://github.com/sattyamjjain/agent-audit-kit/blob/main/CITATION.cff" in out


def test_rewrite_leaves_sibling_and_absolute_links_alone() -> None:
    """Siblings are published too, so they already resolve."""
    text = "[a](results.json) [b](REPORT.md) [c](https://example.com) [d](#anchor)"
    assert hooks.rewrite_links(text) == text


def test_the_link_scanner_actually_finds_links() -> None:
    """Guard the guard: a regex that matches nothing makes the check vacuous."""
    found = hooks.relative_link_targets(
        (RESEARCH / "REPORT.md").read_text(encoding="utf-8")
    )
    assert len(found) > 3, f"only {len(found)} relative links found in REPORT.md"


def test_report_pdf_is_built_from_the_committed_results() -> None:
    """The site serves this PDF at a stable URL, so a stale one is a wrong number.

    It had been stale for roughly two months: the PDF was last written
    2026-07-26 while results.json moved three times after it, because nothing
    regenerated it and nothing compared them.
    """
    spec = importlib.util.spec_from_file_location(
        "render_report_pdf", REPO_ROOT / "scripts" / "render_report_pdf.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["render_report_pdf"] = module
    spec.loader.exec_module(module)

    stamped = module.stamped_digest()
    assert stamped is not None, (
        "the report PDF carries no source stamp, so nothing records which "
        "numbers it shows. Run `make report-pdf` and commit both files."
    )
    assert stamped == module.results_digest(), (
        "the report PDF was rendered from a different results.json. "
        "Run `make report-pdf` and commit."
    )
