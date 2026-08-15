"""Relative links inside docs/ must resolve to files that exist.

The `Check README + docs links` CI job runs lychee over the whole tree, which
also hits the network — so a flaky external host makes it red and the real
breakage hides in the noise. This test covers only the half that is fully
deterministic and entirely our fault: relative links to files in this repo.

Four were dangling when this was added: a link written one directory level too
shallow, two links to per-rule pages that were never authored (for rules that do
exist in the registry), and a link to a doc explicitly marked "queued for v0.4.0".
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS = REPO_ROOT / "docs"

# [text](./path) or [text](../path) — anchors and query strings stripped.
_RELATIVE_LINK_RE = re.compile(r"\[[^\]]+\]\((\.{1,2}/[^)\s]+)\)")

_SKIP_DIRS = {"node_modules", "site", ".venv", "__pycache__"}


def _markdown_files() -> list[Path]:
    return [
        p for p in DOCS.rglob("*.md")
        if not any(part in _SKIP_DIRS for part in p.parts)
    ]


def test_relative_links_in_docs_resolve() -> None:
    dangling: list[str] = []
    for md in _markdown_files():
        try:
            text = md.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for match in _RELATIVE_LINK_RE.finditer(text):
            raw = match.group(1).split("#", 1)[0].split("?", 1)[0]
            if not raw:
                continue
            target = (md.parent / raw).resolve()
            if not target.exists():
                rel = md.relative_to(REPO_ROOT).as_posix()
                dangling.append(f"{rel}: {match.group(1)}")

    assert not dangling, (
        "relative link(s) in docs/ point at files that do not exist:\n  "
        + "\n  ".join(sorted(set(dangling)))
    )


def test_docs_tree_is_actually_being_checked() -> None:
    """Guard the guard: if the glob stops finding files, the test above is vacuous."""
    files = _markdown_files()
    assert len(files) > 20, f"only {len(files)} markdown files found under docs/"
    assert any(_RELATIVE_LINK_RE.search(p.read_text(encoding="utf-8", errors="ignore"))
               for p in files), "no relative links found at all — the regex may have broken"
