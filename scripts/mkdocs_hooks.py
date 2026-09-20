"""MkDocs build hooks: publish the research artifacts without forking them.

`research/state-of-mcp-2026/` sits outside `docs/`, so MkDocs could not serve it
and the corpus study — the thing every abstract, the citation file and the OWASP
outreach note point a reader at — had no https address at all. The link from
`docs/STATE-OF-MCP-SECURITY-2026.md` to `../research/state-of-mcp-2026/REPORT.md`
answered 404 on the deployed site.

The fix is a build step, not a copy in the tree. `research/state-of-mcp-2026/`
stays the single source: these files are never duplicated into `docs/`, never
committed twice, and `make report` keeps writing to the one path the figure
guards (`scripts/check_report_figures.py`'s ``MUST_AGREE``) already assert
against. MkDocs is told about them at `on_files` time, reading them from where
they live.

**Why the links need rewriting.** The published files are written to be read from
the repository root, so they reach siblings with `../../docs/x` and
`../../CITATION.cff`. Inside the built site the docs directory *is* the root, so
`../../docs/x` climbs above it and `../../CITATION.cff` points at a file the site
does not contain. `_LINK_REWRITES` maps each one explicitly — an enumerated
table, not a pattern, so a rewrite can be read and checked rather than inferred.
Targets that live in `docs/` become site-relative; targets that do not become
absolute GitHub blob URLs, the same convention README.md uses and for the same
reason.

`tests/test_docs_research_publishing.py` fails if a published file grows a
relative link this table does not cover, so the next one is caught at test time
instead of becoming a 404 nobody sees.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from mkdocs.structure.files import File

REPO_ROOT = Path(__file__).resolve().parent.parent
RESEARCH_DIR = "research/state-of-mcp-2026"

_BLOB = "https://github.com/sattyamjjain/agent-audit-kit/blob/main"

#: Files published from `research/state-of-mcp-2026/` into the built site.
#: Markdown becomes a rendered page; everything else is served as-is.
PUBLISHED_FILES: tuple[str, ...] = (
    "REPORT.md",
    "PREVALENCE.md",
    "blackhat-arsenal-abstract.md",
    "blackhat-briefings-abstract.md",
    "results.json",
    "state-of-mcp-security-2026.pdf",
    # Cited by docs/research/mcp-security-baseline-v1.0.md as its snapshot.
    "baseline/mcp-security-baseline-v1.0-2026-07-27.json",
)

#: Every relative link that escapes `research/state-of-mcp-2026/`, mapped to
#: something that resolves inside the built site. Keys are matched literally.
#: A published file is two directories deep in the site, so `../../` reaches the
#: docs root — which is why the `docs/` prefix is dropped rather than kept.
_LINK_REWRITES: dict[str, str] = {
    "../../docs/coverage.json": "../../coverage.json",
    "../../docs/crosswalk/nsa-csi-owasp-agentic.md": "../../crosswalk/nsa-csi-owasp-agentic.md",
    "../../docs/disclosure-policy.md": "../../disclosure-policy.md",
    "../../docs/DISTRIBUTION-CHECKLIST.md": "../../DISTRIBUTION-CHECKLIST.md",
    # Not part of the docs site, so they resolve to the repository instead.
    "../../CITATION.cff": f"{_BLOB}/CITATION.cff",
    "../../rules.json": f"{_BLOB}/rules.json",
    "../../benchmarks/false_positive/RESULTS.md": (
        f"{_BLOB}/benchmarks/false_positive/RESULTS.md"
    ),
}

#: Matches the target of a markdown link that is neither absolute nor an anchor.
_RELATIVE_LINK_RE = re.compile(r"\]\((?!https?:|#|mailto:)([^)]+)\)")


def relative_link_targets(text: str) -> set[str]:
    """Every relative markdown link target in `text`."""
    return set(_RELATIVE_LINK_RE.findall(text))


def uncovered_links(text: str) -> set[str]:
    """Relative targets that escape the research directory and are not rewritten.

    A link that stays inside the directory (``results.json``, ``REPORT.md``)
    resolves on its own because its sibling is published too, so only the
    climbing ones need a rule.
    """
    return {
        target
        for target in relative_link_targets(text)
        if target.startswith("../") and target not in _LINK_REWRITES
    }


def rewrite_links(text: str) -> str:
    """Apply `_LINK_REWRITES` to every relative link target in `text`."""

    def _sub(match: re.Match[str]) -> str:
        target = match.group(1)
        return f"]({_LINK_REWRITES.get(target, target)})"

    return _RELATIVE_LINK_RE.sub(_sub, text)


class _RewrittenFile(File):
    """A `File` whose markdown is rewritten on read.

    MkDocs reads page content through `content_string`; overriding it keeps the
    source file on disk untouched while the built page carries links that work.
    """

    @property
    def content_string(self) -> str:  # type: ignore[override]
        src = self.abs_src_path
        if src is None:  # pragma: no cover - a File built from a real path
            return ""
        return rewrite_links(Path(src).read_text(encoding="utf-8"))


def on_files(files: Any, config: Any) -> Any:
    """Add the research artifacts to the build, read from their real location."""
    for name in PUBLISHED_FILES:
        source = REPO_ROOT / RESEARCH_DIR / name
        if not source.is_file():
            # Loud rather than a quietly missing page: this list is the contract
            # the pointer files in CITATION.cff and the abstracts depend on.
            raise FileNotFoundError(
                f"mkdocs_hooks: {RESEARCH_DIR}/{name} is listed in "
                f"PUBLISHED_FILES but is not on disk. Either restore it or "
                f"remove it from that tuple — the site advertises its URL."
            )
        cls = _RewrittenFile if name.endswith(".md") else File
        files.append(
            cls(
                f"{RESEARCH_DIR}/{name}",
                src_dir=str(REPO_ROOT),
                dest_dir=str(config["site_dir"]),
                use_directory_urls=bool(config["use_directory_urls"]),
            )
        )
    return files
