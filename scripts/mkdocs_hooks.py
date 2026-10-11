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

**The second job: a help page for every rule.** Every rule's SARIF ``helpUri``
points at ``.../docs/rules/<ID>/``, and only 13 rules had a page there. The same
``on_files`` event now adds one page per rule in the registry, rendered by
``scripts/rule_pages.py``, and appends the full list to ``docs/rules/index.md``.
A rule that already has a hand-written ``docs/rules/<ID>.md`` keeps its text
verbatim, with the registry reference appended below it; the file on disk is
never written to and no generated page is committed, so there is nothing to
drift and no ``--check`` to forget. The pages are marked ``NOT_IN_NAV`` (they are
reached from the rules index and from SARIF, not from the sidebar), which also
keeps them out of MkDocs' "pages not in nav" log, where there would be one line
per rule.
`tests/test_rule_pages.py` builds the site and fails unless every registered
rule's page exists exactly where its ``helpUri`` points.

**The third job: refuse a build in which two files share one page.** With
directory URLs ``docs/rules.md`` and ``docs/rules/index.md`` are both
``rules/index.html``, and MkDocs raises nothing for it: the one written last
wins. The "Rule reference" page in the nav was the loser, unnoticed, until an
accessibility review found its links landing on the wrong page. ``on_files`` now
raises on any destination built from more than one source, after the pages above
are added (a generated page can clash with a hand-written one too).
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from typing import Any

from mkdocs.structure.files import File, InclusionLevel

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


_RULE_PAGES_MODULE = "aak_rule_pages"


def _rule_pages() -> Any:
    """Load ``scripts/rule_pages.py``, the page renderer, once.

    Loaded by path rather than imported by name: MkDocs executes this file as a
    hook, not as a member of a package, so a sibling import would depend on
    ``scripts/`` being on ``sys.path``. Registered in ``sys.modules`` before it
    runs because its dataclasses resolve their own module while being defined.
    """
    module = sys.modules.get(_RULE_PAGES_MODULE)
    if module is not None:
        return module
    path = Path(__file__).with_name("rule_pages.py")
    spec = importlib.util.spec_from_file_location(_RULE_PAGES_MODULE, path)
    if spec is None or spec.loader is None:  # pragma: no cover - the file is next to this one
        raise ImportError(f"mkdocs_hooks: cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[_RULE_PAGES_MODULE] = module
    spec.loader.exec_module(module)
    return module


def _publish_rule_pages(files: Any, config: Any) -> None:
    """Add one page per registered rule, and the full list to the rules index.

    The repository root goes on ``sys.path`` first, so the registry rendered is
    the one in the checkout being built rather than whichever copy happens to be
    installed. A page that already exists on disk (a hand-written deep dive, the
    rules index) is replaced in the build by the same text plus the generated
    part; ``Files.remove`` before ``append`` because appending over an existing
    ``src_uri`` is deprecated.
    """
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    rule_pages = _rule_pages()
    pages = rule_pages.build_pages(Path(config["docs_dir"]))
    for src_uri, markdown in pages.items():
        current = files.get_file_from_path(src_uri)
        inclusion = InclusionLevel.NOT_IN_NAV
        if current is not None:
            files.remove(current)
            if src_uri == rule_pages.INDEX_URI:
                # The index is the one page a reader is meant to navigate to.
                inclusion = current.inclusion
        files.append(File.generated(config, src_uri, content=markdown, inclusion=inclusion))


def colliding_destinations(files: Any) -> dict[str, list[str]]:
    """Built file destination -> the source files that would be written to it, when more than one.

    MkDocs does not notice two sources with one destination unless they sit in the
    same directory: with directory URLs ``docs/rules.md`` and ``docs/rules/index.md``
    are both ``rules/index.html``, and whichever is written last wins. For months the
    one called "Rule reference" in the nav was the loser, and nothing said so.

    Files left out of the build (``exclude_docs``) stay in the collection, so only
    the ones that are built count; that is how the clash is resolved on purpose.
    """
    by_destination: dict[str, list[str]] = {}
    for file in files:
        if file.inclusion.is_excluded():
            continue
        by_destination.setdefault(file.dest_uri, []).append(file.src_uri)
    return {dest: sources for dest, sources in by_destination.items() if len(sources) > 1}


def on_files(files: Any, config: Any) -> Any:
    """Add the research artifacts and the per-rule pages to the build."""
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
    _publish_rule_pages(files, config)
    clashes = colliding_destinations(files)
    if clashes:
        # Loud, like the missing research file above: the alternative is a page that
        # is in the nav, builds without a warning, and is not there.
        listing = "; ".join(f"{dest} <- {', '.join(sources)}" for dest, sources in sorted(clashes.items()))
        raise ValueError(
            f"mkdocs_hooks: files that would be built to the same page, so all but one "
            f"would silently not exist: {listing}. Rename one, or add the one to drop "
            f"to `exclude_docs` in mkdocs.yml."
        )
    return files
