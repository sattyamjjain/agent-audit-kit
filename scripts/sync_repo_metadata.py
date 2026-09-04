#!/usr/bin/env python3
"""Sync repo-level metadata with the shipped release.

Three jobs:

1. Rewrite every `sattyamjjain/agent-audit-kit@vX.Y.Z` reference in
   README.md + docs/**/*.md to the version recorded in pyproject.toml.
2. Keep CITATION.cff's `version` / `date-released` on the shipped release.
3. Generate the target GitHub repo-description string so CI can
   `gh repo edit --description "$(python scripts/sync_repo_metadata.py --description)"`.

On (2): CITATION.cff carried a comment reading "Bump `version` and `date-released`
with each release", which is an instruction to a human and was therefore obeyed
until it wasn't. It sat at 0.3.83 / 2026-08-17 while the repo shipped 0.3.93 --
ten releases of drift on the file GitHub renders as "Cite this repository", i.e.
the one surface whose entire purpose is telling a stranger which version they
measured. Nothing checked it: test_version_consistency covers pyproject,
__version__, the README pins and the tag, and stops there.

Neither field is hand-written now. `version` comes from pyproject, and
`date-released` from the CHANGELOG's dated heading for exactly that version --
the release date is already written down there, so asking a human to retype it
somewhere else only creates a second place to be wrong.


Pre-commit use: `python scripts/sync_repo_metadata.py --check` exits
non-zero if README / docs disagree with the live pyproject version.
`--write` rewrites on disk. `--description` prints the canonical
repo-description and exits.

Hard constraints:
- Never auto-edit docs/launch/release-notes-v*.md — those are historical
  artifacts and should pin the version they documented.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:  # Python 3.11+ stdlib
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]


REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"
README = REPO_ROOT / "README.md"
DOCS_DIR = REPO_ROOT / "docs"
AAK_PKG = REPO_ROOT / "agent_audit_kit" / "__init__.py"

_REPO_REF_RE = re.compile(r"sattyamjjain/agent-audit-kit@v\d+\.\d+\.\d+")
# Pre-commit `rev:` strings under a `repos:` block. We only rewrite a
# `rev: vX.Y.Z` line when the surrounding YAML names this repo — a bare
# `rev: v1.2.3` could belong to any hook in the README's example list.
_PRECOMMIT_BLOCK_RE = re.compile(
    r"(?P<prefix>repo:\s*https://github\.com/sattyamjjain/agent-audit-kit\s*\n\s*rev:\s*)"
    r"v\d+\.\d+\.\d+"
)
_HISTORY_STEM_RE = re.compile(r"release-notes-v\d+\.\d+\.\d+")

CITATION = REPO_ROOT / "CITATION.cff"
CHANGELOG = REPO_ROOT / "CHANGELOG.md"

# Top-level keys only. `preferred-citation` carries its own `version: "1.0"` (the
# report's, which moves when a measurement changes, not when the software ships),
# so an unanchored pattern would rewrite the report's identity on every release --
# the exact confusion the file's header comment exists to prevent.
_CFF_VERSION_RE = re.compile(r'(?m)^version:\s*"[^"]*"')
_CFF_DATE_RE = re.compile(r'(?m)^date-released:\s*"[^"]*"')


def _release_date(version: str) -> str | None:
    """The date on the CHANGELOG heading for ``version``, or None if undated.

    Returns None for a version that exists only under `## [Unreleased]`, which is
    the honest answer: a release that has not happened has no release date, and
    inventing today's would put a lie in the citation metadata.
    """
    if not CHANGELOG.is_file():
        return None
    m = re.search(
        rf"^##\s*\[{re.escape(version)}\]\s*-\s*(\d{{4}}-\d{{2}}-\d{{2}})\s*$",
        CHANGELOG.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    return m.group(1) if m else None


def _citation_drift(version: str) -> list[str]:
    """Human-readable descriptions of every stale field in CITATION.cff."""
    if not CITATION.is_file():
        return []
    text = CITATION.read_text(encoding="utf-8")
    out: list[str] = []
    m = _CFF_VERSION_RE.search(text)
    if m and m.group(0) != f'version: "{version}"':
        out.append(f"CITATION.cff {m.group(0)!r} should be 'version: \"{version}\"'")
    date = _release_date(version)
    d = _CFF_DATE_RE.search(text)
    if date and d and d.group(0) != f'date-released: "{date}"':
        out.append(
            f"CITATION.cff {d.group(0)!r} should be 'date-released: \"{date}\"' "
            f"(the CHANGELOG heading for {version})"
        )
    return out


def _rewrite_citation(version: str) -> bool:
    if not CITATION.is_file():
        return False
    text = CITATION.read_text(encoding="utf-8")
    new = _CFF_VERSION_RE.sub(f'version: "{version}"', text, count=1)
    date = _release_date(version)
    if date:
        new = _CFF_DATE_RE.sub(f'date-released: "{date}"', new, count=1)
    if new != text:
        CITATION.write_text(new, encoding="utf-8")
        return True
    return False


def _read_version() -> str:
    with PYPROJECT.open("rb") as fh:
        data = tomllib.load(fh)
    return str(data["project"]["version"])


def _read_rule_count() -> int:
    text = AAK_PKG.read_text(encoding="utf-8")
    m = re.search(r"RULE_COUNT\s*=\s*(\d+)", text)
    if not m:
        raise RuntimeError("RULE_COUNT not found in agent_audit_kit/__init__.py")
    return int(m.group(1))


# Directories whose files are dated artifacts: they record what was true at a
# named point and must keep pinning the version they documented.
#
# The module docstring has always stated that principle, but it was implemented
# for exactly one filename pattern (`release-notes-v*.md`), so every release
# quietly rewrote `@vX.Y.Z` inside launch collateral and dated preset docs --
# editing a published social thread to quote a version it never quoted.
# `scripts/check_counts.py` already treats these same paths as frozen; the two
# guards now agree instead of one freezing a file the other rewrites.
_FROZEN_DIR_PARTS: tuple[str, ...] = (
    "changelog/archive/",  # frozen changelog history
    "presets/",            # "shipped in vX" dated preset facts
    "launch/",             # dated launch collateral (threads, posts, blog drafts)
)


def _is_frozen(path: Path) -> bool:
    """Dated artifacts keep the version they documented."""
    if _HISTORY_STEM_RE.search(path.stem):
        return True
    posix = path.as_posix()
    return any(part in posix for part in _FROZEN_DIR_PARTS)


def _iter_docs() -> list[Path]:
    out: list[Path] = [README] if README.is_file() else []
    if DOCS_DIR.is_dir():
        out.extend(p for p in DOCS_DIR.rglob("*.md") if not _is_frozen(p))
    return out


def _rewrite(doc: Path, target_ref: str, target_version: str) -> tuple[bool, int]:
    text = doc.read_text(encoding="utf-8")
    new_text, n_action = _REPO_REF_RE.subn(target_ref, text)
    new_text, n_rev = _PRECOMMIT_BLOCK_RE.subn(
        lambda m: f"{m.group('prefix')}v{target_version}",
        new_text,
    )
    total = n_action + n_rev
    if total and new_text != text:
        doc.write_text(new_text, encoding="utf-8")
        return True, total
    return False, 0


def _check(target_ref: str, target_version: str) -> list[Path]:
    drift: list[Path] = []
    target_rev = f"v{target_version}"
    for doc in _iter_docs():
        text = doc.read_text(encoding="utf-8")
        for m in _REPO_REF_RE.finditer(text):
            if m.group(0) != target_ref:
                drift.append(doc)
                break
        else:
            for m in _PRECOMMIT_BLOCK_RE.finditer(text):
                if not m.group(0).endswith(target_rev):
                    drift.append(doc)
                    break
    return drift


def _description_string() -> str:
    """The canonical GitHub repo description.

    Delegates to ``render_repo_metadata.render()`` rather than composing a second
    string. Until 2026-09-01 it built its own, and the two disagreed: this module
    is what ``sync-repo-metadata.yml`` would WRITE, while ``description-liveness``
    in release.yml compares the live value against ``render_repo_metadata``. So
    the automation and its own checker wanted different text, and the only reason
    that never produced a permanently red gate is that the write step has never
    run -- it needs a METADATA_SYNC_TOKEN that does not exist. Two latent bugs
    were cancelling each other out.

    ``.github/repo-metadata.yml`` holds the template; every count in it is
    substituted from code there, so nothing needs re-deriving here.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_render_repo_metadata", Path(__file__).resolve().parent / "render_repo_metadata.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return str(module.render())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="exit 1 if pins drift")
    mode.add_argument("--write", action="store_true", help="rewrite README+docs")
    mode.add_argument(
        "--description",
        action="store_true",
        help="print the canonical GitHub repo description and exit",
    )
    args = parser.parse_args(argv)

    version = _read_version()
    target_ref = f"sattyamjjain/agent-audit-kit@v{version}"

    if args.description:
        sys.stdout.write(_description_string() + "\n")
        return 0

    if args.check:
        drift = _check(target_ref, version)
        cff = _citation_drift(version)
        if not drift and not cff:
            return 0
        if drift:
            sys.stderr.write(
                "pin drift: docs reference a version other than "
                f"{target_ref!r}:\n"
            )
            for doc in drift:
                sys.stderr.write(f"  - {doc.relative_to(REPO_ROOT)}\n")
        for line in cff:
            sys.stderr.write(f"  - {line}\n")
        sys.stderr.write(
            "Run `python scripts/sync_repo_metadata.py --write` to fix.\n"
        )
        return 1

    # --write
    total = 0
    for doc in _iter_docs():
        wrote, n = _rewrite(doc, target_ref, version)
        if wrote:
            sys.stdout.write(
                f"{doc.relative_to(REPO_ROOT)}: {n} rewrite(s) → {target_ref}\n"
            )
            total += n
    if _rewrite_citation(version):
        date = _release_date(version)
        sys.stdout.write(
            f"CITATION.cff: version → {version}"
            + (f", date-released → {date}\n" if date else " (no dated CHANGELOG heading yet)\n")
        )
        total += 1
    if total == 0:
        sys.stdout.write("no changes needed.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
