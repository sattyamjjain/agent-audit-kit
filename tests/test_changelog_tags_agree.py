"""A git tag and a dated CHANGELOG heading must agree.

v0.3.82 was tagged, published to PyPI, and its notes stayed under
``## [Unreleased]``. Nothing failed, because nothing looked: the release flow checks
the version in ``pyproject.toml`` against ``__init__``, the README pins and the newest
tag, but never against the changelog. So the published record said "unreleased" for a
version that had been on PyPI since 2026-08-17.

That is the same failure the 0.3.81 entry describes for rule counts, one level up. The
count guard in ``scripts/check_counts.py`` matches counts by *phrase*, and a count
written in an uncovered phrasing was never looked at, so it rotted while
``make count-check`` reported clean. Here the uncovered surface is a whole document.
Fixing 0.3.82 by hand without adding this test would reproduce exactly that: the
instance repaired, the class still open.

Direction of the check
----------------------
This asserts tag -> heading: every released version must be written down. The
inverse direction, heading -> tag (every dated changelog entry must have a tag, which
catches "wrote the notes, never cut the release"), is solved by
``tests/test_version_consistency.py::test_every_dated_changelog_version_has_a_tag`` in
the sibling project *provael*. That test does not exist in this repository; it is
cited as the model for the opposite direction, not as something imported here.
Together the two directions pin tag == heading. Only this direction is implemented
here, because this is the direction that broke.

Offline by construction: tags are read with ``git tag --list 'v*'``, never from a
remote, so this runs in a clean CI checkout with ``fetch-tags`` and needs no network.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = REPO_ROOT / "CHANGELOG.md"
# Frozen history: entries move here once they age out of the live changelog. A tag
# recorded in either file is recorded.
ARCHIVE = REPO_ROOT / "docs" / "changelog" / "archive" / "CHANGELOG.md"

_SEMVER_TAG_RE = re.compile(r"^v(\d+\.\d+\.\d+)$")
_DATED_HEADING_RE = re.compile(
    r"^## \[(\d+\.\d+\.\d+)\]\s*-\s*(\d{4}-\d{2}-\d{2})\s*$", re.M
)
_ANY_VERSION_HEADING_RE = re.compile(r"^## \[(\d+\.\d+\.\d+)\]", re.M)

# Tags that predate this guard and have no entry in either the live changelog or the
# frozen archive. Enumerated so the guard can fail closed on anything NEW: a version
# tagged from here on must be written down, and adding to this list is a deliberate,
# reviewable act rather than a silent pass.
#
# Not backfilled, because the notes for these releases were never written and
# inventing them now would put unsourced content in the audit trail. v0.3.11 is the
# clearest case: that release was abandoned part-way through, so there is nothing
# truthful to record.
KNOWN_UNRECORDED: frozenset[str] = frozenset({
    "0.3.11",  # release abandoned mid-flight; no notes were ever written
    "0.3.34",
    "0.3.35",
    "0.3.41",
    "0.3.46",
    "0.3.47",
    "0.3.48",
    "0.3.49",
    "0.3.50",
    "0.3.57",
    "0.3.76",
})


def _git_tags() -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "tag", "--list", "v*"],
        capture_output=True,
        text=True,
        check=True,
    )
    return [line.strip() for line in out.stdout.splitlines() if line.strip()]


def _tagged_versions() -> list[str]:
    """Semver versions with a tag, e.g. ``v0.3.82`` -> ``0.3.82``.

    Non-semver ``v*`` tags (the repo carries ``v0.2.0-pre-april-2026``) are not
    releases and are out of scope.
    """
    return [m.group(1) for m in (_SEMVER_TAG_RE.match(t) for t in _git_tags()) if m]


def _dated_headings() -> dict[str, str]:
    """version -> date, across the live changelog and the frozen archive."""
    found: dict[str, str] = {}
    for path in (CHANGELOG, ARCHIVE):
        if not path.is_file():
            continue
        for version, date in _DATED_HEADING_RE.findall(path.read_text(encoding="utf-8")):
            found.setdefault(version, date)
    return found


def _pyproject_version() -> str:
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    assert m, 'pyproject.toml has no top-level version = "..."'
    return m.group(1)


def test_every_tag_has_a_dated_changelog_heading() -> None:
    """The check that would have caught 0.3.82."""
    tagged = _tagged_versions()
    assert tagged, "no semver tags found — this guard would pass on nothing"

    dated = _dated_headings()
    missing = sorted(
        (v for v in tagged if v not in dated and v not in KNOWN_UNRECORDED),
        key=lambda v: [int(p) for p in v.split(".")],
    )
    assert not missing, (
        "tagged version(s) with no dated CHANGELOG heading: "
        + ", ".join(missing)
        + ".\nA tag is a published release; the changelog must say so. Add a "
        '"## [<version>] - YYYY-MM-DD" section (moving the notes out of '
        "[Unreleased] if that is where they are). Only add to KNOWN_UNRECORDED for a "
        "release whose notes genuinely were never written."
    )


def test_version_headings_are_dated_not_bare() -> None:
    """``## [0.3.82]`` with no date is a half-finished release, not a record.

    Catches the intermediate state where someone adds the heading but never stamps it,
    which would satisfy a naive substring check while leaving the date unknown.
    """
    text = CHANGELOG.read_text(encoding="utf-8")
    all_versions = set(_ANY_VERSION_HEADING_RE.findall(text))
    dated = set(_DATED_HEADING_RE.findall(text) and
                [v for v, _ in _DATED_HEADING_RE.findall(text)])
    undated = sorted(all_versions - dated)
    assert not undated, (
        f"CHANGELOG.md version heading(s) missing a date: {undated}. "
        'Use "## [<version>] - YYYY-MM-DD".'
    )


def test_pyproject_version_is_recorded_or_not_yet_tagged() -> None:
    """The in-flight version may be unreleased, but it may not be both tagged and unwritten.

    During a release the bump lands before the tag, so an unrecorded version is
    legitimate right up until the tag exists. After that it is drift.
    """
    version = _pyproject_version()
    dated = _dated_headings()
    tagged = set(_tagged_versions())

    if version in dated:
        return
    assert version not in tagged, (
        f"pyproject version {version} is tagged but has no dated CHANGELOG heading. "
        "The release shipped without its notes being written down; move them out of "
        "[Unreleased] into a dated section."
    )


def test_unreleased_section_exists() -> None:
    """``## [Unreleased]`` must survive the move.

    1c moves the 0.3.82 notes into a dated section and keeps [Unreleased] above it.
    If a future edit deletes the heading instead of emptying it, the next change has
    nowhere to land and tends to get appended to the most recent released section,
    silently rewriting shipped history.
    """
    text = CHANGELOG.read_text(encoding="utf-8")
    assert re.search(r"^## \[Unreleased\]\s*$", text, re.M), (
        "CHANGELOG.md lost its ## [Unreleased] heading"
    )


def test_unreleased_is_above_the_newest_release() -> None:
    """Keep-a-Changelog ordering: unreleased first, then newest release."""
    text = CHANGELOG.read_text(encoding="utf-8")
    unreleased = re.search(r"^## \[Unreleased\]\s*$", text, re.M)
    first_version = _ANY_VERSION_HEADING_RE.search(text)
    assert unreleased and first_version
    assert unreleased.start() < first_version.start(), (
        "## [Unreleased] must sit above the newest released section"
    )


@pytest.mark.parametrize("version", sorted(KNOWN_UNRECORDED))
def test_known_unrecorded_entries_are_real_tags(version: str) -> None:
    """Stale exemptions are a lie in the other direction.

    If an entry here stops matching a real tag, the list is claiming to excuse
    something that does not exist, and the next reader trusts it anyway.
    """
    assert version in set(_tagged_versions()), (
        f"KNOWN_UNRECORDED lists {version}, which is not a tag. Remove it."
    )


def test_known_unrecorded_does_not_shadow_a_real_entry() -> None:
    """An exemption must not outlive the gap it excuses.

    If someone later writes the notes for an exempted version, the exemption should be
    dropped rather than left masking a check that would now pass on its own.
    """
    dated = _dated_headings()
    redundant = sorted(KNOWN_UNRECORDED & set(dated))
    assert not redundant, (
        f"these versions now have dated headings and should be removed from "
        f"KNOWN_UNRECORDED: {redundant}"
    )
