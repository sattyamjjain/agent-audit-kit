#!/usr/bin/env python3
"""Compare the DECLARED version to the REGISTRY, not to another in-repo surface.

Every version check this repo owns compares one in-repo surface to another:
``pyproject`` against ``__version__``, the CHANGELOG heading against the newest
tag, the README's Action pin against both. All of them pass while PyPI serves
something older. The repo can be perfectly self-consistent about a version
nobody can install, and on 2026-08-31 it was exactly that: 0.3.91 declared,
changelogged, tested and pushed, with PyPI still serving 0.3.90 because the tag
was never cut. Nothing in CI could see it, because nothing in CI looked outside
the repository.

This looks outside.

The one legitimate state where declared != published is the minutes between the
release commit landing and PyPI accepting the upload. That window is recognised
narrowly — exactly one patch ahead, the CHANGELOG's newest dated section already
naming it, and the declaration young enough to still be in flight. Everything
else fails, loudly, with both versions printed.

The age check is the part a push-only gate cannot do. On push,
0.3.91-declared-vs-0.3.90-published is correct for about ten minutes and a
defect after a day; the two are the same diff and only the clock separates them.
So the clock comes from git — the commit that introduced the declared version
into ``pyproject.toml`` — and this script is wired to run on a schedule as well
as on push. A gate that only fires on push cannot tell a release in progress
from a release that never happened.

Network failure is a SKIP, never a silent pass: if PyPI cannot be reached, the
comparison did not happen and the output says so.

Usage::

    python scripts/check_registry_parity.py              # the gate
    python scripts/check_registry_parity.py --max-ahead-days 2
    python scripts/check_registry_parity.py --published 0.3.90   # offline, for tests

Exit codes: 0 pass or skip, 1 parity failure, 2 usage/parse error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"
CHANGELOG = REPO_ROOT / "CHANGELOG.md"

PACKAGE = "agent-audit-kit"
PYPI_JSON = f"https://pypi.org/pypi/{PACKAGE}/json"
DEFAULT_MAX_AHEAD_DAYS = 1
TIMEOUT_SECONDS = 15

_VERSION_RE = re.compile(r'^version\s*=\s*"([^"]+)"', re.MULTILINE)
# `## [0.3.91] - 2026-08-31`. `## [Unreleased]` carries no date and is skipped,
# which is what makes "newest *dated* section" the right anchor.
_CHANGELOG_SECTION_RE = re.compile(
    r"^##\s*\[(\d+\.\d+\.\d+)\]\s*-\s*(\d{4}-\d{2}-\d{2})\s*$", re.MULTILINE
)


class ParityError(Exception):
    """A problem reading the repo's own surfaces — a usage error, not a failure."""


def declared_version() -> str:
    """The version this repository claims to be."""
    try:
        text = PYPROJECT.read_text(encoding="utf-8")
    except OSError as exc:  # pragma: no cover - unreadable checkout
        raise ParityError(f"cannot read {PYPROJECT}: {exc}") from exc
    match = _VERSION_RE.search(text)
    if match is None:
        raise ParityError(f"no `version = \"...\"` line in {PYPROJECT}")
    return match.group(1)


def newest_changelog_release() -> tuple[str, date] | None:
    """The newest dated CHANGELOG section, as ``(version, date)``."""
    try:
        text = CHANGELOG.read_text(encoding="utf-8")
    except OSError:
        return None
    match = _CHANGELOG_SECTION_RE.search(text)
    if match is None:
        return None
    try:
        return match.group(1), date.fromisoformat(match.group(2))
    except ValueError:
        return None


def published_version(url: str = PYPI_JSON) -> str:
    """What the registry actually serves. Raises on any network/parse problem."""
    request = urllib.request.Request(
        url, headers={"User-Agent": f"{PACKAGE}-registry-parity"}
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        payload = json.load(response)
    version = payload.get("info", {}).get("version")
    if not isinstance(version, str) or not version:
        raise ValueError("PyPI JSON has no info.version")
    return version


def _parse(version: str) -> tuple[int, ...] | None:
    parts = version.split(".")
    if len(parts) != 3:
        return None
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return None


def is_one_patch_ahead(declared: str, published: str) -> bool:
    """True when ``declared`` is exactly ``published`` with the patch incremented."""
    d, p = _parse(declared), _parse(published)
    if d is None or p is None:
        return False
    return d[:2] == p[:2] and d[2] == p[2] + 1


def declared_since(version: str) -> date | None:
    """Commit date of the change that introduced ``version`` into pyproject.toml.

    This is the clock the age check runs on. Reading it from git rather than from
    the CHANGELOG's own date means a back-dated or forgotten heading cannot hide
    how long the declaration has actually been sitting there.
    """
    try:
        out = subprocess.run(
            [
                "git", "-C", str(REPO_ROOT), "log", "-1", "--format=%cI",
                "-S", f'version = "{version}"', "--", "pyproject.toml",
            ],
            capture_output=True, text=True, timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0 or not out.stdout.strip():
        return None
    try:
        return datetime.fromisoformat(out.stdout.strip()).date()
    except ValueError:
        return None


def _emit(level: str, message: str) -> None:
    """Print to stderr, annotated when running under GitHub Actions.

    A skip that exits 0 is invisible in a green job, so it is emitted as a
    workflow annotation too -- the whole point is that a skipped comparison is
    never mistaken for a passed one.
    """
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::{level}::{message}", file=sys.stderr)
    print(f"registry-parity: {level.upper()}: {message}", file=sys.stderr)


def evaluate(
    declared: str,
    published: str,
    *,
    today: date,
    max_ahead_days: int = DEFAULT_MAX_AHEAD_DAYS,
) -> tuple[bool, str]:
    """Return ``(ok, explanation)`` for one declared/published pair."""
    if declared == published:
        return True, f"declared {declared} == published {declared}"

    d, p = _parse(declared), _parse(published)
    if d is not None and p is not None and d < p:
        return False, (
            f"the registry is AHEAD of the repository: PyPI serves {published}, "
            f"pyproject declares {declared}. Something published from a tree "
            f"that is not this one."
        )

    if not is_one_patch_ahead(declared, published):
        return False, (
            f"declared {declared}, PyPI serves {published} — not a single patch "
            f"apart, so this is not a release in flight. Publish {declared} or "
            f"correct the declaration."
        )

    newest = newest_changelog_release()
    if newest is None or newest[0] != declared:
        stated = "none" if newest is None else newest[0]
        return False, (
            f"declared {declared}, PyPI serves {published}. The CHANGELOG's "
            f"newest dated section names {stated}, not {declared}, so this does "
            f"not look like a release that was prepared."
        )

    since = declared_since(declared)
    if since is None:
        return False, (
            f"declared {declared}, PyPI serves {published}, and git cannot say "
            f"when {declared} was declared — refusing to assume the window is open."
        )

    age = (today - since).days
    if age > max_ahead_days:
        return False, (
            f"declared {declared} on {since.isoformat()} — {age} day(s) ago — "
            f"while PyPI still serves {published}. A release in flight takes "
            f"minutes. This one did not happen: cut the tag, or roll the "
            f"declaration back to {published}."
        )

    return True, (
        f"release in flight: declared {declared} ({age} day(s) ago), PyPI still "
        f"on {published}. Within the {max_ahead_days}-day window."
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--max-ahead-days", type=int, default=DEFAULT_MAX_AHEAD_DAYS,
        help="How long the declared version may lead the registry (default: 1).",
    )
    parser.add_argument(
        "--published",
        help="Skip the network and use this as the registry version (tests).",
    )
    parser.add_argument("--url", default=PYPI_JSON, help="Registry JSON endpoint.")
    args = parser.parse_args(argv if argv is not None else [])

    try:
        declared = declared_version()
    except ParityError as exc:
        _emit("error", str(exc))
        return 2

    if args.published:
        published = args.published
    else:
        try:
            published = published_version(args.url)
        except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError) as exc:
            _emit(
                "warning",
                f"SKIPPED — could not reach {args.url} ({exc}). The declared "
                f"version ({declared}) was NOT compared against the registry. "
                f"This is not a pass.",
            )
            return 0

    ok, explanation = evaluate(
        declared, published, today=date.today(), max_ahead_days=args.max_ahead_days
    )
    if ok:
        print(f"registry-parity: OK — {explanation}")
        return 0

    _emit("error", explanation)
    print(
        f"registry-parity: FAIL\n"
        f"  declared (pyproject.toml): {declared}\n"
        f"  published ({PACKAGE} on PyPI): {published}",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv[1:]))
