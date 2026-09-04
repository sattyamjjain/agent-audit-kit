"""Single-source-of-truth fence for the package version.

Four surfaces must never disagree:

1. ``pyproject.toml``'s ``version`` (what PyPI/OIDC publishes).
2. ``agent_audit_kit.__version__`` (what the installed package reports).
3. Every self-referencing ``@vX.Y.Z`` / ``rev: vX.Y.Z`` pin in ``README.md``
   (what we tell users to install).
4. The newest ``vX.Y.Z`` git tag (the version that actually exists to resolve).

Surfaces 1-3 agreeing is not enough: ``@v0.3.61`` matched ``pyproject`` yet no
``v0.3.61`` tag was ever cut, so the README's Action snippet failed to resolve
for everyone who copied it. Surface 4 closes that gap — the pin must point at a
*released* tag, not merely at the declared version.

If a release can't cut the declared tag, the fix is to repin the README to a
tag that *does* resolve (and change the declared version to match) — not to
leave the surfaces disagreeing.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _newest_git_tag() -> str | None:
    """The newest ``vX.Y.Z`` git tag by semantic order, or ``None`` when git or
    the tag list is unavailable (e.g. a shallow CI checkout without tags)."""
    try:
        out = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "tag", "-l", "v*"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    versions: list[tuple[tuple[int, int, int], str]] = []
    for line in out.stdout.split():
        m = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", line.strip())
        if m:
            versions.append(((int(m[1]), int(m[2]), int(m[3])), line.strip()))
    if not versions:
        return None
    versions.sort()
    return versions[-1][1]


def _semver(tag: str) -> tuple[int, int, int]:
    """``v1.2.3`` / ``1.2.3`` -> ``(1, 2, 3)``. Returns ``(-1, -1, -1)`` when
    unparseable, so an odd string sorts below every real version."""
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", tag.strip())
    if not m:
        return (-1, -1, -1)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def _head_is_tagged() -> bool:
    """True when a ``vX.Y.Z`` tag points at HEAD itself.

    Distinct from "a tag is reachable from HEAD": every commit after a release
    has the release tag as an ancestor, but only the release commit carries it.
    That distinction is what separates "the tag was cut" from "the tag has not
    been cut yet", which is the whole question here.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "tag", "--points-at", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if out.returncode != 0:
        return False
    return any(_semver(line) != (-1, -1, -1) for line in out.stdout.split())


def _changelog_top_version() -> str | None:
    """The newest ``## [X.Y.Z] - DATE`` heading in CHANGELOG.md.

    ``[Unreleased]`` is skipped: it carries no version, so it cannot be compared
    against a tag.
    """
    path = REPO_ROOT / "CHANGELOG.md"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    m = re.search(r"^##\s*\[(\d+\.\d+\.\d+)\]\s*-\s*\d{4}-\d{2}-\d{2}", text, re.M)
    return m.group(1) if m else None


def _pyproject_version() -> str:
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert m, "pyproject.toml has no top-level version = \"...\""
    return m.group(1)


def _init_version() -> str:
    from agent_audit_kit import __version__

    return __version__


def test_pyproject_matches_dunder_version() -> None:
    assert _pyproject_version() == _init_version(), (
        f'pyproject version {_pyproject_version()!r} != '
        f'agent_audit_kit.__version__ {_init_version()!r}'
    )


def test_readme_self_pins_match_declared_version() -> None:
    """Every agent-audit-kit self-reference pin in README must equal the declared
    version, so the documented install/CI path always points at a real tag."""
    declared = _init_version()
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

    # GitHub Action usage: `uses: sattyamjjain/agent-audit-kit@vX.Y.Z`
    action_pins = re.findall(
        r"sattyamjjain/agent-audit-kit@v(\d+\.\d+\.\d+)", readme
    )
    # pre-commit hook: `rev: vX.Y.Z` (README has one repos block — ours)
    precommit_pins = re.findall(r"rev:\s*v(\d+\.\d+\.\d+)", readme)
    # pip pin: `agent-audit-kit==X.Y.Z`
    pip_pins = re.findall(r"agent-audit-kit==(\d+\.\d+\.\d+)", readme)

    pins = action_pins + precommit_pins + pip_pins
    assert pins, (
        "README has no agent-audit-kit version pin to check — the @vX / rev: vX / "
        "==X snippets went missing; this fence would silently pass on nothing."
    )
    mismatched = [p for p in pins if p != declared]
    assert not mismatched, (
        f"README pins {sorted(set(mismatched))} disagree with declared version "
        f"{declared!r}. Repin the README (and re-cut the tag) so the documented "
        f"install path resolves."
    )


def test_readme_action_pin_matches_newest_git_tag() -> None:
    """The README's ``agent-audit-kit@vX.Y.Z`` Action pin must equal the newest
    git tag, so the documented CI snippet resolves to a real, *released* tag.

    ``test_readme_self_pins_match_declared_version`` proves README pin ==
    pyproject version; this proves README pin == newest released tag. Together
    they force pin == version == tag, which is what catches "version bumped but
    never tagged" — the exact break where README pinned ``@v0.3.61`` while the
    newest tag was ``v0.3.60`` and the action failed to resolve for every user
    who copied the snippet.

    Skips when no ``vX.Y.Z`` tag is reachable (a shallow CI checkout without
    ``fetch-tags``); CI fetches tags (``.github/workflows/ci.yml``) so this
    enforces there.

    Also skips, with an explicit reason, on a release commit whose tag has not
    been cut yet -- HEAD carries no tag *and* the CHANGELOG's newest dated entry
    is ahead of the newest tag. That window is real and unavoidable, and this
    test going red in it is what kept main's CI badge red across four releases
    while release.yml published regardless. The assertion is not weakened for the
    case it was written for: a cut tag that disagrees with the README still fails
    hard, and release.yml runs this suite on the tagged commit, where the skip
    cannot apply.
    """
    newest = _newest_git_tag()
    if newest is None:
        pytest.skip("no vX.Y.Z git tag reachable in this checkout")

    # A release commit is legitimately in this state for the minutes between
    # "version bumped, README repinned, pushed" and "tag cut". CI runs on the
    # push, so it saw that window and went red on every release: four failed
    # main runs, and the release workflow published anyway because it depended
    # on nothing that tested. Skipping that window is only safe because it is
    # narrow and because the tag itself is tested: release.yml now runs this
    # suite on the tagged commit, where HEAD *is* tagged and the assertion below
    # runs at full strength.
    #
    # Both conditions are required. HEAD carrying no tag alone is the normal
    # state of every ordinary commit; the changelog being ahead of the newest tag
    # alone would let a permanently-untagged bump hide here forever.
    changelog_top = _changelog_top_version()
    if (
        not _head_is_tagged()
        and changelog_top is not None
        and _semver(changelog_top) > _semver(newest)
    ):
        pytest.skip(
            f"release in flight: CHANGELOG's newest dated entry is {changelog_top} "
            f"but the newest tag is {newest}, and HEAD carries no tag. The pin is "
            f"checked at full strength when the tag is cut -- release.yml runs this "
            f"suite on the tagged commit. If you are NOT mid-release, this skip is "
            f"hiding a real drift: cut the tag, or repin the README to {newest}."
        )

    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    pins = re.findall(r"sattyamjjain/agent-audit-kit@v\d+\.\d+\.\d+", readme)
    assert pins, "README has no agent-audit-kit@vX.Y.Z Action pin to check"

    bad = sorted({p for p in pins if not p.endswith("@" + newest)})
    assert not bad, (
        f"README Action pin(s) {bad} do not match the newest git tag {newest!r}. "
        f"If you just bumped the version, cut the tag; if the README is behind, run "
        f"`python scripts/sync_repo_metadata.py --write` and re-tag. A pin to an "
        f"untagged version does not resolve for users."
    )


# ---------------------------------------------------------------------------
# Guard the guard: the release-window skip must fire exactly when intended.
#
# A skip is a hole. These hold that the hole is the shape it is meant to be --
# open only while a release is genuinely in flight, closed everywhere else --
# because a skip that silently widened would look identical to a green run.
# ---------------------------------------------------------------------------

import sys as _sys  # noqa: E402  (test-only, kept next to the tests that use it)

_MODULE = _sys.modules[__name__]


def _with_state(
    monkeypatch: pytest.MonkeyPatch, newest: str, head_tagged: bool, changelog: str
) -> None:
    """Pin the three inputs the skip decision reads."""
    monkeypatch.setattr(_MODULE, "_newest_git_tag", lambda: newest)
    monkeypatch.setattr(_MODULE, "_head_is_tagged", lambda: head_tagged)
    monkeypatch.setattr(_MODULE, "_changelog_top_version", lambda: changelog)


def test_skip_fires_on_an_untagged_release_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The exact state that made four main runs red.

    Version bumped and README repinned to 0.3.99, tag not cut yet. CI runs on
    that push, so it must not go red for a condition the next minute resolves.
    """
    _with_state(monkeypatch, newest="v0.3.98", head_tagged=False, changelog="0.3.99")

    # skip raises an OutcomeException, which derives from BaseException and so is
    # NOT caught by `pytest.raises(Exception)`.
    with pytest.raises(pytest.skip.Exception) as excinfo:
        test_readme_action_pin_matches_newest_git_tag()
    message = str(excinfo.value)
    assert "release in flight" in message
    assert "0.3.99" in message and "v0.3.98" in message
    assert "hiding a real drift" in message, (
        "the skip reason must tell a reader who is NOT mid-release what it means"
    )


def test_no_skip_once_the_tag_is_cut(monkeypatch: pytest.MonkeyPatch) -> None:
    """HEAD tagged means the release landed, so the assertion runs at full strength.

    This is the half that must never be weakened: a cut tag disagreeing with the
    README is the original defect (``@v0.3.61`` pinned against a ``v0.3.60``
    tag), and it still fails hard.
    """
    _with_state(monkeypatch, newest="v0.3.60", head_tagged=True, changelog="0.3.61")

    with pytest.raises(AssertionError) as excinfo:
        test_readme_action_pin_matches_newest_git_tag()
    assert "do not match the newest git tag" in str(excinfo.value)


def test_no_skip_when_the_changelog_is_not_ahead(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A permanently-untagged bump must not be able to hide here.

    HEAD carrying no tag is the normal state of every ordinary commit, so that
    condition alone cannot open the skip. With the changelog level to the newest
    tag the assertion runs, and fails, because the README is pinned ahead.
    """
    _with_state(monkeypatch, newest="v0.3.60", head_tagged=False, changelog="0.3.60")

    with pytest.raises(AssertionError) as excinfo:
        test_readme_action_pin_matches_newest_git_tag()
    assert "do not match the newest git tag" in str(excinfo.value)


def test_head_is_tagged_distinguishes_carrying_from_reachable() -> None:
    """The distinction the skip turns on, asserted against real git.

    Every commit after a release has that tag as an ancestor; only the release
    commit carries it. If ``_head_is_tagged`` collapsed into "reachable", the
    skip would open on every ordinary commit.
    """
    out = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "tag", "--points-at", "HEAD"],
        capture_output=True, text=True, timeout=10,
    )
    carried = [t for t in out.stdout.split() if _semver(t) != (-1, -1, -1)]
    assert _head_is_tagged() == bool(carried)
    assert _newest_git_tag() is not None, "repo has releases; a tag is reachable"


def test_changelog_top_version_reads_the_newest_dated_heading() -> None:
    """The skip compares against this, so a misread would open the hole wrongly."""
    top = _changelog_top_version()
    assert top is not None, "CHANGELOG.md has no dated version heading"
    assert re.fullmatch(r"\d+\.\d+\.\d+", top)
    assert _semver(top) >= _semver(_pyproject_version()) or top == _pyproject_version()


# ---------------------------------------------------------------------------
# Surface 5: CITATION.cff (added 2026-09-04)
#
# The fence above enumerated four surfaces and stopped. CITATION.cff is a fifth,
# and it is the one GitHub renders as "Cite this repository" -- the surface whose
# whole job is telling a stranger which version produced the numbers they are
# about to quote. It sat at 0.3.83 / 2026-08-17 while the repo shipped 0.3.93.
#
# It drifted for the ordinary reason: its header comment said "bump `version` and
# `date-released` with each release", which is a note to a human, and nothing read
# it. Both fields are generated now.
# ---------------------------------------------------------------------------

def _load_sync_repo_metadata():
    import importlib.util
    import sys as _sys

    script = REPO_ROOT / "scripts" / "sync_repo_metadata.py"
    assert script.is_file(), "scripts/sync_repo_metadata.py missing"
    spec = importlib.util.spec_from_file_location("sync_repo_metadata", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    _sys.modules["sync_repo_metadata"] = module
    spec.loader.exec_module(module)
    return module


def test_citation_cff_version_matches_the_declared_version() -> None:
    mod = _load_sync_repo_metadata()
    assert mod._citation_drift(_pyproject_version()) == [], (
        "CITATION.cff is stale; run `python scripts/sync_repo_metadata.py --write`"
    )


def test_citation_release_date_comes_from_the_changelog() -> None:
    """The date is derived, not retyped.

    The release date is already written on the CHANGELOG heading. Asking a human
    to copy it into a second file only creates a second place to be wrong, which
    is what the eight-month-old date in this file was.
    """
    mod = _load_sync_repo_metadata()
    version = _pyproject_version()
    date = mod._release_date(version)
    if date is None:
        pytest.skip(f"{version} has no dated CHANGELOG heading yet (unreleased)")
    text = (REPO_ROOT / "CITATION.cff").read_text(encoding="utf-8")
    assert f'date-released: "{date}"' in text


def test_the_guard_does_not_rewrite_the_reports_own_version() -> None:
    """`preferred-citation.version` is the report's identity, not the software's.

    It moves when a measurement changes, which is a different event from shipping
    a release. An unanchored `version:` pattern would stamp the package version
    over it on every publish -- silently making the citation claim the report was
    revised when it was not. The file's own header comment exists to keep these
    two apart, so the guard has to as well.
    """
    mod = _load_sync_repo_metadata()
    text = (REPO_ROOT / "CITATION.cff").read_text(encoding="utf-8")
    assert '  version: "1.0"' in text, "the report's version should be indented under preferred-citation"
    assert len(mod._CFF_VERSION_RE.findall(text)) == 1, (
        "the version pattern must match only the top-level key"
    )
    assert mod._CFF_VERSION_RE.search(text).group(0) == f'version: "{_pyproject_version()}"'


def test_undated_version_yields_no_release_date() -> None:
    """A version that exists only under `## [Unreleased]` has not been released.

    Returning today's date there would put a plausible lie in citation metadata,
    which is worse than leaving the old one: nobody audits a date that looks right.
    """
    mod = _load_sync_repo_metadata()
    assert mod._release_date("99.99.99") is None
