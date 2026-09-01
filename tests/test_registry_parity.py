"""`scripts/check_registry_parity.py` — the first check that looks outside the repo.

Every other version guard here compares one in-repo surface to another. They all
passed on 2026-08-31 while PyPI served 0.3.90 and pyproject said 0.3.91, because
none of them had any way to know what PyPI served.

``test_the_state_that_motivated_this`` is the important one: it pins the exact
declared/published pair the repository was actually in, and asserts it fails.
If that ever starts passing, this file has stopped doing its job.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "check_registry_parity.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_registry_parity", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_registry_parity"] = module
    spec.loader.exec_module(module)
    return module


mod = _load()


# ---------------------------------------------------------------------------
# The decision table
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "declared,published,today,expected,because",
    [
        ("0.3.90", "0.3.90", date(2026, 9, 1), True, "in parity"),
        ("0.3.91", "0.3.90", date(2026, 8, 31), True, "declared today — in flight"),
        ("0.3.91", "0.3.90", date(2026, 9, 1), True, "one day — still the window"),
        ("0.3.91", "0.3.90", date(2026, 9, 2), False, "two days — did not happen"),
        ("0.3.92", "0.3.90", date(2026, 8, 31), False, "two patches — a release was skipped"),
        ("0.4.0", "0.3.90", date(2026, 8, 31), False, "minor bump is not a patch window"),
        ("0.3.89", "0.3.90", date(2026, 9, 1), False, "registry ahead of the repo"),
    ],
)
def test_decision_table(
    declared: str, published: str, today: date, expected: bool, because: str
) -> None:
    ok, why = mod.evaluate(declared, published, today=today)
    assert ok is expected, f"{because}: {why}"


def test_the_state_that_motivated_this() -> None:
    """0.3.91 declared on 2026-08-31, PyPI on 0.3.90, checked a day later.

    Every in-repo guard passed on this. This one must not.
    """
    ok, why = mod.evaluate("0.3.91", "0.3.90", today=date(2026, 9, 2))
    assert not ok
    assert "0.3.91" in why and "0.3.90" in why, "both versions must be named"
    assert "did not happen" in why


def test_failure_names_both_versions() -> None:
    """A failure that prints one version makes the reader go look up the other."""
    for declared, published in [("0.3.92", "0.3.90"), ("0.3.89", "0.3.90")]:
        _, why = mod.evaluate(declared, published, today=date(2026, 9, 1))
        assert declared in why and published in why


# ---------------------------------------------------------------------------
# Reading the repo's own surfaces
# ---------------------------------------------------------------------------


def test_declared_version_matches_pyproject() -> None:
    """Independent of the script's own regex, and without tomllib.

    `tomllib` is 3.11+, and this package supports 3.9 — the first cut of this test
    used it and the release-time suite failed on the 3.9 matrix leg before
    anything published, which is what that gate exists for.
    """
    import re as _re

    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    project = text.split("[project]", 1)[1].split("\n[", 1)[0]
    expected = _re.search(r'^version\s*=\s*"([^"]+)"', project, _re.MULTILINE)
    assert expected is not None, "pyproject [project] has no version"
    assert mod.declared_version() == expected.group(1)


def test_newest_changelog_release_skips_unreleased() -> None:
    """`## [Unreleased]` carries no date, which is what makes "newest *dated*
    section" a usable anchor rather than a moving one."""
    newest = mod.newest_changelog_release()
    assert newest is not None
    version, released = newest
    assert version[0].isdigit()
    assert isinstance(released, date)


def test_one_patch_ahead() -> None:
    assert mod.is_one_patch_ahead("0.3.91", "0.3.90")
    assert not mod.is_one_patch_ahead("0.3.92", "0.3.90")
    assert not mod.is_one_patch_ahead("0.4.0", "0.3.90")
    assert not mod.is_one_patch_ahead("0.3.90", "0.3.90")
    assert not mod.is_one_patch_ahead("garbage", "0.3.90")


def test_declared_since_reads_git_not_the_changelog() -> None:
    """The clock comes from git so a back-dated heading cannot hide the age."""
    since = mod.declared_since(mod.declared_version())
    assert since is None or isinstance(since, date)


# ---------------------------------------------------------------------------
# The script as CI runs it
# ---------------------------------------------------------------------------


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args], capture_output=True, text=True, timeout=60
    )


def test_offline_parity_passes() -> None:
    out = _run(["--published", mod.declared_version()])
    assert out.returncode == 0, out.stderr


def test_offline_mismatch_fails_loudly() -> None:
    out = _run(["--published", "0.1.0"])
    assert out.returncode == 1
    combined = out.stdout + out.stderr
    assert "0.1.0" in combined and mod.declared_version() in combined
    assert "FAIL" in combined


def test_unreachable_registry_is_a_skip_not_a_pass() -> None:
    """A network failure must say the comparison did not happen.

    Exiting 0 is correct — an outage is not a defect — but exiting 0 *quietly*
    would make an unreachable registry indistinguishable from a matching one,
    which is the failure this whole script exists to stop.
    """
    out = _run(["--url", "https://pypi.invalid/nope/json"])
    assert out.returncode == 0
    assert "SKIP" in out.stderr.upper()
    assert "not compared" in out.stderr.lower()
    assert "not a pass" in out.stderr.lower()


def test_wired_into_ci() -> None:
    """A guard nothing runs is a guard that does not exist.

    Both triggers are asserted: the failure mode is time-based, so a push-only
    wiring cannot tell a release in flight from one that never happened.
    """
    workflows = list((REPO_ROOT / ".github" / "workflows").glob("*.yml"))
    referencing = [
        w for w in workflows if "check_registry_parity.py" in w.read_text(encoding="utf-8")
    ]
    assert referencing, "check_registry_parity.py is not run by any workflow"
    text = "\n".join(w.read_text(encoding="utf-8") for w in referencing)
    assert "schedule:" in text, "must run on a schedule, not only on push"
    assert "push:" in text, "must also run on push"
