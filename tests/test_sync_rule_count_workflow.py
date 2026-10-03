"""The rule-count bot commits everything its sync scripts rewrote.

`sync-rule-count.yml` runs `sync_rule_count.py --regenerate` and
`sync_scanner_count.py`, checks `git diff --quiet`, and commits. Its commit step
used to `git add` four named files while the scripts also rewrite
`scanners.json`, `docs/rules.md` and the anchored docs pages, so a run that
touched any of those would have pushed a partial sync and left the rest
drifting on main. A hand-copied file list is the failure this repo keeps
having; staging every tracked change commits exactly what the drift check saw.
"""

from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "sync-rule-count.yml"


def _step_runs() -> dict[str, str]:
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    return {step.get("name", ""): step.get("run", "") for step in data["jobs"]["sync"]["steps"]}


def test_the_sync_steps_are_the_ones_this_guard_assumes() -> None:
    runs = _step_runs()
    assert "python scripts/sync_rule_count.py --regenerate" in runs["Regenerate bundle + sync surfaces"]
    assert "python scripts/sync_scanner_count.py" in runs["Sync scanner-module count"]


def test_the_drift_check_and_the_commit_see_the_same_files() -> None:
    """`git diff --quiet` sees tracked changes only, and so does `git add -u`."""
    runs = _step_runs()
    assert "git diff --quiet" in runs["Check for drift"]
    adds = [line.strip() for line in runs["Commit"].splitlines() if line.strip().startswith("git add")]
    assert adds == ["git add -u"], (
        "stage with `git add -u` so the commit carries every file the sync "
        f"scripts rewrote, not a hand-kept list; got {adds}"
    )
