"""``cve-deferred`` must name a target date, or it is a mute button.

The label is the single thing that turns the release gate off (release.yml,
docs/RELEASING.md §5). Its only stated obligation was a prose disposition
comment, checked by nobody, so the difference between "read, scheduled, will be
covered" and "made to go away" was a convention. The 2026-08-31 wave honoured it
-- all ten of those deferrals carry ``**Target: YYYY-MM-DD.**`` -- which is
exactly why nobody noticed the obligation was unenforced.

These tests pin the enforcement, and they pin the two decisions inside it that
could reasonably have gone the other way:

* the legacy ``**Target: …**`` prose spelling counts as a date, so landing the
  guard did not retroactively convict ten correctly-dated issues; and
* a date in the past is reported, never fatal, so a deferral cannot become a
  release blocker on a morning nobody chose.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import date
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load():
    """Import scripts/check_cve_deferrals.py -- the single source shared by this
    test and the release gate, so the two cannot drift apart."""
    script = REPO_ROOT / "scripts" / "check_cve_deferrals.py"
    assert script.is_file(), "scripts/check_cve_deferrals.py missing"
    spec = importlib.util.spec_from_file_location("check_cve_deferrals", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_cve_deferrals"] = module
    spec.loader.exec_module(module)
    return module


mod = _load()


def _issue(number: int, *, labels=("cve-response", "cve-deferred"), body="", comments=()):
    return {
        "number": number,
        "title": f"CVE-response: CVE-2026-{number:05d} (HIGH CVSS 7.7)",
        "labels": [{"name": name} for name in labels],
        "body": body,
        "comments": [{"body": text} for text in comments],
    }


# ---------------------------------------------------------------------------
# The obligation itself
# ---------------------------------------------------------------------------

def test_undated_deferral_is_a_violation() -> None:
    """A disposition comment with no date does not earn the exemption."""
    issue = _issue(1, comments=("## Disposition: in scope, rule queued\n\nQueued.",))
    assert mod.find_undated_deferrals([issue]) == ["#1  CVE-response: CVE-2026-00001 (HIGH CVSS 7.7)"]


def test_structured_target_date_field_satisfies_the_guard() -> None:
    issue = _issue(2, comments=("disposition: DEFERRED\ntarget date: 2026-09-30\nreason: pin floor.",))
    assert mod.find_undated_deferrals([issue]) == []
    assert mod.target_date(issue) == date(2026, 9, 30)


def test_legacy_prose_target_spelling_still_counts() -> None:
    """The exact form the 2026-08-31 wave used, bold markers and trailing period.

    If this ever stops passing, landing the guard convicts ten issues that did
    the right thing, and the lesson taught is that the guard is wrong.
    """
    issue = _issue(3, comments=("**Target: 2026-09-09.**",))
    assert mod.find_undated_deferrals([issue]) == []
    assert mod.target_date(issue) == date(2026, 9, 9)


@pytest.mark.parametrize("spelling", [
    "deferred-until: 2026-09-30",
    "deferred until: 2026-09-30",
    "deferred_until: 2026-09-30",
])
def test_deferred_until_spelling_counts(spelling) -> None:
    """The spelling a maintainer reaches for, because it names the label.

    Added by alternation rather than by replacing `target date:`. Switching
    outright was considered and rejected for the same reason the legacy prose
    form is still accepted: it would have convicted every dated deferral in the
    queue, teaching that the guard is wrong and worth routing around.
    """
    issue = _issue(20, comments=(spelling,))
    assert mod.find_undated_deferrals([issue]) == []
    assert mod.target_date(issue) == date(2026, 9, 30)


def test_date_in_the_body_counts_too() -> None:
    issue = _issue(4, body="target date: 2026-10-01", comments=())
    assert mod.find_undated_deferrals([issue]) == []


def test_date_shaped_but_not_a_date_is_not_a_date() -> None:
    """``2026-13-45`` is a typo, and a typo must read as "no date given".

    Accepting it would let the guard pass on a value nothing can order, which is
    worse than failing: it looks dated and cannot be scheduled against.
    """
    issue = _issue(5, comments=("target date: 2026-13-45",))
    assert mod.target_date(issue) is None
    assert mod.find_undated_deferrals([issue])


def test_latest_date_wins_on_a_re_deferral() -> None:
    """"We said September, then we said October" honestly reads as October."""
    issue = _issue(6, comments=("**Target: 2026-09-09.**", "Slipping. target date: 2026-10-20"))
    assert mod.target_date(issue) == date(2026, 10, 20)


# ---------------------------------------------------------------------------
# Scope: this guard judges the exempt set and nothing else
# ---------------------------------------------------------------------------

def test_untriaged_cve_response_issues_are_not_this_guards_business() -> None:
    """An undeferred issue is already blocked by the cve-response gate.

    Judging it here too would report one problem twice and, worse, imply that
    adding a date to an untriaged issue is what it needs.
    """
    issue = _issue(7, labels=("cve-response",), comments=())
    assert mod.find_undated_deferrals([issue]) == []
    assert mod.deferred_issues([issue]) == []


def test_a_deferred_label_outside_the_cve_queue_is_ignored() -> None:
    issue = _issue(8, labels=("cve-deferred",), comments=())
    assert mod.find_undated_deferrals([issue]) == []


@pytest.mark.parametrize("labels", [
    [{"name": "cve-response"}, {"name": "cve-deferred"}],
    ["cve-response", "cve-deferred"],
])
def test_both_gh_label_shapes_are_understood(labels) -> None:
    """`gh issue list --json labels` and a hand-written fixture disagree on shape.

    A guard that silently sees zero labels reports a clean queue, which is the
    one failure mode a gate must not have.
    """
    issue = {"number": 9, "title": "t", "labels": labels, "body": "", "comments": []}
    assert mod.deferred_issues([issue]) == [issue]


# ---------------------------------------------------------------------------
# Past-due is reported, never fatal
# ---------------------------------------------------------------------------

def test_past_due_deferrals_are_listed() -> None:
    issue = _issue(10, comments=("target date: 2026-01-01",))
    rows = mod.find_past_due([issue], today=date(2026, 9, 4))
    assert len(rows) == 1 and "2026-01-01" in rows[0]


def test_past_due_does_not_fail_the_run(tmp_path, capsys) -> None:
    """The trap this avoids: every deferral becomes a release blocker the morning
    its date passes, so an unrelated tag dies on a note somebody typed weeks ago."""
    path = tmp_path / "issues.json"
    path.write_text(json.dumps([_issue(11, comments=("target date: 2020-01-01",))]), encoding="utf-8")
    assert mod.main(["--issues-json", str(path)]) == 0
    assert "past their target date" in capsys.readouterr().out


def test_undated_deferral_fails_the_run(tmp_path) -> None:
    path = tmp_path / "issues.json"
    path.write_text(json.dumps([_issue(12, comments=("no date here",))]), encoding="utf-8")
    assert mod.main(["--issues-json", str(path)]) == 1


def test_clean_queue_passes(tmp_path) -> None:
    path = tmp_path / "issues.json"
    path.write_text(json.dumps([_issue(13, comments=("target date: 2027-01-01",))]), encoding="utf-8")
    assert mod.main(["--issues-json", str(path)]) == 0


def test_empty_queue_passes(tmp_path) -> None:
    path = tmp_path / "issues.json"
    path.write_text("[]", encoding="utf-8")
    assert mod.main(["--issues-json", str(path)]) == 0


# ---------------------------------------------------------------------------
# The documented contract names the requirement
# ---------------------------------------------------------------------------

def test_releasing_doc_states_the_date_requirement() -> None:
    """§5 is where a maintainer reads what the label obliges them to write.

    The guard and the doc are the same promise; a guard nobody is told about is
    just a surprising failure at tag time.
    """
    text = (REPO_ROOT / "docs" / "RELEASING.md").read_text(encoding="utf-8")
    assert "target date:" in text.lower(), "RELEASING.md must state the target-date requirement"
    assert "check_cve_deferrals.py" in text, "RELEASING.md must name the guard that enforces it"
