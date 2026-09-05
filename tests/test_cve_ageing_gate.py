"""The CVE queue may age, but not silently.

The release gate answers "has every disclosure been looked at?" and stops
there, on purpose: it must never be the thing that cannot be satisfied, because
a tag that could not be cut is what turned ``cve-deferred`` into the cheapest
way out. Queue *latency* therefore needed a check that holds no lever over
shipping, and this is the test for it.

Three decisions inside it could reasonably have gone the other way, so each is
pinned here rather than left to the reader of the script:

* a ``cve-deferred`` issue is exempt from its band's budget and judged against
  its own stated date instead -- otherwise #656, correctly deferred to a named
  date, fails on day four no matter what anybody does, and the honest
  disposition scores the same as the dishonest one;
* past-due *is* fatal here, while the same fact is only reported by
  ``check_cve_deferrals.py`` -- that guard runs at tag time, where a scheduling
  note must not kill an unrelated release, and this one runs on a cron where
  there is no tag to protect; and
* an unparseable score is held to the strictest budget, not the most lenient,
  because the disclosure nobody has classified is the one that should surface
  fastest.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from datetime import date
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load():
    """Import scripts/check_cve_ageing.py -- the source shared with the cron job."""
    script = REPO_ROOT / "scripts" / "check_cve_ageing.py"
    assert script.is_file(), "scripts/check_cve_ageing.py missing"
    spec = importlib.util.spec_from_file_location("check_cve_ageing", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_cve_ageing"] = module
    spec.loader.exec_module(module)
    return module


mod = _load()

TODAY = date(2026, 9, 5)


def _issue(number, *, cvss="7.7", labels=("cve-response",), created="2026-09-04",
           body="", comments=()):
    score = "n/a" if cvss is None else cvss
    return {
        "number": number,
        "title": f"CVE-response: CVE-2026-{number:05d} (SEV CVSS {score})",
        "labels": [{"name": name} for name in labels],
        "createdAt": f"{created}T09:00:00Z",
        "body": body,
        "comments": [{"body": text} for text in comments],
    }


# ---------------------------------------------------------------------------
# Band boundaries -- CVSS v3.1 qualitative ratings, inclusive lower bounds
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("score,band", [
    (10.0, "critical"), (9.0, "critical"),
    (8.9, "high"), (7.0, "high"),
    (6.9, "medium"), (4.0, "medium"),
    (3.9, "low"), (0.0, "low"),
])
def test_band_boundaries(score, band) -> None:
    assert mod.band_for_score(score) == band


def test_parse_cvss_reads_the_watcher_title_format() -> None:
    """The exact string scripts/cve_watcher.py writes."""
    assert mod.parse_cvss("CVE-response: CVE-2026-85620 (HIGH CVSS 8.6)") == 8.6


def test_parse_cvss_handles_an_integer_score() -> None:
    """#656 and #699 carry `CVSS 10` and `CVSS 5` -- NVD does not pad them."""
    assert mod.parse_cvss("CVE-response: CVE-2026-81096 (CRITICAL CVSS 10)") == 10.0


@pytest.mark.parametrize("title", [
    "CVE-response: CVE-2026-1 (unknown CVSS n/a)",
    "CVE-response: CVE-2026-1 (no score at all)",
    "CVE-response: CVE-2026-1 (bogus CVSS 11)",
    "CVE-response: CVE-2026-1 (bogus CVSS -1)",
])
def test_unscoreable_titles_yield_no_score(title) -> None:
    """A value off the 0-10 scale is not a score, and must not be coerced onto
    the scale -- that would file the issue in a band nobody chose."""
    assert mod.parse_cvss(title) is None
    assert mod.band_for_issue({"title": title}) == mod.UNKNOWN_BAND


def test_cve_id_digits_are_not_mistaken_for_a_score() -> None:
    """`CVE-2026-85620` is full of numbers; only the one after CVSS counts."""
    assert mod.parse_cvss("CVE-response: CVE-2026-85620 (HIGH CVSS 8.6)") == 8.6


# ---------------------------------------------------------------------------
# Budgets
# ---------------------------------------------------------------------------

def test_budgets_are_the_documented_four_plus_unknown() -> None:
    assert mod.AGE_BUDGET_DAYS == {
        "critical": 3, "high": 7, "medium": 21, "low": 60, "unknown": 3,
    }


def test_an_issue_exactly_at_its_budget_is_not_overdue() -> None:
    """The budget is the allowance, not the deadline it has already missed."""
    issue = _issue(1, cvss="8.6", created="2026-08-29")  # 7 days on 2026-09-05
    assert mod.age_days(issue, TODAY) == 7
    assert mod.find_overdue([issue], TODAY) == []


def test_one_day_past_the_budget_is_overdue() -> None:
    issue = _issue(2, cvss="8.6", created="2026-08-28")  # 8 days
    rows = mod.find_overdue([issue], TODAY)
    assert len(rows) == 1
    assert "sev/high" in rows[0] and "8d (budget 7d)" in rows[0]


def test_unknown_band_is_held_to_the_critical_budget() -> None:
    """Lenience here would let a malformed title age out of sight forever,
    which is the single outcome this gate exists to prevent."""
    issue = _issue(3, cvss=None, created="2026-08-30")  # 6 days
    assert mod.band_for_issue(issue) == "unknown"
    assert mod.find_overdue([issue], TODAY), "unknown must not get the low budget"


def test_the_report_is_ordered_oldest_first() -> None:
    issues = [
        _issue(4, cvss="8.6", created="2026-08-28"),
        _issue(5, cvss="8.6", created="2026-08-20"),
    ]
    rows = mod.find_overdue(issues, TODAY)
    assert rows[0].startswith("#5"), "the worst offender leads the list"


def test_an_issue_with_no_creation_date_is_skipped_not_crashed_on() -> None:
    """A gate that raises on one malformed row reports nothing about the rest."""
    issue = {"number": 6, "title": "CVE-response: x (HIGH CVSS 8.6)",
             "labels": [{"name": "cve-response"}], "createdAt": ""}
    assert mod.find_overdue([issue], TODAY) == []


def test_non_cve_response_issues_are_not_this_gates_business() -> None:
    issue = _issue(7, cvss="9.9", created="2020-01-01", labels=("bug",))
    assert mod.find_overdue([issue], TODAY) == []


# ---------------------------------------------------------------------------
# Deferral moves an issue between two accounting systems
# ---------------------------------------------------------------------------

def test_a_dated_deferral_is_exempt_from_its_band_budget() -> None:
    """#656 is the live case: critical, far past 3 days, correctly deferred."""
    issue = _issue(656, cvss="10", created="2026-08-27",
                   labels=("cve-response", "cve-deferred"),
                   comments=("target date: 2026-09-30",))
    assert mod.age_days(issue, TODAY) == 9
    assert mod.find_overdue([issue], TODAY) == [], "a dated deferral is not overdue"
    assert mod.find_undated_or_past_due([issue], TODAY) == []


def test_an_undated_deferral_is_a_fault() -> None:
    issue = _issue(8, labels=("cve-response", "cve-deferred"), comments=("queued.",))
    rows = mod.find_undated_or_past_due([issue], TODAY)
    assert len(rows) == 1 and "no target date" in rows[0]


def test_a_past_due_deferral_is_fatal_here() -> None:
    """The counterpart guard only *reports* this. See the module docstring for
    why the two readings differ: that one runs at tag time, this one does not."""
    issue = _issue(9, labels=("cve-response", "cve-deferred"),
                   comments=("target date: 2026-08-01",))
    rows = mod.find_undated_or_past_due([issue], TODAY)
    assert len(rows) == 1 and "passed" in rows[0] and "35d ago" in rows[0]


def test_a_deferral_due_today_has_not_passed() -> None:
    """Due today is still due, not late."""
    issue = _issue(10, labels=("cve-response", "cve-deferred"),
                   comments=("target date: 2026-09-05",))
    assert mod.find_undated_or_past_due([issue], TODAY) == []


def test_the_deferred_until_spelling_is_accepted() -> None:
    """Added alongside `target date:` rather than replacing it -- switching
    outright would have convicted every dated deferral already in the queue."""
    issue = _issue(11, labels=("cve-response", "cve-deferred"),
                   comments=("deferred-until: 2026-12-01",))
    assert mod.find_undated_or_past_due([issue], TODAY) == []


def test_date_parsing_is_delegated_not_reimplemented() -> None:
    """Two guards that each parse dates their own way will disagree, and the
    disagreement shows up as a gate that passes at tag time and fails on cron."""
    deferrals = mod._load_deferrals_module()
    issue = _issue(12, labels=("cve-response", "cve-deferred"),
                   comments=("**Target: 2026-11-11.**",))
    assert deferrals.target_date(issue) == date(2026, 11, 11)
    assert mod.find_undated_or_past_due([issue], TODAY) == []


@pytest.mark.parametrize("labels", [
    [{"name": "cve-response"}],
    ["cve-response"],
])
def test_both_gh_label_shapes_are_understood(labels) -> None:
    """A guard that silently sees zero labels reports a clean queue, which is
    the one failure mode a gate must not have."""
    issue = {"number": 13, "title": "CVE-response: x (HIGH CVSS 8.6)",
             "labels": labels, "createdAt": "2026-01-01T00:00:00Z"}
    assert mod.response_issues([issue]) == [issue]


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

def _run(tmp_path, issues, today=TODAY):
    path = tmp_path / "issues.json"
    path.write_text(json.dumps(issues), encoding="utf-8")
    return mod.main(["--issues-json", str(path), "--today", today.isoformat()])


def test_clean_queue_exits_zero(tmp_path) -> None:
    assert _run(tmp_path, [_issue(14, cvss="8.6", created="2026-09-04")]) == 0


def test_empty_queue_exits_zero(tmp_path) -> None:
    assert _run(tmp_path, []) == 0


def test_overdue_queue_exits_one(tmp_path) -> None:
    assert _run(tmp_path, [_issue(15, cvss="8.6", created="2026-08-01")]) == 1


def test_undated_deferral_exits_one(tmp_path) -> None:
    issue = _issue(16, labels=("cve-response", "cve-deferred"), comments=("no date",))
    assert _run(tmp_path, [issue]) == 1


# ---------------------------------------------------------------------------
# The label and the budget must come from the same string
# ---------------------------------------------------------------------------

WORKFLOW = REPO_ROOT / ".github" / "workflows" / "cve-watcher.yml"


def _watcher_script() -> str:
    wf = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    for job in wf["jobs"].values():
        for step in job.get("steps") or []:
            if step.get("name") == "File response-tracking issue":
                return step["with"]["script"]
    raise AssertionError("the issue-filing step is gone from cve-watcher.yml")


def test_the_workflow_regex_matches_the_python_one_exactly() -> None:
    """The label is applied in JS at creation; the budget is enforced in Python
    on a cron. They read the same title, so they must read it the same way --
    otherwise an issue carries `sev/high` while ageing as `sev/medium`, and
    nothing anywhere reports the contradiction."""
    found = re.search(r"const CVSS_RE = /(.+?)/i;", _watcher_script())
    assert found, "CVSS_RE is no longer declared in the workflow"
    assert found.group(1) == mod.CVSS_RE.pattern, (
        f"workflow regex {found.group(1)!r} has drifted from "
        f"check_cve_ageing.py's {mod.CVSS_RE.pattern!r}"
    )


def test_the_workflow_applies_a_severity_label() -> None:
    script = _watcher_script()
    assert "sevLabel" in script
    assert "labels: ['cve-response', sevLabel]" in script


def test_the_workflow_band_thresholds_match_the_python_ones() -> None:
    """Both sides hard-code 9.0/7.0/4.0. A silent edit to one is a mislabelled
    queue that still passes every other test in this file."""
    script = _watcher_script()
    for floor in ("9.0", "7.0", "4.0"):
        assert f"score >= {floor}" in script, f"workflow lost the {floor} threshold"
    assert [f for _, f in mod._BAND_FLOORS] == [9.0, 7.0, 4.0, 0.0]


def test_the_age_gate_job_does_not_gate_the_release() -> None:
    """The whole design: a red check that blocks nothing. If this job ever
    becomes a dependency of a publish step, the deferral pressure that created
    `cve-deferred` comes back."""
    release = (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "check_cve_ageing" not in release, (
        "the ageing gate must not be wired into the release pipeline"
    )


def test_the_two_jobs_select_different_crons() -> None:
    """Without the `if:` guards both jobs run on both crons, and the gate
    reports four times a day -- which trains people to stop reading it."""
    wf = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    # PyYAML parses a bare `on:` key as the boolean True.
    crons = [entry["cron"] for entry in wf[True]["schedule"]]
    assert crons == ["17 */6 * * *", "41 7 * * *"]
    assert crons[0] in wf["jobs"]["watch"]["if"]
    assert crons[1] in wf["jobs"]["age-gate"]["if"]
