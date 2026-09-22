"""The published latency figure may not omit the queue it is waiting on.

Until 2026-09-22, `docs/cve-latency.md` had three coverage rows — measured,
undated, adjudicated out of scope — and every one of them describes a CVE that
already reached a disposition. "Shipped" is the date of the `CHANGELOG.cves.md`
section carrying the CVE, so a disclosure that is open and untriaged appeared in
no population at all. Not measured, not undated, not out of scope. Absent.

The omission is directional, which is what makes it worth a guard rather than a
footnote. A CVE joins the measurement only on the day it is dispositioned, so
every slow case is invisible for exactly as long as it is slow, and is counted
only once it resolves. Leaving the queue to sit moves the published median down,
never up — the one bias a latency number must not have, because the reader is
consulting it to judge that very thing.

It was live, not theoretical. On 2026-09-22 the tracker held ten open
`cve-response` issues opened 2026-09-19 — one CRITICAL, none deferred, none
commented — while the page published a median of 1.0 days. `check_cve_ageing.py`
already held critical to three days and ran daily, so the repo knew; the ageing
signal simply had no path into the measurement.

The test that matters here is the negative one,
`test_a_page_with_an_open_queue_and_no_open_row_is_refused`. A guard that only
proves it passes on a good page proves nothing: the defect was a page that was
silently *missing* a row, and a checker that cannot fail on that is the same
omission one level down.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PAGE = REPO_ROOT / "docs" / "cve-latency.md"


def _load():
    """Import scripts/cve_latency.py — the source the cron and the tag both run."""
    script = REPO_ROOT / "scripts" / "cve_latency.py"
    assert script.is_file(), "scripts/cve_latency.py missing"
    spec = importlib.util.spec_from_file_location("cve_latency", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["cve_latency"] = module
    spec.loader.exec_module(module)
    return module


mod = _load()

TODAY = date(2026, 9, 22)


def _issue(number: int, created: str, labels: list[str], title: str = "") -> dict:
    return {
        "number": number,
        "title": title or f"CVE-response: CVE-2026-{number} (HIGH CVSS 7.5)",
        "labels": [{"name": name} for name in labels],
        "createdAt": created,
    }


#: The wave that was live when this guard was written, shortened.
_WAVE = [
    _issue(758, "2026-09-19T10:59:21Z", ["cve-response", "sev/critical"],
           "CVE-response: CVE-2026-54618 (CRITICAL CVSS 9.4)"),
    _issue(759, "2026-09-19T10:59:22Z", ["cve-response", "sev/high"]),
    _issue(767, "2026-09-19T15:53:05Z", ["cve-response", "sev/high"]),
]


# ---------------------------------------------------------------------------
# Reading the queue
# ---------------------------------------------------------------------------

def test_the_open_queue_counts_undeferred_cve_response_issues() -> None:
    queue = mod.open_queue_from_issues(_WAVE, TODAY)
    assert queue.read is True
    assert queue.count == 3
    assert queue.oldest_number == 758
    assert queue.oldest_age_days == 3


def test_a_deferral_is_a_disposition_and_leaves_the_queue() -> None:
    """`cve-deferred` moves an issue to the other accounting system.

    `check_cve_deferrals.py` judges it against the date it names. Counting it
    here as well would put one issue in two places and double-report it.
    """
    deferred = _issue(700, "2026-08-01T00:00:00Z", ["cve-response", "cve-deferred"])
    queue = mod.open_queue_from_issues([*_WAVE, deferred], TODAY)
    assert queue.count == 3
    assert queue.oldest_number == 758, "a deferral must not become the oldest"


def test_non_cve_response_issues_are_not_counted() -> None:
    other = _issue(900, "2026-01-01T00:00:00Z", ["bug"])
    assert mod.open_queue_from_issues([*_WAVE, other], TODAY).count == 3


def test_the_oldest_of_a_same_day_wave_is_the_lowest_numbered() -> None:
    """Creation dates are dates, so a wave opened in one batch ties on all rows.

    `gh` lists newest first, so an unbroken tie named #767 — the newest of the
    tied set — as the oldest. Issue numbers are monotonic with creation, so they
    order a tie correctly.
    """
    assert mod.open_queue_from_issues(list(reversed(_WAVE)), TODAY).oldest_number == 758


def test_an_unreadable_tracker_is_a_stated_gap_not_a_zero() -> None:
    """`read=False` and `count=0` must never render the same.

    Substituting a zero for "I could not look" is the same flattering omission
    the row exists to close, one layer down.
    """
    unread = mod.OpenQueue(read=False)
    assert unread.read is False
    assert "not read this run" in mod.render(
        [], [], set(), unread
    ), "an unread queue must say so on the page"


# ---------------------------------------------------------------------------
# The row on the page
# ---------------------------------------------------------------------------

def test_the_rendered_page_names_the_open_queue() -> None:
    page = mod.render([], [], set(), mod.open_queue_from_issues(_WAVE, TODAY))
    assert "Disclosed, open and not yet dispositioned" in page
    assert "#758" in page
    assert "3 days" in page


def test_the_marker_round_trips_so_check_can_read_it_back() -> None:
    queue = mod.open_queue_from_issues(_WAVE, TODAY)
    parsed = mod.parse_open_queue(mod.render([], [], set(), queue))
    assert parsed is not None
    assert queue.agrees_with(parsed)


def test_a_page_without_a_marker_parses_as_unknown_not_empty() -> None:
    """None and "zero open" are different claims and must not collapse."""
    assert mod.parse_open_queue("# a page written before this row existed") is None


def test_agreement_ignores_the_age_in_days() -> None:
    """The age is a function of the render date, not of the tracker.

    Comparing it would make the guard red every morning with nothing having
    changed, and a check that is red every morning is one nobody reads by the
    end of the week.
    """
    monday = mod.open_queue_from_issues(_WAVE, date(2026, 9, 22))
    friday = mod.open_queue_from_issues(_WAVE, date(2026, 9, 26))
    assert monday.oldest_age_days != friday.oldest_age_days
    assert monday.agrees_with(friday)


def test_a_changed_queue_does_not_agree() -> None:
    smaller = mod.open_queue_from_issues(_WAVE[:2], TODAY)
    assert not mod.open_queue_from_issues(_WAVE, TODAY).agrees_with(smaller)


# ---------------------------------------------------------------------------
# The guard — the negative case is the one that matters
# ---------------------------------------------------------------------------

def _run(args: list[str], issues: list[dict], tmp_path: Path, page: str) -> subprocess.CompletedProcess:
    issues_file = tmp_path / "issues.json"
    issues_file.write_text(json.dumps(issues), encoding="utf-8")
    page_file = tmp_path / "page.md"
    page_file.write_text(page, encoding="utf-8")
    return subprocess.run(
        [
            sys.executable, "scripts/cve_latency.py", "--check-queue",
            "--issues-json", str(issues_file),
            "--out", str(page_file),
            "--today", TODAY.isoformat(),
            *args,
        ],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
    )


def test_a_page_with_an_open_queue_and_no_open_row_is_refused(tmp_path) -> None:
    """The defect itself: a non-empty queue, and a page that never mentions it.

    This is the state `docs/cve-latency.md` shipped in until 2026-09-22 — a
    median of 1.0 days published beside ten untriaged disclosures, with nothing
    on the page and nothing in CI able to say so.
    """
    page_without_the_row = "# CVE-to-rule latency\n\n| Median | 1.0 |\n"
    result = _run([], _WAVE, tmp_path, page_without_the_row)
    assert result.returncode == 1, (
        "a page that omits the open-queue row while the tracker is non-empty "
        "must be refused; this is the omission the row exists to close\n"
        + result.stdout + result.stderr
    )
    assert "no open-queue row" in result.stderr
    assert "#758" in result.stderr, "the error must name the oldest issue"


def test_a_page_whose_row_matches_the_tracker_passes(tmp_path) -> None:
    page = mod.render([], [], set(), mod.open_queue_from_issues(_WAVE, TODAY))
    result = _run([], _WAVE, tmp_path, page)
    assert result.returncode == 0, result.stdout + result.stderr


def test_a_page_whose_row_drifted_from_the_tracker_is_refused(tmp_path) -> None:
    """Two issues closed; the page still claims three."""
    page = mod.render([], [], set(), mod.open_queue_from_issues(_WAVE, TODAY))
    result = _run([], _WAVE[:1], tmp_path, page)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "disagrees with the tracker" in result.stderr


def test_an_empty_queue_and_a_page_predating_the_row_is_not_a_failure(tmp_path) -> None:
    """Nothing is being hidden, so there is nothing to report."""
    result = _run([], [], tmp_path, "# old page\n")
    assert result.returncode == 0, result.stdout + result.stderr


def test_a_page_claiming_it_could_not_read_while_the_tracker_reads_is_refused(tmp_path) -> None:
    """A stated gap is honest only until it can be closed."""
    page = mod.render([], [], set(), mod.OpenQueue(read=False))
    result = _run([], _WAVE, tmp_path, page)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "not read" in result.stderr


# ---------------------------------------------------------------------------
# The separation that keeps this out of the release path
# ---------------------------------------------------------------------------

def test_check_stays_offline_and_does_not_read_the_tracker() -> None:
    """`--check` runs inside pytest and on every tag; both need it offline.

    A network read there would make the suite depend on a token and let queue
    depth fail a release — the mistake `check_cve_ageing.py`'s docstring was
    written to avoid.
    """
    import os

    env = dict(os.environ, PATH="/usr/bin:/bin", GH_TOKEN="", GITHUB_TOKEN="")
    result = subprocess.run(
        [sys.executable, "scripts/cve_latency.py", "--check"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120, env=env,
    )
    assert result.returncode == 0, (
        "`--check` must pass with no `gh` on PATH and no token — it is the "
        "offline, byte-deterministic half.\n" + result.stdout + result.stderr
    )


def test_the_daily_cron_runs_the_queue_check_and_the_release_does_not() -> None:
    """Wiring, asserted rather than assumed.

    The whole reason `--check-queue` is a separate flag is that the release
    must not be blocked on queue depth. If a future edit moves it into
    release.yml, this fails.
    """
    watcher = (REPO_ROOT / ".github/workflows/cve-watcher.yml").read_text(encoding="utf-8")
    release = (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    assert "--check-queue" in watcher, "the daily cron must run the queue check"
    assert "--check-queue" not in release, (
        "release.yml must not run --check-queue: a published number is not a "
        "release gate, and a tag blocked on queue depth is what produced the "
        "cve-deferred label in the first place"
    )


def test_the_committed_page_carries_the_row() -> None:
    """The artifact readers actually see, not just the generator."""
    page = PAGE.read_text(encoding="utf-8")
    assert "Disclosed, open and not yet dispositioned" in page
    assert mod.parse_open_queue(page) is not None, (
        "docs/cve-latency.md has no open-queue marker — regenerate it with "
        "`python scripts/cve_latency.py`"
    )


@pytest.mark.parametrize("helper", ["response_issues", "created_on", "DEFERRED_LABEL"])
def test_the_queue_is_read_through_the_ageing_gates_helpers(helper: str) -> None:
    """One reader of the tracker, not two.

    Two parsers would eventually disagree about what "open and undeferred"
    means, and the disagreement would surface as a published number nobody
    could reproduce.
    """
    ageing = mod._load_ageing_module()
    assert hasattr(ageing, helper)
