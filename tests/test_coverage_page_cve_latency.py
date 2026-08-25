"""The coverage page must publish its CVE-response latency, and say when.

The 48-hour SLA was retired because a promise is the wrong instrument. What
replaces it is a recomputed number — but a number on a static page decays the
same way a promise does, silently, and the reader cannot tell a figure computed
this morning from one computed in June.

So the page carries the date it was computed, and `build_coverage_page.py
--check` fails once that date is more than a week old. That is the same shape as
`scripts/index_cadence.py`, deliberately: two published surfaces that both
depend on a workflow continuing to run should not disagree about what "current"
means.

The tests below cover both directions. A guard that only ever passes is exactly
the failure this repo keeps finding in its own automation.
"""

from __future__ import annotations

import re
from datetime import date, timedelta
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PAGE = REPO_ROOT / "site" / "coverage" / "index.html"
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "coverage-page.yml"

MARKER_RE = re.compile(r"<!--\s*cve-latency-computed-on:\s*(\d{4}-\d{2}-\d{2})\s*-->")


@pytest.fixture(scope="module")
def page() -> str:
    return PAGE.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# The figure
# ---------------------------------------------------------------------------


def test_page_publishes_the_latency_figure(page: str) -> None:
    assert "CVE response latency" in page
    assert "p90" in page
    assert "Median" in page


def test_the_figure_prints_its_sample_size(page: str) -> None:
    """A median over three CVEs is not a median.

    Whatever else moves, the denominator has to be on the page beside the
    figure — a reader who cannot see n cannot tell which they are looking at.
    """
    from scripts.cve_latency import window_stats  # noqa: PLC0415

    stats = window_stats(90)
    assert stats is not None, "no CVE in the trailing window; the figure is untestable"
    assert "Sample (n)" in page
    assert f"<td>{stats.n}</td>" in page


def test_the_figure_matches_a_fresh_computation(page: str) -> None:
    """The page and docs/cve-latency.md compute from one function.

    They read the same ledger, so quoting different numbers for the same window
    would mean one of them was rendered from a stale copy.
    """
    from scripts.cve_latency import window_stats  # noqa: PLC0415

    stats = window_stats(90)
    assert stats is not None
    assert f"<td>{stats.median_days:.1f} days</td>" in page
    assert f"<td>{stats.p90_days} days</td>" in page


def test_the_window_is_stated_not_implied(page: str) -> None:
    assert "trailing 90 days" in page


def test_the_page_does_not_promise_a_service_level(page: str) -> None:
    """The retired SLA must not come back in through this figure."""
    assert "no CVE-response SLA" in page
    lowered = page.lower()
    for promise in ("within 48 hours", "48-hour sla", "guaranteed"):
        assert promise not in lowered


# ---------------------------------------------------------------------------
# The staleness guard, in both directions
# ---------------------------------------------------------------------------


def test_page_states_when_the_figure_was_computed(page: str) -> None:
    assert MARKER_RE.search(page), "the page must carry a computed-on marker"


def test_committed_figure_is_currently_fresh(page: str) -> None:
    found = MARKER_RE.search(page)
    assert found
    computed = date.fromisoformat(found.group(1))
    from scripts.build_coverage_page import MAX_FIGURE_AGE_DAYS  # noqa: PLC0415

    age = (date.today() - computed).days
    assert age <= MAX_FIGURE_AGE_DAYS, (
        f"the committed coverage page's latency figure is {age} days old; "
        "the nightly coverage-page workflow has stopped publishing"
    )


def test_check_passes_on_the_committed_page() -> None:
    from scripts.build_coverage_page import check_figure_freshness  # noqa: PLC0415

    assert check_figure_freshness() == 0


def test_check_fails_on_a_stale_figure(tmp_path: Path, monkeypatch) -> None:
    """The direction that matters. Without this, deleting the comparison passes."""
    import scripts.build_coverage_page as bcp  # noqa: PLC0415

    stale = date.today() - timedelta(days=bcp.MAX_FIGURE_AGE_DAYS + 1)
    out = tmp_path / "index.html"
    out.write_text(
        f"<html><!-- cve-latency-computed-on: {stale.isoformat()} --></html>",
        encoding="utf-8",
    )
    monkeypatch.setattr(bcp, "OUT_DIR", tmp_path)
    assert bcp.check_figure_freshness() == 1


def test_check_fails_when_the_marker_is_missing(tmp_path: Path, monkeypatch) -> None:
    """A page that states no date cannot be shown to be current."""
    import scripts.build_coverage_page as bcp  # noqa: PLC0415

    (tmp_path / "index.html").write_text("<html>no marker</html>", encoding="utf-8")
    monkeypatch.setattr(bcp, "OUT_DIR", tmp_path)
    assert bcp.check_figure_freshness() == 1


def test_the_boundary_is_inclusive(tmp_path: Path, monkeypatch) -> None:
    """Exactly at the limit passes; one day past it fails."""
    import scripts.build_coverage_page as bcp  # noqa: PLC0415

    monkeypatch.setattr(bcp, "OUT_DIR", tmp_path)
    for offset, expected in ((bcp.MAX_FIGURE_AGE_DAYS, 0), (bcp.MAX_FIGURE_AGE_DAYS + 1, 1)):
        stamp = date.today() - timedelta(days=offset)
        (tmp_path / "index.html").write_text(
            f"<!-- cve-latency-computed-on: {stamp.isoformat()} -->", encoding="utf-8"
        )
        assert bcp.check_figure_freshness() == expected, offset


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------


def test_ci_checks_the_committed_page() -> None:
    """A guard nobody runs is the situation this replaced."""
    assert "build_coverage_page.py --check" in CI.read_text(encoding="utf-8")


def test_the_workflow_rebuilds_when_the_ledger_changes() -> None:
    """The figure is computed from CHANGELOG.cves.md.

    Without this trigger the page would only move on the nightly cron, so it
    would read as a day stale after every CVE that shipped a rule.
    """
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert "CHANGELOG.cves.md" in workflow
    assert "scripts/cve_latency.py" in workflow


def test_window_stats_returns_none_on_an_empty_window() -> None:
    """So the caller renders "no data" rather than a statistic over nothing."""
    from scripts.cve_latency import window_stats  # noqa: PLC0415

    assert window_stats(90, today=date(1990, 1, 1)) is None
