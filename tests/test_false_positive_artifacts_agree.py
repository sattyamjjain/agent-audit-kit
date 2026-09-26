"""The false-positive benchmark's artifacts must agree with each other.

The published FP rate went stale in the most ordinary way available: the corpus
manifest was refreshed (1,374 -> 1,641 registry servers), the benign slice grew
with it (368 -> 536), and nothing re-ran the benchmark. The README went on
advertising ``0/1 (n=1)`` — a rate measured against a slice that no longer
existed — and no guard noticed, because there was no guard.

``make fp-check`` is the full drift guard, but it re-scans 536 configs and takes
minutes, so it is a tag-time check rather than a pytest one. These tests are the
fast half: they never re-scan, they only assert that the four committed
artifacts tell the same story.

  results.json      slice size + which configs produced HIGH/CRITICAL findings
  benign-slice.json which servers were measured, with provenance
  adjudication.json the human verdict on each of those findings
  README.md         the badge rendered from the two numbers above

Any of these drifting from the others means a published number is describing
something that did not happen.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FP_DIR = REPO_ROOT / "benchmarks" / "false_positive"
RESULTS = FP_DIR / "results.json"
SLICE = FP_DIR / "benign-slice.json"
ADJUDICATION = FP_DIR / "adjudication.json"
RESULTS_MD = FP_DIR / "RESULTS.md"
README = REPO_ROOT / "README.md"


@pytest.fixture(scope="module")
def results() -> dict:
    return json.loads(RESULTS.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def slice_manifest() -> dict:
    return json.loads(SLICE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def adjudication() -> dict:
    return json.loads(ADJUDICATION.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# The artifacts agree on the slice
# ---------------------------------------------------------------------------


def test_slice_manifest_size_matches_the_measured_run(results, slice_manifest) -> None:
    """The exact drift that produced the stale badge."""
    assert slice_manifest["n"] == results["benign_slice_n"], (
        "benign-slice.json and results.json disagree on the slice size - one of "
        "them was regenerated without the other. Run 'make fp'."
    )


def test_slice_manifest_lists_every_server_it_counts(slice_manifest) -> None:
    assert len(slice_manifest["servers"]) == slice_manifest["n"]


def test_every_slice_server_carries_citable_provenance(slice_manifest) -> None:
    """A manifest without provenance is a list, not evidence."""
    for server in slice_manifest["servers"]:
        assert server.get("name")
        assert server.get("source_url"), f"{server.get('name')} has no source_url"
        assert server.get("registry_status") == "active"
        assert server.get("fetched_at")


def test_corpus_level_provenance_is_recorded(slice_manifest) -> None:
    assert "registry.modelcontextprotocol.io" in (slice_manifest.get("source") or "")
    assert slice_manifest.get("source_fetched_at")
    assert slice_manifest.get("upstream_servers", 0) >= slice_manifest["n"]


def test_the_predicate_is_the_one_that_was_pre_registered(slice_manifest) -> None:
    """Loosening a pre-registered predicate after seeing the result is the
    failure mode pre-registration exists to prevent, so it is pinned here."""
    from benchmarks.false_positive.corpus import PREDICATE  # noqa: PLC0415

    assert slice_manifest["predicate"] == PREDICATE
    for required in ("status=active", "auth_mode in", "CVE"):
        assert required in PREDICATE


# ---------------------------------------------------------------------------
# The adjudication covers exactly what was found
# ---------------------------------------------------------------------------


def test_every_high_critical_finding_was_adjudicated(results, adjudication) -> None:
    found = {f["config"] for f in results["top30_high_critical"]}
    judged = {v["config"] for v in adjudication["verdicts"]}
    assert judged == found, (
        "the adjudication and the run disagree about which configs produced "
        f"HIGH/CRITICAL findings. only-in-run={sorted(found - judged)} "
        f"only-in-adjudication={sorted(judged - found)}"
    )


def test_adjudication_count_matches_the_finding_count(results, adjudication) -> None:
    assert len(adjudication["verdicts"]) == results["high_critical_findings"]


def test_verdicts_use_the_documented_vocabulary(adjudication) -> None:
    allowed = {"true_positive", "false_positive", "ambiguous"}
    for verdict in adjudication["verdicts"]:
        assert verdict["verdict"] in allowed, verdict


def test_the_harness_does_not_label_its_own_findings(results) -> None:
    """A benchmark that adjudicated itself would be measuring nothing.

    ``run.py`` must never emit a verdict field; the FP rate is a human judgement
    recorded separately.
    """
    blob = json.dumps(results)
    for banned in ('"verdict"', '"false_positive"', '"true_positive"'):
        assert banned not in blob


# ---------------------------------------------------------------------------
# The published badge and prose match the artifacts
# ---------------------------------------------------------------------------


def test_readme_badge_is_generated_not_hand_typed() -> None:
    from scripts.sync_fp_badge import badge_markup, current_numbers  # noqa: PLC0415

    slice_n, fps, adjudicated = current_numbers()
    assert badge_markup(slice_n, fps, adjudicated) in README.read_text(encoding="utf-8")


def test_readme_badge_shows_the_slice_size(results) -> None:
    """The old badge said ``n=1`` and read as "one thing was tested".

    Whatever else the badge says, the number of configs scanned has to be on it,
    because that is the figure a reader uses to judge whether the measurement
    means anything.
    """
    from scripts.sync_fp_badge import badge_markup, current_numbers  # noqa: PLC0415

    markup = badge_markup(*current_numbers())
    assert str(results["benign_slice_n"]) in markup


def test_readme_badge_names_the_surface_it_measured() -> None:
    """The slice is MCP server configs, and nothing else is in it.

    "536 configs" let a reader take the rate to cover every file AAK reads,
    including the instruction files (CLAUDE.md, AGENTS.md) where an outside
    report on 930 repositories found AAK-AGENT-002 firing on a third of them.
    The label and the alt text both say which configs were measured.
    """
    from scripts.sync_fp_badge import badge_markup, current_numbers  # noqa: PLC0415

    markup = badge_markup(*current_numbers())
    assert "MCP%20configs" in markup, "the shields label must name MCP configs"
    assert "MCP configs scanned" in markup, "the alt text must name MCP configs"


def test_results_md_headline_matches_the_run(results, adjudication) -> None:
    text = RESULTS_MD.read_text(encoding="utf-8")
    fps = sum(1 for v in adjudication["verdicts"] if v["verdict"] == "false_positive")
    assert f"{results['benign_slice_n']}-config benign slice" in text
    assert f"{fps} / {len(adjudication['verdicts'])}" in text


def test_results_md_still_states_the_conversion_limitation() -> None:
    """It caused two of the 2026-08-24 false positives, and the fix narrowed it
    rather than removing it: one remote per server is still converted, so the
    limitation section is load-bearing rather than boilerplate."""
    text = RESULTS_MD.read_text(encoding="utf-8")
    assert "first remote" in text.lower()


# ---------------------------------------------------------------------------
# RESULTS.md prose outside the History table describes the headline run
# ---------------------------------------------------------------------------

# The Limitations bullet as it stood until this guard existed, verbatim. It
# described the 2026-08-24 run while the headline above it reported 2026-09-03's,
# and nothing read past the headline. Kept as the negative fixture: a check that
# has never failed on the real defect has not been shown to catch it.
_STALE_LIMITATION = """\
- **Small adjudication denominator → wide interval.** 6 HIGH/CRITICAL findings
  across 536 configs gives a Wilson 95% CI of [30.0%, 90.3%] on the FP rate. The
  point estimate (66.7%) should not be read as precise; the interval is the
  honest summary. The *slice* is large; the number of high-severity findings it
  provokes is small, and that is what bounds the precision of this rate.
"""
_LIMITATIONS_HEADING = "## Limitations (stated plainly)\n\n"


def test_results_md_numbers_outside_history_match_the_run() -> None:
    """Every HIGH/CRITICAL count, percentage and interval in the page body
    describes the run the headline reports. Earlier runs' numbers belong in the
    History table, which is exempt, and which holds several of them."""
    from scripts.check_fp_results_page import find_disagreements  # noqa: PLC0415

    assert find_disagreements(RESULTS_MD.read_text(encoding="utf-8")) == []


def test_the_stale_limitation_bullet_fails_the_page_check() -> None:
    from scripts.check_fp_results_page import find_disagreements  # noqa: PLC0415

    page = RESULTS_MD.read_text(encoding="utf-8")
    assert _LIMITATIONS_HEADING in page
    problems = "\n".join(find_disagreements(
        page.replace(_LIMITATIONS_HEADING, _LIMITATIONS_HEADING + _STALE_LIMITATION)
    ))
    assert "'6 HIGH/CRITICAL'" in problems
    assert "[30.0%, 90.3%]" in problems
    assert "'66.7%'" in problems
