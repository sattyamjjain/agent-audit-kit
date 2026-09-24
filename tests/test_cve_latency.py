"""Tests for scripts/cve_latency.py — the published CVE-to-rule latency number.

The figure goes in a doc that is regenerated on every tag, so the parsing has to
be right about three things a rule count never had to care about: which release
actually shipped a CVE's rule, which CVEs never got one, and which CVEs are only
mentioned in passing.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from datetime import date
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "cve_latency.py"
_spec = importlib.util.spec_from_file_location("cve_latency", _SCRIPT)
assert _spec and _spec.loader
cve_latency = importlib.util.module_from_spec(_spec)
sys.modules["cve_latency"] = cve_latency
_spec.loader.exec_module(cve_latency)

REPO_ROOT = Path(__file__).resolve().parent.parent

parse_ledger = cve_latency.parse_ledger
build_rows = cve_latency.build_rows
percentile_nearest_rank = cve_latency.percentile_nearest_rank
render = cve_latency.render


LEDGER = """# AAK CVE-to-Rule Ledger

Preamble prose mentioning CVE-2026-00000 must not become a row.

## 2026-08-14 (v0.3.75)

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-73498 (thing < 0.22.0 — desc) | [NVD](x) | **In scope, pinned** `AAK-A-001`. Distinct from the earlier chain (CVE-2026-27825/27826). | 2026-08-14 |

## 2026-08-12 (v0.3.74)

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-73222 (other < 1.29.4 — desc) | [NVD](x) | **In scope, pinned** `AAK-B-001`. | 2026-08-12 |

## 2026-08-10 (unreleased)

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-70001 (landed between tags) | [NVD](x) | **In scope, pinned** `AAK-C-001`. | 2026-08-10 |
| CVE-2026-70002 (ruled out) | [NVD](x) | **Out of scope** — no MCP surface. | 2026-08-10 |

## 2026-08-03 (v0.3.67)

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-60001 (early) | [NVD](x) | **In scope, pinned** `AAK-D-001`. | 2026-08-03 |
"""


@pytest.fixture()
def parsed() -> tuple[dict, set]:
    return parse_ledger(LEDGER)


# --- ledger parsing ---------------------------------------------------------


def test_in_scope_rows_are_attributed_to_their_release(parsed) -> None:
    shipped, _ = parsed
    assert shipped["CVE-2026-73498"] == (date(2026, 8, 14), "v0.3.75")
    assert shipped["CVE-2026-73222"] == (date(2026, 8, 12), "v0.3.74")
    assert shipped["CVE-2026-60001"] == (date(2026, 8, 3), "v0.3.67")


def test_unreleased_section_rolls_up_to_the_next_tagged_release(parsed) -> None:
    """A section between tags shipped in the nearest tagged release above it."""
    shipped, _ = parsed
    assert shipped["CVE-2026-70001"] == (date(2026, 8, 10), "v0.3.74")


def test_out_of_scope_rows_are_tracked_separately(parsed) -> None:
    shipped, out_of_scope = parsed
    assert "CVE-2026-70002" not in shipped
    assert "CVE-2026-70002" in out_of_scope


def test_context_mentions_do_not_become_rows(parsed) -> None:
    """A CVE named only in a disposition cell must not be backdated into that release."""
    shipped, out_of_scope = parsed
    assert "CVE-2026-27825" not in shipped
    assert "CVE-2026-27826" not in shipped
    assert "CVE-2026-27825" not in out_of_scope


def test_cve_referenced_inside_the_subject_description_is_not_counted() -> None:
    """A prior CVE named in the row's own description must not be attributed here.

    The ledger has rows like "CVE-2026-69263 (Flowise < 3.1.3 — the CVE-2025-8943
    mitigation denied ...)". Counting the referenced CVE gave it a 356-day
    latency and dragged p90 from 2 days to 4.
    """
    ledger = """## 2026-08-05 (v0.3.71)

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-69263 (Flowise < 3.1.3 — the CVE-2025-8943 mitigation denied `-y` on npx) | [NVD](x) | **In scope, pinned** `AAK-F-001`. | 2026-08-05 |
"""
    shipped, out_of_scope = parse_ledger(ledger)
    assert "CVE-2026-69263" in shipped
    assert "CVE-2025-8943" not in shipped
    assert "CVE-2025-8943" not in out_of_scope


def test_a_row_covering_several_cves_counts_all_of_them() -> None:
    """Multi-CVE subjects are real; only the leading run is the subject."""
    ledger = """## 2026-08-05 (v0.3.71)

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-55604, CVE-2026-55605 (one server, two arms — supersedes CVE-2026-11111) | [NVD](x) | **In scope, pinned** `AAK-G-001`. | 2026-08-05 |
"""
    shipped, _ = parse_ledger(ledger)
    assert "CVE-2026-55604" in shipped
    assert "CVE-2026-55605" in shipped
    assert "CVE-2026-11111" not in shipped


# A negative latency is normally a parsing fault. It is legitimate only when
# coverage was genuinely written from a vendor advisory before NVD published,
# and each such row has to be checked by hand and recorded here with what was
# verified. Anything NOT on this list still fails, which is the signal the test
# was built for.
_VERIFIED_PRE_COVERAGE = {
    # Dispositioned 2026-08-16 from GHSA-9hgc-g3w5-67cm, which is the source the
    # ledger row cites; AAK-SSRF-TOCTOU-001 was widened that day (guard
    # recognition became body-based as well as name-based). NVD published it on
    # 2026-09-14, 29 days later. The rule really did predate the disclosure.
    "CVE-2026-53708",
    # Dispositioned 2026-08-16 (v0.3.80) from GHSA-49m4-vp58-wgc9, which the
    # ledger row cites and which GitHub published on 2026-08-12 — four days
    # before the section. NVD published it on 2026-09-21, 36 days after the rule
    # shipped, and the `--refresh` on 2026-09-24 filled that date in for the
    # first time, which is when this row appeared at all. The pin
    # (AAK-MCP-STATA-CVE-2026-47708-001, floor moved to 1.19.0) really did
    # predate the disclosure.
    "CVE-2026-55071",
}


def test_real_ledger_produces_no_impossible_latency() -> None:
    """Guard the parsing, not the calendar.

    An earlier version of this asserted every row was under 90 days, on the
    theory that a long latency meant a referenced CVE had leaked into the
    measurement. That conflated two different things: CVE-2026-30624 is a
    genuine 122-day row (published April, shipped as the deferred #160 backlog
    item in August), and a real backlog entry should not fail the suite.

    A *negative* latency is the parsing-fault signal — a rule credited to a
    release that predates the CVE. It has exactly one legitimate cause, coverage
    written from a vendor advisory ahead of NVD enrichment, so the exceptions are
    enumerated in `_VERIFIED_PRE_COVERAGE` with the evidence rather than the
    check being relaxed. An unlisted negative row still fails.
    """
    import json

    root = Path(__file__).resolve().parent.parent
    shipped, _ = parse_ledger((root / "CHANGELOG.cves.md").read_text(encoding="utf-8"))
    published = json.loads((root / "docs" / "data" / "cve-published.json").read_text())
    rows, _missing = build_rows(shipped, published)
    assert rows

    negative = [r for r in rows if r.days < 0 and r.cve not in _VERIFIED_PRE_COVERAGE]
    assert not negative, (
        "negative latency means a CVE was credited to a release that predates it. "
        "If coverage genuinely shipped from a vendor advisory before NVD "
        "published, verify it and add it to _VERIFIED_PRE_COVERAGE with the "
        "advisory id: "
        + ", ".join(f"{r.cve} ({r.days}d)" for r in negative)
    )
    for r in rows:
        if r.cve in _VERIFIED_PRE_COVERAGE:
            continue
        assert r.shipped >= r.published, f"{r.cve}: shipped {r.shipped} < published {r.published}"


def test_verified_pre_coverage_rows_are_really_negative() -> None:
    """Keep the allowlist honest: an entry that no longer applies must be removed.

    Without this, a stale exemption would sit there masking a future fault on
    the same CVE id.
    """
    import json

    root = Path(__file__).resolve().parent.parent
    shipped, _ = parse_ledger((root / "CHANGELOG.cves.md").read_text(encoding="utf-8"))
    published = json.loads((root / "docs" / "data" / "cve-published.json").read_text())
    rows, _missing = build_rows(shipped, published)
    by_cve = {r.cve: r for r in rows}
    for cve in _VERIFIED_PRE_COVERAGE:
        assert cve in by_cve, f"{cve} is exempted but no longer in the ledger"
        assert by_cve[cve].days < 0, (
            f"{cve} is no longer a negative row — drop it from "
            "_VERIFIED_PRE_COVERAGE so a real fault there cannot hide"
        )


def test_backlog_rows_are_disclosed_separately() -> None:
    """Long rows must be labelled, so median/p90 aren't read as covering them."""
    rows = [
        cve_latency.Row("CVE-A", date(2026, 8, 12), date(2026, 8, 13), "v1", 1),
        cve_latency.Row("CVE-B", date(2026, 4, 15), date(2026, 8, 15), "v1", 122),
    ]
    doc = render(rows, [], set())
    assert "## Backlog rows" in doc
    assert "CVE-B" in doc.split("## Backlog rows")[1]
    # The fast row is not mislabelled as backlog.
    assert "CVE-A" not in doc.split("## Backlog rows")[1].split("##")[0]


def test_no_backlog_section_when_every_row_is_fast() -> None:
    rows = [cve_latency.Row("CVE-A", date(2026, 8, 12), date(2026, 8, 13), "v1", 1)]
    assert "## Backlog rows" not in render(rows, [], set())


def test_prose_outside_a_table_is_ignored(parsed) -> None:
    shipped, out_of_scope = parsed
    assert "CVE-2026-00000" not in shipped
    assert "CVE-2026-00000" not in out_of_scope


def test_earliest_shipping_release_wins() -> None:
    """A CVE re-mentioned later keeps the release that first carried coverage."""
    ledger = LEDGER + """
## 2026-07-01 (v0.3.60)

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-73222 (same CVE, earlier partial) | [NVD](x) | **In scope, pinned** `AAK-B-000`. | 2026-07-01 |
"""
    shipped, _ = parse_ledger(ledger)
    assert shipped["CVE-2026-73222"] == (date(2026, 7, 1), "v0.3.60")


def test_out_of_scope_then_in_scope_counts_as_in_scope() -> None:
    ledger = """## 2026-08-14 (v0.3.75)

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-70003 (now pinnable) | [NVD](x) | **In scope, pinned** `AAK-E-001`. | 2026-08-14 |

## 2026-08-01 (v0.3.65)

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2026-70003 (no artifact yet) | [NVD](x) | **Out of scope** — nothing to pin. | 2026-08-01 |
"""
    shipped, out_of_scope = parse_ledger(ledger)
    assert "CVE-2026-70003" in shipped
    assert "CVE-2026-70003" not in out_of_scope


# --- latency maths ----------------------------------------------------------


def test_days_are_calendar_days_from_published_to_shipped(parsed) -> None:
    shipped, _ = parsed
    rows, missing = build_rows(shipped, {"CVE-2026-73222": "2026-08-09T10:00:00.000"})
    assert missing  # the rest have no published date
    row = next(r for r in rows if r.cve == "CVE-2026-73222")
    assert row.days == 3
    assert row.published == date(2026, 8, 9)


def test_cves_without_a_published_date_are_reported_not_dropped(parsed) -> None:
    shipped, _ = parsed
    rows, missing = build_rows(shipped, {})
    assert rows == []
    assert set(missing) == set(shipped)


@pytest.mark.parametrize(
    ("values", "pct", "expected"),
    [
        ([1], 90, 1),
        ([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 90, 9),
        ([5, 5, 5], 90, 5),
        ([1, 100], 90, 100),
    ],
)
def test_percentile_is_nearest_rank(values: list[int], pct: int, expected: int) -> None:
    """Every reported figure must be a latency that actually occurred."""
    assert percentile_nearest_rank(values, pct) == expected


def test_percentile_returns_an_observed_value() -> None:
    values = [2, 4, 9, 11, 40]
    assert percentile_nearest_rank(values, 90) in values


# --- rendering --------------------------------------------------------------


def test_render_discloses_every_population(parsed) -> None:
    shipped, out_of_scope = parsed
    rows, missing = build_rows(shipped, {"CVE-2026-73222": "2026-08-09T10:00:00.000"})
    doc = render(rows, missing, out_of_scope)
    assert "# CVE-to-rule latency" in doc
    assert "| Median | 3.0 |" in doc
    assert "Adjudicated out of scope" in doc
    # Missing entries are named, not silently excluded.
    for cve in missing:
        assert cve in doc


def test_render_handles_an_empty_measurement_set() -> None:
    doc = render([], ["CVE-2026-00001"], set())
    assert "No CVE has both a published date and a shipping release yet" in doc


def test_render_states_no_sla_commitment(parsed) -> None:
    shipped, out_of_scope = parsed
    rows, missing = build_rows(shipped, {"CVE-2026-73222": "2026-08-09T10:00:00.000"})
    doc = render(rows, missing, out_of_scope)
    assert "no fixed CVE-response SLA" in doc


# --- the real ledger parses -------------------------------------------------


def test_real_ledger_parses_and_attributes_the_new_cves() -> None:
    repo_ledger = Path(__file__).resolve().parent.parent / "CHANGELOG.cves.md"
    shipped, out_of_scope = parse_ledger(repo_ledger.read_text(encoding="utf-8"))
    assert shipped
    assert out_of_scope
    assert shipped["CVE-2026-73296"][1] == "v0.3.76"
    assert shipped["CVE-2026-73498"][1] == "v0.3.76"
    # Second wave of the same release.
    assert shipped["CVE-2026-49856"][1] == "v0.3.76"
    assert shipped["CVE-2026-49857"][1] == "v0.3.76"
    # Carried by AAK-FLOWISE-001's existing 3.1.3 floor rather than a new pin.
    assert shipped["CVE-2026-73601"][1] == "v0.3.76"
    # Adjudicated out of scope in the 2026-08-13 wave.
    for cve in ("CVE-2026-73614", "CVE-2026-19751", "CVE-2026-19752",
                "CVE-2026-19753", "CVE-2026-73037"):
        assert cve in out_of_scope, f"{cve} should be recorded out of scope"
        assert cve not in shipped
    # Overlap would mean a CVE counted as both covered and ruled out.
    assert not (set(shipped) & out_of_scope)


# --- the two populations must stay separated -------------------------------


def test_summary_reports_response_not_a_mixed_figure() -> None:
    """A backlog row must not drag the headline response number.

    Pinning four old Letta CVEs in one sitting moved a mixed p90 from 2 days to
    122 while the actual response time to fresh disclosures had not changed.
    The summary reports the response population; backlog is disclosed apart.
    """
    rows = [
        cve_latency.Row("CVE-A", date(2026, 8, 12), date(2026, 8, 13), "v1", 1),
        cve_latency.Row("CVE-B", date(2026, 8, 12), date(2026, 8, 14), "v1", 2),
        cve_latency.Row("CVE-OLD", date(2025, 6, 16), date(2026, 8, 15), "v1", 425),
    ]
    doc = render(rows, [], set())
    summary = doc.split("## Summary")[1].split("## Coverage")[0]

    assert "| Median | 1.5 |" in summary, "median must cover the response rows only"
    assert "| Slowest | 2 |" in summary, "the 425-day backlog row must not be the slowest"
    assert "425" in summary, "the backlog range must still be disclosed"
    assert "not response times" in summary


def test_backlog_only_population_does_not_fabricate_a_response_figure() -> None:
    rows = [cve_latency.Row("CVE-OLD", date(2025, 1, 1), date(2026, 8, 15), "v1", 591)]
    summary = render(rows, [], set()).split("## Summary")[1].split("## Coverage")[0]
    assert "no rows in this population" in summary


def test_all_response_rows_needs_no_backlog_note() -> None:
    rows = [cve_latency.Row("CVE-A", date(2026, 8, 12), date(2026, 8, 13), "v1", 1)]
    doc = render(rows, [], set())
    assert "deferred roadmap rows were picked up later" not in doc
    assert "## Backlog rows" not in doc


def test_real_doc_separates_the_populations() -> None:
    """Guard the published artifact, not just the renderer."""
    doc = (Path(__file__).resolve().parent.parent / "docs" / "cve-latency.md")
    if not doc.is_file():
        pytest.skip("doc not generated in this checkout")
    text = doc.read_text(encoding="utf-8")
    summary = text.split("## Summary")[1].split("## Coverage")[0]
    assert "Response to newly disclosed CVEs" in summary
    assert "not response times" in summary


# ---------------------------------------------------------------------------
# Section headings: every dated heading owns its own rows
# ---------------------------------------------------------------------------


def test_every_dated_heading_is_recognised_as_a_section() -> None:
    """The ledger uses three heading forms; the parser must read all of them.

    `## 2026-08-15 (v0.3.77)`      -- parens, no colon
    `## 2026-08-17 — one pin ...`  -- em dash, no parens
    `## 2026-08-22: one new pin`   -- colon, no parens

    The original pattern required parentheses, so the third form never matched
    and its rows silently inherited the date of whichever parenthesised heading
    sat above them. Nine dated sections -- roughly the two most recent weeks --
    were affected, which moved the published p90.
    """
    from scripts.cve_latency import _SECTION_RE, LEDGER  # noqa: PLC0415

    headings = [
        line
        for line in LEDGER.read_text(encoding="utf-8").splitlines()
        if line.startswith("## ")
    ]
    dated = [h for h in headings if re.match(r"^##\s+\d{4}-\d{2}-\d{2}", h)]
    assert dated, "ledger has no dated headings"
    unmatched = [h for h in dated if not _SECTION_RE.match(h)]
    assert not unmatched, f"dated headings the parser cannot see: {unmatched}"


def test_undated_headings_are_not_treated_as_sections() -> None:
    """`## Older CVE ledger` is a pointer, not a section."""
    from scripts.cve_latency import _SECTION_RE  # noqa: PLC0415

    assert not _SECTION_RE.match("## Older CVE ledger")
    assert not _SECTION_RE.match("## Format")


def test_each_cve_is_dated_to_its_own_section() -> None:
    """End-to-end: no row inherits a neighbouring section's date.

    Ground truth is an independent walk over every dated heading, so this fails
    if the parser and the file's own structure ever disagree again -- including
    if a future heading introduces a fourth format.
    """
    from scripts.cve_latency import (  # noqa: PLC0415
        _CVE_RE,
        _OUT_OF_SCOPE_RE,
        _SUBJECT_RE,
        LEDGER,
        parse_ledger,
    )

    text = LEDGER.read_text(encoding="utf-8")
    truth: dict[str, str] = {}
    current: str | None = None
    for line in text.splitlines():
        heading = re.match(r"^##\s+(\d{4}-\d{2}-\d{2})", line)
        if heading:
            current = heading.group(1)
            continue
        subject = _SUBJECT_RE.match(line)
        if subject and current and not _OUT_OF_SCOPE_RE.search(line):
            for cve in _CVE_RE.findall(subject.group(1)):
                # parse_ledger keeps the EARLIEST section that carried coverage.
                if cve not in truth or current < truth[cve]:
                    truth[cve] = current

    shipped, _ = parse_ledger(text)
    mismatches = {
        cve: (str(value[0]), truth[cve])
        for cve, value in shipped.items()
        if cve in truth and str(value[0]) != truth[cve]
    }
    assert not mismatches, f"CVEs dated to the wrong section: {mismatches}"


# ---------------------------------------------------------------------------
# The Release column: a label the ledger stopped writing
#
# On 2026-09-24, 66 of the 102 published rows said `unreleased` — every row from
# 2026-08-16 onward — while PyPI had been serving 0.3.78 through 0.6.7 the whole
# time. `parse_ledger` reads the version out of a section heading's
# parenthesised label and carries the nearest labelled section above it down to
# the ones without. The ledger stopped writing that label after
# `## 2026-08-15 (v0.3.77)`, so twenty-two sections had nothing to inherit and
# fell back to the string the walk starts with.
#
# The parser did what it documents. Nothing compared the Release column against
# the releases that exist, so a reader asking whether their installed 0.6.7
# carried a rule for CVE-2026-91932 read "unreleased" and concluded it did not.
# False, and false in the direction that makes the project look slower to ship
# than it is, on the page whose job is to measure that.
# ---------------------------------------------------------------------------

_FIXTURE_CHANGELOG = """# Changelog

## [Unreleased]

## [0.9.1] - 2026-09-20

## [0.9.0] - 2026-09-10
"""


def _fixture_ledger(section_date: str) -> str:
    """A one-row ledger whose only section carries NO version label."""
    return (
        "# AAK CVE-to-Rule Ledger\n\n"
        f"## {section_date}: a batch with no version label\n\n"
        "| CVE | CVSS | Package | What changed | Issue |\n"
        "|---|---|---|---|---|\n"
        "| CVE-2026-11111 | 9.0 | `x` | New pin. | #1 |\n"
    )


_PUBLISHED_FIXTURE = {"CVE-2026-11111": "2026-09-01T00:00:00"}


def _run_check(tmp_path: Path, ledger: str, changelog: str) -> "object":
    import subprocess

    ledger_file = tmp_path / "ledger.md"
    ledger_file.write_text(ledger, encoding="utf-8")
    changelog_file = tmp_path / "CHANGELOG.md"
    changelog_file.write_text(changelog, encoding="utf-8")
    issues_file = tmp_path / "issues.json"
    issues_file.write_text("[]", encoding="utf-8")
    page = tmp_path / "page.md"

    common = [
        sys.executable, "scripts/cve_latency.py",
        "--ledger", str(ledger_file),
        "--changelog", str(changelog_file),
        "--out", str(page),
        "--issues-json", str(issues_file),
    ]
    # Render first, so a failure below is the Release-column guard and never
    # the byte-drift comparison sitting behind it.
    subprocess.run(common, cwd=REPO_ROOT, capture_output=True, text=True, timeout=120)
    return subprocess.run(
        [*common, "--check"], cwd=REPO_ROOT, capture_output=True, text=True, timeout=120
    )


def test_an_unlabelled_section_older_than_a_release_fails_check(tmp_path) -> None:
    """The defect itself: a section shipped by a release, still saying so nowhere.

    0.9.1 was cut on 2026-09-20. A section dated 2026-09-15 was therefore in the
    tree when it was built, so its rows shipped in 0.9.1 and the heading owes a
    version label.
    """
    result = _run_check(tmp_path, _fixture_ledger("2026-09-15"), _FIXTURE_CHANGELOG)
    assert result.returncode == 1, (
        "a row resolving to 'unreleased' while a later release exists must be "
        "refused\n" + result.stdout + result.stderr
    )
    assert "unreleased" in result.stderr
    assert "CVE-2026-11111" in result.stderr
    assert "0.9.1" in result.stderr, "the error must name the release that overtook it"


def test_an_unlabelled_section_newer_than_every_release_passes(tmp_path) -> None:
    """The positive twin, and the reason the comparison is *strictly* after.

    A ledger section is written when the disposition is done; the tag is cut
    afterwards. The newest section is therefore legitimately unreleased, and
    failing on it would make the guard permanently red and permanently ignored.
    """
    result = _run_check(tmp_path, _fixture_ledger("2026-09-24"), _FIXTURE_CHANGELOG)
    assert result.returncode == 0, (
        "a section newer than every release is honestly unreleased\n"
        + result.stdout + result.stderr
    )


def test_a_section_dated_the_day_of_a_release_is_not_a_fault(tmp_path) -> None:
    """Same-day is the edge the `strictly after` comparison exists for."""
    result = _run_check(tmp_path, _fixture_ledger("2026-09-20"), _FIXTURE_CHANGELOG)
    assert result.returncode == 0, result.stdout + result.stderr


def test_release_dates_reads_only_released_headings() -> None:
    """`## [Unreleased]` names no version and carries no date, so it dates nothing."""
    found = cve_latency.release_dates(_FIXTURE_CHANGELOG)
    assert found == [("0.9.0", date(2026, 9, 10)), ("0.9.1", date(2026, 9, 20))]


def test_release_dates_reads_every_versioned_heading_in_the_real_changelog() -> None:
    """Guard the guard: a regex that stops matching makes the check vacuous.

    Pinned to the file's own count rather than a threshold, so adding releases
    never needs this number edited and a heading the regex stops seeing fails
    here instead of silently shrinking what `--check` can catch.
    """
    text = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    versioned = re.findall(r"^## \[(\d+\.\d+\.\d+)\][^\n]*$", text, re.M)
    found = cve_latency.release_dates(text)
    assert {v for v, _ in found} == set(versioned), (
        "release_dates missed a versioned heading: "
        f"{sorted(set(versioned) - {v for v, _ in found})}"
    )
    assert len(found) == len(versioned) > 40
    assert found == sorted(found, key=lambda pair: pair[1])
    # `## [Unreleased]` names no version and carries no date, so it dates nothing.
    assert "Unreleased" not in {v for v, _ in found}


def test_no_row_on_the_committed_page_is_wrongly_unreleased() -> None:
    """The artifact readers actually see, not just the generator."""
    shipped, _ = parse_ledger((REPO_ROOT / "CHANGELOG.cves.md").read_text(encoding="utf-8"))
    releases = cve_latency.release_dates(
        (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    )
    faults = cve_latency.find_unlabelled_shipped(shipped, releases)
    assert faults == [], (
        "these rows claim 'unreleased' although a release was cut after their "
        "section:\n  " + "\n  ".join(faults)
    )


def test_the_comma_form_keeps_a_qualifier_alongside_the_version() -> None:
    """`(v0.3.89, later)` — the ledger uses `(later)` to separate two same-day
    batches, and the version has to coexist with it."""
    shipped, _ = parse_ledger(
        "## 2026-08-25 (v0.3.89, later): x\n\n"
        "| CVE | a |\n|---|---|\n| CVE-2026-22222 | New pin. |\n"
    )
    assert shipped["CVE-2026-22222"][1] == "v0.3.89"
