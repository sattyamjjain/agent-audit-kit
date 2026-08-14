"""Tests for scripts/cve_latency.py — the published CVE-to-rule latency number.

The figure goes in a doc that is regenerated on every tag, so the parsing has to
be right about three things a rule count never had to care about: which release
actually shipped a CVE's rule, which CVEs never got one, and which CVEs are only
mentioned in passing.
"""

from __future__ import annotations

import importlib.util
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


def test_real_ledger_has_no_implausible_latency() -> None:
    """A year-long latency means a referenced CVE leaked into the measurement."""
    import json

    root = Path(__file__).resolve().parent.parent
    shipped, _ = parse_ledger((root / "CHANGELOG.cves.md").read_text(encoding="utf-8"))
    published = json.loads((root / "docs" / "data" / "cve-published.json").read_text())
    rows, _missing = build_rows(shipped, published)
    assert rows
    worst = max(rows, key=lambda r: r.days)
    assert worst.days < 90, f"{worst.cve} shows {worst.days}d — likely a parsing artefact"
    assert all(r.days >= 0 for r in rows)


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
    assert shipped["CVE-2026-73296"][1] == "v0.3.75"
    assert shipped["CVE-2026-73498"][1] == "v0.3.75"
    # Overlap would mean a CVE counted as both covered and ruled out.
    assert not (set(shipped) & out_of_scope)
