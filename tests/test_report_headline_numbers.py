"""The README's headline numbers must equal the report's, and both must equal the data.

The State of MCP Security 2026 report is the strongest evidence in this repository, and
until now nothing outside it carried its numbers. Quoting them in the README creates a
second copy, and a second copy of a number is how the rule count reached 289 while the
registry said 291.

So this is the same shape as
``tests/test_fix_recipe_coverage.py::test_fix_recipe_coverage_is_canonical``: the
published number is derived, and a hand-edited marker fails here rather than rotting.

Three-way lock, because two of the three are prose:

    results.json  ->  README markers      (rendered by scripts/sync_rule_count.py)
    results.json  ->  REPORT.md prose     (so "verbatim from the report" is genuinely held)

``results.json`` is the anchor: ``make report`` regenerates it deterministically and
offline from the committed corpus, and ``make report-check`` already fails if it is
stale. Comparison is on parsed integers and floats, never on rendered strings, so the
README writing ``1,205`` and the report writing ``1205`` is not a failure - only a
different quantity is.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"
REPORT = REPO_ROOT / "research" / "state-of-mcp-2026" / "REPORT.md"
RESULTS = REPO_ROOT / "research" / "state-of-mcp-2026" / "results.json"

_MARKER_RE = re.compile(
    r"<!--\s*report:([a-z0-9-]+)\s*-->(.*?)<!--\s*/report\s*-->", re.DOTALL
)


def _results() -> dict:
    return json.loads(RESULTS.read_text(encoding="utf-8"))


def _readme_markers() -> dict[str, str]:
    return {k: v for k, v in _MARKER_RE.findall(README.read_text(encoding="utf-8"))}


def _num(raw: str) -> float:
    """Parse a rendered figure: strips thousands separators and stray markup."""
    return float(re.sub(r"[^\d.]", "", raw))


def _expected() -> dict[str, float]:
    data = _results()
    auth = data["auth_profile_2026_07_28"]
    return {
        "corpus": float(data["distinct_configs_scanned"]),
        "rfc9728-n": float(auth["rfc9728_prm_discovery"]["n"]),
        "noauth-pct": float(auth["no_authentication"]["pct"]),
        "noauth-n": float(auth["no_authentication"]["n"]),
        "inline-auth-pct": float(auth["remote_auth_static_credential"]["pct"]),
        "inline-auth-n": float(auth["remote_auth_static_credential"]["n"]),
        "inline-auth-d": float(auth["remote_auth_static_credential"]["denominator"]),
    }


def test_readme_has_the_report_markers() -> None:
    markers = _readme_markers()
    assert markers, (
        "README has no report:* markers - nothing drives the headline numbers, so the "
        "rest of this module would pass on an empty set"
    )
    missing = sorted(set(_expected()) - set(markers))
    assert not missing, f"README is missing report marker(s): {missing}"


@pytest.mark.parametrize("key", sorted(_expected()))
def test_readme_marker_matches_results_json(key: str) -> None:
    """The canonical check: every README figure equals the generated data."""
    markers = _readme_markers()
    assert key in markers, f"README lost the report:{key} marker"
    actual, expected = _num(markers[key]), _expected()[key]
    assert actual == expected, (
        f"README report:{key} claims {markers[key]!r} ({actual}); results.json says "
        f"{expected}. Run `python scripts/sync_rule_count.py`."
    )


def test_no_unknown_report_markers_in_readme() -> None:
    """A marker the sync script does not know is a number nothing regenerates."""
    unknown = sorted(set(_readme_markers()) - set(_expected()))
    assert not unknown, (
        f"README carries report marker(s) with no source in results.json: {unknown}. "
        "Either add them to report_headline_numbers() in scripts/sync_rule_count.py or "
        "remove them - an unowned marker rots."
    )


def test_report_prose_agrees_with_results_json() -> None:
    """The document being cited must say what its data says.

    Without this the README could be faithfully synced to results.json while the report
    itself carried a stale figure, and a reader citing the report would quote a number
    the README contradicts.
    """
    text = REPORT.read_text(encoding="utf-8")
    exp = _expected()
    corpus = int(exp["corpus"])

    checks = [
        (rf"{corpus:,} distinct public", f"corpus size {corpus:,}"),
        (
            rf"RFC 9728 PRM discovery:\*\* {int(exp['rfc9728-n'])} of {corpus:,}",
            "RFC 9728 count",
        ),
        (
            rf"No authentication:\*\* {int(exp['noauth-n'])} of {corpus:,} \(\*\*{exp['noauth-pct']:g}%\*\*\)",
            "no-auth n and pct",
        ),
        (
            rf"{int(exp['inline-auth-n'])} of {int(exp['inline-auth-d'])} \({exp['inline-auth-pct']:g}%\)",
            "inline-auth ratio",
        ),
    ]
    for pattern, label in checks:
        assert re.search(pattern, text), (
            f"REPORT.md prose does not state the {label} that results.json reports "
            f"(expected to match {pattern!r}). Regenerate with `make report` and "
            "reconcile the prose."
        )


def test_citation_badge_points_at_the_citation_section() -> None:
    """3a: the badge is the entry point, so it must land on the citation section."""
    readme = README.read_text(encoding="utf-8")
    assert "REPORT.md#how-to-cite-this-report" in readme, (
        "README has no link to the report's citation section"
    )
    assert re.search(r"<img[^>]*badge/cite-[^>]*>", readme), (
        "README has no 'cite' badge among the badge block"
    )
    report = REPORT.read_text(encoding="utf-8")
    assert re.search(r"^## How to cite this report\s*$", report, re.M), (
        "the anchor the badge points at does not exist in REPORT.md"
    )
