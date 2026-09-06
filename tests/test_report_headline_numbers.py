"""The README's headline numbers must equal the report's, and both must equal the data.

The State of MCP Security 2026 report is the strongest evidence in this repository, and
until now nothing outside it carried its numbers. Quoting them in the README creates a
second copy, and a second copy of a number is how the rule count reached 289 while the
registry said 291.

So this is the same shape as
``tests/test_fix_recipe_coverage.py::test_fix_recipe_coverage_is_canonical``: the
published number is derived, and a hand-edited marker fails here rather than rotting.

The lock used to be three-way and README-shaped, and that is exactly why four
other files rotted. On 2026-08-25 the AAK-MCP-001 header-family fix moved the
headline from 52.3% / 1,205 to 52.2% / 1,203. README and REPORT.md followed,
because they were the only two this module watched. These did not:

    docs/DISTRIBUTION-CHECKLIST.md   the Show HN title and body, and the Reddit
                                    drafts -- copy that gets pasted in public
    docs/STATE-OF-MCP-SECURITY-2026.md
    research/state-of-mcp-2026/PREVALENCE.md
    CITATION.cff                    the abstract people cite

So the lock is now over every published surface that states a headline figure:

    results.json  ->  marker files       (rendered by scripts/sync_rule_count.py)
    results.json  ->  REPORT.md prose    (so "verbatim from the report" is genuinely held)
    results.json  ->  CITATION.cff prose (YAML block scalar; a marker would be
                                          rendered verbatim into the citation, so
                                          it is asserted rather than generated)

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
CITATION = REPO_ROOT / "CITATION.cff"

# Every published surface that carries `report:` markers. Kept in lockstep with
# `_REPORT_MARKER_FILES` in scripts/sync_rule_count.py by
# `test_marker_files_match_the_generator` below, so a file added to one and not
# the other is a failure rather than a silent gap.
MARKER_FILES = (
    "README.md",
    "docs/STATE-OF-MCP-SECURITY-2026.md",
    "research/state-of-mcp-2026/PREVALENCE.md",
)

# Surfaces that state the headline in prose and must NOT carry markers, each for a
# structural reason rather than convenience:
#
#   CITATION.cff                    figures sit in a YAML block scalar, so an HTML
#                                   comment renders verbatim into the abstract that
#                                   every citation tool displays.
#   docs/DISTRIBUTION-CHECKLIST.md  the Show HN body and the Reddit drafts are copy a
#                                   human pastes into a comment box. A marker there
#                                   gets pasted too, which is a louder failure than
#                                   the stale number it would have prevented.
#
# They are asserted against results.json below instead, so drift fails CI without
# putting machinery into text that leaves the repository.
PROSE_SURFACES = ("CITATION.cff", "docs/DISTRIBUTION-CHECKLIST.md")

_MARKER_RE = re.compile(
    r"<!--\s*report:([a-z0-9-]+)\s*-->(.*?)<!--\s*/report\s*-->", re.DOTALL
)


def _results() -> dict:
    return json.loads(RESULTS.read_text(encoding="utf-8"))


def _markers_in(rel: str) -> list[tuple[str, str]]:
    """Every (key, rendered) pair in one file, duplicates preserved.

    Duplicates matter: DISTRIBUTION-CHECKLIST.md states the no-auth figure four
    times, and a dict would hide three of them behind the last one.
    """
    return _MARKER_RE.findall((REPO_ROOT / rel).read_text(encoding="utf-8"))


def _readme_markers() -> dict[str, str]:
    return dict(_markers_in("README.md"))


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
        "critical-pct": float(data["configs_with_critical_pct"]),
        "critical-n": float(data["configs_with_critical"]),
        # PREVALENCE.md row 3 and REPORT.md's OAuth table state the same figure
        # in opposite orders and disagreed -- 421 / 18.3% against 424 / 18.4% --
        # in sibling files, because neither cell was marker-driven.
        "oauth008-n": float(_top_misconfig(data, "AAK-OAUTH-008")["configs"]),
        "oauth008-pct": float(_top_misconfig(data, "AAK-OAUTH-008")["config_pct"]),
    }


def _top_misconfig(data: dict, rule_id: str) -> dict:
    """One top_misconfigurations row by rule id; raises if the rule dropped out."""
    for row in data["top_misconfigurations"]:
        if row["rule_id"] == rule_id:
            return row
    raise AssertionError(
        f"{rule_id} is no longer in results.json top_misconfigurations, but a "
        f"surface still renders its figures"
    )


def test_readme_has_the_report_markers() -> None:
    markers = _readme_markers()
    assert markers, (
        "README has no report:* markers - nothing drives the headline numbers, so the "
        "rest of this module would pass on an empty set"
    )


@pytest.mark.parametrize("rel", MARKER_FILES)
def test_every_marker_file_still_carries_markers(rel: str) -> None:
    """A file that loses its markers stops being generated and starts rotting.

    This is the failure that actually happened: the numbers were in prose, nothing
    rendered them, and nothing noticed for a week.
    """
    assert _markers_in(rel), f"{rel} carries no report:* markers"


@pytest.mark.parametrize("rel", MARKER_FILES)
def test_markers_match_results_json(rel: str) -> None:
    """The canonical check, now over every published surface rather than README.

    Every occurrence is compared, not the last one per key: DISTRIBUTION-CHECKLIST.md
    states the no-auth figure four times and a dict would hide three of them.
    """
    expected = _expected()
    wrong = []
    for key, rendered in _markers_in(rel):
        assert key in expected, (
            f"{rel} carries report marker `{key}` with no source in results.json. "
            "Either add it to report_headline_numbers() in scripts/sync_rule_count.py "
            "or remove it - an unowned marker rots."
        )
        if _num(rendered) != expected[key]:
            wrong.append((key, rendered, expected[key]))
    assert not wrong, (
        f"{rel} disagrees with results.json: {wrong}. "
        "Run `python scripts/sync_rule_count.py`."
    )


def test_every_known_key_is_used_somewhere() -> None:
    """A key nothing renders is a number the generator computes for no one.

    Not asserted per file - README does not state the critical-finding figure and
    PREVALENCE.md does not state the inline-auth ratio, which is fine. What is not
    fine is a key that appears on no surface at all.
    """
    used = {key for rel in MARKER_FILES for key, _ in _markers_in(rel)}
    unused = sorted(set(_expected()) - used)
    assert not unused, (
        f"report_headline_numbers() computes {unused} but no surface renders them"
    )


def test_marker_files_match_the_generator() -> None:
    """This list and the generator's must not drift apart.

    A file added here but not to the generator is asserted and never rendered; a
    file added there but not here is rendered and never asserted. Both are the
    same class of gap this module exists to close.
    """
    import sys

    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    from sync_rule_count import _REPORT_MARKER_FILES  # noqa: PLC0415

    assert sorted(MARKER_FILES) == sorted(_REPORT_MARKER_FILES), (
        "tests/test_report_headline_numbers.py::MARKER_FILES and "
        "scripts/sync_rule_count.py::_REPORT_MARKER_FILES disagree"
    )


@pytest.mark.parametrize("rel", PROSE_SURFACES)
def test_prose_surface_carries_no_markers(rel: str) -> None:
    """These files must stay marker-free, and the reason is not stylistic.

    Both leave the repository as text a human reads or pastes -- a citation
    abstract, a Show HN body. A marker in either is visible to the reader.
    """
    text = (REPO_ROOT / rel).read_text(encoding="utf-8")
    assert "report:" not in text, (
        f"{rel} carries a report: marker. It is prose-asserted on purpose - the "
        "marker would be visible to whoever reads or pastes this text."
    )


@pytest.mark.parametrize("rel", PROSE_SURFACES)
def test_prose_surface_states_the_current_headline(rel: str) -> None:
    """Nothing generates these, so this is the only thing standing between them
    and the drift that put 52.3% / 1,205 into the Show HN title for a week."""
    text = (REPO_ROOT / rel).read_text(encoding="utf-8")
    exp = _expected()
    stale = re.findall(r"\b52\.3%|\b1,205\b|\b1,217\b", text)
    assert not stale, (
        f"{rel} still states superseded headline figures {sorted(set(stale))}; "
        f"results.json says {exp['noauth-pct']:g}% ({int(exp['noauth-n']):,}) no-auth "
        f"and {int(exp['critical-n']):,} configs with a critical finding"
    )
    assert re.search(
        rf"{exp['noauth-pct']:g}%[^\n]*?\(?{int(exp['noauth-n']):,}", text
    ), (
        f"{rel} does not state the current no-auth figure "
        f"{exp['noauth-pct']:g}% ({int(exp['noauth-n']):,})"
    )


def test_citation_abstract_agrees_with_results_json() -> None:
    """CITATION.cff is asserted rather than generated, and the reason is structural.

    Its figures sit in a YAML block scalar (``abstract: >-``), so an HTML comment
    marker would be rendered verbatim into the abstract every citation tool shows.
    It went stale with the others and nothing caught it, so it is checked here
    against the same source instead.
    """
    text = CITATION.read_text(encoding="utf-8")
    exp = _expected()
    corpus = int(exp["corpus"])
    checks = [
        (rf"{corpus:,} distinct public Model Context Protocol", "corpus size"),
        (rf"{int(exp['rfc9728-n'])} of {corpus:,} configs serving RFC 9728", "RFC 9728"),
        (
            rf"{exp['noauth-pct']:g}% \({int(exp['noauth-n']):,}\) declaring a remote server",
            "no-auth pct and n",
        ),
        (
            rf"{exp['inline-auth-pct']:g}% \({int(exp['inline-auth-n'])} of "
            rf"{int(exp['inline-auth-d'])}\)",
            "inline-auth ratio",
        ),
    ]
    for pattern, label in checks:
        assert re.search(pattern, text), (
            f"CITATION.cff does not state the {label} that results.json reports "
            f"(expected to match {pattern!r}). It is hand-maintained on purpose - "
            "a marker would leak into the rendered citation - so correct it by hand."
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
