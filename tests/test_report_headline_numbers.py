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
import math
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"
REPORT = REPO_ROOT / "research" / "state-of-mcp-2026" / "REPORT.md"
RESULTS = REPO_ROOT / "research" / "state-of-mcp-2026" / "results.json"
MANIFEST = REPO_ROOT / "research" / "state-of-mcp-2026" / "corpus" / "registry-manifest.json"
CITATION = REPO_ROOT / "CITATION.cff"

# Every published surface that carries `report:` markers. Kept in lockstep with
# `_REPORT_MARKER_FILES` in scripts/sync_rule_count.py by
# `test_marker_files_match_the_generator` below, so a file added to one and not
# the other is a failure rather than a silent gap.
MARKER_FILES = (
    "README.md",
    "docs/STATE-OF-MCP-SECURITY-2026.md",
    "research/state-of-mcp-2026/PREVALENCE.md",
    "research/state-of-mcp-2026/REPORT.md",
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
        **_prevalence_expected(data),
        **_report_expected(data),
    }


def _prevalence_expected(data: dict) -> dict[str, float]:
    """PREVALENCE.md's grade table, severity line and category table, re-derived.

    Computed here independently of the generator, as the rest of _expected() is:
    each share is the count over the corpus to one decimal, and the cumulative
    column sums the counts before dividing, so 89.3 for A+B rather than the 89.4
    that adding the two rounded shares gives.
    """
    total = data["distinct_configs_scanned"]
    grades = data["grade_distribution"]

    def share(n: int) -> float:
        return float(f"{100 * n / total:.1f}")

    out: dict[str, float] = {}
    running = 0
    for grade in "ABCDF":
        running += grades[grade]
        out[f"grade-{grade.lower()}"] = float(grades[grade])
        out[f"grade-{grade.lower()}-pct"] = share(grades[grade])
        if grade != "F":
            out[f"grade-{grade.lower()}-cum"] = share(running)
    out["grade-ab-n"] = float(grades["A"] + grades["B"])
    out["grade-df-n"] = float(grades["D"] + grades["F"])
    out["grade-df-pct"] = share(grades["D"] + grades["F"])
    for severity in ("critical", "high", "medium", "low"):
        out[f"findings-{severity}"] = float(data["severity_totals"][severity])
    out["high-pct"] = float(data["configs_with_high_pct"])
    return out


def _pct(n: int, total: int) -> float:
    """A share to one decimal, computed here rather than read from results.json."""
    return float(f"{100 * n / total:.1f}")


# Rules REPORT.md states on their own, and the three categories v1.1 moved.
_REPORT_RULES = {
    "mcp005": "AAK-MCP-005", "supply001": "AAK-SUPPLY-001", "mcp006": "AAK-MCP-006",
    "mcp003": "AAK-MCP-003", "secret007": "AAK-SECRET-007",
    "launcher-inject": "AAK-MCP-STDIO-LAUNCHER-INJECT-001", "mcp009": "AAK-MCP-009",
    "transport003": "AAK-TRANSPORT-003",
}
_REPORT_CATEGORIES = {"secret": "secret-exposure", "supply-chain": "supply-chain",
                      "legal": "legal-compliance", "transport": "transport-security"}


def _report_expected(data: dict) -> dict[str, float]:
    """REPORT.md's figures beyond the headline, re-derived.

    A rule or category that never fired is absent from results.json, and reads
    0. Shares are recomputed from the counts, not copied from the stored pct.
    """
    total = data["distinct_configs_scanned"]
    auth = data["auth_profile_2026_07_28"]
    transport = data["transport_distribution"]
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    # run_report reads a registry server only when it carries a config.
    registry_candidates = len([s for s in manifest["servers"] if s.get("config")])
    out: dict[str, float] = {
        "registry-servers": float(manifest["distinct_latest_servers"]),
        "registry-candidates": float(registry_candidates),
        "crawl-candidates": float(data["corpus_total_candidates"] - registry_candidates),
        "corpus-crawl": float(data["corpus_sources"]["crawl"]),
        "corpus-registry": float(data["corpus_sources"]["registry"]),
        "corpus-candidates": float(data["corpus_total_candidates"]),
        "corpus-duplicates": float(data["duplicates_removed"]),
        "corpus-unparseable": float(data["unparseable_removed"]),
        "rfc9728-pct": _pct(auth["rfc9728_prm_discovery"]["n"], total),
        "remote-n": float(auth["remote_configs"]["n"]),
        "remote-pct": _pct(auth["remote_configs"]["n"], total),
        "transport-http": float(transport.get("streamable-http", 0)),
        "transport-stdio": float(transport.get("stdio", 0)),
        "transport-sse": float(transport.get("sse", 0)),
        "high-n": float(data["configs_with_high"]),
        "median-rank": float(math.ceil(total / 2)),
        "top-decile-n": float(math.floor(total / 10)),
    }
    for key, rule_id in _REPORT_RULES.items():
        n = data["rule_hit_rate"].get(rule_id, {}).get("configs", 0)
        out[f"{key}-n"] = float(n)
        out[f"{key}-pct"] = _pct(n, total)
    for key, category in _REPORT_CATEGORIES.items():
        n = data["category_hit_rate"].get(category, {}).get("configs", 0)
        out[f"cat-{key}-n"] = float(n)
        out[f"cat-{key}-pct"] = _pct(n, total)
    owasp07 = data["owasp_mcp_hit_rate"].get("MCP07:2025", {}).get("configs", 0)
    out["owasp-mcp07-n"] = float(owasp07)
    out["owasp-mcp07-pct"] = _pct(owasp07, total)
    return out


def _words_expected(data: dict) -> dict[str, str]:
    """The two grade letters: the median config's, and the worst of the best tenth.

    Re-derived by laying the configs out best first, one entry each, rather than
    by summing the bands as the generator does.
    """
    total = data["distinct_configs_scanned"]
    laid_out = [g for g in "ABCDF" for _ in range(data["grade_distribution"].get(g, 0))]
    assert len(laid_out) == total
    return {
        "median-grade": laid_out[math.ceil(total / 2) - 1],
        "top-decile-grade": laid_out[math.floor(total / 10) - 1],
    }


def _table_rows(rendered: str) -> list[list[str]]:
    """Body rows of the one markdown table in a rendered block, as cell lists."""
    lines = [line.strip() for line in rendered.strip().splitlines() if line.strip().startswith("|")]
    assert len(lines) >= 2, f"no table in {rendered!r}"
    return [[cell.strip() for cell in line.strip("|").split("|")] for line in lines[2:]]


def _count(cell: str) -> int:
    return int(cell.replace(",", ""))


def _share_cell(cell: str) -> float:
    return float(cell.rstrip("%"))


def _check_top_misconfig_table(rendered: str, data: dict) -> list[str]:
    """Each row is the results.json row of the same rank: rule, title, severity, share."""
    total = data["distinct_configs_scanned"]
    rows = _table_rows(rendered)
    want = data["top_misconfigurations"]
    problems = [] if len(rows) == len(want) else [f"{len(rows)} rows, results.json has {len(want)}"]
    for rank, (cells, row) in enumerate(zip(rows, want), start=1):
        got = (int(cells[0]), cells[1].strip("`"), cells[2], cells[3].strip("*").lower(),
               _count(cells[4]), _share_cell(cells[5]))
        exp = (rank, row["rule_id"], row["title"], row["severity"], row["configs"],
               _pct(row["configs"], total))
        if got != exp:
            problems.append(f"rank {rank}: {got} != {exp}")
    return problems


def _check_category_table(rendered: str, data: dict) -> list[str]:
    """Each row is one results.json category, in results.json's ranked order."""
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    from sync_rule_count import _CATEGORY_DISPLAY  # noqa: PLC0415

    from agent_audit_kit.models import Category

    total = data["distinct_configs_scanned"]
    rows = _table_rows(rendered)
    want = list(data["category_hit_rate"].items())
    problems = [] if len(rows) == len(want) else [f"{len(rows)} rows, results.json has {len(want)}"]
    for cells, (value, row) in zip(rows, want):
        got = (cells[0], _count(cells[1]), _share_cell(cells[2]))
        exp = (_CATEGORY_DISPLAY[Category(value).name], row["configs"], _pct(row["configs"], total))
        if got != exp:
            problems.append(f"{value}: {got} != {exp}")
    return problems


def _check_owasp_mcp_table(rendered: str, data: dict) -> list[str]:
    """Each row is one OWASP MCP id under OWASP's own title, in results.json's order."""
    from agent_audit_kit.output.owasp_report import OWASP_MCP

    total = data["distinct_configs_scanned"]
    rows = _table_rows(rendered)
    want = list(data["owasp_mcp_hit_rate"].items())
    problems = [] if len(rows) == len(want) else [f"{len(rows)} rows, results.json has {len(want)}"]
    for cells, (code, row) in zip(rows, want):
        got = (cells[0].strip("*"), cells[1], _count(cells[2]), _share_cell(cells[3]))
        exp = (code, OWASP_MCP[code], row["configs"], _pct(row["configs"], total))
        if got != exp:
            problems.append(f"{code}: {got} != {exp}")
    return problems


_TABLE_CHECKS = {
    "top-misconfig-table": _check_top_misconfig_table,
    "category-table": _check_category_table,
    "owasp-mcp-table": _check_owasp_mcp_table,
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
    data = _results()
    expected = _expected()
    words = _words_expected(data)
    wrong = []
    for key, rendered in _markers_in(rel):
        if key in _TABLE_CHECKS:
            wrong.extend((key, problem) for problem in _TABLE_CHECKS[key](rendered, data))
            continue
        if key in words:
            if rendered.strip() != words[key]:
                wrong.append((key, rendered, words[key]))
            continue
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
    known = set(_expected()) | set(_words_expected(_results())) | set(_TABLE_CHECKS)
    unused = sorted(known - used)
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
    # 52.3% / 1,205 / 1,217 sat in the Show HN title for a week in 2026-08; the
    # rest are report v1.0's headline, MCP07 and unpinned-launch figures.
    stale = re.findall(
        r"\b52\.3%|\b1,205\b|\b1,217\b|\b52\.1%|\b1,201\b|\b52\.7%|\b1,213\b|\b99\.8%",
        text,
    )
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
        (rf"{int(exp['rfc9728-n'])} of {corpus:,} configs referencing RFC 9728", "RFC 9728"),
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


def _rendered(text: str) -> str:
    """The text a reader sees: every marker replaced by the value it carries."""
    return _MARKER_RE.sub(lambda m: m.group(2), text)


def test_report_prose_agrees_with_results_json() -> None:
    """The document being cited must say what its data says.

    Without this the README could be faithfully synced to results.json while the report
    itself carried a stale figure, and a reader citing the report would quote a number
    the README contradicts. Since v1.1 the figures are markers, so this reads the
    rendered text: it pins the sentences the markers sit in, which the marker test
    cannot see.
    """
    text = _rendered(REPORT.read_text(encoding="utf-8"))
    exp = _expected()
    corpus = int(exp["corpus"])

    checks = [
        (rf"{corpus:,} distinct public", f"corpus size {corpus:,}"),
        (
            rf"RFC 9728 PRM discovery:\*\* {int(exp['rfc9728-n']):,} of {corpus:,}",
            "RFC 9728 count",
        ),
        (
            rf"No authentication:\*\* {int(exp['noauth-n']):,} of {corpus:,} \(\*\*{exp['noauth-pct']:g}%\*\*\)",
            "no-auth n and pct",
        ),
        (
            rf"{int(exp['inline-auth-n']):,} of {int(exp['inline-auth-d']):,} \({exp['inline-auth-pct']:g}%\)",
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
    # Either spelling lands on the same section. The report is now served as a
    # rendered page at .../REPORT/ as well as existing as REPORT.md in the repo,
    # so pin the anchor rather than one of the two paths that carry it.
    assert (
        "REPORT.md#how-to-cite-this-report" in readme
        or "REPORT/#how-to-cite-this-report" in readme
    ), "README has no link to the report's citation section"
    assert re.search(r"<img[^>]*badge/cite-[^>]*>", readme), (
        "README has no 'cite' badge among the badge block"
    )
    report = REPORT.read_text(encoding="utf-8")
    assert re.search(r"^## How to cite this report\s*$", report, re.M), (
        "the anchor the badge points at does not exist in REPORT.md"
    )


# ---------------------------------------------------------------------------
# REPORT.md since v1.1: its version, its change table, and the claims that rest
# on a figure without being one
# ---------------------------------------------------------------------------

_VERSION_RE = re.compile(r"\*\*Report version (\d+\.\d+)\*\*")
# A step label, (0) or a roman numeral, then its signed delta: "(viii) +11".
_STEP_DELTA_RE = re.compile(r"\((?:0|[ivx]+)\) ([+-]\d[\d,]*)")


def _report_version() -> str:
    match = _VERSION_RE.search(REPORT.read_text(encoding="utf-8"))
    assert match, "REPORT.md has no **Report version X.Y** line"
    return match.group(1)


def test_report_version_is_stated_the_same_everywhere() -> None:
    """Every surface that names the report's version names REPORT.md's.

    v1.0's numbers moved three times without a bump, and the version is copied
    onto six surfaces besides the header: two citation forms, CITATION.cff, the
    README badge, the docs page and the crosswalk's evidence line.
    """
    v = re.escape(_report_version())
    report = REPORT.read_text(encoding="utf-8")
    crosswalk = REPO_ROOT / "agent_audit_kit" / "output" / "crosswalk.py"
    surfaces = {
        "REPORT.md stable identity": (report, rf"version {v}\. The version changes"),
        "REPORT.md plain-text citation": (report, rf"\(Version {v}\)\. AgentAuditKit"),
        "REPORT.md BibTeX": (report, rf"number\s*=\s*\{{Version {v}\}}"),
        "CITATION.cff": (CITATION.read_text(encoding="utf-8"), rf'(?m)^  version: "{v}"$'),
        "README cite badge": (README.read_text(encoding="utf-8"),
                              rf"State_of_MCP_Security_2026_v{v}-.*version {v}\b"),
        "docs page": ((REPO_ROOT / "docs" / "STATE-OF-MCP-SECURITY-2026.md").read_text(encoding="utf-8"),
                      rf"\(v{v}, citable\)[\s\S]*\(v{v}, with methods"),
        "crosswalk": (crosswalk.read_text(encoding="utf-8"), rf"2026\* \(v{v}\)"),
    }
    missing = [name for name, (text, pattern) in surfaces.items() if not re.search(pattern, text)]
    assert not missing, f"report version {_report_version()} is not what these state: {missing}"


def _first_int(cell: str) -> int:
    match = re.search(r"\d[\d,]*", cell)
    assert match, f"no figure in {cell!r}"
    return int(match.group(0).replace(",", ""))


_CHANGES_HEADING_RE = re.compile(r"^## What changed in v\d+\.\d+\s*$", re.M)


def _change_table() -> tuple[list[str], list[tuple[str, int, int, list[int]]]]:
    """The change table's version columns, and each row as (figure, first, last, deltas).

    The first and last columns are the figure and the steps that moved it; every
    column between is one version's value, oldest first. A row reads its first
    and last version values, and the signed delta after each step label.
    """
    text = REPORT.read_text(encoding="utf-8")
    match = _CHANGES_HEADING_RE.search(text)
    assert match, "REPORT.md has no 'What changed in vX.Y' section"
    section = text[match.end():].split("\n## ", 1)[0]
    versions: list[str] = []
    rows = []
    for line in section.splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if cells[0] == "Figure":
            versions = cells[1:-1]
            continue
        if not versions or all(set(c) <= set("-:") for c in cells):
            continue  # another table, or the separator row
        deltas = [int(d.replace(",", "")) for d in _STEP_DELTA_RE.findall(cells[-1])]
        rows.append((cells[0], _first_int(cells[1]), _first_int(_rendered(cells[-2])), deltas))
    return versions, rows


def test_whats_changed_table_adds_up() -> None:
    """The oldest value plus each step's delta is the current value, row by row.

    The oldest column is history and is typed; the current one is markers. So a
    regeneration that moves a figure without a new version breaks a sum here:
    the version policy ("the version changes only when a number in it changes")
    enforced rather than stated.
    """
    versions, rows = _change_table()
    current = f"v{_report_version()}"
    assert versions and versions[-1] == current, (
        f"the What-changed table's newest column is {versions[-1:]}, but REPORT.md is "
        f"{current}. Add a {current} column that holds the markers, turn the previous "
        "column into the literal values it published, and record the step that moved "
        "each figure."
    )
    assert len(rows) >= 10, "the What-changed table was not found"
    wrong = [(fig, old, deltas, new) for fig, old, new, deltas in rows if old + sum(deltas) != new]
    assert not wrong, (
        "REPORT.md's What-changed table no longer adds up for: "
        + "; ".join(f"{fig}: {old} {deltas} -> {new}" for fig, old, deltas, new in wrong)
        + f". A figure moved after report {current} was published, and its version "
        "changes only when a number in it changes. Either bump the report version and "
        "add a column for it to this table, recording the step that moved each figure, "
        "or revert the regeneration that moved it."
    )


# Sentences whose truth rests on a figure crossing 50% rather than on its value.
# v1.1's 50.6% no-auth and 51.4% critical still support them, narrowly.
_HALF_CLAIMS = (
    ("research/state-of-mcp-2026/REPORT.md",
     "more than half of public MCP servers declare a remote endpoint with no authentication",
     "noauth-pct"),
    ("research/state-of-mcp-2026/PREVALENCE.md",
     "More than 1 in 2 declares a remote server with no authentication", "noauth-pct"),
    ("research/state-of-mcp-2026/PREVALENCE.md",
     "more than half ship a critical-severity flaw", "critical-pct"),
)


@pytest.mark.parametrize(("rel", "claim", "key"), _HALF_CLAIMS)
def test_more_than_half_claims_hold(rel: str, claim: str, key: str) -> None:
    text = " ".join(_rendered((REPO_ROOT / rel).read_text(encoding="utf-8")).split())
    assert claim in text, f"{rel} no longer says {claim!r}; update _HALF_CLAIMS"
    assert _expected()[key] > 50, f"{rel} says {claim!r}, but {key} is {_expected()[key]}%"


def test_headline_table_severities_match_the_registry() -> None:
    """The severity printed beside a rule id in REPORT.md is the registry's.

    #987 moved AAK-SUPPLY-001 from high to medium. A severity is text, not a
    figure, so no marker carries it; this is what keeps it current.
    """
    from agent_audit_kit.rules.builtin import RULES

    pairs = re.findall(r"`(AAK-[A-Z0-9-]+)` \((critical|high|medium|low|info)\)",
                       REPORT.read_text(encoding="utf-8"))
    assert pairs, "REPORT.md names no rule with its severity"
    wrong = [(rid, sev, RULES[rid].severity.value) for rid, sev in pairs
             if RULES[rid].severity.value != sev]
    assert not wrong, f"REPORT.md severities disagree with the registry: {wrong}"


def test_generator_and_this_module_know_the_same_keys() -> None:
    """Every key the generator renders has an independent expectation here.

    A key computed there and not here would render unchecked; one here and not
    there would never render.
    """
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    from sync_rule_count import report_headline_numbers  # noqa: PLC0415

    data = _results()
    mine = set(_expected()) | set(_words_expected(data)) | set(_TABLE_CHECKS)
    assert set(report_headline_numbers()) == mine


def test_distribution_copy_states_the_current_figures() -> None:
    """The checklist's canonical block and its two Headline: blocks, figure by figure.

    They are hand-maintained so a pasted post carries no marker, which leaves this
    test as the only thing tying them to results.json. Its "99.8% trip MCP07" sat
    there under AAK's old OWASP numbering until report v1.1.
    """
    text = " ".join((REPO_ROOT / "docs" / "DISTRIBUTION-CHECKLIST.md").read_text(encoding="utf-8").split())
    e = _expected()

    def n(key: str) -> str:
        return f"{int(e[key]):,}"

    def pct(key: str) -> str:
        return f"{e[key]:g}"

    phrases = [
        f"{pct('critical-pct')}% ({n('critical-n')}) with a critical finding",
        f"{pct('noauth-pct')}% ({n('noauth-n')}) no-auth remote",
        f"{pct('mcp005-pct')}% ({n('mcp005-n')}) `npx`/`uvx` fetch-and-execute",
        f"{pct('supply001-pct')}% ({n('supply001-n')}) launch a package with no pinned version",
        f"{pct('owasp-mcp07-pct')}% ({n('owasp-mcp07-n')}) trip OWASP MCP07",
        f"Headline: {pct('noauth-pct')}% ({n('noauth-n')} of {n('corpus')}) declare a remote server",
        f"{pct('critical-pct')}% carry at least one critical",
        f"{pct('owasp-mcp07-pct')}% trip MCP07",
        f"{pct('owasp-mcp07-pct')}% of configs trip MCP07",
        f"{pct('supply001-pct')}% launch a package with no pinned version",
        f"a package launched with no pinned version ({pct('supply001-pct')}%)",
        f"env block ({pct('mcp003-pct')}%)",
    ]
    missing = [p for p in phrases if p not in text]
    assert not missing, f"DISTRIBUTION-CHECKLIST.md does not state: {missing}"
