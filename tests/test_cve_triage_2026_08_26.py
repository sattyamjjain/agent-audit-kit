"""Dispositions for the thirteen-CVE backlog cleared on 2026-08-26.

Thirteen `cve-response` issues had accumulated on the public tracker of a
security scanner, which is its own credibility problem — but closing them
without reading them just moves the problem, so each was read against NVD and
the upstream advisory and put into exactly one of three buckets.

The deciding question was never severity. Two CRITICALs went opposite ways from
each other, and three HIGHs closed with no rule at all:

**Already covered (3).** All three PraisonAI advisories — CVE-2026-55532,
CVE-2026-55529, CVE-2026-55531 — are fixed in 4.6.58, and
``AAK-MCP-PRAISONAI-CVE-2026-61427-001`` has carried a floor of 4.6.78 since the
2026-07 wave. Every version they affect already fires. They are added to that
rule's ``cve_references`` so the coverage is auditable, and given no pin of their
own: two pins on one package report one dependency twice.

**Pinned (5).** qwed-mcp, nextcloud-mcp-server, browse-mcp, genieacs-mcp, and the
sublinear-time-solver / consciousness-explorer pair.

**Out of scope (5).** The three mcp-shell advisories, Coroot, and the MCP PHP
SDK — none has a vulnerable artifact published where the pin detector looks.

The mcp-shell trio is the one worth reading twice. All three name a package that
exists on **both** npm and PyPI, which is exactly the shape that makes a pin look
obvious. Neither is the vulnerable thing: the advisory describes Go
(``security.go``, ``config.go``, ``cmd/server/main.go``) with a fix at 0.6.0; npm
``mcp-shell`` tops out at 0.1.3 and carries no repository URL, and PyPI
``mcp-shell`` is ``hdresearch/py-mcp-shell`` at 0.0.1. A floor of 0.6.0 on either
would fire on 100% of their releases and never on the vulnerable server.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_cve_pins_2026_07 import _PINS, scan

REPO_ROOT = Path(__file__).resolve().parent.parent
LEDGER = REPO_ROOT / "CHANGELOG.cves.md"
SECTION_DATE, SECTION_TITLE = (
    "2026-08-26",
    "thirteen open issues, and severity decided none of them",
)

def _section_body(date: str, title_prefix: str) -> str:
    """The body of the ledger section headed `date` whose title starts as given.

    Matched on the date plus the title, tolerating any parenthesised label
    between them. The title is what disambiguates two sections dated the same
    day; the label is release metadata a section gains when it ships, and
    twenty-two of them were backfilled at once, so pinning the whole heading
    string made this test fail on a labelling change it has no stake in.
    """
    text = LEDGER.read_text(encoding="utf-8")
    pattern = re.compile(
        r"^##\s+"
        + re.escape(date)
        + r"(?:\s*\([^)]*\))?\s*[:\u2014-]?\s*"
        + re.escape(title_prefix),
        re.M,
    )
    match = pattern.search(text)
    assert match, f"ledger has no {date} section titled {title_prefix!r}"
    return text[match.end():].split("\n## ", 1)[0]


PINNED = {
    "CVE-2026-55546": "AAK-MCP-QWED-CVE-2026-55546-001",
    "CVE-2026-55640": "AAK-MCP-NEXTCLOUD-CVE-2026-55640-001",
    "CVE-2026-55557": "AAK-MCP-BROWSEMCP-CVE-2026-55557-001",
    "CVE-2026-55637": "AAK-MCP-GENIEACS-CVE-2026-55637-001",
    "CVE-2026-55609": "AAK-MCP-SUBLINEAR-CVE-2026-55609-001",
}

ALREADY_COVERED = {
    "CVE-2026-55532": "AAK-MCP-PRAISONAI-CVE-2026-61427-001",
    "CVE-2026-55529": "AAK-MCP-PRAISONAI-CVE-2026-61427-001",
    "CVE-2026-55531": "AAK-MCP-PRAISONAI-CVE-2026-61427-001",
}

OUT_OF_SCOPE = {
    "CVE-2026-55582": "mcp-shell — Go; the npm/PyPI names are different artifacts",
    "CVE-2026-55581": "mcp-shell — same",
    "CVE-2026-55580": "mcp-shell — same",
    "CVE-2026-79786": "Coroot — Go binary, on neither npm nor PyPI",
    "CVE-2026-53965": "MCP PHP SDK — Composer, an ecosystem the detector does not read",
}

# A pin must never be keyed on these. Each is a real published package that is
# not the vulnerable artifact.
COLLIDING_NAMES = ("mcp-shell", "py-mcp-shell", "coroot", "mcp/sdk")


def _ids(tmp_path: Path, name: str, content: str) -> set[str]:
    (tmp_path / name).write_text(content, encoding="utf-8")
    return {f.rule_id for f in scan(tmp_path)[0]}


def _row(cve: str) -> str:
    section = _section_body(SECTION_DATE, SECTION_TITLE)
    rows = [ln for ln in section.splitlines() if ln.startswith("|") and cve in ln]
    assert rows, f"{cve} has no row in the 2026-08-26 ledger section"
    return rows[0]


# ---------------------------------------------------------------------------
# Pinned
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cve,rule_id", sorted(PINNED.items()))
def test_pinned_cve_is_carried_by_its_rule(cve: str, rule_id: str) -> None:
    assert rule_id in RULES
    assert cve in (RULES[rule_id].cve_references or [])


@pytest.mark.parametrize(
    "manifest,content,rule_id",
    [
        ("requirements.txt", "qwed-mcp==0.2.0\n", PINNED["CVE-2026-55546"]),
        (
            "requirements.txt",
            "nextcloud-mcp-server==0.117.1\n",
            PINNED["CVE-2026-55640"],
        ),
        (
            "package.json",
            json.dumps({"dependencies": {"browse-mcp": "0.8.1"}}),
            PINNED["CVE-2026-55557"],
        ),
        (
            "package.json",
            json.dumps({"dependencies": {"genieacs-mcp": "0.3.1"}}),
            PINNED["CVE-2026-55637"],
        ),
        (
            "package.json",
            json.dumps({"dependencies": {"sublinear-time-solver": "1.5.9"}}),
            PINNED["CVE-2026-55609"],
        ),
    ],
)
def test_below_floor_fires(
    tmp_path: Path, manifest: str, content: str, rule_id: str
) -> None:
    assert rule_id in _ids(tmp_path, manifest, content)


@pytest.mark.parametrize(
    "manifest,content,rule_id",
    [
        ("requirements.txt", "qwed-mcp==0.2.1\n", PINNED["CVE-2026-55546"]),
        (
            "requirements.txt",
            "nextcloud-mcp-server==0.117.2\n",
            PINNED["CVE-2026-55640"],
        ),
        (
            "package.json",
            json.dumps({"dependencies": {"browse-mcp": "0.8.2"}}),
            PINNED["CVE-2026-55557"],
        ),
        (
            "package.json",
            json.dumps({"dependencies": {"genieacs-mcp": "0.3.2"}}),
            PINNED["CVE-2026-55637"],
        ),
        (
            "package.json",
            json.dumps({"dependencies": {"consciousness-explorer": "1.1.2"}}),
            PINNED["CVE-2026-55609"],
        ),
    ],
)
def test_at_floor_is_quiet(
    tmp_path: Path, manifest: str, content: str, rule_id: str
) -> None:
    assert rule_id not in _ids(tmp_path, manifest, content)


def test_one_advisory_two_packages_keeps_two_floors(tmp_path: Path) -> None:
    """CVE-2026-55609 fixes at 1.6.0 in one package and 1.1.2 in the other.

    A single floor would either miss consciousness-explorer 1.1.1 or fire on
    every sublinear-time-solver below 1.6.0 for the wrong reason.
    """
    rule = PINNED["CVE-2026-55609"]
    floors = {
        pin.names[0]: pin.floor for pin in _PINS if pin.rule_id == rule
    }
    assert floors == {
        "sublinear-time-solver": (1, 6, 0),
        "consciousness-explorer": (1, 1, 2),
    }
    assert rule in _ids(
        tmp_path,
        "package.json",
        json.dumps({"dependencies": {"consciousness-explorer": "1.1.1"}}),
    )


def test_browse_mcp_regex_is_bounded(tmp_path: Path) -> None:
    """The `cline` lesson, held for this name."""
    pin = next(p for p in _PINS if p.rule_id == PINNED["CVE-2026-55557"])
    assert pin.regexes, "browse-mcp must carry an explicit bounded regex"
    assert PINNED["CVE-2026-55557"] not in _ids(
        tmp_path,
        "package.json",
        json.dumps({"dependencies": {"browse-mcp-client": "0.1.0"}}),
    )


def test_qwed_rule_names_the_source_rule_that_also_covers_it() -> None:
    """The pin is the dependency surface; the shape was already reported.

    ``AAK-MCP-TOOL-UNSAFE-EVAL-001`` names unpinned ``parse_expr`` explicitly and
    fires on this handler. A reader who sees only one of the two should be told
    the other exists rather than concluding coverage started here.
    """
    description = RULES[PINNED["CVE-2026-55546"]].description
    assert "AAK-MCP-TOOL-UNSAFE-EVAL-001" in description


# ---------------------------------------------------------------------------
# Already covered
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cve,rule_id", sorted(ALREADY_COVERED.items()))
def test_already_covered_cve_is_recorded_on_the_covering_rule(
    cve: str, rule_id: str
) -> None:
    assert cve in (RULES[rule_id].cve_references or [])


@pytest.mark.parametrize("cve", sorted(ALREADY_COVERED))
def test_already_covered_cve_gets_no_second_pin(cve: str) -> None:
    """Two pins on one package report one dependency twice."""
    claiming = sorted(
        rid for rid, rule in RULES.items() if cve in (rule.cve_references or [])
    )
    assert claiming == [ALREADY_COVERED[cve]], claiming


def test_the_praisonai_floor_still_sits_above_the_new_fix(tmp_path: Path) -> None:
    """The whole basis for "already covered": 4.6.78 > 4.6.58.

    If the floor is ever lowered, these three stop being covered and this fails
    rather than the coverage silently disappearing.
    """
    pin = next(
        p for p in _PINS if p.rule_id == "AAK-MCP-PRAISONAI-CVE-2026-61427-001"
    )
    assert pin.floor is not None and pin.floor >= (4, 6, 58)
    assert "AAK-MCP-PRAISONAI-CVE-2026-61427-001" in _ids(
        tmp_path, "requirements.txt", "praisonai==4.6.57\n"
    )


# ---------------------------------------------------------------------------
# Out of scope
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cve", sorted(OUT_OF_SCOPE))
def test_no_rule_claims_an_out_of_scope_cve(cve: str) -> None:
    claiming = sorted(
        rid for rid, rule in RULES.items() if cve in (rule.cve_references or [])
    )
    assert not claiming, (
        f"{cve} is recorded out of scope but rule(s) {claiming} reference it"
    )


@pytest.mark.parametrize("name", COLLIDING_NAMES)
def test_no_pin_is_keyed_on_a_colliding_name(name: str) -> None:
    hits = sorted(p.rule_id for p in _PINS if any(n.lower() == name for n in p.names))
    assert not hits, f"pin(s) {hits} are keyed on {name!r}, not the vulnerable artifact"


def test_an_mcp_shell_dependency_stays_quiet(tmp_path: Path) -> None:
    """The false positive this disposition prevents, stated as a scan.

    npm `mcp-shell` never reaches 0.6.0, so a project on its current release must
    not be told it carries a Go server's command-injection CVE.
    """
    ids = _ids(
        tmp_path,
        "package.json",
        json.dumps({"dependencies": {"mcp-shell": "0.1.3"}}),
    )
    assert not [i for i in ids if "SHELL" in i.upper()]


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cve", sorted({**PINNED, **ALREADY_COVERED, **OUT_OF_SCOPE})
)
def test_every_disposition_is_recorded_in_the_ledger(cve: str) -> None:
    assert cve in LEDGER.read_text(encoding="utf-8")


def test_the_mcp_shell_row_names_both_colliding_registries() -> None:
    """"Different project" without the evidence is the part nobody believes."""
    row = _row("CVE-2026-55582")
    assert "Out of scope" in row
    assert "0.1.3" in row
    assert "py-mcp-shell" in row or "0.0.1" in row
