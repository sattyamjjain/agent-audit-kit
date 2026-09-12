"""Regulatory dates this repository states in prose must stay correct.

Two of these assertions exist because the claim was wrong in a shipped release,
not because it might one day be. A compliance tool that misstates a compliance
deadline is worse than one that stays quiet about it, and prose is the one
surface none of the generated-count guards can see.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).parent.parent

# Historical records are excluded on purpose. The repository's discipline is to
# append a dated correction next to a wrong claim rather than rewrite it, so an
# archived changelog legitimately still carries the original sentence.
_HISTORICAL = (
    "docs/changelog/archive",
    "CHANGELOG.md",
    "docs/reports/",
    "launch/",
    "docs/launch/",
    "releases/",
)

_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "site", "public",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build",
}


def _prose_files() -> list[Path]:
    out: list[Path] = []
    for path in REPO.rglob("*"):
        if path.suffix.lower() not in {".md", ".py", ".yaml", ".yml"}:
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        rel = str(path.relative_to(REPO))
        if any(rel.startswith(h) or h in rel for h in _HISTORICAL):
            continue
        # This file quotes the strings it forbids, by necessity.
        if path.resolve() == Path(__file__).resolve():
            continue
        out.append(path)
    return out


# CRA Article 14 reporting started 2026-09-11. 2027-12-11 is the Annex I date
# (machine-readable SBOM, CE marking), which is a different obligation.
_CRA_REPORTING_IN_2027 = re.compile(
    r"reporting\s+obligations?[^.]{0,80}?2027|2027[^.]{0,60}?reporting\s+obligations?",
    re.IGNORECASE | re.DOTALL,
)


def test_no_live_file_says_cra_reporting_starts_in_2027() -> None:
    """docs/vex.md shipped this error in v0.4.0.

    It said reporting begins 11 December 2027. Reporting began 11 September
    2026; December 2027 is Annex I. The error was wrong by fifteen months in
    the direction that lets a reader relax, and the correct pair was already
    recorded in this repository's own changelog before it was written.
    """
    offenders = []
    for path in _prose_files():
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if _CRA_REPORTING_IN_2027.search(text):
            offenders.append(str(path.relative_to(REPO)))
    assert not offenders, (
        "CRA Article 14 reporting started 2026-09-11, not in 2027. "
        f"Files claiming otherwise: {offenders}"
    )


def test_vex_doc_states_both_cra_dates() -> None:
    text = (REPO / "docs" / "vex.md").read_text(encoding="utf-8")
    assert "11 September 2026" in text, "the date reporting actually started"
    assert "11 December 2027" in text, "the Annex I / CE-marking date"
    # The staged clock is the part a reader has to act on.
    assert "24 hours" in text and "72 hours" in text and "14 days" in text


# --------------------------------------------------------------------------
# The latency doc, and the guard that used to be unable to fail
# --------------------------------------------------------------------------


def test_cve_latency_doc_is_not_stale() -> None:
    """`scripts/cve_latency.py --check` against the COMMITTED file.

    The release workflow used to run the generator immediately before this
    check, so the check compared a freshly written file against the ledger it
    had just been generated from and passed by construction. The regenerate
    step is gone; this test is the local half of the same guarantee.
    """
    result = subprocess.run(
        [sys.executable, "scripts/cve_latency.py", "--check"],
        cwd=REPO, capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, (
        "docs/cve-latency.md is stale. Run `python scripts/cve_latency.py` "
        "(and `--refresh` first if new CVEs lack a published date).\n"
        + result.stdout + result.stderr
    )


def test_release_workflow_does_not_regenerate_before_checking() -> None:
    """A check that writes its own input cannot fail. Keep it deleted."""
    wf = (REPO / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    block = wf[wf.index("cve-latency:"):]
    block = block[: block.index("\n  # ---")] if "\n  # ---" in block else block
    bare_runs = [
        line for line in block.splitlines()
        if "python scripts/cve_latency.py" in line
        and "--check" not in line
        and not line.lstrip().startswith("#")
    ]
    assert not bare_runs, (
        "release.yml regenerates docs/cve-latency.md before --check, which makes "
        f"the check tautological: {bare_runs}"
    )


@pytest.mark.parametrize("undated_cap", [8])
def test_latency_doc_does_not_silently_exclude_a_pile_of_cves(undated_cap: int) -> None:
    """The headline figure describes only the CVEs with a published date.

    On 2026-09-12 that exclusion had reached 12, seven of them shipped the same
    day, which quietly made the published median describe a stale subset. A cap
    turns "the number is fine, the population moved" into a failure.
    """
    text = (REPO / "docs" / "cve-latency.md").read_text(encoding="utf-8")
    m = re.search(r"Shipped, but no published date on file \|\s*(\d+)\s*\|", text)
    assert m, "latency doc lost its coverage table"
    assert int(m.group(1)) <= undated_cap, (
        f"{m.group(1)} CVEs excluded for want of a published date. "
        "Run `make cve-latency-refresh` to fetch them from NVD."
    )


# --------------------------------------------------------------------------
# The MCP 2026-07-28 specification is ratified, not a release candidate
# --------------------------------------------------------------------------


# Present-tense claims only. "was a release candidate until it ratified" is a
# correct description of the transition and must stay sayable; "the 2026-07-28
# spec release candidate" is the noun phrase that was wrong once the spec
# published, and it is what this matches.
_PRESENT_TENSE_RC = re.compile(
    r"(?:spec|specification)\s+release[- ]candidate"
    r"|2026-07-28\s+release[- ]candidate"
    r"|stays?\s+labell?ed\s+\**release[- ]candidate"
    r"|is\s+(?:still\s+)?an?\s+\**release[- ]candidate",
    re.IGNORECASE,
)


def test_no_live_file_calls_the_2026_07_28_spec_a_release_candidate() -> None:
    """It ratified on 2026-07-28.

    The rules were deliberately labelled "release candidate" until then, with
    the intent recorded in the archived changelog: relabel at ratification
    rather than prematurely. This test is that relabelling, held in place.
    """
    offenders = []
    for path in _prose_files():
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if _PRESENT_TENSE_RC.search(text):
            offenders.append(str(path.relative_to(REPO)))
    assert not offenders, (
        "The MCP 2026-07-28 spec is ratified; these still call it a release "
        f"candidate: {sorted(set(offenders))}"
    )


def test_rule_text_does_not_cite_the_release_candidate_blog_post() -> None:
    from agent_audit_kit.rules.builtin import RULES

    blob = " ".join(
        f"{r.description} {r.remediation} {r.limitations}" for r in RULES.values()
    )
    assert "2026-07-28-release-candidate" not in blob


# --------------------------------------------------------------------------
# Cross-references to work that has since shipped
# --------------------------------------------------------------------------


def test_no_rule_claims_a_shipped_detector_is_tracked_separately() -> None:
    """AAK-MCP-TOOLUNIVERSE-... pointed at a detector that already exists.

    `AAK-SANDBOX-DENYLIST-001` shipped for issue #704. A limitation that
    forwards a reader to future work which has landed is a live wrong claim,
    not a stale comment.
    """
    from agent_audit_kit.rules.builtin import RULES

    for rule_id, rule in RULES.items():
        if not rule.limitations:
            continue
        assert "tracked separately" not in rule.limitations.lower(), (
            f"{rule_id} forwards to work that may have shipped; name the rule "
            "that covers it instead"
        )
