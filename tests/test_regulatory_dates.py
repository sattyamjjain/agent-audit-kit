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


# --------------------------------------------------------------------------
# Named incidents the rule set claims to answer
# --------------------------------------------------------------------------


def test_deadbugz_is_attached_to_the_rules_that_answer_it() -> None:
    """Deadbugz (Adversa, September 2026) is a delayed tool-metadata rewrite.

    `pin` + `verify` is the defence and was already shipping. A defence the
    project holds but never names is a credibility gap, not a coverage gap.
    """
    from agent_audit_kit.rules.builtin import RULES

    for rule_id in ("AAK-RUGPULL-001", "AAK-RUGPULL-002"):
        assert "DEADBUGZ-2026-09" in RULES[rule_id].incident_references, rule_id


def test_deadbugz_case_study_states_what_pinning_cannot_do() -> None:
    """The case study must not oversell. A constant surface hiding changed
    behaviour is outside what a static pin comparison detects."""
    path = REPO / "examples" / "case-studies" / "deadbugz-delayed-metadata" / "README.md"
    text = path.read_text(encoding="utf-8")
    assert "What this does not claim" in text
    assert "runtime" in text.lower()


# --------------------------------------------------------------------------
# The release automation that docs/RELEASING.md promised
# --------------------------------------------------------------------------


def test_release_workflow_sets_the_repo_description() -> None:
    wf = (REPO / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "REPO_ADMIN_TOKEN" in wf
    assert "gh repo edit" in wf
    # It must verify the write rather than trust it.
    assert "--check-live" in wf


def test_release_workflow_degrades_instead_of_failing_without_the_secret() -> None:
    """A missing secret must not break a tag.

    The branch is in shell rather than a step-level `if:` because the `secrets`
    context is not dependable there, and a condition that silently evaluated
    false would reintroduce the manual step while looking automated.
    """
    wf = (REPO / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    block = wf[wf.index("Set the repo description, or print it"):]
    assert 'if [ -n "${GH_TOKEN:-}" ]; then' in block
    assert "else" in block
    assert "Paste repo description" in block


def test_releasing_doc_no_longer_carries_an_unmet_deadline() -> None:
    text = (REPO / "docs" / "RELEASING.md").read_text(encoding="utf-8")
    assert "Manual is acceptable until\nv0.4.0; wire it then." not in text
    assert "REPO_ADMIN_TOKEN" in text
    # The unmet promise is recorded, not deleted.
    assert "previously read" in text


# --------------------------------------------------------------------------
# Version promises made in shipped code
# --------------------------------------------------------------------------


def test_no_shipped_code_promises_a_version_that_has_passed() -> None:
    """`notify.py` shipped PagerDuty and Linear stubs saying "full impl ships
    in v0.4.0". They were still stubs at v0.6.1, and the module docstring had
    told users to build `.aak-notify.yaml` against the shape "ahead of v0.4.0",
    so anyone who did had a config that raised at runtime.

    A stub is a reasonable thing to ship. A stub carrying a version promise it
    then outlives is not.
    """
    from agent_audit_kit import __version__

    current = tuple(int(p) for p in __version__.split(".")[:3])
    offenders = []
    for path in _prose_files():
        if path.suffix != ".py":
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # Present tense only. "would ship in v0.3.16 ... it was never built" and
        # "shipped in v0.3.6" are accurate descriptions of history and have to
        # stay sayable; "ships in vX.Y.Z" is the live commitment. Same
        # distinction the release-candidate guard above draws, and it was this
        # test's own first version that blurred it.
        for m in re.finditer(r"\bships in v(\d+)\.(\d+)\.(\d+)", text):
            promised = tuple(int(g) for g in m.groups())
            if promised <= current:
                offenders.append(f"{path.relative_to(REPO)}: {m.group(0)}")
    assert not offenders, (
        "code promises a version that has already shipped: " + str(offenders)
    )


def test_the_notify_sinks_are_all_implemented() -> None:
    from agent_audit_kit.integrations.notify import (
        LinearTicketSink,
        PagerDutySink,
        SlackSink,
    )

    for cls in (SlackSink, PagerDutySink, LinearTicketSink):
        assert "NotImplementedError" not in (cls.send.__doc__ or "")
        assert cls.send is not __import__(
            "agent_audit_kit.integrations.notify", fromlist=["NotifySink"]
        ).NotifySink.send, f"{cls.__name__} never overrode send"


# --------------------------------------------------------------------------
# References to work that was closed without shipping
# --------------------------------------------------------------------------


def test_no_user_facing_text_waits_on_closed_issue_22() -> None:
    """#22 closed 2026-08-15 having shipped a TypeScript slice only.

    Rule text saying "until #22 lands tree-sitter-rust" told users to wait for
    something that will not arrive, and it shipped in `rules.json`.
    """
    from agent_audit_kit.rules.builtin import RULES

    blob = " ".join(
        f"{r.description} {r.remediation} {r.limitations}" for r in RULES.values()
    )
    assert "until #22 lands" not in blob
    for path in (REPO / "docs" / "rules").glob("*.md"):
        assert "until #22 lands" not in path.read_text(encoding="utf-8"), path.name


def test_lmdeploy_remediation_names_a_version() -> None:
    """It read "see GHSA for the exact version once NVD enrichment lands" for
    four and a half months, on a CVE exploited within ~12 hours of disclosure.
    A remediation that points somewhere else is not a remediation."""
    from agent_audit_kit.rules.builtin import RULES

    rule = RULES["AAK-LMDEPLOY-VL-SSRF-001"]
    assert "0.12.3" in rule.remediation
    assert "once NVD enrichment lands" not in rule.remediation


def test_rule_lint_incident_filter_exists() -> None:
    """`docs/roadmap/ox-mcp-2026-05-01-batch.md` documented this command as the
    source-of-truth check for a disclosure batch. It did not exist."""
    from agent_audit_kit.rule_lint import rules_for_incident, run_lint

    covered = rules_for_incident("OX-MCP-2026-05-01")
    assert covered, "the batch this filter was written for has no rules"
    assert run_lint(incident_filter="OX-MCP-2026-05-01") == []
    # Case-insensitive: incident ids are quoted in prose with varying case.
    assert rules_for_incident("ox-mcp-2026-05-01") == covered
