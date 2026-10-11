"""The official OWASP id -> title tables, pinned to the versions verified.

AAK shipped its OWASP MCP Top 10 table with OWASP's ``MCPnn:2025`` labels and its
own numbering for most of a year: seven of ten ids named a different risk than
OWASP's list does, so ``AAK-POISON-002`` (prompt injection in a tool description)
carried MCP05, which OWASP defines as Command Injection & Execution. The README's
Agentic table had eight wrong titles. Nothing failed, because nothing compared the
tables with OWASP.

These tests are that comparison, frozen at the versions read on 2026-10-12. When
OWASP renumbers or retitles (the MCP project plans a next release, and its MCP06
title already changed once), this file fails and the edit has to be made on
purpose: update the table in ``owasp_report.py``, re-check every rule reference
against the new meaning, and update the pins with the new source.

Sources, as read on 2026-10-12:

* OWASP MCP Top 10 v0.1 (2025 edition, beta):
  https://github.com/OWASP/www-project-mcp-top-10, ``index.md`` at commit
  165fe0f78ef104459237b4a8e0f6e78db9b02391 (2026-07-29). MCP06 is "Intent Flow
  Subversion" since OWASP PR #21 (merged 2026-02-19); the repo's README.md and
  tab_top10.md still carry the old "Prompt Injection via Contextual Payloads".
* OWASP Top 10 for Agentic Applications, Version 2026 (December 2025): entry
  headings of the official PDF linked from
  https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
* OWASP Agentic Skills Top 10, version badge 1.0-2026: ``ast01.md``..``ast10.md``
  in https://github.com/OWASP/www-project-agentic-skills-top-10
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

from agent_audit_kit.models import Category
from agent_audit_kit.output import owasp_report
from agent_audit_kit.output.owasp_report import OWASP_AGENTIC, OWASP_AST, OWASP_MCP
from agent_audit_kit.rules.builtin import RULES

REPO = Path(__file__).resolve().parent.parent

PINNED_MCP: dict[str, str] = {
    "MCP01:2025": "Token Mismanagement & Secret Exposure",
    "MCP02:2025": "Privilege Escalation via Scope Creep",
    "MCP03:2025": "Tool Poisoning",
    "MCP04:2025": "Software Supply Chain Attacks & Dependency Tampering",
    "MCP05:2025": "Command Injection & Execution",
    "MCP06:2025": "Intent Flow Subversion",
    "MCP07:2025": "Insufficient Authentication & Authorization",
    "MCP08:2025": "Lack of Audit and Telemetry",
    "MCP09:2025": "Shadow MCP Servers",
    "MCP10:2025": "Context Injection & Over-Sharing",
}

PINNED_AGENTIC: dict[str, str] = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution (RCE)",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

PINNED_AST: dict[str, str] = {
    "AST01": "Malicious Skills",
    "AST02": "Supply Chain Compromise",
    "AST03": "Over-Privileged Skills",
    "AST04": "Insecure Metadata",
    "AST05": "Untrusted External Instructions",
    "AST06": "Weak Isolation",
    "AST07": "Update Drift",
    "AST08": "Poor Scanning",
    "AST09": "No Governance",
    "AST10": "Cross-Platform Reuse",
}


# ---------------------------------------------------------------------------
# The tables themselves
# ---------------------------------------------------------------------------


def test_mcp_table_is_the_official_v0_1_list() -> None:
    assert OWASP_MCP == PINNED_MCP
    assert list(OWASP_MCP) == list(PINNED_MCP), "keep the official order"


def test_agentic_table_is_the_official_version_2026_list() -> None:
    assert OWASP_AGENTIC == PINNED_AGENTIC
    assert list(OWASP_AGENTIC) == list(PINNED_AGENTIC), "keep the official order"


def test_agentic_skills_table_is_the_official_1_0_list() -> None:
    assert OWASP_AST == PINNED_AST
    assert list(OWASP_AST) == list(PINNED_AST), "keep the official order"


def test_versions_and_sources_are_recorded() -> None:
    """A table without its version is how the MCP numbering went unchecked."""
    assert owasp_report.OWASP_MCP_VERSION == "v0.1, 2025 edition (beta)"
    assert owasp_report.OWASP_MCP_SOURCE_COMMIT == "165fe0f78ef104459237b4a8e0f6e78db9b02391"
    assert owasp_report.OWASP_AGENTIC_VERSION == "Version 2026 (December 2025)"
    assert owasp_report.OWASP_AST_VERSION == "1.0 (2026)"
    assert owasp_report.OWASP_AGENTIC_URL.startswith("https://genai.owasp.org/")
    assert owasp_report.OWASP_MCP_URL == "https://owasp.org/www-project-mcp-top-10/"
    assert owasp_report.OWASP_AST_URL == "https://owasp.org/www-project-agentic-skills-top-10/"


def test_id_formats_follow_the_official_labels() -> None:
    """MCP ids carry OWASP's own ``:2025`` edition label; Agentic and Skills ids
    carry no year, because the official documents write none."""
    assert all(re.fullmatch(r"MCP(0[1-9]|10):2025", k) for k in OWASP_MCP)
    assert all(re.fullmatch(r"ASI(0[1-9]|10)", k) for k in OWASP_AGENTIC)
    assert all(re.fullmatch(r"AST(0[1-9]|10)", k) for k in OWASP_AST)


# ---------------------------------------------------------------------------
# Every rule reference is an official id
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field,table",
    [
        ("owasp_mcp_references", OWASP_MCP),
        ("owasp_agentic_references", OWASP_AGENTIC),
        ("owasp_ast_references", OWASP_AST),
    ],
)
def test_every_reference_is_an_official_id(field: str, table: dict[str, str]) -> None:
    unknown = sorted(
        {(rid, ref) for rid, rule in RULES.items() for ref in getattr(rule, field) if ref not in table}
    )
    assert not unknown, f"{field} names ids outside the official list: {unknown}"


def test_no_rule_lists_the_same_reference_twice() -> None:
    dupes = [
        (rid, field)
        for rid, rule in RULES.items()
        for field in ("owasp_mcp_references", "owasp_agentic_references", "owasp_ast_references")
        if len(set(getattr(rule, field))) != len(getattr(rule, field))
    ]
    assert not dupes, dupes


# ---------------------------------------------------------------------------
# Sentinels: the old AAK numbering must not creep back
# ---------------------------------------------------------------------------

# rule id -> (MCP id it must carry, MCP id it carried under AAK's old numbering).
# Each pair is one of the seven ids that meant something else in AAK's table.
_SENTINELS: list[tuple[str, str, str]] = [
    ("AAK-POISON-002", "MCP03:2025", "MCP05:2025"),     # tool poisoning is MCP03
    ("AAK-RUGPULL-001", "MCP03:2025", "MCP05:2025"),    # rug pulls are named under MCP03
    ("AAK-SUPPLY-001", "MCP04:2025", "MCP03:2025"),     # supply chain is MCP04
    ("AAK-TAINT-001", "MCP05:2025", "MCP04:2025"),      # command injection is MCP05
    ("AAK-MCP-010", "MCP02:2025", "MCP06:2025"),        # scope creep is MCP02
    ("AAK-SSRF-001", "MCP05:2025", "MCP09:2025"),       # MCP09 is Shadow MCP Servers, not SSRF
    ("AAK-MCP-005", "MCP04:2025", "MCP10:2025"),        # MCP10 is context over-sharing
]


@pytest.mark.parametrize("rule_id,official,old", _SENTINELS)
def test_sentinel_rules_carry_the_official_id(rule_id: str, official: str, old: str) -> None:
    refs = RULES[rule_id].owasp_mcp_references
    assert official in refs, f"{rule_id} should carry {official} ({OWASP_MCP[official]})"
    assert old not in refs, f"{rule_id} carries {old}, the id AAK's retired numbering gave it"


def test_a2a_rules_carry_no_mcp_reference() -> None:
    """A2A is a different protocol; the MCP Top 10 does not cover it."""
    offenders = [
        rid for rid, rule in RULES.items()
        if rule.category == Category.A2A_PROTOCOL and rule.owasp_mcp_references
    ]
    assert not offenders, offenders


def test_statutory_rules_claim_no_owasp_risk() -> None:
    """Licence, privacy-notice and AI-Act duties are not OWASP risks.

    The one exception is a persona that presents an AI as a licensed clinician,
    which is the perceived-expertise trust exploitation ASI09 names.
    """
    offenders = [
        rid for rid, rule in RULES.items()
        if rule.category == Category.LEGAL_COMPLIANCE
        and (rule.owasp_mcp_references or rule.owasp_agentic_references)
        and rid != "AAK-HEALTHCARE-AI-001"
    ]
    assert not offenders, offenders
    assert RULES["AAK-HEALTHCARE-AI-001"].owasp_agentic_references == ["ASI09"]


def test_every_official_entry_has_a_rule() -> None:
    """The 10/10 claims, checked against the real ids."""
    for field, table in (
        ("owasp_mcp_references", OWASP_MCP),
        ("owasp_agentic_references", OWASP_AGENTIC),
    ):
        covered = {ref for rule in RULES.values() for ref in getattr(rule, field)}
        assert set(table) <= covered, f"{field}: no rule for {sorted(set(table) - covered)}"


# ---------------------------------------------------------------------------
# The generators read the tables instead of keeping their own
# ---------------------------------------------------------------------------


def _load_script(name: str):
    path = REPO / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("script", ["gen_owasp_coverage", "gen_coverage"])
def test_generators_use_the_pinned_agentic_titles(script: str) -> None:
    """`gen_owasp_coverage.py` kept a private ASI table with eight wrong titles,
    and the README block was generated from it."""
    assert _load_script(script).ASI_TITLES == PINNED_AGENTIC


def test_readme_block_shows_official_titles() -> None:
    text = (REPO / "README.md").read_text(encoding="utf-8")
    body = text.split("<!-- owasp-coverage:start -->")[1].split("<!-- owasp-coverage:end -->")[0]
    for asi, title in PINNED_AGENTIC.items():
        assert f"| **{asi}** | {title} |" in body, f"README OWASP block lacks {asi} {title}"
