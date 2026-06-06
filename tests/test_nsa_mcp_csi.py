"""Tests for the NSA MCP Security CSI compliance mapping.

Source: National Security Agency Artificial Intelligence Security Center
(AISC) Cybersecurity Information Sheet —
"Model Context Protocol (MCP): Security Design Considerations for
AI-Driven Automation", document U/OO/6030316-26 / PP-26-1834, May 2026
Ver. 1.0. The 9 named "Recommendations" sections (pp.10-14) are the
mappable controls; each is mapped to the AAK rule IDs that evidence it.

This is a *mapping over existing rules* — no new scanner, no new rule IDs.

  - https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf
  - https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4496698/
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_audit_kit.cli import cli
from agent_audit_kit.models import Finding, ScanResult, Severity
from agent_audit_kit.output.compliance import (
    FRAMEWORKS,
    _resolve_control_rules,
    format_results,
)
from agent_audit_kit.rules.builtin import RULES


FRAMEWORK_KEY = "nsa-mcp-csi-2026"


# ---------------------------------------------------------------------------
# Registry & schema sanity
# ---------------------------------------------------------------------------


def test_framework_is_registered() -> None:
    assert FRAMEWORK_KEY in FRAMEWORKS, (
        f"NSA CSI framework missing from FRAMEWORKS — "
        f"got {list(FRAMEWORKS.keys())}"
    )


def test_framework_carries_verbatim_doc_id_citation() -> None:
    """The document ID must be present and exactly match what the CSI's
    cover footer prints (verified against the PDF's cover footer line)."""
    fw = FRAMEWORKS[FRAMEWORK_KEY]
    src = fw["source"]
    assert src["doc_id"] == "U/OO/6030316-26 | PP-26-1834"
    assert src["published"].startswith("May 2026")
    assert "NSA Artificial Intelligence Security Center" in src["publisher"]
    assert src["url"].endswith("CSI_MCP_SECURITY.pdf")
    assert src["title"].startswith("Model Context Protocol (MCP)")


def test_nine_recommendations_correspond_to_csi_sections() -> None:
    """The CSI body has 9 named recommendation sections under
    'Recommendations' (pp.10-14). Each control name in the FRAMEWORKS
    entry must reproduce one of those headings verbatim with its page."""
    fw = FRAMEWORKS[FRAMEWORK_KEY]
    expected_controls = {
        "Choose supported MCP projects when possible (p.10)",
        "Design for boundaries (p.10)",
        "Validate parameters (p.11)",
        "Constrain and sandbox tool execution (p.11)",
        "Sign and verify MCP messages (p.12)",
        "Filter and monitor output pipelines and chained execution (p.12)",
        "Instrument for logging and detection (p.13)",
        "Track and patch MCP related vulnerabilities (p.13)",
        "Scan local network for open or vulnerable MCP servers (p.14)",
    }
    assert set(fw["controls"].keys()) == expected_controls, (
        f"NSA CSI control set drift — "
        f"missing={expected_controls - set(fw['controls'])} "
        f"extra={set(fw['controls']) - expected_controls}"
    )


# ---------------------------------------------------------------------------
# Coverage: every recommendation MUST map to ≥1 existing rule (request spec).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("control", list(FRAMEWORKS[FRAMEWORK_KEY]["controls"].keys()))
def test_each_control_has_at_least_one_existing_rule(control: str) -> None:
    """Per the request: 'asserting the NSA framework renders a non-empty
    report with ≥1 mapped rule per control'."""
    val = FRAMEWORKS[FRAMEWORK_KEY]["controls"][control]
    rules = _resolve_control_rules(val)
    assert rules, f"control resolves to ZERO rules: {control!r}"
    # Every curated rule_id must actually exist in the live registry
    # (defensive against future rule renames silently breaking the map).
    if isinstance(val, dict):
        for rid in val.get("rule_ids", []):
            assert rid in RULES, (
                f"curated rule_id {rid!r} in control {control!r} "
                f"does not exist in the live RULES registry"
            )


def test_no_invented_asi_tokens() -> None:
    """Every `also_covers_asi` token must correspond to an ASI token
    actually carried by at least one live rule — else the fan-out is
    silently empty and the user has no visibility into the gap."""
    fw = FRAMEWORKS[FRAMEWORK_KEY]
    all_asi_in_rules: set[str] = set()
    for r in RULES.values():
        all_asi_in_rules.update(r.owasp_agentic_references)
    for control, val in fw["controls"].items():
        if not isinstance(val, dict):
            continue
        for asi in val.get("also_covers_asi", []):
            assert asi in all_asi_in_rules, (
                f"ASI token {asi!r} in control {control!r} not carried "
                f"by any live rule — fan-out is empty"
            )


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _empty_result() -> ScanResult:
    return ScanResult(findings=[], files_scanned=0, rules_evaluated=0)


def _result_with_finding(rule_id: str, severity: Severity = Severity.CRITICAL) -> ScanResult:
    return ScanResult(
        findings=[Finding(
            rule_id=rule_id,
            title=RULES[rule_id].title,
            description=RULES[rule_id].description,
            severity=severity,
            category=RULES[rule_id].category,
            file_path="x",
            evidence="x",
        )],
        files_scanned=1,
        rules_evaluated=len(RULES),
    )


def test_compliance_report_renders_with_doc_id_citation() -> None:
    """The compliance.format_results() report must include the verbatim
    NSA document ID so the output is independently auditable."""
    out = format_results(_empty_result(), FRAMEWORK_KEY)
    assert "U/OO/6030316-26" in out
    assert "NSA Artificial Intelligence Security Center" in out
    assert "CSI_MCP_SECURITY.pdf" in out
    # Every control heading reproduces in the body
    for control in FRAMEWORKS[FRAMEWORK_KEY]["controls"]:
        assert control in out


def test_compliance_report_pass_when_no_findings() -> None:
    out = format_results(_empty_result(), FRAMEWORK_KEY)
    assert "Controls met: 9/9 (100%)" in out
    assert "FAIL" not in out
    assert "PASS" in out


def test_compliance_report_fails_when_mapped_rule_triggered() -> None:
    """A finding under any mapped rule must flip the relevant control to FAIL.

    AAK-MCP-001 (Remote MCP without auth) is explicitly mapped under
    'Scan local network for open or vulnerable MCP servers (p.14)'.
    """
    out = format_results(_result_with_finding("AAK-MCP-001"), FRAMEWORK_KEY)
    assert "FAIL" in out
    # That specific control must show FAIL; others should still PASS.
    lines = out.splitlines()
    scan_idx = next(
        i for i, ln in enumerate(lines)
        if "Scan local network for open or vulnerable MCP servers" in ln
    )
    # Status line is 1 below the control heading
    status_line = lines[scan_idx + 1]
    assert "FAIL" in status_line, f"unexpected status: {status_line!r}"


# ---------------------------------------------------------------------------
# CLI: --framework nsa-mcp-csi-2026 is accepted by `report --format text`
# ---------------------------------------------------------------------------


def test_cli_report_accepts_new_framework(tmp_path: Path) -> None:
    runner = CliRunner()
    out_file = tmp_path / "report.txt"
    result = runner.invoke(cli, [
        "report", str(tmp_path),
        "--framework", FRAMEWORK_KEY,
        "--format", "text",
        "--output", str(out_file),
    ])
    assert result.exit_code == 0, (
        f"CLI exit non-zero: {result.exit_code}\nstdout: {result.output}"
    )
    body = out_file.read_text(encoding="utf-8")
    # The text-report rendered via pdf_report._text_report must carry the
    # framework title which includes the doc ID.
    assert "U/OO/6030316-26" in body
    assert "NSA MCP Security CSI" in body


def test_cli_compliance_flag_accepts_new_framework(tmp_path: Path) -> None:
    """`agent-audit-kit scan --compliance nsa-mcp-csi-2026` must run cleanly
    and emit the source-citation block from compliance.format_results."""
    runner = CliRunner()
    result = runner.invoke(cli, [
        "scan", str(tmp_path),
        "--compliance", FRAMEWORK_KEY,
    ])
    assert result.exit_code in (0, 1), (
        f"unexpected exit: {result.exit_code}\nstdout: {result.output}"
    )
    assert "U/OO/6030316-26" in result.output
    assert "Choose supported MCP projects" in result.output


# ---------------------------------------------------------------------------
# Backward compat: legacy frameworks still work via list[str] ASI shape.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("legacy_fw", [
    "eu-ai-act", "soc2", "iso27001", "iso42001",
    "hipaa", "nist-ai-rmf", "mcp-2026-roadmap",
])
def test_legacy_framework_still_resolves(legacy_fw: str) -> None:
    """The schema extension to _resolve_control_rules must not break the
    seven pre-existing frameworks that use the list[str] ASI shape."""
    fw = FRAMEWORKS[legacy_fw]
    assert fw["controls"], f"{legacy_fw} has no controls"
    for val in fw["controls"].values():
        rules = _resolve_control_rules(val)
        # Most legacy controls resolve to a non-empty set; a handful
        # (e.g. very narrow ASI tokens with no live rules) may legitimately
        # be empty. We just assert that resolution doesn't crash.
        assert isinstance(rules, list)


# ---------------------------------------------------------------------------
# Coverage-gap closures (audit of the v1 mapping)
#
# The initial mapping (PR #294) omitted several rules that plainly evidence a
# CSI recommendation, while the OWASP-Agentic `also_covers_asi` fan-out could
# not reach the ASI-less ones (e.g. AAK-MCP-STATELESS-002 carries no ASI tag).
# A gap audit added them explicitly. These tests pin those closures so a
# future rule rename or mapping edit cannot silently re-open the gap.
# ---------------------------------------------------------------------------


def _cited_in(control_substr: str) -> set[str]:
    """Return the explicitly-cited rule_ids for the control whose heading
    contains `control_substr`."""
    for ctrl, val in FRAMEWORKS[FRAMEWORK_KEY]["controls"].items():
        if control_substr in ctrl and isinstance(val, dict):
            return set(val.get("rule_ids", []))
    raise AssertionError(f"no control heading contains {control_substr!r}")


@pytest.mark.parametrize("rule_id, control_substr", [
    # Generic SSRF family — the v1 map cited only vendor-specific SSRF.
    ("AAK-SSRF-001", "Constrain and sandbox tool execution"),
    ("AAK-SSRF-004", "Constrain and sandbox tool execution"),
    ("AAK-SSRF-005", "Constrain and sandbox tool execution"),
    ("AAK-SSRF-002", "Scan local network"),   # loopback reach
    ("AAK-SSRF-003", "Scan local network"),   # cloud-metadata reach
    # HOOK-RCE family — v1 cited only -001 of the same family/section.
    ("AAK-HOOK-RCE-002", "Constrain and sandbox tool execution"),
    ("AAK-HOOK-RCE-003", "Constrain and sandbox tool execution"),
    # Path-traversal / input-validation in the MCP server itself.
    ("AAK-MCP-015", "Validate parameters"),
    ("AAK-LANGCHAIN-001", "Validate parameters"),
    ("AAK-LANGCHAIN-002", "Validate parameters"),
    # Boundary / transport.
    ("AAK-A2A-009", "Design for boundaries"),
    ("AAK-A2A-004", "Sign and verify MCP messages"),
    # Detection / logging hygiene.
    ("AAK-AGENT-004", "Instrument for logging and detection"),
    ("AAK-AGENT-005", "Filter and monitor output pipelines"),
    # MCP-stack patch hygiene — incl. the ASI-less STATELESS rule that the
    # fan-out can never reach.
    ("AAK-MCPFRAME-001", "Track and patch MCP related vulnerabilities"),
    ("AAK-MCP-STATELESS-002", "Track and patch MCP related vulnerabilities"),
    ("AAK-CLAUDE-WIN-001", "Track and patch MCP related vulnerabilities"),
])
def test_gap_closure_rule_is_mapped(rule_id: str, control_substr: str) -> None:
    """Each audited gap rule must be explicitly cited under its control and
    must exist in the live registry."""
    assert rule_id in RULES, f"{rule_id} missing from RULES registry"
    assert rule_id in _cited_in(control_substr), (
        f"{rule_id} not explicitly cited under a control matching "
        f"{control_substr!r} — coverage gap re-opened"
    )


def test_deliberate_exclusions_stay_out_of_scope() -> None:
    """These rules are intentionally NOT mapped to the NSA MCP CSI: they are
    either internal sentinels, info-only coverage manifests, or controls
    outside MCP security scope (privacy-policy docs, frontend DoS, pricing,
    EU-locale eval). Mapping them would fabricate coverage. This test
    documents the decision and guards against an over-broad future edit.
    """
    out_of_scope = {
        "AAK-INTERNAL-SCANNER-FAIL",
        "AAK-EU-AI-ACT-ART15-LOCALE-001",
        "AAK-OX-COVERAGE-MANIFEST-001",
        "AAK-PRISMA-AIRS-COVERAGE-001",
        "AAK-STATE-PRIVACY-001",
        "AAK-STATE-PRIVACY-002",
        "AAK-STATE-PRIVACY-003",
        "AAK-NEXT-AI-DRAW-001",
        "AAK-PROJECT-DEAL-DRIFT-001",
    }
    cited: set[str] = set()
    for val in FRAMEWORKS[FRAMEWORK_KEY]["controls"].values():
        if isinstance(val, dict):
            cited.update(val.get("rule_ids", []))
    leaked = out_of_scope & cited
    assert not leaked, (
        f"out-of-scope rules were mapped into the NSA CSI framework: {leaked}"
    )
