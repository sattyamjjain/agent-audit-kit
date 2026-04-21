"""Tests for the AICM tag overlay + `--compliance aicm` CSV output (Task E)."""

from __future__ import annotations

import csv
import io
from pathlib import Path

from click.testing import CliRunner

from agent_audit_kit.cli import cli
from agent_audit_kit.models import Finding, ScanResult
from agent_audit_kit.output.aicm import format_results as fmt_aicm
from agent_audit_kit.rules.builtin import RULES


def _finding(rule_id: str, file: str = "x.py") -> Finding:
    rule = RULES[rule_id]
    return Finding(
        rule_id=rule_id,
        title=rule.title,
        description=rule.description,
        severity=rule.severity,
        category=rule.category,
        file_path=file,
        line_number=1,
        evidence=f"evidence for {rule_id}",
        remediation=rule.remediation,
        cve_references=rule.cve_references,
        owasp_mcp_references=rule.owasp_mcp_references,
        owasp_agentic_references=rule.owasp_agentic_references,
        aicm_references=rule.aicm_references,
        incident_references=rule.incident_references,
    )


# ---------------------------------------------------------------------------
# Tag overlay wired correctly.
# ---------------------------------------------------------------------------


def test_secret_rules_tagged_dsp_17() -> None:
    assert RULES["AAK-SECRET-001"].aicm_references == ["DSP-17"]
    assert RULES["AAK-SECRET-002"].aicm_references == ["DSP-17"]
    assert RULES["AAK-SECRET-006"].aicm_references == ["DSP-17"]


# --------------------------------------------------------------------------
# Density floor (v0.3.3). Expand from 10 → ≥75 rules so ``--compliance
# aicm`` is useful out of the box and the CSA Agentic AI Security
# Summit (2026-04-29) pre-sales angle stops being aspirational.
# --------------------------------------------------------------------------


_AICM_DENSITY_FLOOR = 75


def test_aicm_density_floor() -> None:
    tagged = [rid for rid, r in RULES.items() if r.aicm_references]
    assert len(tagged) >= _AICM_DENSITY_FLOOR, (
        f"{len(tagged)} rules tagged with AICM controls; floor is "
        f"{_AICM_DENSITY_FLOOR}. Extend _AICM_TAGS in "
        "agent_audit_kit/rules/builtin.py."
    )


def test_mcpwn_rule_tagged_iam_01() -> None:
    assert "IAM-01" in RULES["AAK-MCPWN-001"].aicm_references


def test_loginj_rule_tagged_log_06() -> None:
    assert "LOG-06" in RULES["AAK-LOGINJ-001"].aicm_references


def test_overlay_idempotent() -> None:
    from agent_audit_kit.rules.builtin import _apply_aicm_overlay

    before = list(RULES["AAK-SECRET-001"].aicm_references)
    _apply_aicm_overlay()
    _apply_aicm_overlay()
    assert RULES["AAK-SECRET-001"].aicm_references == before


# ---------------------------------------------------------------------------
# CSV output shape.
# ---------------------------------------------------------------------------


def test_csv_ordered_by_control_then_rule() -> None:
    result = ScanResult()
    result.findings = [
        _finding("AAK-MCPWN-001"),       # IAM-01
        _finding("AAK-SECRET-001"),      # DSP-17
        _finding("AAK-SECRET-002"),      # DSP-17
        _finding("AAK-LOGINJ-001"),      # LOG-06
    ]
    csv_text = fmt_aicm(result)
    rows = list(csv.reader(io.StringIO(csv_text)))
    header = rows[0]
    assert header[0] == "aicm_control"
    body = rows[1:]
    controls = [r[0] for r in body]
    # DSP-17 entries first, then IAM-01, then LOG-06.
    assert controls == ["DSP-17", "DSP-17", "IAM-01", "LOG-06"]
    # Within the DSP-17 group, sorted by rule_id.
    assert [r[1] for r in body[:2]] == ["AAK-SECRET-001", "AAK-SECRET-002"]


def test_csv_drops_unmapped_findings() -> None:
    result = ScanResult()
    # AAK-MCP-001 has no AICM tag in our initial overlay — it should be dropped.
    unmapped = _finding("AAK-MCP-001")
    result.findings = [unmapped]
    csv_text = fmt_aicm(result)
    rows = list(csv.reader(io.StringIO(csv_text)))
    assert rows == [list(rows[0])]  # header only


def test_csv_explodes_multi_control_rules() -> None:
    # Synthesize a finding with 2 AICM tags; expect 2 output rows.
    f = _finding("AAK-MCPWN-001")
    f.aicm_references = ["IAM-01", "AIS-03"]
    result = ScanResult()
    result.findings = [f]
    csv_text = fmt_aicm(result)
    rows = list(csv.reader(io.StringIO(csv_text)))[1:]
    assert sorted(r[0] for r in rows) == ["AIS-03", "IAM-01"]


# ---------------------------------------------------------------------------
# CLI integration.
# ---------------------------------------------------------------------------


def test_cli_compliance_aicm_flag_emits_csv(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("ANTHROPIC_API_KEY=sk-ant-fake-xxxxxxxxxxxxxx\n")
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(tmp_path), "--compliance", "aicm"])
    assert result.exit_code in (0, 1), result.output
    assert "aicm_control" in result.output
    # DSP-17 entries are written because AAK-SECRET-001 fired.
    assert "DSP-17" in result.output
