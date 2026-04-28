"""v0.3.9 P1 feature tests: OX coverage, Pipelock translator, IDE LSP."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_audit_kit.cli import cli
from agent_audit_kit.coverage import load_manifest, summarize
from agent_audit_kit.ide.lsp_diag import diagnostics_for
from agent_audit_kit.translators.pipelock import translate

FIXTURES = Path(__file__).parent / "fixtures"


# -------------------- OX coverage manifest --------------------

def test_ox_manifest_has_entries() -> None:
    entries = load_manifest("ox")
    assert len(entries) >= 15
    for e in entries:
        assert re.match(r"^(CVE-|OX-)", e["cve"])


def test_ox_manifest_unknown_source_raises() -> None:
    with pytest.raises(ValueError):
        load_manifest("nope")


def test_ox_summary_reports_coverage_pct() -> None:
    entries = load_manifest("ox")
    summary = summarize(entries)
    assert summary["total"] == len(entries)
    assert 0 <= summary["coverage_pct"] <= 100
    # All current entries are covered.
    assert summary["covered"] == summary["total"]


def test_ox_summary_rules_are_non_empty_when_covered() -> None:
    entries = load_manifest("ox")
    for entry in entries:
        if entry.get("covered"):
            assert entry.get("rules"), entry["cve"]


def test_aak_coverage_cli_text_output() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["coverage", "--source", "ox", "--format", "text"])
    assert result.exit_code == 0
    assert "OX-disclosed CVE coverage:" in result.output


def test_aak_coverage_cli_badge_output() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["coverage", "--source", "ox", "--format", "badge"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["label"] == "OX coverage"
    assert payload["schemaVersion"] == 1
    assert payload["color"] in {"green", "yellow", "red"}


def test_aak_coverage_cli_json_output() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["coverage", "--source", "ox", "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert "entries" in payload
    assert payload["total"] >= 15


# -------------------- Pipelock translator --------------------

def test_pipelock_translate_minimal(tmp_path: Path) -> None:
    out = translate(FIXTURES / "pipelock" / "policy_minimal.yaml")
    assert "AAK-PIPELOCK-POLICY-TRANSLATOR-001" in out
    assert "AAK-MCP-001" in out
    assert "exclude-rules" in out
    assert "fail-on: high" in out


def test_pipelock_translate_parity_block() -> None:
    out = translate(FIXTURES / "pipelock" / "policy_with_parity.yaml")
    assert "parity-dimension: model" in out
    assert "parity-metric: price" in out
    assert "fail-on: critical" in out
    # Untranslated keys are surfaced as a header comment block.
    assert "unsupported_block" in out


def test_pipelock_translate_unsupported_schema_raises() -> None:
    with pytest.raises(ValueError, match="Unsupported Pipelock schema"):
        translate(FIXTURES / "pipelock" / "policy_invalid.yaml")


def test_aak_pipelock_import_cli(tmp_path: Path) -> None:
    runner = CliRunner()
    target = tmp_path / "out.yml"
    result = runner.invoke(
        cli,
        [
            "pipelock", "import",
            str(FIXTURES / "pipelock" / "policy_minimal.yaml"),
            "-o", str(target),
        ],
    )
    assert result.exit_code == 0, result.output
    written = target.read_text(encoding="utf-8")
    assert "AAK-PIPELOCK-POLICY-TRANSLATOR-001" in written


def test_aak_pipelock_import_dry_run() -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "pipelock", "import",
            str(FIXTURES / "pipelock" / "policy_minimal.yaml"),
            "--dry-run",
        ],
    )
    assert result.exit_code == 0
    assert "fail-on: high" in result.output


# -------------------- IDE LSP diagnostics --------------------

def test_diagnostics_shape_for_finding(tmp_path: Path) -> None:
    """Run the inspect-ide adapter on a fixture that triggers a finding."""
    src = (FIXTURES / "langgraph" / "vulnerable" / "graph.py").read_text()
    (tmp_path / "graph.py").write_text(src, encoding="utf-8")
    diags = diagnostics_for(tmp_path)
    assert diags, "expected at least one diagnostic"
    sample = diags[0]
    assert "uri" in sample and sample["uri"].startswith("file://")
    assert "range" in sample and "start" in sample["range"]
    assert "code" in sample and sample["code"].startswith("AAK-")
    assert sample["source"] == "agent-audit-kit"


def test_aak_inspect_ide_text_format(tmp_path: Path) -> None:
    src = (FIXTURES / "langgraph" / "vulnerable" / "graph.py").read_text()
    (tmp_path / "graph.py").write_text(src, encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(
        cli, ["inspect-ide", str(tmp_path), "--format", "text"]
    )
    assert result.exit_code == 0
    assert "AAK-LANGGRAPH-TOOLNODE-LIST-REGRESSION-001" in result.output


def test_aak_inspect_ide_lsp_format(tmp_path: Path) -> None:
    src = (FIXTURES / "langgraph" / "vulnerable" / "graph.py").read_text()
    (tmp_path / "graph.py").write_text(src, encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(
        cli, ["inspect-ide", str(tmp_path), "--format", "lsp"]
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert isinstance(payload, list)
    assert any(d["code"].startswith("AAK-") for d in payload)
