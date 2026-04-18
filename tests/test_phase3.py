"""Phase 3 integration tests: bundle / SBOM / compliance-PDF / CVE-watcher."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from agent_audit_kit.bundle import build_bundle, verify_bundle, write_bundle
from agent_audit_kit.cli import cli
from agent_audit_kit.output.pdf_report import _text_report
from agent_audit_kit.output.sbom import emit_cyclonedx, emit_spdx


def test_build_bundle_is_deterministic_and_contains_every_rule() -> None:
    from agent_audit_kit.rules.builtin import RULES

    bundle = build_bundle()
    ids = [entry["rule_id"] for entry in bundle["rules"]]
    assert len(ids) == len(RULES)
    assert ids == sorted(ids)


def test_write_bundle_and_verify_matches(tmp_path: Path) -> None:
    bundle_path = tmp_path / "rules.json"
    digest = write_bundle(bundle_path)
    ok, message = verify_bundle(bundle_path)
    assert ok
    assert digest in message


def test_verify_bundle_missing_file_is_handled(tmp_path: Path) -> None:
    ok, message = verify_bundle(tmp_path / "missing.json")
    assert not ok
    assert "not found" in message


def test_cyclonedx_sbom_has_required_fields(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fs": {
                        "command": "npx",
                        "args": ["@modelcontextprotocol/server-filesystem@2025.1.1"],
                    }
                }
            }
        )
    )
    text = emit_cyclonedx(tmp_path)
    data = json.loads(text)
    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.5"
    assert data["components"]
    component = data["components"][0]
    assert component["name"] == "@modelcontextprotocol/server-filesystem"
    assert component["version"] == "2025.1.1"


def test_spdx_sbom_emits(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fs": {
                        "command": "npx",
                        "args": ["@modelcontextprotocol/server-filesystem@2025.1.1"],
                    }
                }
            }
        )
    )
    text = emit_spdx(tmp_path)
    data = json.loads(text)
    assert data["spdxVersion"] == "SPDX-2.3"
    assert data["packages"]


def test_compliance_text_report_groups_by_control(tmp_path: Path) -> None:
    from agent_audit_kit.engine import run_scan

    (tmp_path / ".env").write_text("OPENAI_API_KEY=sk-liveKey12345")
    result = run_scan(tmp_path)
    text = _text_report(result, "eu-ai-act")
    assert "EU AI Act" in text
    assert "Findings by control" in text


def test_cli_sbom_command(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fs": {
                        "command": "npx",
                        "args": ["@modelcontextprotocol/server-filesystem@2025.1.1"],
                    }
                }
            }
        )
    )
    runner = CliRunner()
    result = runner.invoke(cli, ["sbom", str(tmp_path), "--format", "cyclonedx"])
    assert result.exit_code == 0, result.output
    assert "CycloneDX" in result.output


def test_cli_export_rules_and_verify(tmp_path: Path) -> None:
    bundle_path = tmp_path / "rules.json"
    runner = CliRunner()
    r1 = runner.invoke(cli, ["export-rules", "--out", str(bundle_path)])
    assert r1.exit_code == 0
    assert bundle_path.is_file()
    r2 = runner.invoke(cli, ["verify-bundle", str(bundle_path)])
    assert r2.exit_code == 0
    assert "sha256" in r2.output


def test_cli_report_text_framework(tmp_path: Path) -> None:
    out = tmp_path / "report.txt"
    runner = CliRunner()
    r = runner.invoke(
        cli,
        ["report", str(tmp_path), "--framework", "soc2", "--format", "text", "--output", str(out)],
    )
    assert r.exit_code == 0, r.output
    assert out.is_file()
    assert "SOC 2" in out.read_text()


def test_cve_watcher_script_is_importable() -> None:
    """Smoke-test: the watcher script parses without reaching out to NVD."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "cve_watcher", "scripts/cve_watcher.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert callable(module.main)
    assert callable(module._already_tracked)
