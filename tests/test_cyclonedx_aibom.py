"""CycloneDX 1.5 AI/ML-BOM emitter tests (Task F)."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from agent_audit_kit.cli import cli
from agent_audit_kit.output.sbom import emit_cyclonedx


def _require_shape(doc: dict) -> None:
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert doc["metadata"]["tools"][0]["name"] == "agent-audit-kit"


def test_default_cyclonedx_has_no_ml_components(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("anthropic==0.25.0\n", encoding="utf-8")
    doc = json.loads(emit_cyclonedx(tmp_path))
    _require_shape(doc)
    assert not any(c.get("type") == "machine-learning-model" for c in doc["components"])


def test_aibom_includes_ml_model_when_anthropic_sdk_declared(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("anthropic==0.25.0\n", encoding="utf-8")
    doc = json.loads(emit_cyclonedx(tmp_path, aibom=True))
    _require_shape(doc)
    ml_models = [c for c in doc["components"] if c.get("type") == "machine-learning-model"]
    assert ml_models, "expected at least one ml-model component"
    assert any("Claude" in c["name"] for c in ml_models)


def test_aibom_formulation_block_lists_platform_sdks(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({
            "dependencies": {
                "@modelcontextprotocol/sdk": "^1.2.3",
                "langchain": "0.1.0",
            }
        }),
        encoding="utf-8",
    )
    doc = json.loads(emit_cyclonedx(tmp_path, aibom=True))
    assert "formulation" in doc
    names = {c["name"] for c in doc["formulation"][0]["components"]}
    assert "langchain" in names
    assert "@modelcontextprotocol/sdk" in names


def test_aibom_metadata_properties_propagate_rule_hash_and_incidents(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("anthropic\n", encoding="utf-8")
    doc = json.loads(emit_cyclonedx(
        tmp_path,
        aibom=True,
        rule_bundle_sha256="deadbeef" * 8,
        fired_incidents=["OX-MCP-2026-04-15", "VERCEL-2026-04-19"],
    ))
    props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert props["aak:rule-bundle-sha256"] == "deadbeef" * 8
    assert props["aak:aibom"] == "1"
    incident_values = [p["value"] for p in doc["metadata"]["properties"]
                       if p["name"] == "aak:incident-fired"]
    assert "OX-MCP-2026-04-15" in incident_values
    assert "VERCEL-2026-04-19" in incident_values


def test_cli_sbom_aibom_flag(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("anthropic\n", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(cli, ["sbom", str(tmp_path), "--format", "aibom"])
    assert result.exit_code == 0, result.output
    doc = json.loads(result.output)
    _require_shape(doc)
    assert any(c.get("type") == "machine-learning-model" for c in doc["components"])
