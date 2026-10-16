"""AAK-SPLUNK-MCP-TOKEN-LEAK-001 — config-side variant."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from agent_audit_kit.scanners.splunk_mcp_config import scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "cve-2026-20205-config"


def test_vulnerable_yaml_fires(tmp_path: Path) -> None:
    shutil.copytree(FIXTURES / "vulnerable-yaml", tmp_path / "splunk-mcp", dirs_exist_ok=True)
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-SPLUNK-MCP-TOKEN-LEAK-001" for f in findings)


def test_patched_yaml_passes(tmp_path: Path) -> None:
    shutil.copytree(FIXTURES / "patched-yaml", tmp_path / "splunk-mcp", dirs_exist_ok=True)
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-SPLUNK-MCP-TOKEN-LEAK-001" for f in findings)


def test_vulnerable_inputs_conf_fires(tmp_path: Path) -> None:
    shutil.copytree(FIXTURES / "vulnerable-inputs", tmp_path / "splunk-mcp", dirs_exist_ok=True)
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-SPLUNK-MCP-TOKEN-LEAK-001" for f in findings)


# ---------------------------------------------------------------------------
# The path gate opens on any directory named for splunk and mcp
#
# Only a directory named exactly `splunk-mcp` or `splunk_mcp` (or an
# `inputs.conf`, or `splunk-mcp.yaml`) opened it, so the server's own repository
# name, `splunk-mcp-server/`, vendored below the scan root, was never read.
# ---------------------------------------------------------------------------

_ROUTES_TOKEN = "inputs:\n  - path: /var/log/mcp/session.log\n    sourcetype: session_token\n    index: _internal\n"


@pytest.mark.parametrize(
    "rel",
    [
        "splunk-mcp/config.yaml",
        "splunk-mcp-server/config.yaml",
        "splunk_mcp_server/config.yaml",
        "services/splunk-mcp-server/config/sources.yml",
        "deploy/mcp-server-splunk/config.yaml",
        "Splunk-MCP-Server/config.yaml",
    ],
)
def test_the_path_gate_opens_on_a_directory_named_for_splunk_and_mcp(tmp_path: Path, rel: str) -> None:
    path = tmp_path / rel
    path.parent.mkdir(parents=True)
    path.write_text(_ROUTES_TOKEN, encoding="utf-8")

    findings, scanned = scan(tmp_path)

    assert [(f.rule_id, f.file_path) for f in findings] == [("AAK-SPLUNK-MCP-TOKEN-LEAK-001", rel)]
    assert rel in scanned


@pytest.mark.parametrize("rel", ["splunk/config.yaml", "mcp-server/config.yaml", "splunkmcp/config.yaml"])
def test_the_path_gate_stays_shut_elsewhere(tmp_path: Path, rel: str) -> None:
    path = tmp_path / rel
    path.parent.mkdir(parents=True)
    path.write_text(_ROUTES_TOKEN, encoding="utf-8")

    assert scan(tmp_path)[0] == []
