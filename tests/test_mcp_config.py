from __future__ import annotations

from pathlib import Path

from agent_audit_kit.scanners.mcp_config import scan


def test_vulnerable_mcp_triggers_expected_rules(vulnerable_mcp_project: Path) -> None:
    findings, _ = scan(vulnerable_mcp_project)
    rule_ids = {f.rule_id for f in findings}

    # Must trigger these rules
    assert "AAK-MCP-001" in rule_ids, "Should detect remote server without auth"
    assert "AAK-MCP-002" in rule_ids, "Should detect shell injection in command"
    assert "AAK-MCP-003" in rule_ids, "Should detect hardcoded secrets in env"
    assert "AAK-MCP-004" in rule_ids, "Should detect excessive server count (13 servers)"
    assert "AAK-MCP-005" in rule_ids, "Should detect npx/uvx usage"
    assert "AAK-MCP-006" in rule_ids, "Should detect relative path command"
    assert "AAK-MCP-007" in rule_ids, "Should detect unpinned package version"
    assert "AAK-MCP-008" in rule_ids, "Should detect headersHelper"
    assert "AAK-MCP-009" in rule_ids, "Should detect internal network URL"


def test_clean_mcp_produces_zero_findings(clean_mcp_project: Path) -> None:
    findings, _ = scan(clean_mcp_project)
    assert len(findings) == 0, f"Clean MCP config should produce zero findings, got: {[f.rule_id for f in findings]}"


def test_empty_file(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text("")
    findings, _ = scan(tmp_path)
    assert len(findings) == 0


def test_malformed_json(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text("{not valid json!!!")
    findings, _ = scan(tmp_path)
    assert len(findings) == 0


def test_missing_keys(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text('{"mcpServers": {}}')
    findings, _ = scan(tmp_path)
    assert len(findings) == 0


def test_env_variable_references_not_flagged(tmp_path: Path) -> None:
    """Env values that are ${VAR} references should NOT be flagged."""
    import json
    config = {
        "mcpServers": {
            "safe-server": {
                "command": "node",
                "args": ["server.js"],
                "env": {
                    "API_KEY": "${MY_API_KEY}",
                    "SECRET_TOKEN": "${SECRET_FROM_VAULT}"
                }
            }
        }
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(config))
    findings, _ = scan(tmp_path)
    secret_findings = [f for f in findings if f.rule_id == "AAK-MCP-003"]
    assert len(secret_findings) == 0, "Variable references should not be flagged as hardcoded secrets"


def test_authenticated_remote_server_not_flagged(tmp_path: Path) -> None:
    """Remote server WITH auth headers should not trigger AAK-MCP-001."""
    import json
    config = {
        "mcpServers": {
            "authed-remote": {
                "url": "https://mcp.example.com/api",
                "headers": {
                    "Authorization": "Bearer sk-abc123"
                }
            }
        }
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(config))
    findings, _ = scan(tmp_path)
    no_auth_findings = [f for f in findings if f.rule_id == "AAK-MCP-001"]
    assert len(no_auth_findings) == 0


def test_absolute_path_command_not_flagged(tmp_path: Path) -> None:
    """Commands with absolute paths should not trigger AAK-MCP-006."""
    import json
    config = {
        "mcpServers": {
            "absolute-path": {
                "command": "/usr/local/bin/mcp-server",
                "args": ["--port", "3000"]
            }
        }
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(config))
    findings, _ = scan(tmp_path)
    relative_findings = [f for f in findings if f.rule_id == "AAK-MCP-006"]
    assert len(relative_findings) == 0
