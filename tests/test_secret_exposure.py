from __future__ import annotations

import json
from pathlib import Path

from agent_audit_kit.scanners.secret_exposure import scan, _shannon_entropy


def test_vulnerable_env_triggers_secret_rules(project_with_secrets: Path) -> None:
    findings, _ = scan(project_with_secrets)
    rule_ids = {f.rule_id for f in findings}

    assert "AAK-SECRET-001" in rule_ids, "Should detect Anthropic API key"
    assert "AAK-SECRET-002" in rule_ids, "Should detect OpenAI API key"
    assert "AAK-SECRET-003" in rule_ids, "Should detect AWS credentials"
    assert "AAK-SECRET-006" in rule_ids, "Should detect .env not in .gitignore"


def test_clean_project_no_secrets(tmp_path: Path) -> None:
    """A project with no secret files should produce zero findings."""
    (tmp_path / "README.md").write_text("# My Project\n")
    (tmp_path / ".gitignore").write_text(".env\n.env.*\n")
    findings, _ = scan(tmp_path)
    assert len(findings) == 0, f"Clean project should have no findings, got: {[f.rule_id for f in findings]}"


def test_env_in_gitignore_not_flagged(tmp_path: Path) -> None:
    """If .env is in .gitignore, AAK-SECRET-006 should not fire."""
    (tmp_path / ".env").write_text("SAFE_VAR=hello\n")
    (tmp_path / ".gitignore").write_text(".env\nnode_modules/\n")
    findings, _ = scan(tmp_path)
    env_findings = [f for f in findings if f.rule_id == "AAK-SECRET-006"]
    assert len(env_findings) == 0


def test_shannon_entropy_calculation() -> None:
    """Test the Shannon entropy implementation."""
    # Empty string
    assert _shannon_entropy("") == 0.0
    # Single repeated char (0 entropy)
    assert _shannon_entropy("aaaa") == 0.0
    # Binary string (1 bit)
    entropy = _shannon_entropy("ab")
    assert abs(entropy - 1.0) < 0.01
    # High entropy (random-looking)
    high_entropy = _shannon_entropy("aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7bC9dE1fG3hI5jK7")
    assert high_entropy > 4.5, f"High entropy string should have entropy > 4.5, got {high_entropy}"


def test_generic_high_entropy_secret_detected(tmp_path: Path) -> None:
    """AAK-SECRET-004 should trigger on high-entropy values."""
    content = 'SECRET_KEY="aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7bC9dE1fG3hI5jK7"\n'
    (tmp_path / "config.json").write_text(content)
    findings, _ = scan(tmp_path)
    entropy_findings = [f for f in findings if f.rule_id == "AAK-SECRET-004"]
    assert len(entropy_findings) > 0, "High-entropy secret should be detected"


def test_private_key_file_detected(tmp_path: Path) -> None:
    """AAK-SECRET-005 should detect private key files."""
    (tmp_path / "server.key").write_text("-----BEGIN PRIVATE KEY-----\nMIIEvQ...\n-----END PRIVATE KEY-----\n")
    findings, _ = scan(tmp_path)
    key_findings = [f for f in findings if f.rule_id == "AAK-SECRET-005"]
    assert len(key_findings) > 0, "Private key file should be detected"


def test_mcp_env_secret_in_settings(tmp_path: Path) -> None:
    """AAK-SECRET-007 should detect secrets in MCP env blocks outside .mcp.json."""
    config = {
        "mcpServers": {
            "test-server": {
                "command": "node",
                "args": ["server.js"],
                "env": {
                    "API_KEY": "hardcoded-secret-value-1234567890"
                }
            }
        }
    }
    (tmp_path / "custom-mcp-config.json").write_text(json.dumps(config))
    findings, _ = scan(tmp_path)
    mcp_secret_findings = [f for f in findings if f.rule_id == "AAK-SECRET-007"]
    assert len(mcp_secret_findings) > 0, "MCP env secrets should be detected"


def test_empty_dir(tmp_path: Path) -> None:
    findings, _ = scan(tmp_path)
    assert len(findings) == 0
