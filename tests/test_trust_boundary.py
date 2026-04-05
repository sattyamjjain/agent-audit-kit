from __future__ import annotations

import json
from pathlib import Path

from agent_audit_kit.scanners.trust_boundary import scan


def test_vulnerable_settings_triggers_trust_rules(vulnerable_settings_project: Path) -> None:
    findings, _ = scan(vulnerable_settings_project)
    rule_ids = {f.rule_id for f in findings}

    assert "AAK-TRUST-001" in rule_ids, "Should detect enableAllProjectMcpServers: true"
    assert "AAK-TRUST-002" in rule_ids, "Should detect ANTHROPIC_BASE_URL override"
    assert "AAK-TRUST-003" in rule_ids, "Should detect wildcard permissions"
    assert "AAK-TRUST-004" in rule_ids, "Should detect missing deny rules"
    assert "AAK-TRUST-005" in rule_ids, "Should detect custom API URL override"
    assert "AAK-TRUST-006" in rule_ids, "Should detect project settings overriding user denys"


def test_clean_settings_produces_zero_findings(clean_settings_project: Path) -> None:
    findings, _ = scan(clean_settings_project)
    assert len(findings) == 0, f"Clean settings should produce zero findings, got: {[f.rule_id for f in findings]}"


def test_empty_settings(tmp_path: Path) -> None:
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / "settings.json").write_text("{}")
    findings, _ = scan(tmp_path)
    assert len(findings) == 0


def test_anthropic_url_to_anthropic_domain_not_flagged(tmp_path: Path) -> None:
    """ANTHROPIC_BASE_URL pointing to anthropic.com should not be flagged."""
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    settings = {
        "env": {
            "ANTHROPIC_BASE_URL": "https://api.anthropic.com/v1"
        }
    }
    (claude_dir / "settings.json").write_text(json.dumps(settings))
    findings, _ = scan(tmp_path)
    trust002 = [f for f in findings if f.rule_id == "AAK-TRUST-002"]
    assert len(trust002) == 0, "Anthropic's own URL should not be flagged"


def test_scoped_permissions_with_deny_not_flagged(tmp_path: Path) -> None:
    """Specific permissions with deny rules should not trigger AAK-TRUST-003/004."""
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    settings = {
        "permissions": {
            "allow": ["Bash(npm test)", "Edit(src/**)"],
            "deny": ["Bash(rm *)", "Bash(curl *)"]
        }
    }
    (claude_dir / "settings.json").write_text(json.dumps(settings))
    findings, _ = scan(tmp_path)
    wildcard_findings = [f for f in findings if f.rule_id == "AAK-TRUST-003"]
    deny_findings = [f for f in findings if f.rule_id == "AAK-TRUST-004"]
    assert len(wildcard_findings) == 0, "Scoped permissions should not be flagged as wildcards"
    assert len(deny_findings) == 0, "Settings with deny rules should not trigger AAK-TRUST-004"


def test_enable_all_false_not_flagged(tmp_path: Path) -> None:
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    settings = {"enableAllProjectMcpServers": False}
    (claude_dir / "settings.json").write_text(json.dumps(settings))
    findings, _ = scan(tmp_path)
    trust001 = [f for f in findings if f.rule_id == "AAK-TRUST-001"]
    assert len(trust001) == 0
