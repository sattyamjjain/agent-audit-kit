from __future__ import annotations

from pathlib import Path

from agent_audit_kit.scanners.hook_injection import scan


def test_vulnerable_settings_triggers_hook_rules(vulnerable_settings_project: Path) -> None:
    findings, _ = scan(vulnerable_settings_project)
    rule_ids = {f.rule_id for f in findings}

    assert "AAK-HOOK-001" in rule_ids, "Should detect network-capable hook (curl, wget, nc)"
    assert "AAK-HOOK-002" in rule_ids, "Should detect credential exfiltration ($ANTHROPIC_API_KEY)"
    assert "AAK-HOOK-003" in rule_ids, "Should detect write outside project (/tmp/)"
    assert "AAK-HOOK-004" in rule_ids, "Should detect suspicious lifecycle hooks"
    assert "AAK-HOOK-005" in rule_ids, "Should detect base64 operations"
    assert "AAK-HOOK-006" in rule_ids, "Should detect privilege escalation (sudo)"
    assert "AAK-HOOK-007" in rule_ids, "Should detect excessive hook count"
    assert "AAK-HOOK-008" in rule_ids, "Should detect obfuscated payload (hex encoding)"


def test_clean_settings_produces_zero_findings(clean_settings_project: Path) -> None:
    findings, _ = scan(clean_settings_project)
    assert len(findings) == 0, f"Clean settings should produce zero findings, got: {[f.rule_id for f in findings]}"


def test_empty_settings(tmp_path: Path) -> None:
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / "settings.json").write_text("{}")
    findings, _ = scan(tmp_path)
    assert len(findings) == 0


def test_malformed_settings(tmp_path: Path) -> None:
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / "settings.json").write_text("{invalid json!!")
    findings, _ = scan(tmp_path)
    assert len(findings) == 0


def test_formatting_hooks_not_flagged(tmp_path: Path) -> None:
    """Hooks that only run formatting tools should not trigger AAK-HOOK-004."""
    import json
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    settings = {
        "hooks": {
            "PreToolUse": [
                {"command": "prettier --check ."},
                {"command": "eslint --fix src/"}
            ]
        }
    }
    (claude_dir / "settings.json").write_text(json.dumps(settings))
    findings, _ = scan(tmp_path)
    lifecycle_findings = [f for f in findings if f.rule_id == "AAK-HOOK-004"]
    assert len(lifecycle_findings) == 0, "Formatting tools on lifecycle events should not be flagged"


def test_very_long_command_flagged(tmp_path: Path) -> None:
    """Commands > 500 chars should trigger AAK-HOOK-008."""
    import json
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    long_cmd = "echo " + "A" * 600
    settings = {
        "hooks": {
            "AfterEdit": [{"command": long_cmd}]
        }
    }
    (claude_dir / "settings.json").write_text(json.dumps(settings))
    findings, _ = scan(tmp_path)
    obfuscation_findings = [f for f in findings if f.rule_id == "AAK-HOOK-008"]
    assert len(obfuscation_findings) > 0, "Very long commands should be flagged as obfuscated"
