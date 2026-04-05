"""Tests for agent_audit_kit.fix module."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from agent_audit_kit.fix import (
    FixAction,
    _apply_fix,
    _fix_enable_all_mcp,
    _fix_env_gitignore,
    _fix_missing_allowlist,
    _fix_missing_deny,
    _write_fix_log,
    run_fixes,
)
from agent_audit_kit.models import Category, Finding, ScanResult, Severity
from agent_audit_kit.rules.builtin import RuleDefinition


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _setup_fixable_scan(
    tmp_path: Path,
    rule_id: str,
    file_path: str,
    auto_fixable: bool = True,
) -> tuple[ScanResult, dict]:
    """Build a mock ScanResult and RULES dict for a single finding."""
    finding = Finding(
        rule_id=rule_id,
        title="Test",
        description="Test",
        severity=Severity.CRITICAL,
        category=Category.TRUST_BOUNDARY,
        file_path=file_path,
    )
    mock_rules = {
        rule_id: RuleDefinition(
            rule_id=rule_id,
            title="T",
            description="D",
            severity=Severity.CRITICAL,
            category=Category.TRUST_BOUNDARY,
            remediation="R",
            auto_fixable=auto_fixable,
        ),
    }
    return ScanResult(findings=[finding]), mock_rules


# ---------------------------------------------------------------------------
# _fix_enable_all_mcp
# ---------------------------------------------------------------------------


class TestFixEnableAllMcp:
    def test_sets_flag_to_false(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "settings.json"
        cfg_file.write_text(json.dumps({"enableAllProjectMcpServers": True}))

        fix = _fix_enable_all_mcp(cfg_file, dry_run=False)
        assert fix.applied is True
        assert fix.rule_id == "AAK-TRUST-001"

        data = json.loads(cfg_file.read_text())
        assert data["enableAllProjectMcpServers"] is False

    def test_dry_run_does_not_modify(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "settings.json"
        original = json.dumps({"enableAllProjectMcpServers": True})
        cfg_file.write_text(original)

        fix = _fix_enable_all_mcp(cfg_file, dry_run=True)
        assert fix.applied is False
        assert cfg_file.read_text() == original

    def test_malformed_json_returns_failed_action(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "settings.json"
        cfg_file.write_text("{bad json}")

        fix = _fix_enable_all_mcp(cfg_file, dry_run=False)
        assert fix.applied is False
        assert "Failed" in fix.description


# ---------------------------------------------------------------------------
# _fix_env_gitignore
# ---------------------------------------------------------------------------


class TestFixEnvGitignore:
    def test_adds_env_to_gitignore(self, tmp_path: Path) -> None:
        (tmp_path / ".gitignore").write_text("node_modules/\n")

        fix = _fix_env_gitignore(tmp_path, dry_run=False)
        assert fix.applied is True
        assert fix.rule_id == "AAK-SECRET-006"

        content = (tmp_path / ".gitignore").read_text()
        assert ".env" in content

    def test_creates_gitignore_if_missing(self, tmp_path: Path) -> None:
        fix = _fix_env_gitignore(tmp_path, dry_run=False)
        assert fix.applied is True
        assert (tmp_path / ".gitignore").exists()
        assert ".env" in (tmp_path / ".gitignore").read_text()

    def test_dry_run_does_not_create_gitignore(self, tmp_path: Path) -> None:
        fix = _fix_env_gitignore(tmp_path, dry_run=True)
        assert fix.applied is False

    def test_skips_if_env_already_in_gitignore(self, tmp_path: Path) -> None:
        (tmp_path / ".gitignore").write_text(".env\nnode_modules/\n")
        original = (tmp_path / ".gitignore").read_text()

        fix = _fix_env_gitignore(tmp_path, dry_run=False)
        assert fix.applied is True
        assert (tmp_path / ".gitignore").read_text() == original


# ---------------------------------------------------------------------------
# _write_fix_log
# ---------------------------------------------------------------------------


class TestWriteFixLog:
    def test_creates_log_file(self, tmp_path: Path) -> None:
        fixes = [
            FixAction("AAK-TRUST-001", "file.json", "Fixed trust", applied=True),
            FixAction("AAK-SECRET-006", ".gitignore", "Fixed env", applied=True),
        ]
        _write_fix_log(tmp_path, fixes)

        log_file = tmp_path / ".agent-audit-kit" / "fix-log.json"
        assert log_file.exists()

        log = json.loads(log_file.read_text())
        assert "timestamp" in log
        assert len(log["fixes_applied"]) == 2
        assert log["fixes_applied"][0]["rule_id"] == "AAK-TRUST-001"

    def test_only_logs_applied_fixes(self, tmp_path: Path) -> None:
        fixes = [
            FixAction("AAK-TRUST-001", "file.json", "Applied", applied=True),
            FixAction("AAK-SECRET-006", ".gitignore", "Dry run", applied=False),
        ]
        _write_fix_log(tmp_path, fixes)

        log_file = tmp_path / ".agent-audit-kit" / "fix-log.json"
        log = json.loads(log_file.read_text())
        assert len(log["fixes_applied"]) == 1


# ---------------------------------------------------------------------------
# _apply_fix
# ---------------------------------------------------------------------------


class TestApplyFix:
    def test_trust_001_dispatches_correctly(self, tmp_path: Path) -> None:
        cfg = tmp_path / "settings.json"
        cfg.write_text(json.dumps({"enableAllProjectMcpServers": True}))

        fix = _apply_fix(tmp_path, "AAK-TRUST-001", "settings.json", dry_run=False)
        assert fix is not None
        assert fix.rule_id == "AAK-TRUST-001"
        assert fix.applied is True

    def test_secret_006_dispatches_correctly(self, tmp_path: Path) -> None:
        (tmp_path / ".gitignore").write_text("node_modules/\n")
        fix = _apply_fix(tmp_path, "AAK-SECRET-006", ".gitignore", dry_run=False)
        assert fix is not None
        assert fix.rule_id == "AAK-SECRET-006"

    def test_trust_004_dispatches_correctly(self, tmp_path: Path) -> None:
        cfg = tmp_path / "settings.json"
        cfg.write_text(json.dumps({"permissions": {"allow": ["*"]}}))

        fix = _apply_fix(tmp_path, "AAK-TRUST-004", "settings.json", dry_run=False)
        assert fix is not None
        assert fix.rule_id == "AAK-TRUST-004"
        assert fix.applied is True

    def test_trust_007_dispatches_correctly(self, tmp_path: Path) -> None:
        cfg = tmp_path / "settings.json"
        cfg.write_text(json.dumps({"other": "data"}))

        fix = _apply_fix(tmp_path, "AAK-TRUST-007", "settings.json", dry_run=False)
        assert fix is not None
        assert fix.rule_id == "AAK-TRUST-007"
        assert fix.applied is True

    def test_unknown_rule_returns_none(self, tmp_path: Path) -> None:
        cfg = tmp_path / "somefile.json"
        cfg.write_text("{}")
        fix = _apply_fix(tmp_path, "AAK-UNKNOWN-999", "somefile.json", dry_run=False)
        assert fix is None

    def test_missing_file_returns_none(self, tmp_path: Path) -> None:
        fix = _apply_fix(tmp_path, "AAK-TRUST-001", "nonexistent.json", dry_run=False)
        assert fix is None


# ---------------------------------------------------------------------------
# run_fixes
# ---------------------------------------------------------------------------


class TestRunFixes:
    def test_dry_run_creates_fix_actions_without_modifying_files(
        self, tmp_path: Path
    ) -> None:
        """run_fixes with dry_run=True creates FixAction objects but doesn't modify files."""
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings = {"enableAllProjectMcpServers": True}
        settings_file = claude_dir / "settings.json"
        settings_file.write_text(json.dumps(settings))
        original_content = settings_file.read_text()

        result, mock_rules = _setup_fixable_scan(
            tmp_path, "AAK-TRUST-001", str(settings_file)
        )

        with patch("agent_audit_kit.fix.run_scan") as mock_scan, patch(
            "agent_audit_kit.fix.RULES", mock_rules
        ):
            mock_scan.return_value = result
            fixes = run_fixes(tmp_path, dry_run=True)

        assert len(fixes) > 0
        for fix in fixes:
            assert isinstance(fix, FixAction)
            assert fix.applied is False

        # File should be unchanged
        assert settings_file.read_text() == original_content
        # No fix-log should be written
        assert not (tmp_path / ".agent-audit-kit" / "fix-log.json").exists()

    def test_fixing_trust_001_sets_enable_all_false(self, tmp_path: Path) -> None:
        """Fixing AAK-TRUST-001 sets enableAllProjectMcpServers to false."""
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings_file = claude_dir / "settings.json"
        settings_file.write_text(
            json.dumps({"enableAllProjectMcpServers": True})
        )

        result, mock_rules = _setup_fixable_scan(
            tmp_path, "AAK-TRUST-001", str(settings_file)
        )

        with patch("agent_audit_kit.fix.run_scan") as mock_scan, patch(
            "agent_audit_kit.fix.RULES", mock_rules
        ):
            mock_scan.return_value = result
            fixes = run_fixes(tmp_path, dry_run=False)

        assert any(f.rule_id == "AAK-TRUST-001" and f.applied for f in fixes)
        data = json.loads(settings_file.read_text())
        assert data["enableAllProjectMcpServers"] is False

    def test_fixing_secret_006_adds_env_to_gitignore(self, tmp_path: Path) -> None:
        """Fixing AAK-SECRET-006 adds .env to .gitignore."""
        gitignore = tmp_path / ".gitignore"
        gitignore.write_text("node_modules/\n")

        result, mock_rules = _setup_fixable_scan(
            tmp_path, "AAK-SECRET-006", ".gitignore"
        )

        with patch("agent_audit_kit.fix.run_scan") as mock_scan, patch(
            "agent_audit_kit.fix.RULES", mock_rules
        ):
            mock_scan.return_value = result
            fixes = run_fixes(tmp_path, dry_run=False)

        assert any(f.rule_id == "AAK-SECRET-006" and f.applied for f in fixes)
        content = gitignore.read_text()
        assert ".env" in content

    def test_fix_log_json_is_created(self, tmp_path: Path) -> None:
        """Fix log JSON file is created when fixes are applied."""
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings_file = claude_dir / "settings.json"
        settings_file.write_text(
            json.dumps({"enableAllProjectMcpServers": True})
        )

        result, mock_rules = _setup_fixable_scan(
            tmp_path, "AAK-TRUST-001", str(settings_file)
        )

        with patch("agent_audit_kit.fix.run_scan") as mock_scan, patch(
            "agent_audit_kit.fix.RULES", mock_rules
        ):
            mock_scan.return_value = result
            run_fixes(tmp_path, dry_run=False)

        log_file = tmp_path / ".agent-audit-kit" / "fix-log.json"
        assert log_file.exists()
        log = json.loads(log_file.read_text())
        assert "timestamp" in log
        assert "fixes_applied" in log
        assert len(log["fixes_applied"]) >= 1

    def test_empty_project_no_fixable_findings_returns_empty(
        self, tmp_path: Path
    ) -> None:
        """Empty project (no fixable findings) returns empty list."""
        result = ScanResult(findings=[])

        with patch("agent_audit_kit.fix.run_scan") as mock_scan, patch(
            "agent_audit_kit.fix.RULES", {}
        ):
            mock_scan.return_value = result
            fixes = run_fixes(tmp_path, dry_run=False)

        assert fixes == []
        assert not (tmp_path / ".agent-audit-kit" / "fix-log.json").exists()


# ---------------------------------------------------------------------------
# _fix_missing_deny
# ---------------------------------------------------------------------------


class TestFixMissingDeny:
    def test_adds_deny_rules(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "settings.json"
        cfg_file.write_text(json.dumps({"permissions": {"allow": ["*"]}}))

        fix = _fix_missing_deny(cfg_file, dry_run=False)
        assert fix.applied is True
        assert fix.rule_id == "AAK-TRUST-004"

        data = json.loads(cfg_file.read_text())
        assert "deny" in data["permissions"]
        assert len(data["permissions"]["deny"]) > 0

    def test_dry_run_does_not_modify(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "settings.json"
        original = json.dumps({"permissions": {"allow": ["*"]}})
        cfg_file.write_text(original)

        fix = _fix_missing_deny(cfg_file, dry_run=True)
        assert fix.applied is False
        assert cfg_file.read_text() == original

    def test_skips_if_deny_already_present(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "settings.json"
        cfg_file.write_text(json.dumps({
            "permissions": {"allow": ["*"], "deny": ["Bash(rm -rf *)"]}
        }))
        original = cfg_file.read_text()

        fix = _fix_missing_deny(cfg_file, dry_run=False)
        assert fix.rule_id == "AAK-TRUST-004"
        # File should remain unchanged since deny already exists
        assert cfg_file.read_text() == original

    def test_creates_permissions_if_missing(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "settings.json"
        cfg_file.write_text(json.dumps({"other": "data"}))

        fix = _fix_missing_deny(cfg_file, dry_run=False)
        assert fix.applied is True

        data = json.loads(cfg_file.read_text())
        assert "permissions" in data
        assert "deny" in data["permissions"]

    def test_malformed_json_returns_failed(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "settings.json"
        cfg_file.write_text("{invalid")

        fix = _fix_missing_deny(cfg_file, dry_run=False)
        assert fix.applied is False
        assert "Failed" in fix.description


# ---------------------------------------------------------------------------
# _fix_missing_allowlist
# ---------------------------------------------------------------------------


class TestFixMissingAllowlist:
    def test_adds_enabled_mcp_servers(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "settings.json"
        cfg_file.write_text(json.dumps({"other": "data"}))

        fix = _fix_missing_allowlist(cfg_file, dry_run=False)
        assert fix.applied is True
        assert fix.rule_id == "AAK-TRUST-007"

        data = json.loads(cfg_file.read_text())
        assert "enabledMcpjsonServers" in data
        assert data["enabledMcpjsonServers"] == []

    def test_dry_run_does_not_modify(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "settings.json"
        original = json.dumps({"other": "data"})
        cfg_file.write_text(original)

        fix = _fix_missing_allowlist(cfg_file, dry_run=True)
        assert fix.applied is False
        assert cfg_file.read_text() == original

    def test_skips_if_allowlist_already_present(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "settings.json"
        cfg_file.write_text(json.dumps({"enabledMcpjsonServers": ["server1"]}))
        original = cfg_file.read_text()

        fix = _fix_missing_allowlist(cfg_file, dry_run=False)
        assert fix.rule_id == "AAK-TRUST-007"
        # File should remain unchanged
        assert cfg_file.read_text() == original

    def test_malformed_json_returns_failed(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "settings.json"
        cfg_file.write_text("{invalid")

        fix = _fix_missing_allowlist(cfg_file, dry_run=False)
        assert fix.applied is False
        assert "Failed" in fix.description
