"""Tests for agent_audit_kit.fix module."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from unittest.mock import patch

import agent_audit_kit
from agent_audit_kit.fix import (
    FixAction,
    _apply_fix,
    _fix_enable_all_mcp,
    _fix_env_gitignore,
    _fix_litellm_version,
    _fix_missing_allowlist,
    _fix_missing_deny,
    _fix_secret_env_ref,
    _write_fix_log,
    _write_inside_project,
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


class TestFixEnvGitignoreAgreesWithTheRule:
    """`aak fix` judged coverage with a substring test after AAK-SECRET-006 stopped
    doing so: with `!.env.example`, `# .env` or `.envrc` in `.gitignore`, or `.env.local`
    beside a `.env` pattern, it reported the finding fixed and wrote nothing."""

    @pytest.mark.parametrize(
        "gitignore", ["!.env.example\n", "# .env\n", ".envrc\n", ".env\n", "  .env\n", "node_modules/\n"]
    )
    def test_run_fixes_leaves_no_env_file_unignored(self, tmp_path: Path, gitignore: str) -> None:
        from agent_audit_kit.scanners.secret_exposure import scan as secret_scan

        (tmp_path / ".env").write_text("A=1\n")
        (tmp_path / ".env.local").write_text("A=1\n")
        (tmp_path / ".gitignore").write_text(gitignore)
        assert [f for f in secret_scan(tmp_path)[0] if f.rule_id == "AAK-SECRET-006"]

        fixes = [f for f in run_fixes(tmp_path) if f.rule_id == "AAK-SECRET-006"]

        assert fixes and all(f.applied for f in fixes)
        assert [f for f in secret_scan(tmp_path)[0] if f.rule_id == "AAK-SECRET-006"] == []

    def test_a_template_the_gitignore_takes_back_stays_committable(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("A=1\n")
        (tmp_path / ".env.example").write_text("A=\n")
        (tmp_path / ".gitignore").write_text("!.env.example\n")

        run_fixes(tmp_path)

        from agent_audit_kit.scanners.secret_exposure import _gitignore_ignores, _gitignore_rules

        rules = _gitignore_rules((tmp_path / ".gitignore").read_text())
        assert _gitignore_ignores(rules, ".env")
        assert not _gitignore_ignores(rules, ".env.example")

    def test_a_gitignore_that_already_ignores_every_env_file_is_left_alone(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("A=1\n")
        (tmp_path / ".gitignore").write_text(".env*\n")

        fix = _fix_env_gitignore(tmp_path, dry_run=False)

        assert fix.applied is True
        assert (tmp_path / ".gitignore").read_text() == ".env*\n"

    def test_the_fix_appends_to_the_whole_gitignore_and_keeps_every_byte(self, tmp_path: Path) -> None:
        """The fix rewrote `.gitignore` from the scanner's read, bounded to 1,000,000 bytes
        and decoded with replacement, so a longer file lost its tail and a byte that is
        not UTF-8 came back as U+FFFD."""
        (tmp_path / ".env").write_text("A=1\n")
        (tmp_path / ".env.example").write_text("A=\n")
        original = b"# caf\xe9\n" + b"# filler line\n" * 80_000 + b"build/\n!.env.example\n"
        (tmp_path / ".gitignore").write_bytes(original)

        fix = _fix_env_gitignore(tmp_path, dry_run=False)

        assert fix.applied is True
        written = (tmp_path / ".gitignore").read_bytes()
        assert written == original + b"\n# Environment files\n.env\n.env.*\n!.env.example\n"

    @pytest.mark.parametrize(
        "original",
        [b"node_modules/\nsecret\\ \n", b"node_modules/\nsecret\t\n", b"node_modules/\nsecret\\ ", b"secret\t"],
    )
    def test_the_fix_leaves_the_last_line_as_it_was(self, tmp_path: Path, original: bytes) -> None:
        """`rstrip()` before appending turned `secret\\ ` into `secret\\` and `secret<tab>`
        into `secret`, which changes what git ignores. Only a missing newline is added."""
        (tmp_path / ".env").write_text("A=1\n")
        (tmp_path / ".gitignore").write_bytes(original)

        assert _fix_env_gitignore(tmp_path, dry_run=False).applied is True

        separator = b"\n" if original.endswith(b"\n") else b"\n\n"
        assert (tmp_path / ".gitignore").read_bytes() == original + separator + b"# Environment files\n.env\n.env.*\n"


# A child process runs the fix, so a write that blocks on a FIFO fails the test on its
# timeout instead of hanging the suite.
_CHILD = (
    "import sys\n"
    "from pathlib import Path\n"
    "from agent_audit_kit.fix import _fix_env_gitignore, _write_inside_project\n"
    "root = Path(sys.argv[1])\n"
    "if sys.argv[2] == 'fix':\n"
    "    print(_fix_env_gitignore(root, dry_run=False).description)\n"
    "else:\n"
    "    print(_write_inside_project(root / '.gitignore', b'x\\n', root, mode='append'))\n"
)


def _run_in_child(project: Path, what: str) -> str:
    package_root = Path(agent_audit_kit.__file__).resolve().parent.parent
    env = {**os.environ, "PYTHONPATH": str(package_root)}
    done = subprocess.run(
        [sys.executable, "-c", _CHILD, str(project), what], capture_output=True, text=True, timeout=30, env=env
    )
    assert done.returncode == 0, done.stderr
    return done.stdout.strip()


class TestFixEnvGitignoreWritesOnlyInsideTheProject:
    """A scanned repository controls its `.gitignore` and the env file names that make the
    fix run. Written through `Path.write_text`, a `.gitignore` linked to a file outside the
    project had the fix's lines appended to that file, a dangling link created it, and a
    FIFO named `.gitignore` blocked `aak fix` forever."""

    def _project(self, tmp_path: Path) -> Path:
        project = tmp_path / "proj"
        project.mkdir()
        (project / ".env").write_text("A=1\n")
        return project

    def test_a_symlinked_gitignore_is_refused_and_its_target_left_alone(self, tmp_path: Path) -> None:
        project = self._project(tmp_path)
        outside = tmp_path / "outside.txt"
        outside.write_bytes(b"do not touch\n")
        (project / ".gitignore").symlink_to(outside)

        fix = _fix_env_gitignore(project, dry_run=False)

        assert fix.applied is False and fix.description.startswith("Failed to fix: ")
        assert outside.read_bytes() == b"do not touch\n"

    def test_a_dangling_symlink_creates_nothing(self, tmp_path: Path) -> None:
        project = self._project(tmp_path)
        target = tmp_path / "created-by-fix.txt"
        (project / ".gitignore").symlink_to(target)

        fix = _fix_env_gitignore(project, dry_run=False)

        assert fix.applied is False and fix.description.startswith("Failed to fix: ")
        assert not target.exists()

    def test_a_directory_named_gitignore_is_refused(self, tmp_path: Path) -> None:
        project = self._project(tmp_path)
        (project / ".gitignore").mkdir()

        fix = _fix_env_gitignore(project, dry_run=False)

        assert fix.applied is False and fix.description.startswith("Failed to fix: ")

    def test_a_dry_run_reports_the_refusal_too(self, tmp_path: Path) -> None:
        project = self._project(tmp_path)
        (project / ".gitignore").symlink_to(tmp_path / "elsewhere")

        assert _fix_env_gitignore(project, dry_run=True).description.startswith("Failed to fix: ")

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs POSIX FIFOs")
    def test_a_fifo_named_gitignore_is_refused_without_blocking(self, tmp_path: Path) -> None:
        project = self._project(tmp_path)
        os.mkfifo(project / ".gitignore")

        assert _run_in_child(project, "fix").startswith("Failed to fix: ")


class TestWriteInsideProject:
    """The one write path `aak fix` should use: a regular file, or a missing one, whose path
    and directory resolve inside the project, opened without following a link. It returns
    None once written, or the reason it refused, and never raises for a refusal."""

    def test_it_appends_replaces_and_creates(self, tmp_path: Path) -> None:
        target = tmp_path / "notes.txt"
        target.write_bytes(b"a\n")

        assert _write_inside_project(target, b"b\n", tmp_path, mode="append") is None
        assert target.read_bytes() == b"a\nb\n"
        assert _write_inside_project(target, b"c\n", tmp_path, mode="replace") is None
        assert target.read_bytes() == b"c\n"
        assert _write_inside_project(tmp_path / "new.txt", b"d\n", tmp_path, mode="append") is None
        assert (tmp_path / "new.txt").read_bytes() == b"d\n"

    def test_it_refuses_a_symlink_even_to_a_file_inside(self, tmp_path: Path) -> None:
        (tmp_path / "real.txt").write_bytes(b"keep\n")
        (tmp_path / "link.txt").symlink_to(tmp_path / "real.txt")

        reason = _write_inside_project(tmp_path / "link.txt", b"x\n", tmp_path, mode="replace")

        assert reason is not None and "symlink" in reason
        assert (tmp_path / "real.txt").read_bytes() == b"keep\n"

    def test_it_refuses_a_path_under_a_symlinked_directory(self, tmp_path: Path) -> None:
        project = tmp_path / "proj"
        project.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (project / "sub").symlink_to(outside, target_is_directory=True)

        reason = _write_inside_project(project / "sub" / "settings.json", b"{}\n", project, mode="replace")

        assert reason is not None and "outside the project" in reason
        assert not (outside / "settings.json").exists()

    def test_it_refuses_a_path_outside_the_project(self, tmp_path: Path) -> None:
        project = tmp_path / "proj"
        project.mkdir()

        reason = _write_inside_project(project / ".." / "escaped.txt", b"x\n", project, mode="replace")

        assert reason is not None and "outside the project" in reason
        assert not (tmp_path / "escaped.txt").exists()

    def test_it_refuses_a_directory(self, tmp_path: Path) -> None:
        (tmp_path / "folder").mkdir()

        reason = _write_inside_project(tmp_path / "folder", b"x\n", tmp_path, mode="append")

        assert reason is not None and "not a regular file" in reason

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs POSIX FIFOs")
    def test_it_refuses_a_fifo_without_blocking(self, tmp_path: Path) -> None:
        os.mkfifo(tmp_path / ".gitignore")

        assert "not a regular file" in _run_in_child(tmp_path, "helper")


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


class TestRequirementPinRewrite:
    def test_blank_lines_and_indentation_are_kept(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("click\n\n\n  litellm == 1.80.0\nrequests\n", encoding="utf-8")
        assert _fix_litellm_version(req, dry_run=False).applied
        assert req.read_text(encoding="utf-8") == "click\n\n\n  litellm>=1.83.7\nrequests\n"

    def test_a_crafted_requirements_file_rewrites_in_linear_time(self, tmp_path: Path) -> None:
        """1 MB of blank lines with no pin after them, then a name and 1 MB of
        blanks with no version. `^\\s*` started at every blank line and read to
        the end of the run (40,000 took 4.3 seconds), and the blanks around the
        optional operator were split every way (20,000 took 1 second); both
        grew with the square. The bound is loose for slow CI runners."""
        req = tmp_path / "requirements.txt"
        req.write_text("\n" * 1_000_000 + "x\nlitellm" + " " * 1_000_000 + "x\n", encoding="utf-8")
        started = time.perf_counter()
        _fix_litellm_version(req, dry_run=False)
        assert time.perf_counter() - started < 5.0


# ---------------------------------------------------------------------------
# AAK-SECRET-007: the env reference goes back into the map the server came from
# ---------------------------------------------------------------------------


class TestFixSecretEnvRef:
    def test_a_vscode_server_gets_an_env_reference_in_its_own_map(self, tmp_path: Path) -> None:
        """VS Code substitutes `${env:KEY}`; a bare `${KEY}` would reach the server as
        written. The server stays under `servers`, and no `mcpServers` key appears."""
        path = tmp_path / ".vscode" / "mcp.json"
        path.parent.mkdir()
        path.write_text(json.dumps({
            "servers": {"gh": {"command": "npx", "env": {"GITHUB_TOKEN": "literal-value"}}},
        }))
        action = _fix_secret_env_ref(path, dry_run=False)
        assert action is not None and action.applied
        data = json.loads(path.read_text())
        assert data == {
            "servers": {"gh": {"command": "npx", "env": {"GITHUB_TOKEN": "${env:GITHUB_TOKEN}"}}},
        }
        from agent_audit_kit.scanners.secret_exposure import scan as secret_scan
        assert not [f for f in secret_scan(tmp_path)[0] if f.rule_id == "AAK-SECRET-007"]

    def test_each_map_keeps_its_servers_and_its_own_form(self, tmp_path: Path) -> None:
        path = tmp_path / "mcp.json"
        path.write_text(json.dumps({
            "mcpServers": {"a": {"env": {"API_KEY": "one"}}},
            "servers": {"b": {"env": {"API_KEY": "two"}}},
        }))
        assert _fix_secret_env_ref(path, dry_run=False) is not None
        assert json.loads(path.read_text()) == {
            "mcpServers": {"a": {"env": {"API_KEY": "${API_KEY}"}}},
            "servers": {"b": {"env": {"API_KEY": "${env:API_KEY}"}}},
        }

    def test_a_jsonc_config_is_left_alone(self, tmp_path: Path) -> None:
        """Writing a JSONC file back through `json.dumps` would delete its comments."""
        path = tmp_path / "mcp.json"
        text = '{\n  // keep this\n  "servers": {"b": {"env": {"API_KEY": "two"}}}\n}\n'
        path.write_text(text)
        assert _fix_secret_env_ref(path, dry_run=False) is None
        assert path.read_text() == text
