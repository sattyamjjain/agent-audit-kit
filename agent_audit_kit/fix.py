from __future__ import annotations

import datetime
import json
from dataclasses import dataclass
from pathlib import Path

from agent_audit_kit.engine import run_scan
from agent_audit_kit.rules.builtin import RULES


@dataclass
class FixAction:
    """Represents an auto-fix action applied (or proposed) for a finding.

    Attributes:
        rule_id: The rule ID that triggered the fix.
        file_path: Path to the file that was fixed.
        description: Human-readable description of the fix.
        applied: Whether the fix was actually applied (False in dry-run).
    """

    rule_id: str
    file_path: str
    description: str
    applied: bool = False


def run_fixes(project_root: Path, dry_run: bool = False) -> list[FixAction]:
    """Run auto-fixes for all fixable findings in a project.

    Performs a scan, identifies findings for rules marked as
    ``auto_fixable``, and applies the corresponding fix logic.
    When fixes are actually applied (not dry-run), a log file is
    written to ``.agent-audit-kit/fix-log.json``.

    Args:
        project_root: The project root directory to scan and fix.
        dry_run: If True, report what would be fixed without modifying
            any files.

    Returns:
        A list of FixAction objects describing what was (or would be)
        fixed.
    """
    result = run_scan(project_root=project_root)
    fixable_rules = {rid for rid, rule in RULES.items() if rule.auto_fixable}
    fixes: list[FixAction] = []

    for finding in result.findings:
        if finding.rule_id not in fixable_rules:
            continue
        fix = _apply_fix(project_root, finding.rule_id, finding.file_path, dry_run)
        if fix:
            fixes.append(fix)

    if not dry_run and fixes:
        _write_fix_log(project_root, fixes)

    return fixes


def _write_fix_log(project_root: Path, fixes: list[FixAction]) -> None:
    """Write a JSON log of applied fixes to .agent-audit-kit/fix-log.json.

    Args:
        project_root: The project root directory.
        fixes: List of FixAction objects that were applied.
    """
    log_dir = project_root / ".agent-audit-kit"
    log_dir.mkdir(exist_ok=True)
    log_file = log_dir / "fix-log.json"

    log_data = {
        "timestamp": datetime.datetime.now().isoformat(),
        "fixes_applied": [
            {
                "rule_id": fix.rule_id,
                "file": fix.file_path,
                "description": fix.description,
            }
            for fix in fixes
            if fix.applied
        ],
    }
    log_file.write_text(json.dumps(log_data, indent=2) + "\n")


def _apply_fix(
    project_root: Path,
    rule_id: str,
    file_path: str,
    dry_run: bool,
) -> FixAction | None:
    """Dispatch to the appropriate fix function for a given rule.

    Args:
        project_root: The project root directory.
        rule_id: The rule ID to fix.
        file_path: Relative path to the file containing the finding.
        dry_run: If True, do not modify files.

    Returns:
        A FixAction if a fix was attempted, or None if not applicable.
    """
    full_path = project_root / file_path
    if not full_path.is_file():
        return None

    if rule_id == "AAK-TRUST-001":
        return _fix_enable_all_mcp(full_path, dry_run)
    elif rule_id == "AAK-TRUST-004":
        return _fix_missing_deny(full_path, dry_run)
    elif rule_id == "AAK-TRUST-007":
        return _fix_missing_allowlist(full_path, dry_run)
    elif rule_id == "AAK-SECRET-006":
        return _fix_env_gitignore(project_root, dry_run)
    return None


def _fix_enable_all_mcp(path: Path, dry_run: bool) -> FixAction:
    """Set enableAllProjectMcpServers to false."""
    try:
        data = json.loads(path.read_text())
        data["enableAllProjectMcpServers"] = False
        if not dry_run:
            path.write_text(json.dumps(data, indent=2) + "\n")
        return FixAction(
            "AAK-TRUST-001",
            str(path),
            "Set enableAllProjectMcpServers to false",
            not dry_run,
        )
    except (json.JSONDecodeError, OSError):
        return FixAction("AAK-TRUST-001", str(path), "Failed to fix", False)


def _fix_missing_deny(path: Path, dry_run: bool) -> FixAction:
    """Add default deny rules to the permissions block."""
    try:
        data = json.loads(path.read_text())
        perms = data.setdefault("permissions", {})
        if not perms.get("deny"):
            perms["deny"] = [
                "Bash(rm -rf *)",
                "Bash(curl *)",
                "Bash(wget *)",
            ]
            if not dry_run:
                path.write_text(json.dumps(data, indent=2) + "\n")
        return FixAction(
            "AAK-TRUST-004",
            str(path),
            "Added default deny rules",
            not dry_run,
        )
    except (json.JSONDecodeError, OSError):
        return FixAction("AAK-TRUST-004", str(path), "Failed to fix", False)


def _fix_missing_allowlist(path: Path, dry_run: bool) -> FixAction:
    """Add an empty enabledMcpjsonServers allowlist."""
    try:
        data = json.loads(path.read_text())
        if "enabledMcpjsonServers" not in data:
            data["enabledMcpjsonServers"] = []
            if not dry_run:
                path.write_text(json.dumps(data, indent=2) + "\n")
        return FixAction(
            "AAK-TRUST-007",
            str(path),
            "Added empty enabledMcpjsonServers allowlist",
            not dry_run,
        )
    except (json.JSONDecodeError, OSError):
        return FixAction("AAK-TRUST-007", str(path), "Failed to fix", False)


def _fix_env_gitignore(project_root: Path, dry_run: bool) -> FixAction:
    """Add .env patterns to .gitignore."""
    gitignore = project_root / ".gitignore"
    try:
        content = gitignore.read_text() if gitignore.is_file() else ""
        if ".env" not in content:
            new_content = content.rstrip() + "\n\n# Environment files\n.env\n.env.*\n"
            if not dry_run:
                gitignore.write_text(new_content)
        return FixAction(
            "AAK-SECRET-006",
            ".gitignore",
            "Added .env patterns to .gitignore",
            not dry_run,
        )
    except OSError:
        return FixAction("AAK-SECRET-006", ".gitignore", "Failed to fix", False)
