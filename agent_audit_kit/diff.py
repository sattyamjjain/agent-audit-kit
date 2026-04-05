from __future__ import annotations

import subprocess
from pathlib import Path

from agent_audit_kit.models import ScanResult


def get_changed_files(project_root: Path, base_ref: str = "HEAD~1") -> set[str]:
    """Return set of file paths changed relative to a git base ref.

    Uses ``git diff --name-only`` to determine which files have been
    modified. Returns an empty set on any git error or timeout.

    Args:
        project_root: Root directory of the git repository.
        base_ref: Git reference to diff against (default: HEAD~1).

    Returns:
        A set of relative file path strings that have changed.
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", base_ref],
            cwd=str(project_root),
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return set()
        return {line.strip() for line in result.stdout.splitlines() if line.strip()}
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return set()


def filter_by_diff(
    scan_result: ScanResult,
    project_root: Path,
    base_ref: str = "HEAD~1",
) -> ScanResult:
    """Filter a ScanResult to only include findings in changed files.

    Creates a new ScanResult containing only findings whose file_path
    appears in the git diff. If no changed files are detected (e.g.
    not a git repo), returns the original result unmodified.

    Args:
        scan_result: The full scan result to filter.
        project_root: Root directory of the git repository.
        base_ref: Git reference to diff against (default: HEAD~1).

    Returns:
        A new ScanResult with findings filtered to changed files, or
        the original ScanResult if no changed files were found.
    """
    changed = get_changed_files(project_root, base_ref)
    if not changed:
        return scan_result

    filtered = ScanResult(
        files_scanned=scan_result.files_scanned,
        rules_evaluated=scan_result.rules_evaluated,
        scan_duration_ms=scan_result.scan_duration_ms,
        score=scan_result.score,
        grade=scan_result.grade,
    )
    filtered.findings = [f for f in scan_result.findings if f.file_path in changed]
    return filtered
