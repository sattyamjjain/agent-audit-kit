from __future__ import annotations

import dataclasses
import subprocess
from pathlib import Path

from agent_audit_kit.models import Finding, ScanResult

_GIT_TIMEOUT_SECONDS = 30

# Findings about the run itself rather than about a file. The scanner-failure
# finding is filed against the pseudo-path "<scanner>", which is never in a git
# diff, so a path filter drops it -- and `ScanResult.scanner_failures` is derived
# from the findings, so `scan --diff` then exited 0 on a run in which a scanner
# had crashed, which is exactly what #743 exists to prevent.
_INTERNAL_RULE_PREFIX = "AAK-INTERNAL-"


def _git_paths(args: list[str], cwd: Path) -> set[str] | None:
    """Run a NUL-delimited git listing; ``None`` when git cannot answer.

    ``-z`` output is used so a path git would otherwise quote (non-ASCII, a
    double quote, a control character) comes back exactly as the scanners
    record it rather than as a C-style escaped string that matches nothing.
    """
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT_SECONDS,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    if proc.returncode != 0:
        return None
    return {name for name in proc.stdout.split("\0") if name}


def _changed_paths(project_root: Path, base_ref: str) -> set[str] | None:
    """Paths changed since ``base_ref``, relative to ``project_root``.

    ``None`` means git could not answer (not a repository, an unknown ref, git
    missing, a timeout). An empty set means it answered and nothing under
    ``project_root`` changed. The two used to be the same value, which made a
    clean tree report every finding.
    """
    # --relative: paths come back relative to cwd (the scanned directory, which
    # is how findings record them) and changes outside it are left out. Without
    # it git prints repo-root paths, so scanning a subdirectory matched nothing
    # and dropped every finding. --end-of-options keeps a ref that starts with
    # "-" from being read as an option; "--" keeps it from being read as a path.
    changed = _git_paths(
        ["diff", "--name-only", "--relative", "--no-color", "-z",
         "--end-of-options", base_ref, "--"],
        project_root,
    )
    if changed is None:
        return None
    # A new file nobody has run `git add` on yet is a change too, but it is in
    # no diff. --exclude-standard leaves gitignored files out.
    untracked = _git_paths(["ls-files", "-z", "--others", "--exclude-standard"], project_root)
    return changed | (untracked or set())


def get_changed_files(project_root: Path, base_ref: str = "HEAD~1") -> set[str]:
    """Return the paths changed since a git base ref, relative to ``project_root``.

    A path counts as changed when ``git diff`` against ``base_ref`` lists it
    (tracked files, staged or not) or when it is untracked and not gitignored.
    Paths are relative to ``project_root`` even when it is a subdirectory of
    the repository, and changes outside it are not included.

    Returns an empty set when git cannot answer: ``project_root`` is not in a
    repository, ``base_ref`` does not resolve, git is not installed, or it
    takes longer than 30 seconds.

    Args:
        project_root: The scanned directory, the repository root or any
            directory inside it.
        base_ref: Git reference to diff against (default: HEAD~1).

    Returns:
        A set of relative file path strings that have changed.
    """
    return _changed_paths(project_root, base_ref) or set()


def _describes_the_run(finding: Finding) -> bool:
    """True for findings no changed-file filter may drop."""
    return finding.rule_id.startswith(_INTERNAL_RULE_PREFIX) or finding.file_path.startswith("<")


def filter_by_diff(
    scan_result: ScanResult,
    project_root: Path,
    base_ref: str = "HEAD~1",
) -> ScanResult:
    """Filter a ScanResult to the findings in files changed since ``base_ref``.

    Findings about the run rather than a file (``AAK-INTERNAL-*``, or a
    pseudo-path such as ``<scanner>``) are always kept, so a scanner crash
    still ends the run as INCOMPLETE under ``--diff``.

    When git cannot answer (not a repository, an unknown ref, git missing, a
    timeout) the original result is returned unfiltered, as it always has
    been. When git answers that nothing under ``project_root`` changed, every
    file-level finding is dropped: a scan of an unchanged directory has
    nothing to report under ``--diff``, which matters in a monorepo whose
    pull request touched a sibling package.

    Args:
        scan_result: The full scan result to filter.
        project_root: The scanned directory, the repository root or any
            directory inside it.
        base_ref: Git reference to diff against (default: HEAD~1).

    Returns:
        A copy of ``scan_result`` (every other field preserved) holding only
        the findings that pass the filter, or ``scan_result`` itself when git
        could not answer.
    """
    changed = _changed_paths(project_root, base_ref)
    if changed is None:
        return scan_result
    kept = [f for f in scan_result.findings if f.file_path in changed or _describes_the_run(f)]
    return dataclasses.replace(scan_result, findings=kept)
