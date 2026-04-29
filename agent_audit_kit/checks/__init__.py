"""Runtime checks importable from CI for live parity / drift assertions
+ path / role guards.

Pairs with the static SAST rules (e.g. AAK-PROJECT-DEAL-DRIFT-001,
AAK-LANGCHAIN-PROMPT-LOADER-PATH-001) so consumers can assert at-test
or runtime what the rule warns about at-scan-time. Calling the helper
in the same function as the SAST sink suppresses the rule.
"""
from __future__ import annotations

from pathlib import Path


class PathOutsideRootError(ValueError):
    """Raised when a path resolves outside the configured root."""


def path_under_root(path: str | Path, root: str | Path) -> Path:
    """Return the resolved Path iff it lives under `root`; raise
    PathOutsideRootError otherwise.

    Used by AAK-LANGCHAIN-PROMPT-LOADER-PATH-001 (CVE-2026-34070) and
    AAK-CREWAI-CVE-2026-2285-001 to anchor prompt / loader paths.
    """
    root_resolved = Path(root).resolve()
    try:
        target = Path(path).resolve()
    except (OSError, ValueError) as exc:
        raise PathOutsideRootError(f"unresolvable path {path!r}") from exc
    try:
        target.relative_to(root_resolved)
    except ValueError as exc:
        raise PathOutsideRootError(
            f"{target} escapes allowed root {root_resolved}"
        ) from exc
    return target


__all__ = ["PathOutsideRootError", "path_under_root"]
