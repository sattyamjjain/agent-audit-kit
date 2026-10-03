"""`X | None`, never `Optional[X]` (CLAUDE.md, Code Conventions).

The last `Optional[...]` annotations in the package and the scripts were rewritten
in one pass. Nothing else would stop a new one: the ruff rule set is pinned to
E4, E7, E9 and F, which leaves out pyupgrade's UP007. So this test looks.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
_OPTIONAL_RE = re.compile(r"\bOptional\[")


def test_no_optional_annotations() -> None:
    offenders = [
        f"{path.relative_to(REPO)}:{lineno}"
        for root in ("agent_audit_kit", "scripts")
        for path in sorted((REPO / root).rglob("*.py"))
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if _OPTIONAL_RE.search(line)
    ]
    assert offenders == [], f"write `X | None` instead: {offenders}"
