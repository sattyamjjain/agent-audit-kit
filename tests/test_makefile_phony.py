"""Every Makefile target is declared .PHONY, and .PHONY names only real targets.

None of the targets builds a file named after itself, so each must be phony:
make skips an undeclared target as "up to date" the moment a file or directory
of that name appears in the repo root. `report-figures-check` was the one left
out.
"""

from __future__ import annotations

import re
from pathlib import Path

MAKEFILE = Path(__file__).resolve().parent.parent / "Makefile"

# A rule line: `name:` or `name: prereqs`, never a `NAME := value` assignment.
_TARGET_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)\s*:(?!=)")


def _targets_and_phony() -> tuple[set[str], set[str]]:
    text = MAKEFILE.read_text(encoding="utf-8").replace("\\\n", " ")
    targets: set[str] = set()
    phony: set[str] = set()
    for line in text.splitlines():
        if line.startswith(".PHONY:"):
            phony.update(line.split(":", 1)[1].split())
            continue
        match = _TARGET_RE.match(line)
        if match:
            targets.add(match.group(1))
    return targets, phony


def test_every_target_is_declared_phony() -> None:
    targets, phony = _targets_and_phony()
    assert len(targets) > 10, f"parsed suspiciously few targets: {sorted(targets)}"
    missing = sorted(targets - phony)
    assert not missing, f"declare these in .PHONY: {missing}"


def test_phony_names_only_real_targets() -> None:
    targets, phony = _targets_and_phony()
    stale = sorted(phony - targets)
    assert not stale, f".PHONY names targets the Makefile no longer defines: {stale}"
