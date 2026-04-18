"""Pin-drift scanner.

Fires the RUGPULL rule family (AAK-RUGPULL-001/002/003) during a standard
`agent-audit-kit scan` when a `.agent-audit-kit/tool-pins.json` file exists.

Before v0.3.0, RUGPULL rules only fired during `agent-audit-kit verify`.
That made them invisible in CI `scan` jobs — so pinned tool-surface drift
would ship to production without anyone noticing. This scanner closes
that gap without changing rule IDs (preserves CI-pipeline rule pins).
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.pinning import verify_pins


RULE_IDS = {"AAK-RUGPULL-001", "AAK-RUGPULL-002", "AAK-RUGPULL-003"}


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    pin_file = project_root / ".agent-audit-kit" / "tool-pins.json"
    if not pin_file.is_file():
        return [], set()
    findings = verify_pins(project_root)
    scanned = {str(pin_file.relative_to(project_root))}
    return findings, scanned
