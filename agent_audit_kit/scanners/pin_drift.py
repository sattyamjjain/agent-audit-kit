"""Pin-drift scanner.

Fires the RUGPULL rule family (AAK-RUGPULL-001/002/003) during a standard
`agent-audit-kit scan` when a `.agent-audit-kit/tool-pins.json` file exists.

Before v0.3.0, RUGPULL rules only fired during `agent-audit-kit verify`.
That made them invisible in CI `scan` jobs — so pinned tool-surface drift
would ship to production without anyone noticing. This scanner closes
that gap without changing rule IDs (preserves CI-pipeline rule pins).

A pin file that exists but cannot be used (not valid JSON, not UTF-8, not a
map of pins) is reported as `AAK-INTERNAL-SCANNER-FAIL`, filed against the pin
file. It used to produce no findings at all, so a trailing comma turned all
three rules off and the scan read as clean. A finding under one of those rules
would claim drift nobody observed; the internal-failure rule says what is true,
that the rules this scanner owns were not evaluated, and it carries the
semantics that make that impossible to miss: it is kept through `--rules`
filters, `--diff` and severity floors, and `aak scan` exits 1 as INCOMPLETE
unless `--allow-scanner-failure` is passed. No new rule id, because the
condition is not a new kind of risk; it is this scanner failing to run.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.models import SCANNER_FAIL_RULE_ID, Finding
from agent_audit_kit.pinning import PIN_FILE, PinFileError, verify_pins
from agent_audit_kit.scanners._helpers import make_finding


RULE_IDS = {"AAK-RUGPULL-001", "AAK-RUGPULL-002", "AAK-RUGPULL-003"}

#: This scanner's display name in `engine._OPTIONAL_SCANNERS`. A scanner cannot
#: import the engine (the engine imports scanners), and the JSON report reads the
#: name back out of the `scanner='...'` prefix of the failure evidence, so the two
#: are kept equal by `tests/test_pin_drift.py`.
_SCANNER_NAME = "Pin drift"


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    pin_file = project_root / PIN_FILE
    if not pin_file.is_file():
        return [], set()
    try:
        findings = verify_pins(project_root)
    except PinFileError as exc:
        owned = sorted(RULE_IDS)
        not_evaluated = f"{', '.join(owned[:-1])} and {owned[-1]} were not evaluated"
        return [
            make_finding(
                SCANNER_FAIL_RULE_ID,
                PIN_FILE,
                f"scanner={_SCANNER_NAME!r} error=PinFileError: {exc}; {not_evaluated}",
                exc.line,
            )
        ], {PIN_FILE}
    return findings, {PIN_FILE}
