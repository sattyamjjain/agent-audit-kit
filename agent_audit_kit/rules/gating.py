"""Rules that report at their severity but do not fail a build yet.

The 2026-09-25 post "My Precision Badge Was Right About the Wrong Files"
promised a benign slice for instruction files (``CLAUDE.md``, ``AGENTS.md`` and
the like), built and published like the MCP one, before any rule that reads them
is allowed to fail a build at HIGH. The slice exists
(``benchmarks/false_positive/instruction_files/``) but is not adjudicated, so
``benchmarks/false_positive/RESULTS.md`` says "There is no number for
instruction files". Three rules that read those files sit at HIGH or above, and
from v0.6.8, the release the post went out with, to v0.6.36 every one of them
failed ``--ci``, the GitHub Action (``fail-on: high``) and the pre-commit hook
(which runs ``--ci``): AAK-AGENT-001 (CRITICAL), AAK-AGENT-003 and
AAK-AGENT-006 (both HIGH).

Their severities are unchanged, so scores, SARIF levels and existing
code-scanning alerts are unchanged too. Only the gates change: ``scan
--fail-on`` (and ``--ci``, which sets it) and ``aak diff --fail-on-new`` skip
these findings and list them under "Reported, not gating", so a passing build
says why it passed.

Exit criterion: an instruction-file section with a number in RESULTS.md.
Publish it and empty this set in the same change. ``tests/test_gating.py``
fails while the two disagree, and also when a HIGH or CRITICAL rule in
``scanners/agent_config.py`` is missing from the set, so a new instruction-file
rule cannot start failing builds unmeasured.

A set here rather than a ``RuleDefinition`` field: the state is temporary and
covers three rules. A field would add a key to every entry in ``rules.json`` and
every generated surface for a condition meant to disappear, and lifting it would
touch three definitions instead of one line.
"""

from __future__ import annotations

NOT_GATING: frozenset[str] = frozenset({
    "AAK-AGENT-001",
    "AAK-AGENT-003",
    "AAK-AGENT-006",
})

#: Printed with the findings a gate skips, so the log says why they did not count.
NOT_GATING_REASON = (
    "instruction-file rules whose precision is not published yet "
    "(benchmarks/false_positive/RESULTS.md)"
)


def gates_build(rule_id: str) -> bool:
    """Return whether a finding from ``rule_id`` may fail a build.

    Args:
        rule_id: The finding's rule identifier.

    Returns:
        False for the rules in ``NOT_GATING``, True for every other rule.
    """
    return rule_id not in NOT_GATING
