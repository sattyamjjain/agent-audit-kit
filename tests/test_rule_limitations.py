"""Every stated rule limitation is proven by a fixture.

``RuleDefinition.limitations`` is defined as what a rule provably does not
catch. This test is where "provably" is enforced. Each directory
``tests/fixtures/limitations/<RULE_ID>/`` holds two minimal projects:

- ``positive/``, which the rule flags, so the fixture shows the rule working;
- ``blind_spot/``, kept as close to ``positive/`` as possible, which carries the
  same risk in a form the rule misses.

The test fails when the rule stops firing on ``positive/`` (the pair no longer
shows a working rule, so the blind spot proves nothing), when it starts firing
on ``blind_spot/`` (the limitation is no longer true: rewrite or delete it), or
when the registry states no limitation for a rule that has a fixture.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_audit_kit.engine import run_scan
from agent_audit_kit.rules.builtin import RULES

FIXTURES = Path(__file__).parent / "fixtures" / "limitations"
RULE_DIRS = sorted(p for p in FIXTURES.iterdir() if p.is_dir()) if FIXTURES.is_dir() else []

# A rule that is off by default is measured with its opt-in set: its limitation
# says what it misses once it runs, and without the switch positive/ proves nothing.
OPT_IN_ENV = {"AAK-TOXICFLOW-001": {"AAK_TOXIC_FLOW": "1"}}


def _fires(rule_id: str, project: Path) -> bool:
    result = run_scan(project_root=project, rules=[rule_id])
    return any(f.rule_id == rule_id for f in result.findings)


def test_fixture_tree_is_not_empty() -> None:
    assert RULE_DIRS, f"no limitation fixtures under {FIXTURES}"


@pytest.mark.parametrize("rule_dir", RULE_DIRS, ids=lambda p: p.name)
def test_limitation_is_proven(rule_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rule_id = rule_dir.name
    for name, value in OPT_IN_ENV.get(rule_id, {}).items():
        monkeypatch.setenv(name, value)
    assert rule_id in RULES, f"{rule_id}: fixture directory names no registered rule"
    assert RULES[rule_id].limitations.strip(), (
        f"{rule_id}: has a fixture but the registry states no limitation"
    )
    assert _fires(rule_id, rule_dir / "positive"), (
        f"{rule_id}: the rule does not fire on positive/, so the pair proves nothing"
    )
    assert not _fires(rule_id, rule_dir / "blind_spot"), (
        f"{rule_id}: the rule fires on blind_spot/, so the stated limitation is no longer true"
    )
