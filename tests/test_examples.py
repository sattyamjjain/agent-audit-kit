"""Validate that all vulnerable config examples trigger their expected rules.

Discovers every subdirectory under examples/vulnerable-configs/ that contains
an expected-findings.json and runs the scanner against it, asserting that
all expected rule IDs are present in the actual findings.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_audit_kit.engine import run_scan

EXAMPLES_DIR = Path(__file__).parent.parent / "examples" / "vulnerable-configs"


def _discover_examples() -> list[tuple[str, Path, list[str]]]:
    """Return (name, directory, expected_rules) for each example."""
    examples = []
    if not EXAMPLES_DIR.is_dir():
        return examples
    for d in sorted(EXAMPLES_DIR.iterdir()):
        expected_file = d / "expected-findings.json"
        if d.is_dir() and expected_file.exists():
            data = json.loads(expected_file.read_text())
            examples.append((d.name, d, data["expectedRules"]))
    return examples


_EXAMPLES = _discover_examples()


@pytest.mark.parametrize(
    "name,example_dir,expected_rules",
    _EXAMPLES,
    ids=[e[0] for e in _EXAMPLES],
)
def test_example_findings(
    name: str, example_dir: Path, expected_rules: list[str]
) -> None:
    result = run_scan(example_dir, include_user_config=True)
    actual_rules = {f.rule_id for f in result.findings}
    missing = set(expected_rules) - actual_rules
    assert not missing, (
        f"Example '{name}' missing expected rules: {sorted(missing)}. "
        f"Actual rules: {sorted(actual_rules)}"
    )
