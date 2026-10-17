"""The same project gives the same findings, in the same order, in every run.

Python randomises the hash of a string per process, so a set of strings
iterates in a different order in each run. Three scanners walked such a set
where the order reached the output:

- `mcp_deprecated_features` read its config names from a set and the
  capabilities a JSON config declares into another, so two runs of `aak scan`
  listed the same AAK-MCP-DEPRECATED findings in different orders, and the
  JSON and SARIF output differed between them;
- `stainless_lineage` reported the first Stainless config it found, so a
  project holding two was reported at one path or the other;
- `skill_poisoning` named the first trusted skill a name resembles, so a name
  close to two of them named either.

Each probe runs in its own process under its own PYTHONHASHSEED. Six seeds give
six different orders for the first case on the old code.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO = str(Path(__file__).resolve().parent.parent)
SEEDS = range(6)

_PROBE = """
import json, sys
from pathlib import Path
from agent_audit_kit.scanners import {module}
{setup}
findings, _ = {module}.scan(Path(sys.argv[1]))
print(json.dumps([[f.rule_id, f.file_path, f.line_number, f.evidence] for f in findings]))
"""


def _runs(root: Path, module: str, setup: str = "") -> set[str]:
    """The scanner's findings as printed by one process per hash seed."""
    probe = _PROBE.format(module=module, setup=setup)
    outputs = set()
    for seed in SEEDS:
        env = dict(os.environ, PYTHONHASHSEED=str(seed), PYTHONPATH=REPO)
        out = subprocess.run(
            [sys.executable, "-c", probe, str(root)],
            capture_output=True, text=True, env=env, timeout=120, check=True,
        )
        outputs.add(out.stdout)
    return outputs


def test_deprecated_capability_findings_keep_one_order(tmp_path: Path) -> None:
    declared = {"capabilities": {"roots": {"listChanged": True}, "sampling": {}, "logging": {}}}
    for name in (".mcp.json", "mcp.json", "claude_desktop_config.json", "package.json"):
        (tmp_path / name).write_text(json.dumps(declared, indent=2) + "\n", encoding="utf-8")
    outputs = _runs(tmp_path, "mcp_deprecated_features")
    assert len(outputs) == 1, outputs
    rows = json.loads(outputs.pop())
    assert len(rows) == 12
    assert [r[0] for r in rows[:3]] == [
        "AAK-MCP-DEPRECATED-001", "AAK-MCP-DEPRECATED-002", "AAK-MCP-DEPRECATED-003",
    ]
    assert [r[1] for r in rows[::3]] == [
        ".mcp.json", "mcp.json", "claude_desktop_config.json", "package.json",
    ]


def test_stainless_config_is_reported_at_one_path(tmp_path: Path) -> None:
    for name in ("stainless.yml", ".stainless.yaml", "stainless.config.json"):
        (tmp_path / name).write_text("organization:\n  name: acme\n", encoding="utf-8")
    outputs = _runs(tmp_path, "stainless_lineage")
    assert len(outputs) == 1, outputs
    (row,) = [r for r in json.loads(outputs.pop()) if r[0] == "AAK-MCP-LINEAGE-STAINLESS-001"]
    assert row[1] == "stainless.yml"


def test_a_name_close_to_two_trusted_skills_names_one(tmp_path: Path) -> None:
    """`docs` is one letter from both stand-in names. The shipped list holds no
    such pair today, so the probe swaps in a list that does."""
    skill = tmp_path / "skills" / "docs"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: docs\ndescription: Docs.\n---\n\nbody\n", encoding="utf-8")
    setup = (
        "skill_poisoning._TRUSTED_NAMES = frozenset("
        "{'docx', 'dots', 'dock', 'doc', 'dogs', 'does'})"
    )
    outputs = _runs(tmp_path, "skill_poisoning", setup)
    assert len(outputs) == 1, outputs
    (row,) = [r for r in json.loads(outputs.pop()) if r[0] == "AAK-SKILL-004"]
    assert "'doc'" in row[3]
