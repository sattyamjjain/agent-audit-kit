"""Tests for AAK-MCP-ARGV-TOCTOU-001 (CVE-2026-53822, CWE-77 + CWE-367).

A command/argv buffer approved against an allowlist and then rebuilt before
spawning executes a different shape than was approved. CVE-2026-53822: OpenClaw
< 2026.5.18 let the shell wrapper argv change between approval and execution.

Fixtures pin the contract: approve -> mutate -> spawn FLAGS (Python + JS); a
spawn of the unchanged approved buffer PASSES; a re-check after the mutation
PASSES. SARIF output carries the rule ID, a partial fingerprint, a `fixes[]`
entry, and a `security-severity` score.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_audit_kit.models import ScanResult
from agent_audit_kit.output.sarif import format_results
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.argv_toctou import scan

RULE_ID = "AAK-MCP-ARGV-TOCTOU-001"


def _write(tmp_path: Path, name: str, src: str) -> None:
    (tmp_path / name).write_text(src, encoding="utf-8")


def _hits(findings: list) -> list:
    return [f for f in findings if f.rule_id == RULE_ID]


# ---------------------------------------------------------------------------
# Rule registration
# ---------------------------------------------------------------------------


def test_rule_is_registered_with_cve_and_cwe() -> None:
    assert RULE_ID in RULES
    rule = RULES[RULE_ID]
    assert rule.severity.value == "high"
    assert "CVE-2026-53822" in rule.cve_references
    assert "CWE-77" in rule.description and "CWE-367" in rule.description
    assert "MCP05:2025" in rule.owasp_mcp_references


# ---------------------------------------------------------------------------
# Vulnerable — must FLAG
# ---------------------------------------------------------------------------


def test_python_rebuild_after_approval_is_flagged(tmp_path: Path) -> None:
    """The CVE-2026-53822 shape: argv approved, re-split, then spawned."""
    _write(tmp_path, "wrapper.py", '''
import shlex, subprocess
ALLOWED = {"ls", "cat"}

def run(cmd):
    if cmd[0] not in ALLOWED:        # approve against allowlist
        raise ValueError("denied")
    cmd = shlex.split(" ".join(cmd)) # rebuild argv AFTER approval (TOCTOU)
    subprocess.run(cmd)              # spawns the unapproved shape
''')
    findings, scanned = scan(tmp_path)
    assert "wrapper.py" in scanned
    assert _hits(findings), f"approve->rebuild->spawn must fire {RULE_ID}"


def test_python_extend_after_approval_is_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "exec.py", '''
import subprocess

def run(argv):
    if not is_allowed(argv):
        return
    argv = argv + build_extra()
    subprocess.Popen(argv)
''')
    findings, _ = scan(tmp_path)
    assert _hits(findings), "argv extended after approval then Popen must fire"


def test_js_argv_rebuilt_after_approval_is_flagged(tmp_path: Path) -> None:
    """OpenClaw is Node.js — the canonical CVE-2026-53822 language."""
    _write(tmp_path, "shellwrap.js", '''
const cp = require("child_process");

function run(argv) {
  if (!allowlist.includes(argv[0])) throw new Error("denied");
  argv = rebuildArgv(argv);
  cp.spawn(argv);
}
''')
    findings, _ = scan(tmp_path)
    assert _hits(findings), "JS argv rebuilt after allowlist check must fire"


# ---------------------------------------------------------------------------
# Safe — must PASS
# ---------------------------------------------------------------------------


def test_python_spawn_unchanged_passes(tmp_path: Path) -> None:
    """Approve then spawn the same buffer, no mutation -> safe."""
    _write(tmp_path, "wrapper.py", '''
import subprocess
ALLOWED = {"ls", "cat"}

def run(cmd):
    if cmd[0] not in ALLOWED:
        raise ValueError("denied")
    subprocess.run(cmd)
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "spawning the approved buffer unchanged must pass"


def test_python_revalidated_after_mutation_passes(tmp_path: Path) -> None:
    """Re-checking the rebuilt argv before spawn closes the TOCTOU window."""
    _write(tmp_path, "wrapper.py", '''
import shlex, subprocess
ALLOWED = {"ls"}

def run(cmd):
    if cmd[0] not in ALLOWED:
        raise ValueError
    cmd = shlex.split(" ".join(cmd))
    if cmd[0] not in ALLOWED:      # re-validate after rebuild
        raise ValueError
    subprocess.run(cmd)
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "re-validation after mutation must pass"


def test_js_spawn_unchanged_passes(tmp_path: Path) -> None:
    _write(tmp_path, "shellwrap.js", '''
const cp = require("child_process");

function run(argv) {
  if (!allowlist.includes(argv[0])) throw new Error("denied");
  cp.spawn(argv);
}
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "JS spawn of unchanged approved argv must pass"


# ---------------------------------------------------------------------------
# SARIF: fingerprint + fixes[] + security-severity
# ---------------------------------------------------------------------------


def test_sarif_carries_fingerprint_fixes_and_severity(tmp_path: Path) -> None:
    _write(tmp_path, "wrapper.py", '''
import shlex, subprocess
ALLOWED = {"ls"}

def run(cmd):
    if cmd[0] not in ALLOWED:
        raise ValueError
    cmd = shlex.split(" ".join(cmd))
    subprocess.run(cmd)
''')
    findings, _ = scan(tmp_path)
    assert _hits(findings)
    result = ScanResult()
    result.findings.extend(_hits(findings))
    sarif = json.loads(format_results(result))
    run = sarif["runs"][0]
    res = next(r for r in run["results"] if r["ruleId"] == RULE_ID)
    # security-severity on the rule
    rule_obj = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == RULE_ID)
    assert "security-severity" in rule_obj["properties"]
    # partial fingerprint on the result
    assert "partialFingerprints" in res
    # fixes[] on the result
    assert res["fixes"][0]["description"]["text"]
    # CVE tag carried
    assert "CVE-2026-53822" in rule_obj["properties"]["tags"]
