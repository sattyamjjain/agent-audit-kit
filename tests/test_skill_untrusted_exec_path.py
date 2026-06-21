"""Tests for AAK-SKILL-UNTRUSTED-EXEC-PATH (CVE-2026-53819, CWE-426).

Install / skill-setup code that resolves an executable from a workspace-
controlled source (a `.env` var, an env-overridden PATH, `shutil.which()` over a
tainted PATH, or a Homebrew binary chosen via env) and runs it without an
absolute-path pin is an untrusted-search-path code-execution sink. CVE-2026-53819
(OpenClaw < 2026.5.27) is the anchor: a workspace `.env` overrode the Homebrew
executable selection during skill install.

Fixtures pin the contract: a `.env`/PATH-resolved binary FLAGS; an absolute-path-
pinned binary PASSES. SARIF output carries the rule ID + CWE-426 + the fix hint.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_audit_kit.models import ScanResult
from agent_audit_kit.output.sarif import format_results
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.skill_untrusted_exec_path import scan

RULE_ID = "AAK-SKILL-UNTRUSTED-EXEC-PATH"


def _write(tmp_path: Path, name: str, src: str) -> None:
    (tmp_path / name).write_text(src, encoding="utf-8")


def _hits(findings: list) -> list:
    return [f for f in findings if f.rule_id == RULE_ID]


# ---------------------------------------------------------------------------
# Rule registration
# ---------------------------------------------------------------------------


def test_rule_is_registered_with_cwe_and_cve() -> None:
    assert RULE_ID in RULES
    rule = RULES[RULE_ID]
    assert rule.severity.value == "high"
    assert "CVE-2026-53819" in rule.cve_references
    assert "CWE-426" in rule.description
    assert "absolute path" in rule.remediation


# ---------------------------------------------------------------------------
# Vulnerable — must FLAG
# ---------------------------------------------------------------------------


def test_dotenv_sourced_brew_is_flagged(tmp_path: Path) -> None:
    """The CVE-2026-53819 shape: workspace .env overrides the brew binary."""
    _write(tmp_path, "install_skill.py", '''
import os, subprocess
from dotenv import load_dotenv

load_dotenv()  # loads the workspace .env into os.environ
brew = os.environ.get("BREW_BIN", "brew")
subprocess.run([brew, "install", "ripgrep"], check=True)
''')
    findings, scanned = scan(tmp_path)
    assert "install_skill.py" in scanned
    assert _hits(findings), f".env-sourced brew binary must fire {RULE_ID}"


def test_path_prepend_shutil_which_is_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "skill_setup.py", '''
import os, shutil, subprocess

os.environ["PATH"] = os.getcwd() + os.pathsep + os.environ["PATH"]
brew = shutil.which("brew")
subprocess.run([brew, "install", "tool"])
''')
    findings, _ = scan(tmp_path)
    assert _hits(findings), "shutil.which over a workspace-prepended PATH must fire"


def test_env_command_direct_is_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "postinstall.py", '''
import os, subprocess
subprocess.run([os.getenv("BUILD_TOOL"), "build"])
''')
    findings, _ = scan(tmp_path)
    assert _hits(findings), "direct env-sourced command must fire"


def test_shell_source_env_then_brew_is_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "install.sh", '''#!/bin/bash
source ./.env
brew install ripgrep
''')
    findings, _ = scan(tmp_path)
    assert _hits(findings), "shell sourcing workspace .env then running brew must fire"


# ---------------------------------------------------------------------------
# Safe — must PASS
# ---------------------------------------------------------------------------


def test_absolute_pinned_binary_passes(tmp_path: Path) -> None:
    _write(tmp_path, "install_skill.py", '''
import subprocess
BREW = "/opt/homebrew/bin/brew"  # absolute-path pinned
subprocess.run([BREW, "install", "ripgrep"], check=True)
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "absolute-path-pinned binary must pass"


def test_allowlisted_resolution_passes(tmp_path: Path) -> None:
    _write(tmp_path, "setup.py", '''
import os, subprocess
brew = os.environ.get("BREW_BIN", "/usr/local/bin/brew")
if not os.path.isabs(brew):
    raise SystemExit("refusing relative brew path")
subprocess.run([brew, "install", "x"])
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "os.path.isabs allowlist check must clear the file"


def test_non_install_file_passes(tmp_path: Path) -> None:
    """A plain app module reading an env var (no install context) must pass."""
    _write(tmp_path, "handler.py", '''
import os, subprocess
tool = os.environ.get("TOOL")
subprocess.run([tool, "--version"])
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "no install/skill context -> must not fire"


def test_absolute_pinned_shell_passes(tmp_path: Path) -> None:
    _write(tmp_path, "install.sh", '''#!/bin/bash
source ./.env
/opt/homebrew/bin/brew install ripgrep
''')
    findings, _ = scan(tmp_path)
    # Shell PATH/source taint present, but the brew invocation is absolute-pinned.
    assert not _hits(findings), "absolute-pinned brew in shell must pass"


# ---------------------------------------------------------------------------
# SARIF carries rule ID + CWE-426 + fix hint
# ---------------------------------------------------------------------------


def test_sarif_carries_rule_cwe_and_fix_hint(tmp_path: Path) -> None:
    _write(tmp_path, "install_skill.py", '''
import os, subprocess
from dotenv import load_dotenv
load_dotenv()
brew = os.environ.get("BREW_BIN", "brew")
subprocess.run([brew, "install", "ripgrep"])
''')
    findings, _ = scan(tmp_path)
    hits = _hits(findings)
    assert hits
    result = ScanResult()
    result.findings.extend(hits)
    sarif = json.loads(format_results(result))
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    rule_obj = next(r for r in rules if r["id"] == RULE_ID)
    blob = json.dumps(sarif)
    # rule ID present on the result
    assert any(r["ruleId"] == RULE_ID for r in sarif["runs"][0]["results"])
    # CWE-426 carried in the rule description
    assert "CWE-426" in rule_obj["fullDescription"]["text"]
    # fix hint carried in help text / fixes
    assert "absolute path" in rule_obj["help"]["text"]
    assert "absolute path" in blob
    # CVE tag carried
    assert "CVE-2026-53819" in rule_obj["properties"]["tags"]
