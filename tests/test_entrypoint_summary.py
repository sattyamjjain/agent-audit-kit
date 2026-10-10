"""The Action's summary tells a crashed scan apart from findings over the threshold.

Both end in exit 1, and entrypoint.sh used to print "FAILED (findings exceed
--fail-on ...)" for either, so a run in which a scanner crashed (#743) read as a
run that merely found something. These tests run the real entrypoint.sh against a
stand-in `agent-audit-kit` that writes a SARIF file and exits 1.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ENTRYPOINT = Path(__file__).resolve().parent.parent / "entrypoint.sh"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")


def _run(tmp_path: Path, results: list[dict], exit_code: int) -> tuple[subprocess.CompletedProcess[str], str]:
    sarif = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "agent-audit-kit", "rules": []}}, "results": results}],
    }
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "agent-audit-kit"
    fake.write_text(
        "#!/usr/bin/env bash\n"
        "out=''\n"
        'while [ $# -gt 0 ]; do if [ "$1" = "-o" ]; then out="$2"; fi; shift; done\n'
        f"printf '%s' '{json.dumps(sarif)}' > \"$out\"\n"
        f"exit {exit_code}\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    summary = tmp_path / "summary.md"
    env = {
        key: value for key, value in os.environ.items()
        if key not in ("GITHUB_EVENT_NAME", "GITHUB_TOKEN", "GITHUB_EVENT_PATH")
    }
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    env["GITHUB_STEP_SUMMARY"] = str(summary)
    # path, severity, fail-on, format, upload-sarif, include-user-config,
    # rules, exclude-rules, preset, ignore-paths, config, comment-on-pr
    args = [".", "low", "high", "sarif", "false", "false", "", "", "", "", "", "false"]
    proc = subprocess.run(
        ["bash", str(ENTRYPOINT), *args], cwd=tmp_path, env=env, capture_output=True, text=True
    )
    return proc, summary.read_text(encoding="utf-8")


def _result(rule_id: str) -> dict:
    return {"ruleId": rule_id, "level": "note", "message": {"text": rule_id}}


def test_a_crashed_scanner_is_reported_as_incomplete(tmp_path: Path) -> None:
    proc, summary = _run(tmp_path, [_result("AAK-INTERNAL-SCANNER-FAIL")], exit_code=1)

    assert proc.returncode == 1
    assert "Result: INCOMPLETE (1 scanner(s) crashed" in proc.stdout
    assert "**Result: INCOMPLETE**" in summary
    assert "findings exceed" not in proc.stdout


def test_findings_over_the_threshold_still_read_as_failed(tmp_path: Path) -> None:
    proc, summary = _run(tmp_path, [_result("AAK-MCP-001")], exit_code=1)

    assert proc.returncode == 1
    assert "Result: FAILED (findings exceed --fail-on high threshold)" in proc.stdout
    assert "**Result: FAILED**" in summary
    assert "INCOMPLETE" not in proc.stdout
