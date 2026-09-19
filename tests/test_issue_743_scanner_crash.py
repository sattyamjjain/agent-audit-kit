"""Issue #743: a run in which a scanner crashed must not report success.

The reported shape: a `.mcp.json` holding one invalid UTF-8 byte kills four
scanners on `UnicodeDecodeError`. The engine files each as
``AAK-INTERNAL-SCANNER-FAIL`` at INFO, INFO sits below the default reporting
floor of LOW, and the run exits 0 with an empty findings array, a 100/100 A
and a SARIF file with zero results. Every MCP config rule was skipped and the
output is indistinguishable from a clean project.

Three separate defects had to line up for that, and each is pinned here:

1. the failure was filed below the reporting floor, so nothing printed it;
2. nothing mapped "a scanner crashed" onto a non-zero exit;
3. ``files_scanned`` counted rule ids, so the run also claimed to have read
   files it never opened, which made the empty result look substantiated.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from agent_audit_kit.cli import cli
from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import SCANNER_FAIL_RULE_ID, Severity

runner = CliRunner()

# The reported inputs, byte for byte.
BAD_UTF8 = b'{"mcpServers": {"a": "\xff\xfe bad"}}'
BAD_ARGS = '{"mcpServers": {"a": {"command": "node", "args": 42}}}'


def _project(tmp_path: Path, name: str, content: bytes | str) -> Path:
    p = tmp_path / "proj"
    p.mkdir()
    target = p / name
    if isinstance(content, bytes):
        target.write_bytes(content)
    else:
        target.write_text(content, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# 1d - files_scanned counted rule ids, not files
# ---------------------------------------------------------------------------


def test_empty_directory_reports_zero_files_scanned(tmp_path: Path) -> None:
    """The headline symptom: an empty directory claimed 15 files.

    Eight scanners returned the set of rule ids they evaluate as the second
    element of their tuple, and the engine unions that into ``files_scanned``.
    """
    empty = tmp_path / "empty"
    empty.mkdir()
    assert run_scan(project_root=empty).files_scanned == 0


def test_empty_directory_reports_zero_files_scanned_via_cli(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    out = tmp_path / "out.json"
    runner.invoke(cli, ["scan", str(empty), "--format", "json", "-o", str(out)])
    assert json.loads(out.read_text())["summary"]["filesScanned"] == 0


def test_no_scanner_returns_a_rule_id_as_a_scanned_path(tmp_path: Path) -> None:
    """Guards the contract itself, not just the count it corrupted."""
    from agent_audit_kit import engine

    empty = tmp_path / "empty"
    empty.mkdir()
    for reg in engine._get_registry():
        kwargs = {"project_root": empty}
        for key in reg.kwargs_keys:
            kwargs[key] = False if key == "include_user_config" else None
        _, scanned = reg.scan_fn(**kwargs)
        assert scanned == set(), (
            f"{reg.name} returned {sorted(scanned)} for an empty directory; the "
            f"second element is scanned file paths, not rule ids"
        )


# ---------------------------------------------------------------------------
# 1b - the failure must clear the reporting floor
# ---------------------------------------------------------------------------


def test_scanner_failure_survives_the_default_severity_floor(tmp_path: Path) -> None:
    project = _project(tmp_path, ".mcp.json", BAD_UTF8)
    result = run_scan(project_root=project)
    assert result.scanner_failures, "expected the UTF-8 crash to be recorded"
    # LOW is the CLI default; the failure is filed at INFO, below it.
    shown = result.findings_at_or_above(Severity.LOW)
    assert any(f.rule_id == SCANNER_FAIL_RULE_ID for f in shown)


def test_floor_exemption_does_not_leak_other_info_findings(tmp_path: Path) -> None:
    """The exemption is for one rule id, not for INFO as a class."""
    from agent_audit_kit.models import Category, Finding, ScanResult

    other_info = Finding(
        rule_id="AAK-SOMETHING-ELSE", title="t", description="d",
        severity=Severity.INFO, category=Category.MCP_CONFIG,
        file_path="f", line_number=1, evidence="e", remediation="r",
    )
    result = ScanResult(findings=[other_info])
    assert result.findings_at_or_above(Severity.LOW) == []


# ---------------------------------------------------------------------------
# 1a / 1f - crash input 1: invalid UTF-8
# ---------------------------------------------------------------------------


def test_utf8_crash_exits_non_zero(tmp_path: Path) -> None:
    project = _project(tmp_path, ".mcp.json", BAD_UTF8)
    res = runner.invoke(cli, ["scan", str(project)])
    assert res.exit_code != 0, "a run with four dead scanners exited 0"


def test_utf8_crash_is_visible_at_default_severity(tmp_path: Path) -> None:
    project = _project(tmp_path, ".mcp.json", BAD_UTF8)
    out = tmp_path / "out.json"
    runner.invoke(cli, ["scan", str(project), "--format", "json", "-o", str(out)])
    payload = json.loads(out.read_text())
    assert payload["summary"]["complete"] is False
    assert payload["summary"]["scannerFailures"] >= 1
    reported = {f["ruleId"] for f in payload["findings"]}
    assert SCANNER_FAIL_RULE_ID in reported, "no --severity info was passed"


def test_allow_scanner_failure_opts_back_into_exit_zero(tmp_path: Path) -> None:
    project = _project(tmp_path, ".mcp.json", BAD_UTF8)
    res = runner.invoke(cli, ["scan", str(project), "--allow-scanner-failure"])
    assert res.exit_code == 0


def test_the_opt_out_is_a_flag_not_the_default() -> None:
    """The safe state has to be what you get by not thinking about it."""
    params = {p.name for p in cli.commands["scan"].params}
    assert "allow_scanner_failure" in params
    flag = next(p for p in cli.commands["scan"].params if p.name == "allow_scanner_failure")
    assert flag.is_flag and flag.default is False


def test_sarif_marks_the_run_unsuccessful(tmp_path: Path) -> None:
    project = _project(tmp_path, ".mcp.json", BAD_UTF8)
    out = tmp_path / "o.sarif"
    runner.invoke(cli, ["scan", str(project), "--format", "sarif", "-o", str(out)])
    run = json.loads(out.read_text())["runs"][0]
    invocation = run["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert len(invocation["toolExecutionNotifications"]) >= 1
    assert invocation["toolExecutionNotifications"][0]["level"] == "error"
    # and it is still a result, so a consumer that only reads results sees it
    assert any(r["ruleId"] == SCANNER_FAIL_RULE_ID for r in run["results"])


def test_score_output_does_not_read_as_a_clean_bill_of_health(tmp_path: Path) -> None:
    project = _project(tmp_path, ".mcp.json", BAD_UTF8)
    res = runner.invoke(cli, ["scan", str(project), "--score"])
    assert "100/100" in res.output
    assert "UNRELIABLE" in res.output


def test_score_subcommand_warns_and_exits_non_zero(tmp_path: Path) -> None:
    project = _project(tmp_path, ".mcp.json", BAD_UTF8)
    res = runner.invoke(cli, ["score", str(project)])
    assert res.exit_code != 0
    assert "upper bound" in res.output


# ---------------------------------------------------------------------------
# 1e / 1f - crash input 2: args as a scalar
# ---------------------------------------------------------------------------


def test_malformed_args_does_not_crash_the_composition_scanner(tmp_path: Path) -> None:
    from agent_audit_kit.scanners.composition import scan as composition_scan

    project = _project(tmp_path, ".mcp.json", BAD_ARGS)
    composition_scan(project)  # used to raise TypeError: 'int' object is not iterable
    assert not run_scan(project_root=project).scanner_failures


def test_malformed_args_is_reported_at_default_severity(tmp_path: Path) -> None:
    project = _project(tmp_path, ".mcp.json", BAD_ARGS)
    out = tmp_path / "out.json"
    runner.invoke(cli, ["scan", str(project), "--format", "json", "-o", str(out)])
    reported = {f["ruleId"] for f in json.loads(out.read_text())["findings"]}
    assert "AAK-MCP-CONFIG-MALFORMED-001" in reported, (
        "the malformed value must be rejected as a finding, not swallowed"
    )


def test_malformed_args_exits_non_zero_under_a_threshold(tmp_path: Path) -> None:
    """Exit is --fail-on driven once the crash is gone.

    The finding is MEDIUM, and `--fail-on` defaults to `none`, so the
    non-zero exit for this input comes from the threshold a CI user sets
    rather than from the finding existing. Making any finding exit non-zero
    by default would be a breaking change to the documented contract and is
    not what issue #743 asks for.
    """
    project = _project(tmp_path, ".mcp.json", BAD_ARGS)
    res = runner.invoke(cli, ["scan", str(project), "--fail-on", "medium"])
    assert res.exit_code != 0


def test_a_malformed_env_is_caught_too(tmp_path: Path) -> None:
    """`args` was the reported field; the check is not special-cased to it."""
    project = _project(
        tmp_path, ".mcp.json",
        '{"mcpServers": {"a": {"command": "node", "env": "nope"}}}',
    )
    result = run_scan(project_root=project)
    evidence = " ".join(
        f.evidence for f in result.findings
        if f.rule_id == "AAK-MCP-CONFIG-MALFORMED-001"
    )
    assert "env" in evidence
    assert not result.scanner_failures


def test_remaining_malformed_shapes_are_now_reported_not_crashed(
    tmp_path: Path,
) -> None:
    """`"url": 42` and `"command": ["node"]` are hardened as of v0.6.7.

    They are the same class as the reported `"args": 42` and were found by
    widening the fixture while writing these tests. When issue #743 shipped they
    were deliberately left crashing — that issue asked for the exit path, not a
    per-field audit of every scanner — and this test asserted only that the exit
    path kept them from passing a run.

    Four scanners were taking them down: `mcp_config` and `transport_security`
    on the int url, `mcp_config` and `supply_chain` on the list command, plus the
    shared `find_line_number` helper, which fed a non-string straight into a
    substring search. A field whose JSON type contradicts the MCP schema is now
    reported by AAK-MCP-CONFIG-MALFORMED-001 and skipped by the rules that
    cannot evaluate it, so the run still fails — on a finding a reader can act
    on rather than a stack trace.
    """
    for body, field, wrong_type in (
        ('{"mcpServers": {"a": {"url": 42}}}', "url", "int"),
        ('{"mcpServers": {"a": {"command": ["node"], "args": ["x"]}}}',
         "command", "list"),
    ):
        project = tmp_path / f"p{abs(hash(body))}"
        project.mkdir()
        (project / ".mcp.json").write_text(body, encoding="utf-8")
        result = run_scan(project_root=project)

        assert not result.scanner_failures, (
            f"{body} crashed a scanner: "
            + "; ".join(f.evidence for f in result.scanner_failures)
        )
        malformed = [
            f for f in result.findings
            if f.rule_id == "AAK-MCP-CONFIG-MALFORMED-001"
        ]
        assert malformed, f"no malformed-field finding for {body}"
        assert any(
            field in f.evidence and wrong_type in f.evidence for f in malformed
        ), f"finding does not name {field}/{wrong_type}: {[f.evidence for f in malformed]}"

        # The finding is MEDIUM, so it answers to --fail-on like any other
        # MEDIUM finding. Before the hardening these configs forced a non-zero
        # exit through the scanner-failure path, which was the crash acting as
        # an accidental severity floor rather than a decision about how bad a
        # malformed field is.
        assert runner.invoke(
            cli, ["scan", str(project), "--fail-on", "medium"]
        ).exit_code == 1, f"{body} did not fail at --fail-on medium"


def test_a_wrong_typed_command_is_not_coerced_into_a_shell_finding(
    tmp_path: Path,
) -> None:
    """Skipping must not become guessing.

    `str(["node"])` is `"['node']"`, which contains quotes and brackets — feed
    that to the shell-metacharacter check and AAK-MCP-002 fires on punctuation
    the operator never wrote. The field is unevaluable, so no rule that reads it
    as a command may report on it.
    """
    project = tmp_path / "coerce"
    project.mkdir()
    (project / ".mcp.json").write_text(
        '{"mcpServers": {"a": {"command": ["node"], "args": ["x"]}}}',
        encoding="utf-8",
    )
    result = run_scan(project_root=project)
    assert "AAK-MCP-002" not in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# A clean project must stay clean - the fix must not invert the default
# ---------------------------------------------------------------------------


def test_a_clean_project_still_exits_zero(tmp_path: Path) -> None:
    project = _project(
        tmp_path, ".mcp.json",
        '{"mcpServers": {"ok": {"command": "node", "args": ["server.js"]}}}',
    )
    res = runner.invoke(cli, ["scan", str(project)])
    assert not run_scan(project_root=project).scanner_failures
    assert res.exit_code == 0
