"""Tests for B5 (`fix --cve`), B6 (`watch`), B7 (`--advisories`)."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from agent_audit_kit import advisories, fix, watch
from agent_audit_kit.cli import cli
from agent_audit_kit.models import Category, Finding, Severity


# ---------------------------------------------------------------------------
# B5 — fix --cve
# ---------------------------------------------------------------------------


def test_cve_fix_bumps_requirements(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "langchain==1.1.5\nlangchain-core==0.3.10\nrequests==2.31.0\n"
    )
    fixes = fix.run_cve_fixes(tmp_path, dry_run=False)
    assert fixes
    text = (tmp_path / "requirements.txt").read_text()
    assert ">=1.2.22" in text
    # requests line should be untouched
    assert "requests==2.31.0" in text


def test_cve_fix_dry_run_does_not_modify(tmp_path: Path) -> None:
    original = "langchain==1.1.5\n"
    (tmp_path / "requirements.txt").write_text(original)
    fixes = fix.run_cve_fixes(tmp_path, dry_run=True)
    # The fix is proposed but not applied.
    assert (tmp_path / "requirements.txt").read_text() == original
    assert fixes and all(not f.applied for f in fixes)


def test_cve_fix_bumps_package_json(tmp_path: Path) -> None:
    # Use a compact package.json that triggers AAK-LANGCHAIN-001
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "my-mcp",
                "dependencies": {
                    "langchainjs": "0.2.0",
                    "express": "^4.18.0",
                },
            }
        )
    )
    fixes = fix.run_cve_fixes(tmp_path, dry_run=False)
    data = json.loads((tmp_path / "package.json").read_text())
    # langchainjs bumped, express untouched
    assert data["dependencies"]["langchainjs"].startswith(">=")
    assert data["dependencies"]["express"] == "^4.18.0"
    assert fixes


def test_cve_fix_ignores_non_langchain_rules(tmp_path: Path) -> None:
    # A project with no langchain but a trust-boundary issue should have
    # nothing to fix under --cve.
    (tmp_path / ".claude" / "settings.json").parent.mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(
        json.dumps({"enableAllProjectMcpServers": True})
    )
    fixes = fix.run_cve_fixes(tmp_path, dry_run=True)
    assert fixes == []


def test_cli_fix_cve_flag(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("langchain==1.1.5\n")
    runner = CliRunner()
    r = runner.invoke(cli, ["fix", str(tmp_path), "--cve", "--dry-run"])
    assert r.exit_code == 0, r.output
    assert "CVE mode" in r.output or "AAK-LANGCHAIN" in r.output


# ---------------------------------------------------------------------------
# B6 — watch daemon
# ---------------------------------------------------------------------------


def test_watch_single_iteration_clean_pin(tmp_path: Path, monkeypatch) -> None:
    # Stub verify_pins to return no drift.
    monkeypatch.setattr(watch, "verify_pins", lambda _p: [])
    result = watch.run_watch(tmp_path, interval_seconds=0, max_iterations=1)
    assert result.iterations == 1
    assert result.drift_events == 0


def test_watch_fires_on_drift(tmp_path: Path, monkeypatch) -> None:
    f = Finding(
        rule_id="AAK-RUGPULL-001",
        title="Tool changed",
        description="",
        severity=Severity.HIGH,
        category=Category.TOOL_POISONING,
        file_path=".mcp.json",
    )
    monkeypatch.setattr(watch, "verify_pins", lambda _p: [f])
    calls: list[tuple[int, list[Finding]]] = []
    result = watch.run_watch(
        tmp_path,
        interval_seconds=0,
        max_iterations=2,
        on_drift=lambda i, fs: calls.append((i, fs)),
    )
    assert result.iterations == 2
    assert result.drift_events == 2
    assert len(calls) == 2


def test_watch_posts_webhook(tmp_path: Path, monkeypatch) -> None:
    f = Finding(
        rule_id="AAK-RUGPULL-002",
        title="New tool",
        description="",
        severity=Severity.HIGH,
        category=Category.TOOL_POISONING,
        file_path=".mcp.json",
    )
    monkeypatch.setattr(watch, "verify_pins", lambda _p: [f])
    posted: list[tuple[str, dict]] = []
    monkeypatch.setattr(watch, "_post_webhook", lambda url, payload: posted.append((url, payload)))
    watch.run_watch(
        tmp_path,
        interval_seconds=0,
        max_iterations=1,
        webhook_url="https://hooks.example.com/T/B/z",
    )
    assert len(posted) == 1
    assert posted[0][0] == "https://hooks.example.com/T/B/z"
    assert "AAK-RUGPULL-002" in posted[0][1]["text"]


def test_cli_watch_once(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(watch, "verify_pins", lambda _p: [])
    runner = CliRunner()
    r = runner.invoke(cli, ["watch", str(tmp_path), "--once", "--interval", "0"])
    assert r.exit_code == 0, r.output


# ---------------------------------------------------------------------------
# B7 — GitHub Security Advisories
# ---------------------------------------------------------------------------


def _finding(rule_id: str, severity: Severity) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=f"{rule_id} title",
        description="desc",
        severity=severity,
        category=Category.MCP_CONFIG,
        file_path="x.py",
        line_number=10,
        evidence="example",
        remediation="fix it",
        cve_references=["CVE-2026-XXXXX"],
        owasp_mcp_references=["MCP01:2025"],
    )


def test_open_advisories_dry_run() -> None:
    findings = [_finding("AAK-MCP-001", Severity.CRITICAL), _finding("AAK-X", Severity.MEDIUM)]
    results = advisories.open_advisories(findings, "acme/repo", dry_run=True)
    # Only CRITICAL qualifies; dry-run creates a stub result.
    assert len(results) == 1
    assert results[0].rule_id == "AAK-MCP-001"
    assert not results[0].created


def test_advisory_body_includes_cve_and_owasp() -> None:
    body = advisories._build_advisory_body(_finding("AAK-MCP-011", Severity.CRITICAL))
    assert "CVE-2026-XXXXX" in body
    assert "MCP01:2025" in body
    assert "fix it" in body
    assert "aak-mcp-011" in body.lower() or "AAK-MCP-011" in body


def test_advisory_severity_mapping() -> None:
    assert advisories._severity_to_ghsa(Severity.CRITICAL) == "critical"
    assert advisories._severity_to_ghsa(Severity.HIGH) == "high"
    assert advisories._severity_to_ghsa(Severity.INFO) == "low"


def test_open_advisories_handles_missing_gh(monkeypatch) -> None:
    # Simulate `gh` not on PATH
    monkeypatch.setattr(advisories.shutil, "which", lambda _b: None)
    results = advisories.open_advisories(
        [_finding("AAK-MCP-001", Severity.CRITICAL)],
        "acme/repo",
        dry_run=False,
    )
    assert len(results) == 1
    assert not results[0].created
    assert "gh CLI not found" in results[0].error


def test_open_advisories_posts_via_gh(monkeypatch) -> None:
    # Simulate gh on PATH + successful POST
    monkeypatch.setattr(advisories.shutil, "which", lambda _b: "/usr/local/bin/gh")

    class Result:
        def __init__(self) -> None:
            self.returncode = 0
            self.stdout = json.dumps({"html_url": "https://github.com/acme/repo/security/advisories/GHSA-xxxx"})
            self.stderr = ""

    monkeypatch.setattr(advisories.subprocess, "run", lambda *a, **kw: Result())
    results = advisories.open_advisories(
        [_finding("AAK-MCP-001", Severity.CRITICAL)],
        "acme/repo",
        dry_run=False,
    )
    assert results[0].created
    assert "GHSA-xxxx" in results[0].url
