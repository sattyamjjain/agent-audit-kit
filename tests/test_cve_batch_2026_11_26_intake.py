"""2026-11-26 intake: GitLab EE's MCP OAuth SSRF (CVE-2026-135221) and pain001-mcp (CVE-2026-136620, #1286).

GitLab's range is the vendor's (the 19.6.2 patch release and the CNA record, EE alone); its
image tags are tested in tests/test_container_image_pins.py. pain001-mcp's range was read in the
wheels. NVD's records are saved unedited under tests/fixtures/nvd_cna as the API returned them on
2026-11-26, and `CHANGELOG.cves.md` holds the reasoning. Nothing here touches the network.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agent_audit_kit import advisory_feed, nvd_feed
from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import mcp_cve_pins_2026_07

GITLAB_PIN = "AAK-MCP-GITLAB-CVE-2026-135221-001"
PAIN_PIN = "AAK-MCP-PAIN001-CVE-2026-136620-001"
KNOWN = "AAK-KNOWN-VULN-001"
GITLAB, PAIN = "CVE-2026-135221", "CVE-2026-136620"

HERE = Path(__file__).parent
CVES = HERE / "fixtures" / "cves"
NVD_CNA = HERE / "fixtures" / "nvd_cna"
LEDGER = HERE.parent / "CHANGELOG.cves.md"

PIN_RULES: dict[str, tuple[str, Severity, str, list[str]]] = {
    GITLAB_PIN: (GITLAB, Severity.MEDIUM, "cve-2026-135221-gitlab-ee", ["MCP05:2025", "MCP04:2025"]),
    PAIN_PIN: (PAIN, Severity.HIGH, "cve-2026-136620-pain001-mcp", ["MCP02:2025", "MCP04:2025"]),
}


def _nvd(cve: str) -> dict[str, Any]:
    (vuln,) = json.loads((NVD_CNA / f"{cve}.json").read_text(encoding="utf-8"))["vulnerabilities"]
    return vuln


def _pin_ids(root: Path) -> set[str]:
    return {f.rule_id for f in mcp_cve_pins_2026_07.scan(root)[0]}


def _requirements(root: Path, line: str) -> Path:
    (root / "requirements.txt").write_text(line + "\n", encoding="utf-8")
    return root


def _mcp(root: Path, command: str, args: list[str]) -> Path:
    (root / ".mcp.json").write_text(json.dumps(
        {"mcpServers": {"s": {"command": command, "args": args}}}), encoding="utf-8")
    return root


# ---- the saved records ----------------------------------------------------------------------


@pytest.mark.parametrize(("cve", "opening"), [
    (GITLAB, "GitLab has remediated an issue in GitLab EE affecting all versions from 18.10 before 19.4.11"),
    (PAIN, "pain001-mcp 0.0.72 before 0.0.80 contains a path traversal vulnerability"),
])
def test_each_saved_nvd_record_is_the_one_read(cve: str, opening: str) -> None:
    record = _nvd(cve)["cve"]
    assert record["id"] == cve
    (text,) = [d["value"] for d in record["descriptions"] if d["lang"] == "en"]
    assert text.startswith(opening)


# ---- the rules and their fixtures -----------------------------------------------------------


@pytest.mark.parametrize("rule_id", sorted(PIN_RULES))
def test_rule_metadata(rule_id: str) -> None:
    cve, severity, _fixture, owasp_mcp = PIN_RULES[rule_id]
    rule = RULES[rule_id]
    assert rule.cve_references == [cve]
    assert rule.severity is severity
    assert rule.owasp_mcp_references == owasp_mcp
    assert "ASI04" in rule.owasp_agentic_references


@pytest.mark.parametrize("rule_id", sorted(PIN_RULES))
def test_fixture_pair(rule_id: str) -> None:
    _cve, _severity, fixture, _owasp = PIN_RULES[rule_id]
    vulnerable = [f for f in run_scan(CVES / fixture / "vulnerable").findings if f.rule_id == rule_id]
    assert len(vulnerable) == 1 and vulnerable[0].line_number is not None
    assert rule_id not in {f.rule_id for f in run_scan(CVES / fixture / "negative").findings}


# ---- pain001-mcp, CVE-2026-136620 -----------------------------------------------------------


@pytest.mark.parametrize(("line", "fires"), [
    ("pain001-mcp==0.0.71", False),   # no commit_payment_batch yet
    ("pain001-mcp==0.0.72", True),
    ("pain001-mcp==0.0.79", True),
    ("pain001-mcp==0.0.80", False),
    ("pain001-mcp==0.0.91", False),   # `latest` on 2026-11-26
    ("pain001-mcp>=0.0.70", True),    # a range that admits an affected version
    ("pain001-mcp", False),           # `latest` is fixed, so a version must be stated
    ("pain001_mcp==0.0.75", True),    # PEP 503 name
])
def test_pain001_requirements(tmp_path: Path, line: str, fires: bool) -> None:
    assert (PAIN_PIN in _pin_ids(_requirements(tmp_path, line))) is fires


@pytest.mark.parametrize(("command", "args", "fires"), [
    ("uvx", ["pain001-mcp==0.0.79"], True),
    ("uvx", ["pain001-mcp@0.0.72"], True),
    ("uvx", ["pain001-mcp==0.0.80"], False),
    ("uvx", ["pain001-mcp"], False),
    ("npx", ["-y", "pain001-mcp@0.0.79"], False),   # not an npm name; the pin is PyPI's
])
def test_pain001_launches(tmp_path: Path, command: str, args: list[str], fires: bool) -> None:
    assert (PAIN_PIN in _pin_ids(_mcp(tmp_path, command, args))) is fires


def test_pain001_npm_manifest_is_not_judged(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"dependencies": {"pain001-mcp": "0.0.79"}}', encoding="utf-8")
    assert PAIN_PIN not in _pin_ids(tmp_path)


def test_the_advisory_feed_stands_down_for_the_pain001_pin(tmp_path: Path) -> None:
    """The CNA record's packageURL maps it to PyPI, so `aak update` carries it and
    AAK-KNOWN-VULN-001 would report it; on the line the pin reports, it stands down."""
    assert [(e, n) for e, n, _ in nvd_feed.record_packages(_nvd(PAIN), nvd_feed.load_package_map())] == [
        ("PyPI", "pain001-mcp")]
    entries = nvd_feed.record_entries(_nvd(PAIN), nvd_feed.load_package_map(), nvd_feed.Tally())
    path = advisory_feed.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"generated_at": "t", "source": "test", "records": [],
                                "nvd": nvd_feed.merged(entries)}), encoding="utf-8")
    findings = run_scan(_requirements(tmp_path, "pain001-mcp==0.0.79")).findings
    assert [f.rule_id for f in findings if f.rule_id in (PAIN_PIN, KNOWN)] == [PAIN_PIN]
    # The feed entry is live: with the pin's rule left out, the feed reports the line.
    kept = run_scan(tmp_path, rules=[KNOWN]).findings
    assert [(f.rule_id, f.line_number) for f in kept if f.rule_id in (PAIN_PIN, KNOWN)] == [(KNOWN, 1)]


def test_gitlab_record_maps_to_no_package() -> None:
    assert nvd_feed.record_packages(_nvd(GITLAB), nvd_feed.load_package_map()) == []


# ---- the ledger -----------------------------------------------------------------------------


@pytest.mark.parametrize(("cve", "issue", "says"), [
    (GITLAB, "#1290", GITLAB_PIN), (PAIN, "#1286", PAIN_PIN),
])
def test_every_record_has_one_ledger_row(cve: str, issue: str, says: str) -> None:
    rows = [line for line in LEDGER.read_text(encoding="utf-8").splitlines() if line.startswith(f"| {cve} ")]
    assert len(rows) == 1 and rows[0].rstrip().endswith(f"| {issue} |") and says in rows[0]
