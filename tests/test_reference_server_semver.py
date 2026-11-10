"""The npm reference servers left their date line, so nothing should send you to it.

server-filesystem, server-memory, server-everything and server-sequential-thinking
published date versions, then went back to semantic versioning at 1.0.0 on 2026-10-11,
and npm marks the date line deprecated. AAK-MCP-007 and AAK-SUPPLY-001 recommended
`@modelcontextprotocol/server-filesystem@2025.1.1`, a version npm never had. The OSV
records here are saved unedited from https://api.osv.dev/v1/vulns/<id> on 2026-11-07.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from agent_audit_kit import advisory_feed
from agent_audit_kit.engine import run_scan
from agent_audit_kit.malicious_feed import version_order
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import known_vulns

REPO = Path(__file__).resolve().parent.parent
RECORDS = Path(__file__).parent / "fixtures" / "known_vulns" / "reference_servers"
FILESYSTEM = "@modelcontextprotocol/server-filesystem"
HC55, Q66Q = "GHSA-hc55-p739-j48w", "GHSA-q66q-fx2p-7w4m"


def _cache(records: list[dict[str, Any]]) -> None:
    path = advisory_feed.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"generated_at": "t", "source": "test", "records": records}))


def _records() -> list[dict[str, Any]]:
    return [json.loads((RECORDS / f"{ident}.json").read_text()) for ident in (HC55, Q66Q)]


def _lock(name: str, version: str) -> str:
    return json.dumps({"lockfileVersion": 3, "packages": {f"node_modules/{name}": {"version": version}}})


@pytest.mark.parametrize("version,affected", [
    ("0.6.2", True), ("2025.1.14", True), ("2025.3.28", True),
    ("2025.7.1", False), ("2026.8.31", False), ("1.0.0", False), ("2.0.1", False), ("2.1.0", False),
])
def test_the_records_match_as_published(version: str, affected: bool) -> None:
    _cache(_records())
    feed = advisory_feed.load_feed()
    assert {a.id for a in feed.match("npm", FILESYSTEM, version)} == ({HC55, Q66Q} if affected else set())


def test_a_lockfile_on_0_6_2_is_told_the_fix_is_on_the_deprecated_line(tmp_path: Path) -> None:
    _cache(_records())
    (tmp_path / "package-lock.json").write_text(_lock(FILESYSTEM, "0.6.2"))
    findings = [f for f in run_scan(tmp_path).findings if f.rule_id == "AAK-KNOWN-VULN-001"]
    assert len(findings) == 2
    for finding in findings:
        assert "it is fixed in 2025.7.1, on the date line npm has since deprecated" in finding.evidence
        assert "went back to semantic versioning at 1.0.0 on 2026-10-11" in finding.evidence
        assert "this advisory lists none of those releases" in finding.evidence


def test_an_install_on_the_date_line_is_told_the_same(tmp_path: Path) -> None:
    _cache(_records())
    (tmp_path / "package-lock.json").write_text(_lock(FILESYSTEM, "2025.3.28"))
    findings = [f for f in run_scan(tmp_path).findings if f.rule_id == "AAK-KNOWN-VULN-001"]
    assert findings and all("npm has since deprecated" in f.evidence for f in findings)


def test_a_range_is_told_the_same(tmp_path: Path) -> None:
    _cache(_records())
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {FILESYSTEM: "^0.6.0"}}))
    findings = [f for f in run_scan(tmp_path).findings if f.rule_id == "AAK-KNOWN-VULN-001"]
    assert findings and all("npm has since deprecated" in f.evidence for f in findings)


@pytest.mark.parametrize("events", [
    # A later advisory that lists SemVer releases, or fixes in them, keeps its own wording.
    ([{"introduced": "1.0.0"}, {"fixed": "2.1.0"}], [{"introduced": "2025.1.14"}, {"fixed": "2025.7.1"}]),
    ([{"introduced": "0"}, {"last_affected": "1.5.0"}], [{"introduced": "2025.1.14"}, {"fixed": "2025.7.1"}]),
], ids=["fixed-in-semver", "last-affected-in-semver"])
def test_the_note_is_not_written_for_an_advisory_on_the_semver_line(tmp_path: Path, events: tuple[list, list]) -> None:
    _cache([{"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-90099"], "affected": [
        {"package": {"ecosystem": "npm", "name": FILESYSTEM}, "ranges": [{"type": "SEMVER", "events": e}]}
        for e in events]}])
    (tmp_path / "package-lock.json").write_text(_lock(FILESYSTEM, "2025.3.28"))
    (finding,) = [f for f in run_scan(tmp_path).findings if f.rule_id == "AAK-KNOWN-VULN-001"]
    assert "it is fixed in 2025.7.1" in finding.evidence
    assert "deprecated" not in finding.evidence


def test_a_package_off_the_list_keeps_its_plain_wording(tmp_path: Path) -> None:
    """A date version is current on PyPI (mcp-server-git still publishes them), and
    a date-shaped fix of any other package says nothing about deprecation."""
    _cache([{"id": "GHSA-dddd-eeee-ffff", "aliases": ["CVE-2026-90098"], "affected": [
        {"package": {"ecosystem": "PyPI", "name": "mcp-server-git"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2026.1.14"}]}]}]}])
    (tmp_path / "uv.lock").write_text('version = 1\n\n[[package]]\nname = "mcp-server-git"\nversion = "2025.7.1"\n')
    (finding,) = [f for f in run_scan(tmp_path).findings if f.rule_id == "AAK-KNOWN-VULN-001"]
    assert "it is fixed in 2026.1.14" in finding.evidence and "deprecated" not in finding.evidence


def test_the_reviewed_list_says_what_was_read() -> None:
    doc = json.loads((REPO / "agent_audit_kit" / "data" / "date_line_packages.json").read_text())
    assert doc["read_on"] and doc["source"].startswith("https://registry.npmjs.org/")
    names = [row["name"] for row in doc["packages"]]
    assert names == [f"@modelcontextprotocol/server-{n}" for n in
                     ("everything", "filesystem", "memory", "sequential-thinking")]
    for row in doc["packages"]:
        assert row["ecosystem"] == "npm" and row["semver_from"] == "1.0.0"
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", row["semver_published"])
        assert "resumed semantic versioning" in row["npm_deprecation"]
        first, line, top, latest = (version_order("npm", row[k]) for k in
                                    ("semver_from", "date_line_from", "date_line_top", "latest_read"))
        assert first < latest < line <= top


def test_a_missing_list_costs_the_note_and_not_the_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    def refused(*_: object, **__: object) -> str:
        raise OSError("gone")

    known_vulns._date_line_packages.cache_clear()
    with monkeypatch.context() as patched:
        patched.setattr(Path, "read_text", refused)
        assert known_vulns._date_line_packages() == {}
    known_vulns._date_line_packages.cache_clear()


_DATE_PIN_RE = re.compile(r"@modelcontextprotocol/server-[\w-]+@20\d\d\.")


def test_no_remediation_recommends_a_date_version_of_a_reference_server() -> None:
    offenders = [rule_id for rule_id, rule in RULES.items() if _DATE_PIN_RE.search(rule.remediation)]
    assert offenders == []


@pytest.mark.parametrize("rule_id", ["AAK-MCP-007", "AAK-SUPPLY-001"])
def test_the_pin_rules_name_the_switch_and_what_a_launcher_pin_misses(rule_id: str) -> None:
    text = RULES[rule_id].remediation
    assert "some-mcp-server@1.4.2" in text and "semantic versioning in October 2026" in text
    assert "lockfile install or an image digest" in text and "--readOnly" in text


def test_the_published_rule_text_drops_the_version_npm_never_had() -> None:
    for name in ("rules.json", "docs/rules.md"):
        assert "2025.1.1" not in (REPO / name).read_text(), name
