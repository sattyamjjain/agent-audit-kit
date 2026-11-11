"""2026-11-11 wave, group "tssdk": #1223 and two records the watcher held, all three on
the MCP TypeScript SDK, read on 2026-11-11.

CVE-2026-111770 (#1223, the 2.x server delivers one HTTP client's messages to another),
CVE-2026-111771 (server bearer authentication takes a token issued for another service)
and CVE-2026-111769 (the HTTP client follows a cross-origin redirect with its headers and
body) each get a rule of their own. The OSV record of each advisory is saved unedited
under its fixture's `osv/`, as `https://api.osv.dev/v1/vulns/<id>` returned it on
2026-11-11; a test that needs the feed `aak update` writes builds it from those records,
in the empty HOME every test gets. `CHANGELOG.cves.md` holds the reasoning. Nothing here
touches the network.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_audit_kit import advisory_feed
from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import known_vulns, mcp_cve_pins_2026_07

SHARED_RULE = "AAK-MCP-TSSDK-CVE-2026-111770-001"
AUDIENCE_RULE = "AAK-MCP-TSSDK-CVE-2026-111771-001"
REDIRECT_RULE = "AAK-MCP-TSSDK-CVE-2026-111769-001"
MEMORY_RULE = "AAK-MCP-TSSDK-CVE-2026-111768-001"
TASKS_RULE = "AAK-MCP-TSSDK-CVE-2026-111767-001"
ISSUER_RULE = "AAK-MCP-TSSDK-CVE-2026-104850-001"
KNOWN_VULN_RULE = "AAK-KNOWN-VULN-001"

SHARED_GHSA, AUDIENCE_GHSA, REDIRECT_GHSA = "GHSA-jm63-cq47-j5jp", "GHSA-rvq5-wwqv-78pq", "GHSA-6prh-2h8m-c8cw"

HERE = Path(__file__).parent
CVES = HERE / "fixtures" / "cves"
SHARED = CVES / "cve-2026-111770-tssdk-shared-server"
AUDIENCE = CVES / "cve-2026-111771-tssdk-bearer-audience"
REDIRECT = CVES / "cve-2026-111769-tssdk-redirects"
OSV_RECORDS = {SHARED_GHSA: SHARED, AUDIENCE_GHSA: AUDIENCE, REDIRECT_GHSA: REDIRECT}
LEDGER = HERE.parent / "CHANGELOG.cves.md"

SDK, SERVER, CLIENT = "@modelcontextprotocol/sdk", "@modelcontextprotocol/server", "@modelcontextprotocol/client"
EXPRESS, LEGACY = "@modelcontextprotocol/express", "@modelcontextprotocol/server-legacy"


def _pin_ids(root: Path) -> set[str]:
    return {f.rule_id for f in mcp_cve_pins_2026_07.scan(root)[0]}


def _placed(root: Path, rule_id: str) -> list[tuple[str, int | None]]:
    return sorted((f.file_path, f.line_number) for f in mcp_cve_pins_2026_07.scan(root)[0] if f.rule_id == rule_id)


def _package_json(root: Path, name: str, version: str) -> Path:
    (root / "package.json").write_text(json.dumps({"dependencies": {name: version}}), encoding="utf-8")
    return root


def _rows(rule_id: str) -> list[tuple[str, tuple[int, int, int] | None, tuple[int, int, int] | None]]:
    return [(p.names[0], p.introduced, p.floor) for p in mcp_cve_pins_2026_07._PINS if p.rule_id == rule_id]


def _cache_feed() -> None:
    """The cached feed `aak update` writes, holding the three advisories: each is handed
    to the collector once per export that lists one of its packages."""
    collector = advisory_feed.Collector()
    for ghsa, root in OSV_RECORDS.items():
        record = json.loads((root / "osv" / f"{ghsa}.json").read_text(encoding="utf-8"))
        for ecosystem in sorted({a["package"]["ecosystem"] for a in record["affected"]}):
            collector.add(ecosystem, record)
    collector.write()


# --- the three rules ----------------------------------------------------------------


@pytest.mark.parametrize(("rule_id", "severity", "cve"), [
    (SHARED_RULE, Severity.HIGH, "CVE-2026-111770"),
    (AUDIENCE_RULE, Severity.MEDIUM, "CVE-2026-111771"),
    (REDIRECT_RULE, Severity.MEDIUM, "CVE-2026-111769"),
])
def test_each_rule_carries_its_cve_and_severity(rule_id: str, severity: Severity, cve: str) -> None:
    rule = RULES[rule_id]
    assert rule.cve_references == [cve]
    assert rule.severity is severity
    assert rule.category.value == "supply-chain"
    assert rule.aicm_references


@pytest.mark.parametrize(("rule_id", "rows"), [
    (SHARED_RULE, [(SERVER, (2, 0, 0), (2, 3, 0))]),
    (AUDIENCE_RULE, [(SDK, (1, 6, 0), (1, 32, 0)), (SERVER, (2, 0, 0), (2, 3, 0)),
                     (EXPRESS, (2, 0, 0), (2, 0, 2)), (LEGACY, (2, 0, 0), (2, 3, 1))]),
    (REDIRECT_RULE, [(SDK, None, (1, 32, 0)), (CLIENT, (2, 0, 0), (2, 3, 0))]),
])
def test_the_pin_rows(rule_id: str, rows: list) -> None:
    assert _rows(rule_id) == rows
    pins = [p for p in mcp_cve_pins_2026_07._PINS if p.rule_id == rule_id]
    assert all(p.requires_version and p.ecosystem == "js" for p in pins)


def test_the_pin_module_lists_the_three_rules() -> None:
    doc = mcp_cve_pins_2026_07.__doc__ or ""
    assert all(cve in doc for cve in ("CVE-2026-111770", "CVE-2026-111771", "CVE-2026-111769"))


def test_the_remediations_name_the_code_change_each_needs() -> None:
    assert "per session" in RULES[SHARED_RULE].remediation
    assert "upgrading alone changes nothing" in RULES[AUDIENCE_RULE].remediation
    assert "expectedResource" in RULES[AUDIENCE_RULE].remediation
    assert "redirectPolicy: 'follow'" in RULES[REDIRECT_RULE].remediation


def test_the_shared_server_rule_says_the_1x_sdk_is_not_read() -> None:
    limitations = RULES[SHARED_RULE].limitations
    assert "`@modelcontextprotocol/sdk` is not read" in limitations and "1.26.0" in limitations


# --- #1223: CVE-2026-111770, the 2.x server shared by several clients ---------------


def test_shared_server_fixtures() -> None:
    assert _placed(SHARED / "vulnerable", SHARED_RULE) == [("package.json", 6)]
    assert SHARED_RULE not in _pin_ids(SHARED / "negative")
    assert SHARED_RULE in {f.rule_id for f in run_scan(SHARED / "vulnerable").findings}


def test_the_1x_sdk_is_not_read_for_the_shared_server() -> None:
    """The advisory names only the 2.x server, and sdk 1.26.0 and later refuse a second
    connect and a reused stateless transport (checked at 1.26.0 and 1.31.0). The other
    SDK rules still read 1.31.0."""
    ids = _pin_ids(SHARED / "negative-sdk-1x")
    assert SHARED_RULE not in ids
    assert {TASKS_RULE, MEMORY_RULE, AUDIENCE_RULE, REDIRECT_RULE} <= ids


@pytest.mark.parametrize(("version", "fires"), [
    ("2.0.0-alpha.1", True),  # reads as 2.0.0
    ("2.0.0", True),          # the first release; no guard in the tarball
    ("2.1.0", True),
    ("2.2.0", True),          # newest affected; no guard in the tarball
    ("^2.2.0", True),         # admits 2.2.x
    ("2.3.0", False),         # refuses a second connect and a reused stateless transport
    ("2.4.0", False),         # latest on 2026-11-11
    ("latest", False),
])
def test_the_shared_server_pin(tmp_path: Path, version: str, fires: bool) -> None:
    assert (SHARED_RULE in _pin_ids(_package_json(tmp_path, SERVER, version))) is fires


# --- CVE-2026-111771: bearer authentication without an audience check --------------


def test_bearer_audience_fixtures() -> None:
    assert _placed(AUDIENCE / "vulnerable", AUDIENCE_RULE) == [
        ("package-lock.json", 16), ("package-lock.json", 20), ("package-lock.json", 24)]
    assert _placed(AUDIENCE / "oldest", AUDIENCE_RULE) == [("package.json", 6)]
    assert AUDIENCE_RULE not in _pin_ids(AUDIENCE / "negative")
    assert AUDIENCE_RULE not in _pin_ids(AUDIENCE / "negative-before-bearer")
    assert AUDIENCE_RULE in {f.rule_id for f in run_scan(AUDIENCE / "vulnerable").findings}


@pytest.mark.parametrize(("name", "version", "fires"), [
    (SDK, "1.5.0", False),       # no bearer middleware in the tarball
    (SDK, "1.6.0", True),        # requireBearerAuth first ships
    (SDK, "1.31.0", True),       # no audience option
    (SDK, "1.32.0", False),      # expectedResource
    (SDK, "latest", False),
    (SERVER, "2.0.0", True),
    (SERVER, "2.2.0", True),
    (SERVER, "2.3.0", False),
    (EXPRESS, "2.0.0", True),
    (EXPRESS, "2.0.1", True),
    (EXPRESS, "2.0.2", False),   # latest on 2026-11-11
    (LEGACY, "2.0.0", True),
    (LEGACY, "2.3.0", True),     # the server package is fixed here, server-legacy is not
    (LEGACY, "2.3.1", False),
    (LEGACY, "2.4.0", False),
])
def test_the_bearer_audience_pins(tmp_path: Path, name: str, version: str, fires: bool) -> None:
    assert (AUDIENCE_RULE in _pin_ids(_package_json(tmp_path, name, version))) is fires


# --- CVE-2026-111769: the HTTP client follows a cross-origin redirect ---------------


def test_redirect_fixtures() -> None:
    assert _placed(REDIRECT / "vulnerable", REDIRECT_RULE) == [("package-lock.json", 14)]
    assert _placed(REDIRECT / "oldest", REDIRECT_RULE) == [("package.json", 6)]
    assert REDIRECT_RULE not in _pin_ids(REDIRECT / "negative")
    assert REDIRECT_RULE in {f.rule_id for f in run_scan(REDIRECT / "vulnerable").findings}


@pytest.mark.parametrize(("name", "version", "fires"), [
    (SDK, "0.4.0", True),        # the first release posts through fetch's default redirect handling
    (SDK, "1.0.4", True),        # no custom headers yet; a 307 or 308 still re-sends the body
    (SDK, "1.1.0", True),        # the SSE client takes requestInit headers
    (SDK, "1.31.0", True),
    (SDK, "1.32.0", False),      # redirects followed only within the origin
    (SDK, "1.32.2", False),      # latest on 2026-11-11
    (CLIENT, "2.0.0", True),
    (CLIENT, "2.2.0", True),     # fixed for the OAuth issuer pin, affected here
    (CLIENT, "2.3.0", False),
    (CLIENT, "latest", False),
])
def test_the_redirect_pins(tmp_path: Path, name: str, version: str, fires: bool) -> None:
    assert (REDIRECT_RULE in _pin_ids(_package_json(tmp_path, name, version))) is fires


def test_client_2_2_0_fires_without_the_issuer_pin(tmp_path: Path) -> None:
    ids = _pin_ids(_package_json(tmp_path, CLIENT, "2.2.0"))
    assert REDIRECT_RULE in ids and ISSUER_RULE not in ids


# --- the advisory feed --------------------------------------------------------------


@pytest.mark.parametrize("root", [SHARED / "vulnerable", AUDIENCE / "vulnerable", AUDIENCE / "oldest",
                                  REDIRECT / "vulnerable", REDIRECT / "oldest"])
def test_the_bundled_feed_holds_none_of_the_three(root: Path) -> None:
    assert known_vulns.scan(root)[0] == []


@pytest.mark.parametrize(("root", "ghsas"), [
    (SHARED / "vulnerable", {SHARED_GHSA, AUDIENCE_GHSA}),
    (AUDIENCE / "vulnerable", {SHARED_GHSA, AUDIENCE_GHSA}),
    (AUDIENCE / "oldest", {AUDIENCE_GHSA, REDIRECT_GHSA}),
    (REDIRECT / "vulnerable", {REDIRECT_GHSA}),
    (REDIRECT / "oldest", {REDIRECT_GHSA}),
])
def test_after_aak_update_the_feed_stands_down_for_the_rules(root: Path, ghsas: set[str]) -> None:
    """OSV holds all three advisories, so AAK-KNOWN-VULN-001 reports them once `aak update`
    has run. Each rule reports its CVE on the same line at the advisory's severity or
    above, so the engine drops the feed's finding and the project sees one per flaw."""
    _cache_feed()
    reported = {g for f in known_vulns.scan(root)[0] for g in OSV_RECORDS if g in f.evidence}
    assert reported == ghsas
    assert KNOWN_VULN_RULE not in {f.rule_id for f in run_scan(root).findings}


def test_after_aak_update_a_fixed_release_gets_nothing(tmp_path: Path) -> None:
    _cache_feed()
    for root in (SHARED / "negative", AUDIENCE / "negative", REDIRECT / "negative"):
        assert known_vulns.scan(root)[0] == []


# --- the ledger ---------------------------------------------------------------------


@pytest.mark.parametrize(("cve", "issue", "rule_id"), [
    ("CVE-2026-111770", "#1223", SHARED_RULE),
    ("CVE-2026-111771", "not filed", AUDIENCE_RULE),
    ("CVE-2026-111769", "not filed", REDIRECT_RULE),
])
def test_each_cve_has_one_covered_ledger_row(cve: str, issue: str, rule_id: str) -> None:
    rows = [line for line in LEDGER.read_text(encoding="utf-8").splitlines() if line.startswith(f"| {cve} ")]
    assert len(rows) == 1
    (row,) = rows
    assert row.rstrip().endswith(f"| {issue} |")
    assert f"`{rule_id}`" in row and "out of scope" not in row.lower()
