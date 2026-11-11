"""#1167, #1169, #1172, #1173 and #1182 (n8n), and #1179 and #1180 (network-ai).

Five VulnCheck records for npm `n8n`, which the watcher filed `pin floor stale` against
AAK-MCP-N8N-CVE-2026-72768-001, and two for npm `network-ai`, filed against
AAK-MCP-NETWORKAI-CVE-2026-109332-001. The n8n flaws are not on n8n's MCP surface, so
they reach AAK-KNOWN-VULN-001 after `aak update` and the MCP rule keeps its floor. The
network-ai flaws are a new rule. The NVD API records are saved unedited under
tests/fixtures/nvd_cna, read on 2026-11-11. `CHANGELOG.cves.md` holds the reasoning.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_audit_kit import advisory_feed, nvd_feed
from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import known_vulns, mcp_cve_pins_2026_07
from agent_audit_kit.scanners.known_vulns import evidence_cves

FIXTURES = Path(__file__).parent / "fixtures"
NVD_CNA = FIXTURES / "nvd_cna"
CVE_FIXTURES = FIXTURES / "cves" / "cve-2026-120311-network-ai"
LEDGER = Path(__file__).resolve().parent.parent / "CHANGELOG.cves.md"
FEED_RULE = "AAK-KNOWN-VULN-001"
N8N = "AAK-MCP-N8N-CVE-2026-72768-001"
NETWORKAI = "AAK-NETWORKAI-CVE-2026-120311-001"
N8N_CVES = ["CVE-2026-118643", "CVE-2026-118644", "CVE-2026-118645", "CVE-2026-118647", "CVE-2026-118649"]
NETWORKAI_CVES = ["CVE-2026-120311", "CVE-2026-120312"]


def _cache(*cves: str) -> None:
    """Write the records to the feed cache as `aak update` converts them (HOME is per test)."""
    entries = []
    for cve in cves:
        (vuln,) = json.loads((NVD_CNA / f"{cve}.json").read_text())["vulnerabilities"]
        entries.extend(nvd_feed.record_entries(vuln, nvd_feed.load_package_map(), nvd_feed.Tally()))
    path = advisory_feed.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"generated_at": "t", "source": "test", "records": [],
                                "nvd": nvd_feed.merged(entries)}))


def _lockfile(root: Path, name: str, version: str) -> None:
    (root / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": {f"node_modules/{name}": {"version": version}}}))


def _feed_cves(root: Path) -> dict[str, Severity]:
    found: dict[str, Severity] = {}
    for f in run_scan(root).findings:
        if f.rule_id == FEED_RULE:
            for cve in evidence_cves(f.evidence):
                found[cve] = f.severity
    return found


# --- n8n: advisory feed after `aak update`, no pin -------------------------------------

# Three records share the same three ranges: below 1.123.85, 2.0.0 below 2.43.5 and
# 2.44.0 below 2.44.1. The 2.41.x and 2.42.x lines have no fixed release.
_THREE_LINES = [("1.123.84", True), ("1.123.85", False), ("2.41.4", True), ("2.41.7", True),
                ("2.42.7", True), ("2.43.4", True), ("2.43.5", False), ("2.44.0", True),
                ("2.44.1", False), ("2.45.0", False)]
_CASES = (
    [("CVE-2026-118643", v, fires) for v, fires in _THREE_LINES]
    + [("CVE-2026-118645", v, fires) for v, fires in _THREE_LINES]
    + [("CVE-2026-118647", v, fires) for v, fires in _THREE_LINES]
    # The Data Table record: below 2.43.5 and 2.44.0 below 2.44.1, every 1.x release too.
    + [("CVE-2026-118649", v, fires) for v, fires in [
        ("1.123.85", True), ("2.41.4", True), ("2.43.4", True), ("2.43.5", False), ("2.44.0", True),
        ("2.44.1", False), ("2.47.3", False)]]
    # The error-workflow record: below 2.41.5 and 2.42.0 below 2.42.2.
    + [("CVE-2026-118644", v, fires) for v, fires in [
        ("1.123.85", True), ("2.41.4", True), ("2.41.5", False), ("2.42.0", True), ("2.42.1", True),
        ("2.42.2", False), ("2.43.0", False)]]
)


@pytest.mark.parametrize("cve,version,fires", _CASES)
def test_each_n8n_record_reaches_the_advisory_feed_rule(tmp_path: Path, cve: str, version: str,
                                                         fires: bool) -> None:
    _cache(cve)
    _lockfile(tmp_path, "n8n", version)
    found = _feed_cves(tmp_path)
    assert (cve in found) is fires
    if fires:
        assert found[cve] is Severity.HIGH


def test_the_releases_the_watcher_named_are_reported_with_all_five_cached(tmp_path: Path) -> None:
    """2.41.4 sits on the MCP rule's floor: no pin reports it, the feed reports all five."""
    _cache(*N8N_CVES)
    _lockfile(tmp_path, "n8n", "2.41.4")
    result = run_scan(tmp_path)
    assert sorted(cve for f in result.findings if f.rule_id == FEED_RULE for cve in evidence_cves(f.evidence)) \
        == N8N_CVES
    assert not [f for f in result.findings if f.rule_id.startswith("AAK-MCP-N8N-")]


def test_without_aak_update_the_n8n_records_are_not_reported(tmp_path: Path) -> None:
    _lockfile(tmp_path, "n8n", "2.43.4")
    assert not set(_feed_cves(tmp_path)) & set(N8N_CVES)


def test_the_bundled_feed_holds_none_of_the_n8n_records() -> None:
    """The bundled feed is held to the pins (tests/test_pin_floors_vs_advisories.py)."""
    text = advisory_feed.BUNDLED_FEED.read_text()
    assert [cve for cve in N8N_CVES + NETWORKAI_CVES if cve in text] == []


def test_the_n8n_mcp_rules_keep_their_floors_and_claim_none_of_the_records() -> None:
    for rule_id in ("AAK-MCP-N8N-CVE-2026-59207-001", N8N):
        (pin,) = [p for p in mcp_cve_pins_2026_07._PINS if p.rule_id == rule_id]
        assert (pin.floor, pin.also) == ((2, 41, 4), (((2, 42, 0), (2, 42, 1)),))
    named = {cve for rule_id, rule in RULES.items() if rule_id.startswith("AAK-MCP-N8N")
             for cve in rule.cve_references}
    assert not named & set(N8N_CVES)


def test_the_saved_n8n_records_name_the_package_by_its_package_url() -> None:
    for cve in N8N_CVES:
        (vuln,) = json.loads((NVD_CNA / f"{cve}.json").read_text())["vulnerabilities"]
        entries = nvd_feed.record_entries(vuln, nvd_feed.load_package_map(), nvd_feed.Tally())
        assert {(e["ecosystem"], e["name"], e["mapped_by"]) for e in entries} == {("npm", "n8n", "packageURL")}, cve


# --- network-ai: a new rule --------------------------------------------------------------

def test_the_network_ai_rule_is_registered_as_its_own_high_rule() -> None:
    rule = RULES[NETWORKAI]
    assert rule.severity is Severity.HIGH
    assert rule.cve_references == NETWORKAI_CVES
    assert rule.owasp_mcp_references == []      # no MCP tool, hook or CLI reaches the flaw
    for other in ("AAK-MCP-NETWORKAI-CVE-2026-109331-001", "AAK-MCP-NETWORKAI-CVE-2026-109332-001"):
        assert not set(RULES[other].cve_references) & set(NETWORKAI_CVES)


def test_network_ai_fixtures_positive_and_negative() -> None:
    fired = [f for f in mcp_cve_pins_2026_07.scan(CVE_FIXTURES / "vulnerable")[0] if f.rule_id == NETWORKAI]
    assert [(f.file_path, f.severity) for f in fired] == [("package.json", Severity.HIGH)]
    assert NETWORKAI not in {f.rule_id for f in mcp_cve_pins_2026_07.scan(CVE_FIXTURES / "negative")[0]}


@pytest.mark.parametrize("version,fires", [
    ("4.15.3", False),   # neither module ships yet
    ("5.0.0", True),     # both modules arrive with the unchecked join
    ("5.13.3", True),    # below both records' 5.13.4, same code
    ("5.13.4", True),
    ("5.15.4", True),    # the last affected release
    ("5.15.5", False),   # InputSanitizer.safeChildPath
    ("6.0.1", False),    # latest on 2026-11-11
    ("^5.15.0", True),   # admits 5.15.0 to 5.15.4
    ("^5.15.5", False),
    ("latest", False),   # resolves to 6.0.1: a stated version is required
])
def test_network_ai_versions(tmp_path: Path, version: str, fires: bool) -> None:
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"network-ai": version}}))
    assert (NETWORKAI in {f.rule_id for f in mcp_cve_pins_2026_07.scan(tmp_path)[0]}) is fires


def test_the_records_say_5_13_4_and_the_rule_starts_at_5_0_0() -> None:
    for cve in NETWORKAI_CVES:
        (vuln,) = json.loads((NVD_CNA / f"{cve}.json").read_text())["vulnerabilities"]
        (entry,) = nvd_feed.record_entries(vuln, nvd_feed.load_package_map(), nvd_feed.Tally())
        assert (entry["name"], entry["ranges"]) == ("network-ai", [{"introduced": "5.13.4", "fixed": "5.15.5"}])
    (pin,) = [p for p in mcp_cve_pins_2026_07._PINS if p.rule_id == NETWORKAI]
    assert (pin.introduced, pin.floor, pin.requires_version, pin.ecosystem) == ((5, 0, 0), (5, 15, 5), True, "js")


@pytest.mark.parametrize("version,feed", [("5.13.3", False), ("5.14.0", True), ("5.15.4", True)])
def test_after_aak_update_the_feed_stands_down_where_the_rule_reports(tmp_path: Path, version: str,
                                                                       feed: bool) -> None:
    """The feed reads the records' range, 5.13.4 to 5.15.4, and would miss 5.13.3. Where it
    does fire, the rule reports both CVEs on the same line, so AAK-KNOWN-VULN-001 stands down."""
    _cache(*NETWORKAI_CVES)
    _lockfile(tmp_path, "network-ai", version)
    raw = {cve for f in known_vulns.scan(tmp_path)[0] if f.rule_id == FEED_RULE for cve in evidence_cves(f.evidence)}
    assert (set(NETWORKAI_CVES) <= raw) is feed
    found = run_scan(tmp_path).findings
    assert NETWORKAI in {f.rule_id for f in found}
    assert not [f for f in found if f.rule_id == FEED_RULE and set(evidence_cves(f.evidence)) & set(NETWORKAI_CVES)]


# --- the ledger ----------------------------------------------------------------------------

@pytest.mark.parametrize("issue,cve", [
    ("#1167", "CVE-2026-118645"), ("#1169", "CVE-2026-118649"), ("#1172", "CVE-2026-118643"),
    ("#1173", "CVE-2026-118647"), ("#1182", "CVE-2026-118644"), ("#1179", "CVE-2026-120311"),
    ("#1180", "CVE-2026-120312"),
])
def test_every_issue_has_one_ledger_row(issue: str, cve: str) -> None:
    rows = [line for line in LEDGER.read_text().splitlines() if line.startswith(f"| {cve} ")]
    assert len(rows) == 1 and rows[0].rstrip().endswith(f"| {issue} |")
    assert "out of scope" not in rows[0].lower()
