"""2026-11-14 wave, group "contextforge": eight held IBM ContextForge MCP Gateway records.

IBM published all eight on 2026-11-13, each with a security bulletin that names the fixed
release. Every range below was read on 2026-11-14 in the PyPI wheels of
mcp-contextforge-gateway (0.5.0, 0.6.0, 0.7.0, 0.8.0, 0.9.0, 1.0.0, 1.0.7,
1.0.7.post20260921, 1.0.8, 1.0.9, 1.0.11, 1.1.0 and 1.1.1), and the image tags on GHCR
(`latest` and v1.1.1 were one digest, whose label names the v1.1.1 tag's commit).

* Fixed in 1.1.0, MEDIUM, inside the range of AAK-MCP-CONTEXTFORGE-CVE-2026-18484-001
  (0.7.0 below 1.1.0), so they join it: CVE-2026-110178 (the import's `update` strategy
  checks no owner, from 0.7.0), CVE-2026-110194 (DCR endpoints from the authorization
  server's metadata go unchecked, from 0.8.0), CVE-2026-110195 (the token exchange cache
  key leaves out the inbound JWT, by 1.0.7), CVE-2026-110199 (the Admin UI banner writes
  `?error=` as HTML, from 0.8.0) and CVE-2026-94407 (schema `pattern` runs unbounded,
  from 0.9.0).
* Fixed only in 1.1.1: CVE-2026-110279 (HIGH, X-Upstream-Authorization replaces the
  gateway's upstream credential, from 0.8.0) and CVE-2026-110278 (HIGH, identity headers
  skip the per-gateway setting, from 1.0.0) get AAK-MCP-CONTEXTFORGE-CVE-2026-110279-001,
  0.8.0 below 1.1.1, and CVE-2026-110189 (MEDIUM, the jq guard 1.0.8 added misses
  `halt` and the loop built-ins, 1.0.8 to 1.1.0) shares their fix and range, so it joins
  that rule.

NVD's records are saved unedited under tests/fixtures/nvd_cna as the API returned them
on 2026-11-14. OSV has no record of any of them and none for the package at 1.0.11 or
1.1.0, so only these rules report them. `CHANGELOG.cves.md` holds the reasoning. Nothing
here touches the network.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agent_audit_kit import advisory_feed, nvd_feed
from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Category, Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import container_image_pins, mcp_cve_pins_2026_07

UPSTREAM_PIN = "AAK-MCP-CONTEXTFORGE-CVE-2026-110279-001"
MEDIUM_PIN = "AAK-MCP-CONTEXTFORGE-CVE-2026-18484-001"
CRITICAL_PIN = "AAK-MCP-CONTEXTFORGE-CVE-2026-77822-001"
CONTEXTFORGE_RULES = {UPSTREAM_PIN, MEDIUM_PIN, CRITICAL_PIN}
IMAGE = "ghcr.io/ibm/mcp-context-forge"

JOINED_MEDIUM = ("CVE-2026-110178", "CVE-2026-110194", "CVE-2026-110195", "CVE-2026-110199",
                 "CVE-2026-94407")
ON_THE_NEW_RULE = ("CVE-2026-110279", "CVE-2026-110278", "CVE-2026-110189")
RECORDS = JOINED_MEDIUM + ON_THE_NEW_RULE
# CVSS 3.1 from IBM's records (NVD's Primary metric), and the release each bulletin fixes.
SCORES = {
    "CVE-2026-110178": 4.1, "CVE-2026-110194": 5.4, "CVE-2026-110195": 5.4,
    "CVE-2026-110199": 4.8, "CVE-2026-94407": 6.5, "CVE-2026-110279": 8.1,
    "CVE-2026-110278": 7.4, "CVE-2026-110189": 6.5,
}

HERE = Path(__file__).resolve().parent
CVES = HERE / "fixtures" / "cves"
NVD_CNA = HERE / "fixtures" / "nvd_cna"
LEDGER = HERE.parent / "CHANGELOG.cves.md"


def _pins(root: Path) -> list:
    return mcp_cve_pins_2026_07.scan(root)[0] + container_image_pins.scan(root)[0]


def _ids(root: Path) -> set[str]:
    return {f.rule_id for f in _pins(root)} & CONTEXTFORGE_RULES


def _write(root: Path, name: str, content: str) -> set[str]:
    (root / name).write_text(content, encoding="utf-8")
    return _ids(root)


def _rows(rule_id: str) -> list[tuple]:
    return [(p.names, p.floor, p.introduced, p.requires_version, p.ecosystem)
            for p in mcp_cve_pins_2026_07._PINS if p.rule_id == rule_id]


def _image_rows(rule_id: str) -> list[tuple]:
    return [(p.image, p.floor, p.introduced, p.floating_affected, p.cves)
            for p in container_image_pins._PINS if p.rule_id == rule_id]


def _nvd_record(cve: str) -> dict[str, Any]:
    (vuln,) = json.loads((NVD_CNA / f"{cve}.json").read_text(encoding="utf-8"))["vulnerabilities"]
    return vuln


# ---- the rules -------------------------------------------------------------------------------


def test_the_new_rule_is_high_and_names_its_three_records() -> None:
    rule = RULES[UPSTREAM_PIN]
    assert rule.severity is Severity.HIGH
    assert rule.category is Category.SUPPLY_CHAIN
    assert rule.cve_references == list(ON_THE_NEW_RULE)
    assert all(cve in rule.description for cve in ON_THE_NEW_RULE)
    assert "MCP07:2025" in rule.owasp_mcp_references and "ASI03" in rule.owasp_agentic_references


def test_the_medium_rule_takes_the_five_records_fixed_in_1_1_0() -> None:
    """Same fix release and severity band, every affected release inside its range: the
    records join it rather than a second rule that would report 0.7.0 to 1.0.11 twice."""
    rule = RULES[MEDIUM_PIN]
    assert rule.severity is Severity.MEDIUM
    assert rule.cve_references == ["CVE-2026-18484", *JOINED_MEDIUM]
    assert all(cve in rule.description for cve in JOINED_MEDIUM)
    assert "fixed in 1.1.0" in rule.title


@pytest.mark.parametrize("cve", RECORDS)
def test_each_record_is_on_one_rule(cve: str) -> None:
    """The CRITICAL 1.0.9 rule keeps its nine: these are fixed above its floor, and a floor
    raise there would report 1.0.9 to 1.1.0 at CRITICAL under flaws fixed by 1.0.9."""
    owner = MEDIUM_PIN if cve in JOINED_MEDIUM else UPSTREAM_PIN
    assert [rid for rid, rule in RULES.items() if cve in rule.cve_references] == [owner]
    assert cve not in RULES[CRITICAL_PIN].cve_references


def test_the_pin_rows() -> None:
    """The new rule starts at 0.8.0, where the X-Upstream-Authorization rename arrives
    (0.7.0 has no such header); the 1.1.0 row does not move. `latest` is 1.1.1, fixed, so
    both require a stated version."""
    assert _rows(UPSTREAM_PIN) == [(("mcp-contextforge-gateway",), (1, 1, 1), (0, 8, 0), True, "py")]
    assert _rows(MEDIUM_PIN) == [(("mcp-contextforge-gateway",), (1, 1, 0), (0, 7, 0), True, "py")]
    assert _rows(CRITICAL_PIN) == [(("mcp-contextforge-gateway",), (1, 0, 9), None, False, None)]


def test_the_image_rows() -> None:
    assert _image_rows(UPSTREAM_PIN) == [(IMAGE, (1, 1, 1), (0, 8, 0), False, ON_THE_NEW_RULE)]
    assert _image_rows(MEDIUM_PIN) == [
        (IMAGE, (1, 1, 0), (0, 7, 0), False, ("CVE-2026-18484", *JOINED_MEDIUM))]


# ---- fixtures --------------------------------------------------------------------------------

# (fixture, rule, where the vulnerable tree reports it, what the negative tree still gets)
FIXTURES = [
    ("cve-2026-110279-contextforge", UPSTREAM_PIN,
     {("requirements.txt", 3), ("values.yaml", 5)}, set()),
    ("cve-2026-110278-contextforge", UPSTREAM_PIN, {("pyproject.toml", 6)}, set()),
    ("cve-2026-110189-contextforge", UPSTREAM_PIN, {("docker-compose.yml", 4)}, set()),
    # 1.1.0 fixes the MEDIUM rule's flaws and is still below the new rule's 1.1.1 floor.
    ("cve-2026-110178-contextforge", MEDIUM_PIN, {("requirements.txt", 3)}, {UPSTREAM_PIN}),
    ("cve-2026-110194-contextforge", MEDIUM_PIN, {("Dockerfile", 2)}, {UPSTREAM_PIN}),
    ("cve-2026-110195-contextforge", MEDIUM_PIN, {("requirements.txt", 2)}, {UPSTREAM_PIN}),
    ("cve-2026-110199-contextforge", MEDIUM_PIN, {("values.yaml", 4)}, {UPSTREAM_PIN}),
    ("cve-2026-94407-contextforge", MEDIUM_PIN, {("requirements.txt", 2)}, {UPSTREAM_PIN}),
]


@pytest.mark.parametrize(("fixture", "rule_id", "where", "negative"), FIXTURES)
def test_fixtures_positive_and_negative(fixture: str, rule_id: str, where: set, negative: set) -> None:
    root = CVES / fixture
    found = [f for f in _pins(root / "vulnerable") if f.rule_id == rule_id]
    assert {(f.file_path, f.line_number) for f in found} == where
    assert rule_id not in _ids(root / "negative")
    assert _ids(root / "negative") == negative


@pytest.mark.parametrize(("fixture", "rule_id", "_where", "_negative"), FIXTURES)
def test_the_finding_survives_the_full_engine(fixture: str, rule_id: str, _where: set, _negative: set) -> None:
    severity = RULES[rule_id].severity
    found = [f for f in run_scan(CVES / fixture / "vulnerable").findings if f.rule_id == rule_id]
    assert found and all(f.severity is severity for f in found)
    assert not [f for f in run_scan(CVES / fixture / "negative").findings if f.rule_id == rule_id]


# ---- versions and tags -----------------------------------------------------------------------


@pytest.mark.parametrize(("version", "expected"), [
    ("0.6.0", {CRITICAL_PIN}),                            # no teams, no DCR, no header rename
    ("0.7.0", {CRITICAL_PIN, MEDIUM_PIN}),                # teams; the import checks no owner
    ("0.8.0", {CRITICAL_PIN, MEDIUM_PIN, UPSTREAM_PIN}),  # X-Upstream-Authorization, DCR, banner
    ("0.9.0", {CRITICAL_PIN, MEDIUM_PIN, UPSTREAM_PIN}),  # results validated against the schema
    ("1.0.0rc1", {CRITICAL_PIN, MEDIUM_PIN, UPSTREAM_PIN}),            # read as 1.0.0
    ("1.0.7.post20260921", {CRITICAL_PIN, MEDIUM_PIN, UPSTREAM_PIN}),  # read as 1.0.7
    ("1.0.8", {CRITICAL_PIN, MEDIUM_PIN, UPSTREAM_PIN}),  # the jq guard arrives, incomplete
    ("1.0.9", {MEDIUM_PIN, UPSTREAM_PIN}),                # the CRITICAL rule's floor
    ("1.0.11", {MEDIUM_PIN, UPSTREAM_PIN}),               # the last release five bulletins list
    ("1.1.0", {UPSTREAM_PIN}),                            # the last release three bulletins list
    ("1.1.1", set()),                                     # #7329, #7341 and the jq denylist
    (">=1.1", {UPSTREAM_PIN}),                            # admits 1.1.0
    ("~=1.1.1", set()),
])
def test_versions(tmp_path: Path, version: str, expected: set[str]) -> None:
    pinned = version if version[0] in "<>=!~" else f"=={version}"
    assert _write(tmp_path, "requirements.txt", f"mcp-contextforge-gateway{pinned}\n") == expected


def test_an_unversioned_reference_is_left_to_the_critical_rule(tmp_path: Path) -> None:
    """`latest` on PyPI is 1.1.1, fixed for both rules here."""
    assert _write(tmp_path, "requirements.txt", "mcp-contextforge-gateway\n") == {CRITICAL_PIN}


@pytest.mark.parametrize(("tag", "expected"), [
    ("0.7.0", {CRITICAL_PIN, MEDIUM_PIN}),
    ("0.8.0", {CRITICAL_PIN, MEDIUM_PIN, UPSTREAM_PIN}),  # the 0.x tags without the `v` too
    ("v0.8.0", {CRITICAL_PIN, MEDIUM_PIN, UPSTREAM_PIN}),
    ("1.0.0-RC-2", {CRITICAL_PIN, MEDIUM_PIN, UPSTREAM_PIN}),
    ("v1.0.7-20260921", {CRITICAL_PIN, MEDIUM_PIN, UPSTREAM_PIN}),
    ("v1.0.11", {MEDIUM_PIN, UPSTREAM_PIN}),
    ("v1.1.0", {UPSTREAM_PIN}),
    ("v1.1.1", set()),
    ("latest", set()),                                    # the v1.1.1 digest on 2026-11-14
    (None, set()),
])
def test_image_tags(tmp_path: Path, tag: str | None, expected: set[str]) -> None:
    ref = IMAGE if tag is None else f"{IMAGE}:{tag}"
    assert _write(tmp_path, "docker-compose.yml", f"services:\n  gateway:\n    image: {ref}\n") == expected


def test_the_image_finding_names_the_three_records(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(f"FROM {IMAGE}:v1.1.0\n", encoding="utf-8")
    (finding,) = [f for f in container_image_pins.scan(tmp_path)[0] if f.rule_id == UPSTREAM_PIN]
    assert all(cve in finding.evidence for cve in ON_THE_NEW_RULE)
    assert "Fixed in 1.1.1." in finding.evidence


# ---- the feeds -------------------------------------------------------------------------------


@pytest.mark.parametrize("cve", RECORDS)
def test_nvds_records_map_to_nothing(cve: str) -> None:
    """IBM's CNA data names the product with a bare version range and no packageURL, and no
    reviewed row maps it, so `aak update` keeps none of them: the pins are the only thing
    that reports these records."""
    vuln = _nvd_record(cve)
    assert vuln["cve"]["id"] == cve and vuln["cve"]["sourceIdentifier"] == "psirt@us.ibm.com"
    (metric,) = vuln["cve"]["metrics"]["cvssMetricV31"]
    assert metric["type"] == "Primary" and metric["cvssData"]["baseScore"] == SCORES[cve]
    assert nvd_feed.record_packages(vuln, nvd_feed.load_package_map()) == []
    assert nvd_feed.record_entries(vuln, nvd_feed.load_package_map(), nvd_feed.Tally(),
                                   launch_rows=nvd_feed.load_launch_map()) == []


def test_no_record_is_bundled() -> None:
    text = advisory_feed.BUNDLED_FEED.read_text(encoding="utf-8")
    assert not any(cve in text for cve in RECORDS)


# ---- the ledger ------------------------------------------------------------------------------


@pytest.mark.parametrize("cve", RECORDS)
def test_each_record_has_one_ledger_row(cve: str) -> None:
    rows = [line for line in LEDGER.read_text(encoding="utf-8").splitlines() if line.startswith(f"| {cve} ")]
    assert len(rows) == 1 and rows[0].rstrip().endswith("| not filed |")
    assert "out of scope" not in rows[0].lower()
    assert (MEDIUM_PIN if cve in JOINED_MEDIUM else UPSTREAM_PIN) in rows[0]
    assert f"| {SCORES[cve]} |" in rows[0]
