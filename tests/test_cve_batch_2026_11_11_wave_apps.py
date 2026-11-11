"""2026-11-11 wave, group "apps": nine held NVD records, read on 2026-11-11.

Six new pins: fast-agent (PyPI), the pgEdge Postgres MCP Server (one HIGH image rule for
three CVEs and two GHSA records that have none), Dagu (the npm launcher and the image),
and the Trawl, SiYuan and ezBookkeeping images. GHSA-7qmf-c45g-5p4q, a Trawl advisory
with no CVE id, joins the Trawl rule. Vikunja is out of scope: its flaw is the app's
API-token check for bot users, reached by every surface, MCP included. NVD's records are
saved unedited under tests/fixtures/nvd_cna and OSV's under tests/fixtures/osv, as the
APIs returned them on 2026-11-11; a test that needs the feed `aak update` writes builds it from those records
in the empty HOME every test gets. `CHANGELOG.cves.md` holds the reasoning. Nothing here
touches the network.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from agent_audit_kit import advisory_feed, nvd_feed
from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import container_image_pins, mcp_cve_pins_2026_07

FASTAGENT_PIN = "AAK-MCP-FASTAGENT-CVE-2026-102610-001"
PGEDGE_PIN = "AAK-MCP-PGEDGE-CVE-2026-125320-001"
DAGU_PIN = "AAK-MCP-DAGU-CVE-2026-102943-001"
TRAWL_PIN = "AAK-MCP-TRAWL-CVE-2026-122140-001"
SIYUAN_PIN = "AAK-MCP-SIYUAN-CVE-2026-123492-001"
SIYUAN_ASSET_PIN = "AAK-MCP-SIYUAN-CVE-2026-116168-001"
EZB_PIN = "AAK-MCP-EZBOOKKEEPING-CVE-2026-86041-001"
KNOWN_VULN_RULE = "AAK-KNOWN-VULN-001"

HERE = Path(__file__).parent
CVES = HERE / "fixtures" / "cves"
OSV = HERE / "fixtures" / "osv"
NVD_CNA = HERE / "fixtures" / "nvd_cna"
LEDGER = HERE.parent / "CHANGELOG.cves.md"
NOW = datetime(2026, 11, 11, 6, 0, tzinfo=timezone.utc)
FASTAGENT_GHSA = "GHSA-9vhv-g5hf-m7m7"
EZB_GHSA = "GHSA-wchh-mrv2-5h4q"
TRAWL_REBIND_GHSA = "GHSA-7qmf-c45g-5p4q"
PGEDGE_READONLY_GHSA = "GHSA-j7mp-839j-jrm7"
PGEDGE_PLDO_GHSA = "GHSA-r5pp-jx86-r6r9"


def _pin_ids(root: Path) -> set[str]:
    return {f.rule_id for f in mcp_cve_pins_2026_07.scan(root)[0]}


def _image_ids(root: Path) -> set[str]:
    return {f.rule_id for f in container_image_pins.scan(root)[0]}


def _compose(root: Path, image: str) -> set[str]:
    (root / "compose.yaml").write_text(f"services:\n  s:\n    image: {image}\n", encoding="utf-8")
    return _image_ids(root)


def _nvd_record(cve: str) -> dict[str, Any]:
    (vuln,) = json.loads((NVD_CNA / f"{cve}.json").read_text(encoding="utf-8"))["vulnerabilities"]
    return vuln


def _cache_osv(*idents: str) -> None:
    """The cached feed `aak update` writes, holding these OSV records: each is handed
    to the collector once per export that lists one of its packages."""
    collector = advisory_feed.Collector()
    for ident in idents:
        record = json.loads((OSV / f"{ident}.json").read_text(encoding="utf-8"))
        for ecosystem in sorted({a["package"]["ecosystem"] for a in record["affected"]}):
            collector.add(ecosystem, record)
    collector.write(now=NOW)


def _cache_nvd(*cves: str) -> None:
    """The cached feed holding only NVD's records, as `nvd_feed` converts them."""
    entries: list[dict[str, Any]] = []
    for cve in cves:
        entries.extend(nvd_feed.merged(nvd_feed.record_entries(
            _nvd_record(cve), nvd_feed.load_package_map(), nvd_feed.Tally())))
    path = advisory_feed.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"generated_at": "t", "source": "test", "records": [], "nvd": entries,
                                "launch": []}))


def _uv_lock(root: Path, name: str, version: str) -> None:
    (root / "uv.lock").write_text(
        f'version = 1\n\n[[package]]\nname = "{name}"\nversion = "{version}"\n'
        'source = { registry = "https://pypi.org/simple" }\n', encoding="utf-8")


@pytest.mark.parametrize(("rule_id", "cves", "severity"), [
    (FASTAGENT_PIN, ["CVE-2026-102610"], Severity.MEDIUM),
    (PGEDGE_PIN, ["CVE-2026-125320", "CVE-2026-125321", "CVE-2026-125322"], Severity.HIGH),
    (DAGU_PIN, ["CVE-2026-102943"], Severity.MEDIUM),
    (TRAWL_PIN, ["CVE-2026-122140"], Severity.MEDIUM),
    (SIYUAN_PIN, ["CVE-2026-123492"], Severity.MEDIUM),
    (EZB_PIN, ["CVE-2026-86041"], Severity.MEDIUM),
])
def test_each_rule_carries_its_cves_and_severity(rule_id: str, cves: list[str], severity: Severity) -> None:
    rule = RULES[rule_id]
    assert rule.cve_references == cves
    assert rule.severity is severity
    assert rule.category.value == "supply-chain"


@pytest.mark.parametrize(("cve", "packages"), [
    ("CVE-2026-125320", []), ("CVE-2026-125321", []), ("CVE-2026-125322", []),
    ("CVE-2026-102943", []), ("CVE-2026-122140", []), ("CVE-2026-102610", []),
    ("CVE-2026-86041", []), ("CVE-2026-123492", []),
    ("CVE-2026-123493", [("Go", "code.vikunja.io/api", "packageURL")]),
])
def test_what_nvds_records_map_to(cve: str, packages: list[tuple[str, str, str]]) -> None:
    """Only Vikunja's CNA data names a package a feed can match. pgEdge, Dagu, fast-agent
    and ezBookkeeping give a bare version range, Trawl a `pkg:github` URL and SiYuan
    neither, so `nvd_feed` keeps none of them and only the pins report them."""
    assert nvd_feed.record_packages(_nvd_record(cve), nvd_feed.load_package_map()) == packages


# --- fast-agent (CVE-2026-102610) ------------------------------------------------------


def test_fast_agent_row() -> None:
    (row,) = [p for p in mcp_cve_pins_2026_07._PINS if p.rule_id == FASTAGENT_PIN]
    assert (row.names, row.introduced, row.floor, row.also, row.requires_version, row.ecosystem) == (
        ("fast-agent-mcp",), (0, 3, 18), (0, 7, 21), (), True, "py",
    )


def test_fast_agent_fixtures_positive_and_negative() -> None:
    root = CVES / "cve-2026-102610-fast-agent"
    assert [(f.rule_id, f.file_path, f.line_number) for f in mcp_cve_pins_2026_07.scan(root / "vulnerable")[0]] == [
        (FASTAGENT_PIN, "requirements.txt", 2),
    ]
    assert _pin_ids(root / "negative") == set()
    assert FASTAGENT_PIN in {f.rule_id for f in run_scan(root / "vulnerable").findings}
    assert FASTAGENT_PIN not in {f.rule_id for f in run_scan(root / "negative").findings}


@pytest.mark.parametrize(("spec", "fires"), [
    ("fast-agent-mcp==0.3.17\n", False),     # no `serve` command in the wheel
    ("fast-agent-mcp==0.3.18\n", True),      # cli/commands/serve.py, --host 0.0.0.0
    ("fast-agent-mcp==0.7.20\n", True),      # the GHSA's last affected release
    ("fast-agent-mcp==0.7.21\n", False),     # DEFAULT_HTTP_HOST = "127.0.0.1"
    ("fast-agent-mcp==0.10.54\n", False),    # latest on 2026-11-11
    ("fast-agent-mcp\n", False),             # resolves to latest, fixed
    ("fast-agent-mcp>=0.7,<0.8\n", True),    # admits 0.7.0 to 0.7.20
    ("fast-agent-mcp~=0.3.18\n", True),
])
def test_fast_agent_versions(tmp_path: Path, spec: str, fires: bool) -> None:
    (tmp_path / "requirements.txt").write_text(spec, encoding="utf-8")
    assert (FASTAGENT_PIN in _pin_ids(tmp_path)) is fires


@pytest.mark.parametrize(("args", "fires"), [
    (["fast-agent-mcp@0.7.20", "serve", "--shell"], True),
    (["--from", "fast-agent-mcp==0.7.20", "fast-agent", "serve"], True),
    (["fast-agent-mcp@latest", "-x"], False),     # the README's own quickstart
    (["fast-agent-mcp==0.7.21", "serve"], False),
])
def test_fast_agent_uvx_launches(tmp_path: Path, args: list[str], fires: bool) -> None:
    (tmp_path / ".mcp.json").write_text(json.dumps(
        {"mcpServers": {"agent": {"command": "uvx", "args": args}}}), encoding="utf-8")
    assert (FASTAGENT_PIN in _pin_ids(tmp_path)) is fires


def test_fast_agent_acp_launcher_is_a_stated_limit(tmp_path: Path) -> None:
    """`fast-agent-acp` requires `fast-agent-mcp` at its own version, but no source names
    it, so it is not matched; a lockfile records the `fast-agent-mcp` it pulls in."""
    (tmp_path / "requirements.txt").write_text("fast-agent-acp==0.7.20\n", encoding="utf-8")
    assert FASTAGENT_PIN not in _pin_ids(tmp_path)
    assert "`fast-agent-acp`, a launcher" in RULES[FASTAGENT_PIN].limitations
    _uv_lock(tmp_path, "fast-agent-mcp", "0.7.20")
    assert FASTAGENT_PIN in _pin_ids(tmp_path)


def test_fast_agent_osv_record_reaches_older_releases_after_an_update(tmp_path: Path) -> None:
    """OSV's record lists every release below 0.7.21. After `aak update` it reports a
    release before `serve` existed through AAK-KNOWN-VULN-001, and stands down where the
    pin reports the same CVE on the same line."""
    record = json.loads((OSV / f"{FASTAGENT_GHSA}.json").read_text(encoding="utf-8"))
    assert record["aliases"] == ["CVE-2026-102610"]
    (affected,) = record["affected"]
    assert affected["package"]["name"] == "fast-agent-mcp"
    assert affected["ranges"][0]["events"] == [{"introduced": "0"}, {"fixed": "0.7.21"}]
    assert "fast-agent-mcp" not in advisory_feed.BUNDLED_FEED.read_text(encoding="utf-8")

    _uv_lock(tmp_path, "fast-agent-mcp", "0.3.10")
    assert not [f for f in run_scan(tmp_path).findings if "CVE-2026-102610" in f.evidence]
    _cache_osv(FASTAGENT_GHSA)
    older = [(f.rule_id, f.severity) for f in run_scan(tmp_path).findings if "CVE-2026-102610" in f.evidence]
    assert older == [(KNOWN_VULN_RULE, Severity.MEDIUM)]

    _uv_lock(tmp_path, "fast-agent-mcp", "0.7.20")
    found = {f.rule_id for f in run_scan(tmp_path).findings
             if f.rule_id in (FASTAGENT_PIN, KNOWN_VULN_RULE)}
    assert found == {FASTAGENT_PIN}
    _uv_lock(tmp_path, "fast-agent-mcp", "0.7.21")
    assert not [f for f in run_scan(tmp_path).findings if f.rule_id in (FASTAGENT_PIN, KNOWN_VULN_RULE)]


# --- pgEdge Postgres MCP Server (CVE-2026-125320, -125321, -125322) --------------------


def test_pgedge_image_row() -> None:
    rows = [p for p in container_image_pins._PINS if p.rule_id == PGEDGE_PIN]
    assert [(p.image, p.introduced, p.floor, p.cves, p.floating_affected) for p in rows] == [
        ("ghcr.io/pgedge/postgres-mcp", None, (1, 1, 0),
         ("CVE-2026-125320", "CVE-2026-125321", "CVE-2026-125322"), False),
    ]


def test_pgedge_rule_names_the_two_high_advisories() -> None:
    """GHSA-j7mp-839j-jrm7 (read-only bypass, 8.1) and GHSA-r5pp-jx86-r6r9 (pl-do
    injection, 8.8) have no CVE id. Both are fixed in 1.1.0-beta1 with the three CVEs, so
    they join this rule and make it HIGH; the evidence names them."""
    rule = RULES[PGEDGE_PIN]
    assert rule.incident_references == [PGEDGE_READONLY_GHSA, PGEDGE_PLDO_GHSA]
    assert PGEDGE_READONLY_GHSA in rule.description and PGEDGE_PLDO_GHSA in rule.description
    (found,) = [f for f in container_image_pins.scan(CVES / "cve-2026-125320-pgedge" / "vulnerable")[0]
                if f.rule_id == PGEDGE_PIN]
    assert PGEDGE_READONLY_GHSA in found.evidence and PGEDGE_PLDO_GHSA in found.evidence


def test_pgedge_beta2_is_reported_at_high_and_the_rule_says_why() -> None:
    """1.0.0-beta2 (6830caeb) has no custom_tool.go and runs query_database with tx.Query,
    so neither high-severity route is in it, but the tag reads as 1.0.0 and the pin cannot
    tell it apart. The limitation states it; this pins the behaviour."""
    root = CVES / "cve-2026-125320-pgedge" / "beta2"
    found = [f for f in run_scan(root).findings if f.rule_id == PGEDGE_PIN]
    assert [(f.file_path, f.line_number, f.severity) for f in found] == [("compose.yaml", 5, Severity.HIGH)]
    assert ("1.0.0-beta2 is reported at HIGH because it reads as 1.0.0, although that one tag "
            "has neither high-severity route") in RULES[PGEDGE_PIN].limitations


def test_pgedge_fixtures_positive_and_negative() -> None:
    """1.0.0's image (67121476) predates all three fixes; 1.1.0's (25c2aaed) carries
    them. The negative also runs the `nla-web` client image, which is not the server."""
    root = CVES / "cve-2026-125320-pgedge"
    assert [(f.rule_id, f.file_path, f.line_number) for f in container_image_pins.scan(root / "vulnerable")[0]] == [
        (PGEDGE_PIN, "compose.yaml", 3),
    ]
    assert _image_ids(root / "negative") == set()
    assert PGEDGE_PIN in {f.rule_id for f in run_scan(root / "vulnerable").findings}


@pytest.mark.parametrize(("tag", "fires"), [
    ("1.0.0-beta2", True),          # the first image, 6830caeb
    ("1.0.0-beta3a", True),
    ("1.0.0-test1-with-kb", True),  # cc13a18a, June, before the fixes
    ("1.0.0", True),
    ("1.0", True),                  # the 1.0.0 digest
    ("1.1.0-beta1", False),         # b971c413 carries all three fixes
    ("1.1.0-rc1", False),
    ("1.1.0", False),
    ("1.1.0-with-kb", False),
    ("1.1", False),
    ("latest", False),              # the 1.1.0 digest on 2026-11-11
    ("main", False),                # not a version
])
def test_pgedge_tags(tmp_path: Path, tag: str, fires: bool) -> None:
    assert (PGEDGE_PIN in _compose(tmp_path, f"ghcr.io/pgedge/postgres-mcp:{tag}")) is fires


@pytest.mark.parametrize(("name", "content", "fires"), [
    (".mcp.json", '{"mcpServers": {"pg": {"command": "docker", "args": ["run", "-i", "--rm", '
                  '"-e", "PGEDGE_DB_HOST", "ghcr.io/pgedge/postgres-mcp:1.0.0"]}}}', True),
    (".mcp.json", '{"mcpServers": {"pg": {"command": "docker", "args": ["run", "-i", "--rm", '
                  '"ghcr.io/pgedge/postgres-mcp:latest"]}}}', False),
    ("Dockerfile", "FROM ghcr.io/pgedge/postgres-mcp:1.0.0\n", True),
    ("compose.yaml", "services:\n  w:\n    image: ghcr.io/pgedge/nla-web:1.0.0\n", False),
])
def test_pgedge_reference_forms(tmp_path: Path, name: str, content: str, fires: bool) -> None:
    (tmp_path / name).write_text(content, encoding="utf-8")
    assert (PGEDGE_PIN in _image_ids(tmp_path)) is fires


# --- Dagu (CVE-2026-102943) -------------------------------------------------------------


def test_dagu_rows() -> None:
    (row,) = [p for p in mcp_cve_pins_2026_07._PINS if p.rule_id == DAGU_PIN]
    assert (row.names, row.introduced, row.floor, row.requires_version, row.ecosystem) == (
        ("@dagucloud/dagu",), (2, 7, 0), (2, 11, 0), True, "js",
    )
    images = [p for p in container_image_pins._PINS if p.rule_id == DAGU_PIN]
    assert [(p.image, p.introduced, p.floor, p.cves, p.floating_affected) for p in images] == [
        ("ghcr.io/dagucloud/dagu", (2, 7, 0), (2, 11, 0), ("CVE-2026-102943",), False),
    ]


def test_dagu_fixtures_positive_and_negative() -> None:
    root = CVES / "cve-2026-102943-dagu"
    assert [(f.rule_id, f.file_path, f.line_number) for f in mcp_cve_pins_2026_07.scan(root / "vulnerable")[0]] == [
        (DAGU_PIN, "package.json", 8),
    ]
    assert [(f.rule_id, f.file_path, f.line_number) for f in container_image_pins.scan(root / "vulnerable")[0]] == [
        (DAGU_PIN, "compose.yaml", 3),
    ]
    assert _pin_ids(root / "negative") == set()
    assert _image_ids(root / "negative") == set()
    ids = [f.rule_id for f in run_scan(root / "vulnerable").findings]
    assert ids.count(DAGU_PIN) == 2
    assert DAGU_PIN not in {f.rule_id for f in run_scan(root / "negative").findings}


@pytest.mark.parametrize(("version", "fires"), [
    ("2.6.10", False),    # no internal/service/mcp at v2.6.10
    ("2.7.2", True),      # the first npm release after the MCP server shipped in v2.7.0
    ("2.10.7", True),     # locateDAG still returns a separator-bearing name unchecked
    ("2.11.0", False),    # c15c5406 confines resolution to the DAG directories
    ("2.26.0", False),    # latest on 2026-11-11
    ("^2.10.0", True),    # admits 2.10.0 to 2.10.7
    ("^2.11.0", False),
    ("latest", False),
])
def test_dagu_npm_versions(tmp_path: Path, version: str, fires: bool) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"devDependencies": {"@dagucloud/dagu": version}}), encoding="utf-8")
    assert (DAGU_PIN in _pin_ids(tmp_path)) is fires


@pytest.mark.parametrize(("args", "fires"), [
    (["-y", "@dagucloud/dagu@2.10.7", "start-all"], True),
    (["-y", "@dagucloud/dagu", "start-all"], False),
    (["-y", "dagu@1.22.10", "start-all"], False),   # npm's unscoped `dagu` stops before MCP
])
def test_dagu_npx_launches(tmp_path: Path, args: list[str], fires: bool) -> None:
    (tmp_path / ".mcp.json").write_text(json.dumps(
        {"mcpServers": {"dagu": {"command": "npx", "args": args}}}), encoding="utf-8")
    assert (DAGU_PIN in _pin_ids(tmp_path)) is fires


@pytest.mark.parametrize(("tag", "fires"), [
    ("2.6.10", False),
    ("2.7.0", True),
    ("2.7.0-dev", True),
    ("2.10.7-alpine", True),
    ("2.10.7", True),
    ("2.11.0", False),
    ("2.11.0-alpine", False),
    ("latest", False),     # the 2.26.0 build on 2026-11-11
    ("alpine", False),
    ("dev", False),
])
def test_dagu_image_tags(tmp_path: Path, tag: str, fires: bool) -> None:
    assert (DAGU_PIN in _compose(tmp_path, f"ghcr.io/dagucloud/dagu:{tag}")) is fires


def test_dagu_unscoped_npm_package_and_go_mod_stay_quiet(tmp_path: Path) -> None:
    """npm's `dagu` is the 1.x launcher from before the MCP server, and the rule reads no
    go.mod."""
    (tmp_path / "package.json").write_text('{"dependencies": {"dagu": "1.22.10"}}', encoding="utf-8")
    (tmp_path / "go.mod").write_text(
        "module example.com/ops\n\ngo 1.22\n\nrequire github.com/dagucloud/dagu v1.30.3\n", encoding="utf-8")
    assert not [f for f in run_scan(tmp_path).findings if f.rule_id == DAGU_PIN or "CVE-2026-102943" in f.evidence]


# --- Trawl (CVE-2026-122140) ------------------------------------------------------------


def test_trawl_image_row() -> None:
    rows = [p for p in container_image_pins._PINS if p.rule_id == TRAWL_PIN]
    assert [(p.image, p.introduced, p.floor, p.cves, p.floating_affected) for p in rows] == [
        ("ghcr.io/germondai/trawl", (1, 5, 0), (1, 10, 0), ("CVE-2026-122140",), False),
    ]


def test_trawl_rule_names_the_rebinding_advisory() -> None:
    """GHSA-7qmf-c45g-5p4q has no CVE id: the same releases, the same fix (17cdb33a, in
    1.10.0) and the same MCP outbound policy, rated moderate, so it joins this rule the
    way GHSA-f897-62hf-6gxq joined the 111768 one, and the evidence names it."""
    rule = RULES[TRAWL_PIN]
    assert rule.incident_references == [TRAWL_REBIND_GHSA]
    assert rule.cve_references == ["CVE-2026-122140"]
    assert TRAWL_REBIND_GHSA in rule.description
    (found,) = [f for f in container_image_pins.scan(CVES / "cve-2026-122140-trawl" / "vulnerable")[0]
                if f.rule_id == TRAWL_PIN]
    assert TRAWL_REBIND_GHSA in found.evidence


def test_trawl_fixtures_positive_and_negative() -> None:
    root = CVES / "cve-2026-122140-trawl"
    assert [(f.rule_id, f.file_path, f.line_number) for f in container_image_pins.scan(root / "vulnerable")[0]] == [
        (TRAWL_PIN, "compose.yaml", 3),
    ]
    assert _image_ids(root / "negative") == set()
    assert TRAWL_PIN in {f.rule_id for f in run_scan(root / "vulnerable").findings}


@pytest.mark.parametrize(("tag", "fires"), [
    ("v1.1.0", False),
    ("1.4.2", False),            # 7189f101: no MCP routes, no outbound-policy.ts
    ("1.5.0", True),             # c81d628b: both, with the dotted-only mapped match
    ("1.5.0-baseline", True),
    ("1.6.0-fonts", True),
    ("1.9.3", True),             # 4f3a7cf9: outbound-policy.ts unchanged since 1.5.0
    ("1.9.3-baseline", True),
    ("1.10.0", False),           # fc3f64a7: BlockList classification
    ("1.10.0-baseline", False),
    ("1.11.0", False),
    ("latest", False),           # the 1.11.0 digest on 2026-11-11
    ("baseline", False),
    ("nightly-c81d628", False),  # not a version
])
def test_trawl_tags(tmp_path: Path, tag: str, fires: bool) -> None:
    assert (TRAWL_PIN in _compose(tmp_path, f"ghcr.io/germondai/trawl:{tag}")) is fires


def test_trawl_latest_fonts_is_a_stated_limit(tmp_path: Path) -> None:
    """`latest-fonts` still points at the 1.6.0 image (106d5077), but the tag states no
    version, so the rule cannot report it, and says so."""
    assert TRAWL_PIN not in _compose(tmp_path, "ghcr.io/germondai/trawl:latest-fonts")
    assert "`latest-fonts` is still the 1.6.0 image" in RULES[TRAWL_PIN].limitations


def test_trawl_package_names_stay_quiet(tmp_path: Path) -> None:
    """npm's `trawl` (0.0.1, 2017) and PyPI's (0.2.1) are other projects."""
    (tmp_path / "package.json").write_text('{"dependencies": {"trawl": "0.0.1"}}', encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("trawl==0.2.1\n", encoding="utf-8")
    assert not [f for f in run_scan(tmp_path).findings if f.rule_id == TRAWL_PIN or "CVE-2026-122140" in f.evidence]


# --- SiYuan (CVE-2026-123492) -----------------------------------------------------------


def test_siyuan_image_row() -> None:
    rows = [p for p in container_image_pins._PINS if p.rule_id == SIYUAN_PIN]
    assert [(p.image, p.introduced, p.floor, p.cves, p.floating_affected) for p in rows] == [
        ("b3log/siyuan", (3, 8, 0), (3, 8, 9), ("CVE-2026-123492",), False),
    ]


def test_siyuan_fixtures_positive_and_negative() -> None:
    root = CVES / "cve-2026-123492-siyuan"
    assert [(f.rule_id, f.file_path, f.line_number) for f in container_image_pins.scan(root / "vulnerable")[0]] == [
        (SIYUAN_PIN, "compose.yaml", 3),
    ]
    assert _image_ids(root / "negative") == set()
    assert SIYUAN_PIN in {f.rule_id for f in run_scan(root / "vulnerable").findings}


@pytest.mark.parametrize(("tag", "ids"), [
    ("v3.7.3", {SIYUAN_ASSET_PIN}),               # no privateCacheMiddleware yet
    ("v3.8.0", {SIYUAN_PIN, SIYUAN_ASSET_PIN}),   # the middleware arrives; both flaws
    ("v3.8.6", {SIYUAN_PIN, SIYUAN_ASSET_PIN}),
    ("v3.8.7", {SIYUAN_PIN}),
    ("v3.8.8-beta.4", {SIYUAN_PIN}),
    ("v3.8.8", {SIYUAN_PIN}),                     # the advisory's lab image
    ("v3.8.9-alpha.4", set()),                    # pushed after a8b6dd77
    ("v3.8.9", set()),
    ("v3.8.10", set()),
    ("latest", set()),                            # the v3.8.10 digest on 2026-11-11
])
def test_siyuan_tags(tmp_path: Path, tag: str, ids: set[str]) -> None:
    assert _compose(tmp_path, f"b3log/siyuan:{tag}") & {SIYUAN_PIN, SIYUAN_ASSET_PIN} == ids


def test_siyuan_early_389_alphas_are_a_stated_limit(tmp_path: Path) -> None:
    """v3.8.9-alpha.1 to alpha.3 were pushed before the fix but read as 3.8.9."""
    assert SIYUAN_PIN not in _compose(tmp_path, "b3log/siyuan:v3.8.9-alpha.3")
    assert "v3.8.9-alpha.1 to alpha.3 were pushed before the fix" in RULES[SIYUAN_PIN].limitations


# --- ezBookkeeping (CVE-2026-86041) -----------------------------------------------------


def test_ezbookkeeping_image_row() -> None:
    rows = [p for p in container_image_pins._PINS if p.rule_id == EZB_PIN]
    assert [(p.image, p.introduced, p.floor, p.cves, p.floating_affected) for p in rows] == [
        ("mayswind/ezbookkeeping", (0, 10, 0), (1, 6, 0), ("CVE-2026-86041",), False),
    ]


def test_ezbookkeeping_fixtures_positive_and_negative() -> None:
    root = CVES / "cve-2026-86041-ezbookkeeping"
    assert [(f.rule_id, f.file_path, f.line_number) for f in container_image_pins.scan(root / "vulnerable")[0]] == [
        (EZB_PIN, "compose.yaml", 3),
    ]
    assert _image_ids(root / "negative") == set()
    assert EZB_PIN in {f.rule_id for f in run_scan(root / "vulnerable").findings}


@pytest.mark.parametrize(("tag", "fires"), [
    ("0.9.0", False),       # 6222b6ed: no MCP IP limit
    ("0.9", False),
    ("0.10.0", True),       # 06ef2220: mcp_server_ip_limit.go matches c.ClientIP()
    ("0.10", True),
    ("1.0.1", True),
    ("1.5", True),          # the 1.5.1 digest
    ("1.5.1", True),        # 6fa9816c: still no SetTrustedProxies
    ("1.6.0", False),       # e5c12d37 carries d79a5beb
    ("1.6", False),
    ("2.1.1", False),
    ("latest", False),      # the 2.1.1 digest on 2026-11-11
    ("latest-snapshot", False),
    ("SNAPSHOT-20250801", False),
])
def test_ezbookkeeping_tags(tmp_path: Path, tag: str, fires: bool) -> None:
    assert (EZB_PIN in _compose(tmp_path, f"mayswind/ezbookkeeping:{tag}")) is fires


def test_ezbookkeeping_readme_run_and_hub_prefix_are_not_read(tmp_path: Path) -> None:
    """The README's `docker run -p8080:8080 mayswind/ezbookkeeping` floats on `latest`,
    fixed, and a `docker.io/` prefix is not matched."""
    assert EZB_PIN not in _compose(tmp_path, "mayswind/ezbookkeeping")
    assert EZB_PIN not in _compose(tmp_path, "docker.io/mayswind/ezbookkeeping:1.5.1")


@pytest.mark.parametrize(("version", "fires"), [("v1.5.1", True), ("v0.9.0", False), ("v1.6.0", False)])
def test_ezbookkeeping_go_module_after_an_update(tmp_path: Path, version: str, fires: bool) -> None:
    """OSV's record names the Go module from 0.10.0 below 1.6.0. After `aak update`
    AAK-KNOWN-VULN-001 reports a go.mod that requires it; the image rule reads no go.mod."""
    (tmp_path / "go.mod").write_text(
        f"module example.com/books\n\ngo 1.22\n\nrequire github.com/mayswind/ezbookkeeping {version}\n",
        encoding="utf-8")
    assert not [f for f in run_scan(tmp_path).findings if "CVE-2026-86041" in f.evidence]
    _cache_osv(EZB_GHSA)
    found = [f for f in run_scan(tmp_path).findings if "CVE-2026-86041" in f.evidence]
    assert [f.rule_id for f in found] == ([KNOWN_VULN_RULE] if fires else [])


# --- Vikunja (CVE-2026-123493): out of scope --------------------------------------------


def test_vikunja_claims_nothing(tmp_path: Path) -> None:
    """The flaw is Vikunja's API-token check for bot users, shared by the HTTP API,
    CalDAV, feeds and MCP alike, so no rule names it, and its image is not read."""
    (tmp_path / "compose.yaml").write_text(
        "services:\n  vikunja:\n    image: vikunja/vikunja:2.6.0\n", encoding="utf-8")
    assert not [f for f in run_scan(tmp_path).findings if "CVE-2026-123493" in f.evidence]
    assert not [r for r in RULES.values() if "CVE-2026-123493" in r.cve_references]


def test_vikunjas_go_module_names_no_release_a_go_mod_can_require(tmp_path: Path) -> None:
    """NVD's CNA data maps to the Go module `code.vikunja.io/api` from 2.4.0 below 2.7.1,
    but that module declares no `/v2` path, and the Go module proxy resolves it only
    up to v0.24.x, so a go.mod that builds names nothing in the range."""
    entries = nvd_feed.merged(nvd_feed.record_entries(
        _nvd_record("CVE-2026-123493"), nvd_feed.load_package_map(), nvd_feed.Tally()))
    assert [(e["ecosystem"], e["name"], e["ranges"]) for e in entries] == [
        ("Go", "code.vikunja.io/api", [{"introduced": "2.4.0", "fixed": "2.7.1"}]),
    ]
    _cache_nvd("CVE-2026-123493")
    (tmp_path / "go.mod").write_text(
        "module example.com/tasks\n\ngo 1.22\n\nrequire code.vikunja.io/api v0.24.6\n", encoding="utf-8")
    assert not [f for f in run_scan(tmp_path).findings if "CVE-2026-123493" in f.evidence]


# --- the ledger -------------------------------------------------------------------------

ROWS = [
    ("GHSA-7qmf-c45g-5p4q", False), ("GHSA-j7mp-839j-jrm7", False), ("GHSA-r5pp-jx86-r6r9", False),
    ("CVE-2026-125320", False), ("CVE-2026-125321", False), ("CVE-2026-125322", False),
    ("CVE-2026-102943", False), ("CVE-2026-122140", False), ("CVE-2026-102610", False),
    ("CVE-2026-86041", False), ("CVE-2026-123492", False), ("CVE-2026-123493", True),
]


@pytest.mark.parametrize(("cve", "out_of_scope"), ROWS)
def test_every_record_has_one_ledger_row(cve: str, out_of_scope: bool) -> None:
    rows = [line for line in LEDGER.read_text(encoding="utf-8").splitlines() if line.startswith(f"| {cve} ")]
    assert len(rows) == 1 and rows[0].rstrip().endswith("| not filed |")
    assert ("out of scope" in rows[0].lower()) is out_of_scope
