"""2026-11-12 wave, group "misc": #1229, #1230 and two held records, read on 2026-11-12.

One new pin: Helio (CVE-2026-65957), an MCP governance proxy, as the npm package
`@gethelio/proxy` and the image `ghcr.io/gethelio/helio` below 0.8.0. Its range was read
in the npm tarballs (every release from 0.1.0 to 0.8.0, and 0.16.0) and in the source at
the commit each image's label names. Three are out of scope. ByteStash (CVE-2026-126658):
the snippet store's shared API-key check, which its MCP endpoint inherits, the shape of
Vikunja's CVE-2026-123493. SiYuan (CVE-2026-126776): a path traversal that only Windows'
path rules make reachable, while the image `b3log/siyuan` carries only Linux builds. ideon
(CVE-2026-65968): the fix is in the image proxy's URL guard; the record's MCP text names
files ideon does not have. NVD's records are saved unedited under tests/fixtures/nvd_cna,
as the API returned them on 2026-11-12; a test that needs the feed `aak update` writes
builds it from those records in the empty HOME every test gets. `CHANGELOG.cves.md` holds
the reasoning. Nothing here touches the network.
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
from agent_audit_kit.scanners import container_image_pins, mcp_cve_pins_2026_07

HELIO_PIN = "AAK-MCP-HELIO-CVE-2026-65957-001"
SIYUAN_ASSET_PIN = "AAK-MCP-SIYUAN-CVE-2026-116168-001"
SIYUAN_PANIC_PIN = "AAK-MCP-SIYUAN-CVE-2026-123492-001"
KNOWN_VULN_RULE = "AAK-KNOWN-VULN-001"

HERE = Path(__file__).parent
CVES = HERE / "fixtures" / "cves"
NVD_CNA = HERE / "fixtures" / "nvd_cna"
LEDGER = HERE.parent / "CHANGELOG.cves.md"

HELIO = "CVE-2026-65957"
BYTESTASH = "CVE-2026-126658"
SIYUAN = "CVE-2026-126776"
IDEON = "CVE-2026-65968"
HELIO_GHSA = "GHSA-2c3r-q7gv-hp2m"


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


def _mentions(root: Path, cve: str) -> list[str]:
    return [f.rule_id for f in run_scan(root).findings if cve in f.evidence]


def test_nvd_records_are_the_ones_read() -> None:
    """Each saved record is the CVE it is filed under, with the description quoted in
    the ledger."""
    expected = {
        HELIO: "Helio is an MCP proxy",
        BYTESTASH: "ByteStash 1.5.10 before 1.6.2",
        SIYUAN: "SiYuan 3.7.0 before 3.8.10 on Windows",
        IDEON: "ideon is a self-hosted visual workspace",
    }
    for cve, opening in expected.items():
        record = _nvd_record(cve)["cve"]
        assert record["id"] == cve
        (text,) = [d["value"] for d in record["descriptions"] if d["lang"] == "en"]
        assert text.startswith(opening)


@pytest.mark.parametrize(("cve", "packages"), [
    (HELIO, []),
    (BYTESTASH, []),
    (IDEON, []),
    (SIYUAN, [("Go", "github.com/siyuan-note/siyuan/kernel", "packageURL")]),
])
def test_what_nvds_records_map_to(cve: str, packages: list[tuple[str, str, str]]) -> None:
    """Helio's and ideon's CNA data give a bare version range and ByteStash's a
    `pkg:github` URL, so `nvd_feed` keeps none of them; SiYuan's names the kernel's Go
    module, which no go.mod can require at a 3.x release (see below)."""
    assert nvd_feed.record_packages(_nvd_record(cve), nvd_feed.load_package_map()) == packages


# --- Helio (CVE-2026-65957): new pin ----------------------------------------------------


def test_helio_rule() -> None:
    rule = RULES[HELIO_PIN]
    assert rule.cve_references == [HELIO]
    assert rule.severity is Severity.MEDIUM
    assert rule.category.value == "supply-chain"
    assert rule.owasp_mcp_references == ["MCP04:2025", "MCP07:2025"]
    assert rule.aicm_references == ["IAM-01", "IVS-04", "STA-08"]
    assert HELIO_GHSA in rule.description
    assert "allow_open_mode" in rule.description and "api_secret" in rule.limitations


def test_helio_rows() -> None:
    (row,) = [p for p in mcp_cve_pins_2026_07._PINS if p.rule_id == HELIO_PIN]
    assert (row.names, row.introduced, row.floor, row.also, row.requires_version, row.ecosystem) == (
        ("@gethelio/proxy",), None, (0, 8, 0), (), True, "js",
    )
    images = [p for p in container_image_pins._PINS if p.rule_id == HELIO_PIN]
    assert [(p.image, p.introduced, p.floor, p.cves, p.floating_affected) for p in images] == [
        ("ghcr.io/gethelio/helio", None, (0, 8, 0), (HELIO,), False),
    ]


def test_helio_fixtures_positive_and_negative() -> None:
    root = CVES / "cve-2026-65957-helio"
    assert [(f.rule_id, f.file_path, f.line_number) for f in mcp_cve_pins_2026_07.scan(root / "vulnerable")[0]] == [
        (HELIO_PIN, "package.json", 8),
    ]
    assert [(f.rule_id, f.file_path, f.line_number) for f in container_image_pins.scan(root / "vulnerable")[0]] == [
        (HELIO_PIN, "compose.yaml", 3),
    ]
    assert _pin_ids(root / "negative") == set()
    assert _image_ids(root / "negative") == set()
    found = [f for f in run_scan(root / "vulnerable").findings if f.rule_id == HELIO_PIN]
    assert sorted((f.file_path, f.severity) for f in found) == [
        ("compose.yaml", Severity.MEDIUM), ("package.json", Severity.MEDIUM),
    ]
    assert HELIO_PIN not in {f.rule_id for f in run_scan(root / "negative").findings}


@pytest.mark.parametrize(("version", "fires"), [
    ("0.1.0", True),      # the first release already carries the prefix test
    ("0.7.0", True),      # the last affected release
    ("^0.7.0", True),     # admits 0.7.x only, all affected
    ("~0.6.0", True),
    ("0.8.0", False),     # 4ca8329c, isPrivateIpv4
    ("^0.8.0", False),
    ("0.16.0", False),    # latest on 2026-11-12
    ("latest", False),
])
def test_helio_npm_versions(tmp_path: Path, version: str, fires: bool) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"@gethelio/proxy": version}}), encoding="utf-8")
    assert (HELIO_PIN in _pin_ids(tmp_path)) is fires


@pytest.mark.parametrize(("args", "fires"), [
    (["-y", "@gethelio/proxy@0.7.0", "start"], True),
    (["-y", "@gethelio/proxy@0.8.0", "start"], False),
    (["-y", "@gethelio/proxy", "start"], False),     # resolves to 0.16.0
])
def test_helio_npx_launches(tmp_path: Path, args: list[str], fires: bool) -> None:
    (tmp_path / ".mcp.json").write_text(json.dumps(
        {"mcpServers": {"helio": {"command": "npx", "args": args}}}), encoding="utf-8")
    assert (HELIO_PIN in _pin_ids(tmp_path)) is fires


@pytest.mark.parametrize(("script", "fires"), [
    ("npx @gethelio/proxy@0.7.0 start", True),
    ("npx @gethelio/proxy start", False),
])
def test_helio_package_json_scripts(tmp_path: Path, script: str, fires: bool) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"proxy": script}}), encoding="utf-8")
    assert (HELIO_PIN in _pin_ids(tmp_path)) is fires


@pytest.mark.parametrize(("tag", "fires"), [
    ("0.1.0", True),
    ("0.1", True),        # the 0.1.1 digest
    ("0.7", True),        # the 0.7.0 digest
    ("0.7.0", True),
    ("0.8.0", False),
    ("0.8", False),
    ("0.16.0", False),
    ("0", False),         # the 0.16.0 digest on 2026-11-12, and not a version this reader trusts
    ("latest", False),    # the 0.16.0 digest on 2026-11-12
])
def test_helio_image_tags(tmp_path: Path, tag: str, fires: bool) -> None:
    assert (HELIO_PIN in _compose(tmp_path, f"ghcr.io/gethelio/helio:{tag}")) is fires


def test_helio_look_alike_packages_stay_quiet(tmp_path: Path) -> None:
    """npm's unscoped `helio` (a 2015 utility library) and PyPI's `helio` are other
    projects, and the Python SDK `helio-client` serves no dashboard."""
    (tmp_path / "package.json").write_text('{"dependencies": {"helio": "0.0.9"}}', encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("helio==1.0.0b1\nhelio-client==0.7.0\n", encoding="utf-8")
    assert HELIO_PIN not in {f.rule_id for f in run_scan(tmp_path).findings}


def test_helio_has_no_feed_route(tmp_path: Path) -> None:
    """The NVD record names no package, so even after `aak update` only the pin reports
    the CVE."""
    _cache_nvd(HELIO)
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@gethelio/proxy": "0.7.0"}}', encoding="utf-8")
    found = [f.rule_id for f in run_scan(tmp_path).findings if f.rule_id in (HELIO_PIN, KNOWN_VULN_RULE)]
    assert found == [HELIO_PIN]


# --- ByteStash (CVE-2026-126658): out of scope -------------------------------------------


def test_bytestash_claims_nothing(tmp_path: Path) -> None:
    """The flaw is ByteStash's `validateApiKey`, shared by `/api/snippets` and `/mcp`,
    the shape of Vikunja's CVE-2026-123493, so no rule names it and its image is not
    read."""
    (tmp_path / "compose.yaml").write_text(
        "services:\n  bytestash:\n    image: ghcr.io/jordan-dalby/bytestash:1.6.1\n", encoding="utf-8")
    assert _mentions(tmp_path, BYTESTASH) == []
    assert not [r for r in RULES.values() if BYTESTASH in r.cve_references]


# --- SiYuan (CVE-2026-126776): out of scope ----------------------------------------------


@pytest.mark.parametrize(("tag", "ids"), [
    ("v3.7.0", {SIYUAN_ASSET_PIN}),
    ("v3.8.0", {SIYUAN_ASSET_PIN, SIYUAN_PANIC_PIN}),
    ("v3.8.9", set()),
    ("v3.8.10", set()),
])
def test_siyuan_image_rules_do_not_claim_the_windows_flaw(tmp_path: Path, tag: str, ids: set[str]) -> None:
    """The image is Linux-only, where a backslash is a file-name character, so the
    two SiYuan image rules keep their own CVEs, v3.8.9 fires neither, and no finding
    names this record."""
    assert _compose(tmp_path, f"b3log/siyuan:{tag}") == ids
    assert _mentions(tmp_path, SIYUAN) == []
    assert not [r for r in RULES.values() if SIYUAN in r.cve_references]
    assert not [r for r in RULES.values() if SIYUAN in r.description + r.limitations]


def test_siyuans_go_module_names_no_release_a_go_mod_can_require(tmp_path: Path) -> None:
    """NVD's CNA data maps to the Go module `github.com/siyuan-note/siyuan/kernel`
    from 3.7.0 below 3.8.10, but the module sits in `kernel/` with no `kernel/v*` tags
    and no `/v3` path, so the Go module proxy serves only pseudo-versions, which sort
    below 3.7.0."""
    entries = nvd_feed.merged(nvd_feed.record_entries(
        _nvd_record(SIYUAN), nvd_feed.load_package_map(), nvd_feed.Tally()))
    assert [(e["ecosystem"], e["name"], e["ranges"]) for e in entries] == [
        ("Go", "github.com/siyuan-note/siyuan/kernel", [{"introduced": "3.7.0", "fixed": "3.8.10"}]),
    ]
    _cache_nvd(SIYUAN)
    (tmp_path / "go.mod").write_text(
        "module example.com/notes\n\ngo 1.26\n\nrequire github.com/siyuan-note/siyuan/kernel "
        "v0.0.0-20261110041244-be17ed1e0510\n", encoding="utf-8")
    assert _mentions(tmp_path, SIYUAN) == []


# --- ideon (CVE-2026-65968): out of scope ------------------------------------------------


def test_ideon_claims_nothing(tmp_path: Path) -> None:
    """The fix is in ideon's image-proxy guard (`isSafeUrl`); the files and MCP-server
    registration the record describes are not in ideon. No rule names it, and its
    image is not read."""
    (tmp_path / "compose.yaml").write_text(
        "services:\n  ideon:\n    image: ghcr.io/3xpyth0n/ideon:0.9.3\n", encoding="utf-8")
    assert _mentions(tmp_path, IDEON) == []
    assert not [r for r in RULES.values() if IDEON in r.cve_references]


# --- the ledger -------------------------------------------------------------------------

ROWS = [
    (HELIO, "not filed", False),
    (BYTESTASH, "#1229", True),
    (SIYUAN, "#1230", True),
    (IDEON, "not filed", True),
]


@pytest.mark.parametrize(("cve", "issue", "out_of_scope"), ROWS)
def test_every_record_has_one_ledger_row(cve: str, issue: str, out_of_scope: bool) -> None:
    rows = [line for line in LEDGER.read_text(encoding="utf-8").splitlines() if line.startswith(f"| {cve} ")]
    assert len(rows) == 1 and rows[0].rstrip().endswith(f"| {issue} |")
    assert ("out of scope" in rows[0].lower()) is out_of_scope
