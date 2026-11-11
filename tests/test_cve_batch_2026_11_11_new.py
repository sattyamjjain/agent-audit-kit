"""2026-11-11 batch, group "new": #1066, #1067 and #1215 to #1219.

Three new pins (djust, the Trigger.dev CLI, OpenHuman's core image), one CVE the
advisory feed reports after `aak update` (@tsparticles/mcp-server), and three out
of scope (a WordPress plugin, Mendix Studio Pro, Microsoft MCP Gateway). The OSV
records under tests/fixtures/known_vulns/cve_batch_2026_11_11 and the NVD records
under tests/fixtures/nvd_cna are saved unedited, read on 2026-11-11.
`CHANGELOG.cves.md` holds the reasoning. Nothing here touches the network.
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

DJUST = "AAK-MCP-DJUST-CVE-2026-113731-001"
TRIGGERDEV = "AAK-MCP-TRIGGERDEV-CVE-2026-114090-001"
OPENHUMAN = "AAK-MCP-OPENHUMAN-CVE-2026-54140-001"
KNOWN_VULN = "AAK-KNOWN-VULN-001"

HERE = Path(__file__).parent
CVES = HERE / "fixtures" / "cves"
OSV = HERE / "fixtures" / "known_vulns" / "cve_batch_2026_11_11"
NVD_CNA = HERE / "fixtures" / "nvd_cna"
LEDGER = HERE.parent / "CHANGELOG.cves.md"


def _pin_ids(root: Path) -> set[str]:
    return {f.rule_id for f in mcp_cve_pins_2026_07.scan(root)[0]}


def _image_ids(root: Path) -> set[str]:
    return {f.rule_id for f in container_image_pins.scan(root)[0]}


def _nvd_record(cve: str) -> dict[str, Any]:
    (vuln,) = json.loads((NVD_CNA / f"{cve}.json").read_text(encoding="utf-8"))["vulnerabilities"]
    return vuln


def _cache_feed(osv: tuple[str, ...] = (), nvd: tuple[str, ...] = ()) -> None:
    """Write the feed `aak update` would leave, holding only these records."""
    records = [json.loads((OSV / f"{ghsa}.json").read_text(encoding="utf-8")) for ghsa in osv]
    entries: list[dict[str, Any]] = []
    for cve in nvd:
        entries.extend(nvd_feed.merged(nvd_feed.record_entries(
            _nvd_record(cve), nvd_feed.load_package_map(), nvd_feed.Tally())))
    path = advisory_feed.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"generated_at": "t", "source": "test", "records": records, "nvd": entries}))


def _npm_lock(root: Path, name: str, version: str) -> None:
    (root / "package-lock.json").write_text(json.dumps(
        {"lockfileVersion": 3, "packages": {f"node_modules/{name}": {"version": version}}}), encoding="utf-8")


def _uv_lock(root: Path, name: str, version: str) -> None:
    (root / "uv.lock").write_text(
        f'version = 1\n\n[[package]]\nname = "{name}"\nversion = "{version}"\n'
        'source = { registry = "https://pypi.org/simple" }\n', encoding="utf-8")


@pytest.mark.parametrize(("rule_id", "severity", "cve"), [
    (DJUST, "low", "CVE-2026-113731"),
    (TRIGGERDEV, "high", "CVE-2026-114090"),
    (OPENHUMAN, "high", "CVE-2026-54140"),
])
def test_each_rule_carries_its_cve_and_severity(rule_id: str, severity: str, cve: str) -> None:
    rule = RULES[rule_id]
    assert rule.cve_references == [cve]
    assert rule.severity.value == severity
    assert rule.category.value == "supply-chain"


# --- #1066: djust (CVE-2026-113731) --------------------------------------------------


def test_djust_row() -> None:
    (row,) = [p for p in mcp_cve_pins_2026_07._PINS if p.rule_id == DJUST]
    assert (row.names, row.introduced, row.floor, row.also, row.requires_version, row.ecosystem) == (
        ("djust",), (0, 9, 0), (1, 0, 10), (((1, 1, 0), (1, 1, 7)), ((1, 2, 0), (1, 2, 4))), True, "py",
    )


def test_djust_fixtures_positive_and_negative() -> None:
    root = CVES / "cve-2026-113731-djust"
    assert [(f.rule_id, f.file_path, f.line_number) for f in mcp_cve_pins_2026_07.scan(root / "vulnerable")[0]] == [
        (DJUST, "requirements.txt", 1),
    ]
    assert _pin_ids(root / "negative") == set()
    assert DJUST in {f.rule_id for f in run_scan(root / "vulnerable").findings}


@pytest.mark.parametrize(("version", "fires"), [
    ("0.4.4", False),       # no find_handlers_for_template in the sdist
    ("0.9.0", True),        # the tool's first release, reading any absolute path
    ("1.0.0rc11", True),    # reads as 1.0.0, affected
    ("1.0.9", True),
    ("1.0.10", False),
    ("1.1.0", True),
    ("1.1.6", True),
    ("1.1.7", False),
    ("1.2.0", True),
    ("1.2.1rc1", True),     # reads as 1.2.1, affected
    ("1.2.3", True),
    ("1.2.4", False),
    ("1.3.0rc8", False),
    ("1.3.0", False),
    ("1.3.2", False),       # latest on 2026-11-11
])
def test_djust_version_lines(tmp_path: Path, version: str, fires: bool) -> None:
    (tmp_path / "requirements.txt").write_text(f"djust=={version}\n", encoding="utf-8")
    assert (DJUST in _pin_ids(tmp_path)) is fires


@pytest.mark.parametrize(("spec", "fires"), [
    ("djust\n", False),                 # resolves to 1.3.2, fixed
    ("djust>=1.2,<1.3\n", True),        # admits 1.2.0 to 1.2.3
    ("djust>=1.2.4,<1.3\n", False),
    ("djust~=1.1.0\n", True),           # admits 1.1.0 to 1.1.6
])
def test_djust_ranges_and_unversioned(tmp_path: Path, spec: str, fires: bool) -> None:
    (tmp_path / "requirements.txt").write_text(spec, encoding="utf-8")
    assert (DJUST in _pin_ids(tmp_path)) is fires


@pytest.mark.parametrize("version", ["1.3.0rc4", "1.3.0rc7"])
def test_djust_affected_release_candidates_are_a_stated_limit(tmp_path: Path, version: str) -> None:
    """The sdists of 1.3.0rc4 and rc7 read any absolute path, but a pre-release folds
    into its release, 1.3.0, which is fixed, so the pin cannot report them. The rule
    says so, and OSV's record, which `aak update` brings in, does report them."""
    (tmp_path / "requirements.txt").write_text(f"djust=={version}\n", encoding="utf-8")
    assert DJUST not in _pin_ids(tmp_path)
    assert "1.3.0rc4 to 1.3.0rc7, which are affected, read as 1.3.0" in RULES[DJUST].limitations
    _cache_feed(osv=("GHSA-r57g-mc79-8hj2",))
    _uv_lock(tmp_path, "djust", version)
    found = [f for f in run_scan(tmp_path).findings if f.rule_id == KNOWN_VULN]
    assert found and all("CVE-2026-113731" in f.evidence for f in found)


def test_djust_after_update_the_feed_reports_it_too(tmp_path: Path) -> None:
    """After `aak update`, OSV's record reaches AAK-KNOWN-VULN-001 at MEDIUM (the feed
    puts any score below 7.0 at MEDIUM), so it stands beside the LOW pin."""
    _cache_feed(osv=("GHSA-r57g-mc79-8hj2",))
    _uv_lock(tmp_path, "djust", "1.0.9")
    found = {(f.rule_id, f.severity) for f in run_scan(tmp_path).findings if "CVE-2026-113731" in f.evidence
             or f.rule_id == DJUST}
    assert found == {(DJUST, Severity.LOW), (KNOWN_VULN, Severity.MEDIUM)}


# --- #1067: the Trigger.dev CLI (CVE-2026-114090) ------------------------------------


def test_trigger_dev_row() -> None:
    (row,) = [p for p in mcp_cve_pins_2026_07._PINS if p.rule_id == TRIGGERDEV]
    assert (row.names, row.introduced, row.floor, row.also, row.requires_version, row.ecosystem) == (
        ("trigger.dev",), (4, 0, 0), (4, 5, 4), (), True, "js",
    )


def test_trigger_dev_fixtures_positive_and_negative() -> None:
    root = CVES / "cve-2026-114090-trigger-dev"
    assert [(f.rule_id, f.file_path, f.line_number) for f in mcp_cve_pins_2026_07.scan(root / "vulnerable")[0]] == [
        (TRIGGERDEV, "package.json", 8),
    ]
    assert _pin_ids(root / "negative") == set()
    assert TRIGGERDEV in {f.rule_id for f in run_scan(root / "vulnerable").findings}
    assert TRIGGERDEV not in {f.rule_id for f in run_scan(root / "negative").findings}


@pytest.mark.parametrize(("version", "fires"), [
    ("3.0.0", False),            # no `--mcp` in the 3.x tarballs
    ("3.3.17", False),           # the newest 3.x
    ("4.0.0-v4-beta.0", True),   # ships dist/esm/dev/mcpServer.js, reads as 4.0.0
    ("4.0.0", True),
    ("4.4.6", True),
    ("4.5.0-rc.7", True),        # carries the server, reads as 4.5.0
    ("4.5.3", True),             # app.listen(options.port, ...) still
    ("4.5.4", False),            # the option and the server are gone
    ("4.8.4", False),            # latest on 2026-11-11
    ("^4.5.0", True),            # admits 4.5.0 to 4.5.3
    ("^4.5.4", False),
    ("latest", False),
    ("0.0.0-re2-20250815162450", False),  # a snapshot that carries the server: a stated limit
])
def test_trigger_dev_versions(tmp_path: Path, version: str, fires: bool) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"devDependencies": {"trigger.dev": version}}), encoding="utf-8")
    assert (TRIGGERDEV in _pin_ids(tmp_path)) is fires


@pytest.mark.parametrize(("args", "fires"), [
    (["-y", "trigger.dev@4.2.0", "mcp"], True),   # the version, not the subcommand, is read
    (["-y", "trigger.dev@latest", "dev"], False),
    (["-y", "trigger.dev@4.5.4", "mcp"], False),
])
def test_trigger_dev_launches(tmp_path: Path, args: list[str], fires: bool) -> None:
    (tmp_path / ".mcp.json").write_text(json.dumps(
        {"mcpServers": {"trigger": {"command": "npx", "args": args}}}), encoding="utf-8")
    assert (TRIGGERDEV in _pin_ids(tmp_path)) is fires


def test_trigger_dev_snapshot_limit_is_stated() -> None:
    assert "0.0.0-re2-20250815162450 does" in RULES[TRIGGERDEV].limitations


def test_the_advisorys_package_name_is_not_trigger_dev(tmp_path: Path) -> None:
    """NVD's CNA record names `pkg:npm/%40trigger.dev/cli-v3`, which npm does not carry,
    so after `aak update` the feed holds the record under a name no project declares,
    and only the pin reports the CLI."""
    assert nvd_feed.record_packages(_nvd_record("CVE-2026-114090"), nvd_feed.load_package_map()) == [
        ("npm", "@trigger.dev/cli-v3", "packageURL"),
    ]
    _cache_feed(nvd=("CVE-2026-114090",))
    _npm_lock(tmp_path, "trigger.dev", "4.5.3")
    ids = [f.rule_id for f in run_scan(tmp_path).findings]
    assert TRIGGERDEV in ids and KNOWN_VULN not in ids
    (tmp_path / "package-lock.json").unlink()
    (tmp_path / "package.json").write_text(
        json.dumps({"devDependencies": {"@trigger.dev/cli-v3": "4.5.3"}}), encoding="utf-8")
    assert TRIGGERDEV not in _pin_ids(tmp_path)


# --- #1219: OpenHuman's core image (CVE-2026-54140) -----------------------------------


def test_openhuman_image_row() -> None:
    rows = [p for p in container_image_pins._PINS if p.rule_id == OPENHUMAN]
    assert [(p.image, p.introduced, p.floor, p.cves, p.floating_affected) for p in rows] == [
        ("ghcr.io/tinyhumansai/openhuman-core", (0, 54, 0), (0, 57, 12), ("CVE-2026-54140",), False),
    ]


def test_openhuman_fixtures_positive_and_negative() -> None:
    """v0.57.11's image (8476248e) lacks 00b8a669; v0.57.12's (c903227e) carries it."""
    root = CVES / "cve-2026-54140-openhuman"
    assert [(f.rule_id, f.file_path, f.line_number) for f in container_image_pins.scan(root / "vulnerable")[0]] == [
        (OPENHUMAN, "compose.yaml", 3),
    ]
    assert _image_ids(root / "negative") == set()
    assert OPENHUMAN in {f.rule_id for f in run_scan(root / "vulnerable").findings}


@pytest.mark.parametrize(("tag", "fires"), [
    ("v0.53.43", False),   # no src/openhuman/mcp_client yet
    ("v0.54.0", True),     # the MCP client's first image
    ("0.54.0", True),      # the same release without the `v`
    ("v0.57.11", True),
    ("v0.57.12", False),   # the fix's first image, though the advisory names 0.57.13
    ("0.57.13", False),
    ("v0.64.15", False),
    ("latest", False),     # the v0.64.15 digest on 2026-11-11
])
def test_openhuman_tags(tmp_path: Path, tag: str, fires: bool) -> None:
    (tmp_path / "compose.yaml").write_text(
        f"services:\n  core:\n    image: ghcr.io/tinyhumansai/openhuman-core:{tag}\n", encoding="utf-8")
    assert (OPENHUMAN in _image_ids(tmp_path)) is fires


@pytest.mark.parametrize(("name", "content", "fires"), [
    ("compose.yaml", "services:\n  core:\n    image: ghcr.io/tinyhumansai/openhuman-core\n", False),
    ("Dockerfile", "FROM ghcr.io/tinyhumansai/openhuman-core:v0.57.11\n", True),
    (".mcp.json", '{"mcpServers": {"oh": {"command": "docker", "args": ["run", "--rm", '
                  '"ghcr.io/tinyhumansai/openhuman-core:v0.57.11"]}}}', True),
    ("compose.yaml", "services:\n  core:\n    # image: ghcr.io/tinyhumansai/openhuman-core:v0.57.11\n"
                     "    image: ghcr.io/tinyhumansai/openhuman-core:v0.57.12\n", False),
])
def test_openhuman_reference_forms(tmp_path: Path, name: str, content: str, fires: bool) -> None:
    (tmp_path / name).write_text(content, encoding="utf-8")
    assert (OPENHUMAN in _image_ids(tmp_path)) is fires


def test_openhuman_package_names_stay_quiet(tmp_path: Path) -> None:
    """crates.io's, npm's and PyPI's `openhuman` are 2023 packages of other projects,
    and no advisory record names a package: NVD's CNA data maps to nothing and OSV
    holds the CVE only as a git range."""
    (tmp_path / "package.json").write_text('{"dependencies": {"openhuman": "0.1.5"}}', encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("openhuman==1.1.3\n", encoding="utf-8")
    (tmp_path / "Cargo.lock").write_text(
        'version = 3\n\n[[package]]\nname = "openhuman"\nversion = "0.1.0"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n', encoding="utf-8")
    assert not [f for f in run_scan(tmp_path).findings if "CVE-2026-54140" in f.evidence or f.rule_id == OPENHUMAN]
    assert nvd_feed.record_packages(_nvd_record("CVE-2026-54140"), nvd_feed.load_package_map()) == []


# --- #1218: @tsparticles/mcp-server (CVE-2026-76892) ---------------------------------


@pytest.mark.parametrize(("version", "fires"), [
    ("0.1.0", True), ("4.3.0", True), ("4.3.1", False), ("4.5.3", False),
])
def test_tsparticles_osv_record_reaches_the_feed_rule(tmp_path: Path, version: str, fires: bool) -> None:
    """OSV's GHSA-4p8p-pjpq-2w7h, from its npm export, after `aak update`. Every release
    it lists (0.1.0, 4.1.3, 4.2.0, 4.2.1, 4.3.0) is gone from npm, so only a lockfile
    written before they went can name one."""
    _cache_feed(osv=("GHSA-4p8p-pjpq-2w7h",))
    _npm_lock(tmp_path, "@tsparticles/mcp-server", version)
    found = [f for f in run_scan(tmp_path).findings if f.rule_id == KNOWN_VULN]
    assert bool(found) is fires
    if fires:
        assert all(f.severity is Severity.HIGH and "CVE-2026-76892" in f.evidence for f in found)


@pytest.mark.parametrize(("version", "cves"), [
    ("4.3.0", {"CVE-2026-76892", "CVE-2026-76893"}),
    ("4.3.1", {"CVE-2026-76893"}),   # the sibling, fixed in 4.3.2
    ("4.3.2", set()),
])
def test_tsparticles_nvd_records_reach_the_feed_rule_through_the_map_row(
        tmp_path: Path, version: str, cves: set[str]) -> None:
    """The reviewed map row 0.6.34 shipped maps NVD's records, whose CNA data names no
    package, to npm's @tsparticles/mcp-server."""
    _cache_feed(nvd=("CVE-2026-76892", "CVE-2026-76893"))
    _npm_lock(tmp_path, "@tsparticles/mcp-server", version)
    found = [f for f in run_scan(tmp_path).findings if f.rule_id == KNOWN_VULN]
    assert {c for f in found for c in ("CVE-2026-76892", "CVE-2026-76893") if c in f.evidence} == cves


def test_tsparticles_has_no_pin_and_is_not_bundled() -> None:
    assert not [p for p in mcp_cve_pins_2026_07._PINS if "@tsparticles/mcp-server" in p.names]
    assert "@tsparticles/mcp-server" not in advisory_feed.BUNDLED_FEED.read_text(encoding="utf-8")


# --- #1215, #1216, #1217: out of scope ------------------------------------------------


@pytest.mark.parametrize(("name", "content", "cve"), [
    # #1215: the wordpress.org plugin through wpackagist; AAK reads no composer manifest.
    ("composer.json",
     '{"require": {"wpackagist-plugin/ai-workflow-automation-ai-agent-hub": "2.0.1"}}', "CVE-2026-121576"),
    # #1216: npm's `mendix` is the pluggable-widgets typings, versioned with Studio Pro.
    ("package.json", '{"devDependencies": {"mendix": "11.15.0"}}', "CVE-2026-112136"),
    # #1217: both tags the image has, `1.0.0` and `latest`, are fixed builds.
    ("compose.yaml", "services:\n  gw:\n    image: ghcr.io/microsoft/mcp-gateway:1.0.0\n", "CVE-2026-109492"),
])
def test_out_of_scope_records_claim_nothing(tmp_path: Path, name: str, content: str, cve: str) -> None:
    (tmp_path / name).write_text(content, encoding="utf-8")
    assert not [f for f in run_scan(tmp_path).findings if cve in f.evidence]
    assert not [r for r in RULES.values() if cve in r.cve_references]


# --- the ledger -------------------------------------------------------------------------


@pytest.mark.parametrize(("issue", "cve"), [
    ("#1066", "CVE-2026-113731"), ("#1067", "CVE-2026-114090"), ("#1215", "CVE-2026-121576"),
    ("#1216", "CVE-2026-112136"), ("#1217", "CVE-2026-109492"), ("#1218", "CVE-2026-76892"),
    ("#1219", "CVE-2026-54140"),
])
def test_every_issue_has_one_ledger_row(issue: str, cve: str) -> None:
    rows = [line for line in LEDGER.read_text(encoding="utf-8").splitlines() if line.startswith(f"| {cve} ")]
    assert len(rows) == 1 and rows[0].rstrip().endswith(f"| {issue} |")


@pytest.mark.parametrize(("cve", "out_of_scope"), [
    ("CVE-2026-121576", True), ("CVE-2026-112136", True), ("CVE-2026-109492", True),
    ("CVE-2026-76892", False), ("CVE-2026-113731", False), ("CVE-2026-114090", False),
    ("CVE-2026-54140", False),
])
def test_rows_read_as_their_disposition(cve: str, out_of_scope: bool) -> None:
    (row,) = [line for line in LEDGER.read_text(encoding="utf-8").splitlines() if line.startswith(f"| {cve} ")]
    assert ("out of scope" in row.lower()) is out_of_scope
