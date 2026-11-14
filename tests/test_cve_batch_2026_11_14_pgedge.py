"""2026-11-14 batch, group "pgedge": #1238 to #1241, four GitHub records for the pgEdge
Postgres MCP Server, all fixed in 1.1.0.

The server is Go, on neither npm nor PyPI, and its go.mod declares the module
`pgedge-postgres-mcp`, which no other go.mod can require. It ships as release archives and
three GHCR images built from the same commits: the server, `ghcr.io/pgedge/postgres-mcp`,
and its two bundled MCP clients, the agent CLI `ghcr.io/pgedge/nla-cli` and the web client
`ghcr.io/pgedge/nla-web`. Every range below was read on 2026-11-14 in the source at the
commit each image's label (`org.opencontainers.image.revision`) names. NVD's records are
saved unedited under tests/fixtures/nvd_cna. `CHANGELOG.cves.md` holds the reasoning.

CVE-2026-126196 (#1238, HIGH) and CVE-2026-126197 (#1239, HIGH) are GHSA-j7mp-839j-jrm7 and
GHSA-r5pp-jx86-r6r9, the two server advisories that had no CVE id when
AAK-MCP-PGEDGE-CVE-2026-125320-001 shipped in 0.6.35 and already made that rule HIGH. They
join its `cve_references`; its range does not move.

CVE-2026-126199 (#1241, MEDIUM) and CVE-2026-126198 (#1240, LOW) are in the clients' write
confirmation prompt, which the server image does not contain, so they get a rule of their
own on the client images at the higher record's severity. The prompt first ships in 1.0.0,
and both fixes are in 1.1.0-beta1, so the LOW record's affected releases sit inside the
MEDIUM record's and it joins the same rule.
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
from agent_audit_kit.scanners import container_image_pins

SERVER_PIN = "AAK-MCP-PGEDGE-CVE-2026-125320-001"
CLIENTS_PIN = "AAK-MCP-PGEDGE-CVE-2026-126199-001"
SERVER_IMAGE = "ghcr.io/pgedge/postgres-mcp"
CLI_IMAGE = "ghcr.io/pgedge/nla-cli"
WEB_IMAGE = "ghcr.io/pgedge/nla-web"

READONLY_CVE = "CVE-2026-126196"     # #1238, GHSA-j7mp-839j-jrm7
PLDO_CVE = "CVE-2026-126197"         # #1239, GHSA-r5pp-jx86-r6r9
CUSTOM_TOOL_CVE = "CVE-2026-126198"  # #1240, GHSA-v44x-hxg7-5cgc
FIRST_WORD_CVE = "CVE-2026-126199"   # #1241, GHSA-5gmh-9683-hhq9
EARLIER_SERVER_CVES = ["CVE-2026-125320", "CVE-2026-125321", "CVE-2026-125322"]

HERE = Path(__file__).resolve().parent
CVES = HERE / "fixtures" / "cves"
NVD_CNA = HERE / "fixtures" / "nvd_cna"
LEDGER = HERE.parent / "CHANGELOG.cves.md"


def _image_ids(root: Path) -> set[str]:
    return {f.rule_id for f in container_image_pins.scan(root)[0]}


def _compose(root: Path, ref: str) -> Path:
    (root / "compose.yaml").write_text(f"services:\n  s:\n    image: {ref}\n", encoding="utf-8")
    return root


def _nvd_record(cve: str) -> dict[str, Any]:
    (vuln,) = json.loads((NVD_CNA / f"{cve}.json").read_text(encoding="utf-8"))["vulnerabilities"]
    return vuln


# ---- #1238, #1239: the server rule takes the two CVE ids ----------------------------------------


def test_the_server_rule_names_the_two_new_cve_ids() -> None:
    rule = RULES[SERVER_PIN]
    assert rule.severity is Severity.HIGH
    assert rule.cve_references == [*EARLIER_SERVER_CVES, READONLY_CVE, PLDO_CVE]
    # The GHSA ids stay as incident references beside the CVE ids they now carry.
    assert rule.incident_references == ["GHSA-j7mp-839j-jrm7", "GHSA-r5pp-jx86-r6r9"]
    assert f"{READONLY_CVE} (CVSS 3.1 8.1, CWE-89 and CWE-693, GHSA-j7mp-839j-jrm7)" in rule.description
    assert f"{PLDO_CVE} (8.8, CWE-89, GHSA-r5pp-jx86-r6r9)" in rule.description
    assert "no CVE id" not in rule.description


def test_the_server_row_keeps_its_range() -> None:
    """The two records name `< 1.1.0`, the row's floor, and every pre-release; the row's
    range and floating behaviour are unchanged, and its evidence names both new ids."""
    (row,) = [p for p in container_image_pins._PINS if p.rule_id == SERVER_PIN]
    assert (row.image, row.introduced, row.floor, row.floating_affected) == (SERVER_IMAGE, None, (1, 1, 0), False)
    assert set(row.cves) <= set(RULES[SERVER_PIN].cve_references)
    assert f"{READONLY_CVE} (GHSA-j7mp-839j-jrm7" in row.fix_label
    assert f"{PLDO_CVE} (GHSA-r5pp-jx86-r6r9" in row.fix_label


@pytest.mark.parametrize(("fixture", "where"), [
    ("cve-2026-126196-pgedge-readonly", ("compose.yaml", 5)),   # 1.0.0, a read_only connection
    ("cve-2026-126197-pgedge-pldo", ("Dockerfile", 3)),         # 1.0.0-beta3, the first with pl-do tools
])
def test_server_fixtures(fixture: str, where: tuple[str, int]) -> None:
    (finding,) = container_image_pins.scan(CVES / fixture / "vulnerable")[0]
    assert (finding.rule_id, finding.file_path, finding.line_number) == (SERVER_PIN, *where)
    assert READONLY_CVE in finding.evidence and PLDO_CVE in finding.evidence
    assert _image_ids(CVES / fixture / "negative") == set()       # 1.1.0 and 1.1.0-beta1


def test_the_server_finding_survives_the_full_engine_at_high() -> None:
    found = [(f.rule_id, f.severity) for f in run_scan(CVES / "cve-2026-126196-pgedge-readonly" / "vulnerable").findings
             if f.rule_id in (SERVER_PIN, CLIENTS_PIN)]
    assert found == [(SERVER_PIN, Severity.HIGH)]


@pytest.mark.parametrize(("tag", "fires"), [
    ("1.0.0-beta2", True),   # reads as 1.0.0; neither route, which the limitations say
    ("1.0.0-beta3", True),   # tx.Exec on a read-only connection, and pl-do tools
    ("1.0.0", True), ("1.0", True), ("1.0.0-test1", True),
    ("1.1.0-beta1", False),  # b971c413: b5b92930 and per-call dollar-quote tags
    ("1.1.0", False), ("1.1", False), ("latest", False), ("1.2.0-beta1", False),
])
def test_server_tags(tmp_path: Path, tag: str, fires: bool) -> None:
    assert (SERVER_PIN in _image_ids(_compose(tmp_path, f"{SERVER_IMAGE}:{tag}"))) is fires


# ---- #1240, #1241: the clients' rule ------------------------------------------------------------


def test_the_clients_rule_is_registered_at_medium() -> None:
    rule = RULES[CLIENTS_PIN]
    assert rule.severity is Severity.MEDIUM
    assert rule.category is Category.SUPPLY_CHAIN
    assert rule.cve_references == [FIRST_WORD_CVE, CUSTOM_TOOL_CVE]
    assert "GHSA-5gmh-9683-hhq9" in rule.description and "GHSA-v44x-hxg7-5cgc" in rule.description
    assert rule.owasp_agentic_references == ["ASI09", "ASI02", "ASI04"]
    assert "STA-08" in rule.aicm_references


def test_the_severity_split_holds() -> None:
    """The client records are not on the HIGH server rule, which reads only the server
    image, and the server records are not on the clients' rule."""
    assert not {FIRST_WORD_CVE, CUSTOM_TOOL_CVE} & set(RULES[SERVER_PIN].cve_references)
    assert not {READONLY_CVE, PLDO_CVE, *EARLIER_SERVER_CVES} & set(RULES[CLIENTS_PIN].cve_references)


def test_the_client_rows() -> None:
    rows = [(p.image, p.introduced, p.floor, p.floating_affected, p.cves)
            for p in container_image_pins._PINS if p.rule_id == CLIENTS_PIN]
    assert rows == [
        (CLI_IMAGE, None, (1, 1, 0), False, (FIRST_WORD_CVE, CUSTOM_TOOL_CVE)),
        (WEB_IMAGE, None, (1, 1, 0), False, (FIRST_WORD_CVE, CUSTOM_TOOL_CVE)),
    ]


@pytest.mark.parametrize(("tree", "expected"), [
    ("cve-2026-126199-pgedge-clients/vulnerable", [("compose.yaml", 11), ("compose.yaml", 15)]),
    ("cve-2026-126199-pgedge-clients/prerelease", [("compose.yaml", 5)]),
    ("cve-2026-126199-pgedge-clients/negative", []),
    ("cve-2026-126199-pgedge-clients/negative-latest", []),
    ("cve-2026-126198-pgedge-custom-tools/vulnerable", [("values.yaml", 5)]),   # Helm values
    ("cve-2026-126198-pgedge-custom-tools/negative", []),
])
def test_client_fixtures(tree: str, expected: list[tuple[str, int]]) -> None:
    found = sorted((f.file_path, f.line_number or 0)
                   for f in container_image_pins.scan(CVES / tree)[0] if f.rule_id == CLIENTS_PIN)
    assert found == expected
    assert SERVER_PIN not in _image_ids(CVES / tree)


def test_the_client_findings_survive_the_full_engine_at_medium() -> None:
    """The vulnerable compose runs a fixed 1.1.0 server beside 1.0.0 clients: only the
    clients' rule reports, once per client image, and the evidence names both records."""
    found = [f for f in run_scan(CVES / "cve-2026-126199-pgedge-clients" / "vulnerable").findings
             if f.rule_id in (SERVER_PIN, CLIENTS_PIN)]
    assert sorted((f.rule_id, f.line_number, f.severity) for f in found) == [
        (CLIENTS_PIN, 11, Severity.MEDIUM), (CLIENTS_PIN, 15, Severity.MEDIUM),
    ]
    for f in found:
        assert f.evidence.endswith(f"below 1.1.0 ({FIRST_WORD_CVE}, {CUSTOM_TOOL_CVE}). Fixed in 1.1.0.")


@pytest.mark.parametrize("image", [CLI_IMAGE, WEB_IMAGE])
@pytest.mark.parametrize(("tag", "fires"), [
    ("1.0.0-alpha3", True),   # the first image; no prompt, reads as 1.0.0
    ("1.0.0-beta3a", True),   # f1bb9986: allow_writes, no prompt, reads as 1.0.0
    ("1.0.0", True),          # 67121476: the prompt with both flaws
    ("v1.0.0", True),         # the git tag's spelling
    ("1.0", True),            # the 1.0.0 digest
    ("1.0.0-test1", True),    # cc13a18a, June, before both fixes
    ("1.1.0-beta1", False),   # b971c413 carries c86d5cbe and 310c0280
    ("1.1.0-rc1", False), ("1.1.0", False), ("1.1", False),
    ("1.2.0-beta1", False),
    ("latest", False),        # the 1.1.0 digest of both images on 2026-11-14
    ("main", False),          # not a version
    (None, False),
])
def test_client_tags(tmp_path: Path, image: str, tag: str | None, fires: bool) -> None:
    ref = image if tag is None else f"{image}:{tag}"
    assert (CLIENTS_PIN in _image_ids(_compose(tmp_path, ref))) is fires


def test_each_rule_reads_only_its_own_images(tmp_path: Path) -> None:
    assert _image_ids(_compose(tmp_path, f"{SERVER_IMAGE}:1.0.0")) == {SERVER_PIN}
    assert _image_ids(_compose(tmp_path, f"{WEB_IMAGE}:1.0.0")) == {CLIENTS_PIN}
    assert _image_ids(_compose(tmp_path, "ghcr.io/pgedge/nla-web-extra:1.0.0")) == set()


def test_the_stated_limits() -> None:
    """Pre-release tags have no prompt to misjudge but read as 1.0.0; the rule reads the
    tag, not `allow_writes`; a 1.1.0 client against an older server still skips custom
    tools, which only the server rule's tag reports."""
    text = RULES[CLIENTS_PIN].limitations
    assert "reads as 1.0.0 and is reported, although none has a write-confirmation prompt" in text
    assert "a deployment whose connections all leave `allow_writes` off is reported" in text
    assert "A 1.1.0 client still runs a custom tool's write unasked against a server below 1.1.0" in text
    assert SERVER_PIN in text
    assert CLIENTS_PIN in RULES[SERVER_PIN].limitations


# ---- the feeds ---------------------------------------------------------------------------------


@pytest.mark.parametrize("cve", [READONLY_CVE, PLDO_CVE, CUSTOM_TOOL_CVE, FIRST_WORD_CVE])
def test_nvds_records_map_to_nothing(cve: str) -> None:
    """GitHub's CNA data names `pgedge-postgres-mcp` with a bare `< 1.1.0`, no packageURL,
    and no reviewed row maps it, so `aak update` keeps none of the four: the image rules
    are the only thing that reports them. OSV holds each only as an NVD import with git
    ranges."""
    vuln = _nvd_record(cve)
    assert vuln["cve"]["id"] == cve
    assert vuln["cve"]["sourceIdentifier"] == "security-advisories@github.com"
    assert nvd_feed.record_packages(vuln, nvd_feed.load_package_map()) == []
    assert nvd_feed.record_entries(vuln, nvd_feed.load_package_map(), nvd_feed.Tally(),
                                   launch_rows=nvd_feed.load_launch_map()) == []


def test_no_record_is_bundled() -> None:
    text = advisory_feed.BUNDLED_FEED.read_text(encoding="utf-8")
    for cve in (READONLY_CVE, PLDO_CVE, CUSTOM_TOOL_CVE, FIRST_WORD_CVE):
        assert cve not in text


# ---- the ledger --------------------------------------------------------------------------------


@pytest.mark.parametrize(("cve", "issue", "rule_id"), [
    (READONLY_CVE, 1238, SERVER_PIN),
    (PLDO_CVE, 1239, SERVER_PIN),
    (CUSTOM_TOOL_CVE, 1240, CLIENTS_PIN),
    (FIRST_WORD_CVE, 1241, CLIENTS_PIN),
])
def test_each_record_has_one_ledger_row(cve: str, issue: int, rule_id: str) -> None:
    rows = [line for line in LEDGER.read_text(encoding="utf-8").splitlines() if line.startswith(f"| {cve} ")]
    assert len(rows) == 1 and rows[0].rstrip().endswith(f"| #{issue} |")
    assert rule_id in rows[0]
    assert "out of scope" not in rows[0].lower()
