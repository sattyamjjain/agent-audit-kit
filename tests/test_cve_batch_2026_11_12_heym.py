"""Two held heym records: one new image rule, one out of scope.

heym is on neither PyPI nor npm and ships as `ghcr.io/heymrun/heym`. Every range below
was read on 2026-11-12 in the source at the commit each image's label names
(`org.opencontainers.image.revision`): 0.0.1 is 5df3bea6, 0.0.72 is b04ceb3c, 0.0.74 is
e356609b and 0.0.75 is 6c6213f8, each the commit of its release tag. GHCR has no 0.0.70,
0.0.71 or 0.0.73 image. NVD's records are saved unedited under tests/fixtures/nvd_cna.
`CHANGELOG.cves.md` holds the reasoning.

CVE-2026-67546 (HIGH): `POST /api/mcp/fetch-tools` starts any logged-in account's stdio
command on the backend host, from 0.0.1 to 0.0.74; 0.0.75 runs it in a throwaway
container. A different flaw at a higher severity than the MEDIUM 0.0.109 workflow-node
rule, so it is a rule of its own.

CVE-2026-67545 (HIGH): the HTTP workflow node fetched any URL until 0.0.73. The flaw is
outside heym's MCP integration, which the record says already had the guard, so it is
out of scope as n8n's workflow-node records were on 2026-11-11, and no rule names it.
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

HEYM_STDIO_RULE = "AAK-MCP-HEYM-CVE-2026-67546-001"
HEYM_NODE_SSRF_RULE = "AAK-MCP-HEYM-CVE-2026-100858-001"
HEYM_IMAGE = "ghcr.io/heymrun/heym"
STDIO_CVE = "CVE-2026-67546"
HTTP_NODE_CVE = "CVE-2026-67545"

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "fixtures" / "cves" / "cve-2026-67546-heym-mcp-stdio"
NVD_CNA = HERE / "fixtures" / "nvd_cna"
LEDGER = HERE.parent / "CHANGELOG.cves.md"


def _image_ids(root: Path) -> set[str]:
    return {f.rule_id for f in container_image_pins.scan(root)[0]}


def _compose(root: Path, ref: str) -> Path:
    (root / "compose.yaml").write_text(f"services:\n  heym:\n    image: {ref}\n", encoding="utf-8")
    return root


def _nvd_record(cve: str) -> dict[str, Any]:
    (vuln,) = json.loads((NVD_CNA / f"{cve}.json").read_text(encoding="utf-8"))["vulnerabilities"]
    return vuln


# ---- the rule ----------------------------------------------------------------------------------


def test_the_rule_is_registered_at_high() -> None:
    rule = RULES[HEYM_STDIO_RULE]
    assert rule.severity is Severity.HIGH
    assert rule.category is Category.SUPPLY_CHAIN
    assert rule.cve_references == [STDIO_CVE]
    assert STDIO_CVE in rule.description and "GHSA-378x-q589-34mv" in rule.description
    assert "STA-08" in rule.aicm_references


def test_the_workflow_node_rule_is_unchanged() -> None:
    """The 0.0.109 rule keeps its CVE, severity and floor: a MEDIUM SSRF fixed above
    this record's floor, a different flaw."""
    assert RULES[HEYM_NODE_SSRF_RULE].cve_references == ["CVE-2026-100858"]
    assert RULES[HEYM_NODE_SSRF_RULE].severity is Severity.MEDIUM


def test_the_image_rows() -> None:
    rows = [(p.rule_id, p.floor, p.introduced, p.floating_affected, p.cves)
            for p in container_image_pins._PINS if p.image == HEYM_IMAGE]
    assert rows == [
        (HEYM_NODE_SSRF_RULE, (0, 0, 109), None, False, ("CVE-2026-100858",)),
        (HEYM_STDIO_RULE, (0, 0, 75), None, False, (STDIO_CVE,)),
    ]


# ---- fixtures ----------------------------------------------------------------------------------


@pytest.mark.parametrize(("tree", "expected"), [
    ("vulnerable", {HEYM_STDIO_RULE, HEYM_NODE_SSRF_RULE}),          # 0.0.74
    ("vulnerable-first", {HEYM_STDIO_RULE, HEYM_NODE_SSRF_RULE}),    # 0.0.1, the first image
    ("negative", {HEYM_NODE_SSRF_RULE}),                             # 0.0.75: the 0.0.109 rule only
    ("negative-latest", set()),                                      # the README's `latest`
])
def test_fixtures(tree: str, expected: set[str]) -> None:
    assert _image_ids(FIXTURE / tree) == expected


@pytest.mark.parametrize(("tree", "where"), [
    ("vulnerable", ("compose.yaml", 4)),
    ("vulnerable-first", ("Dockerfile", 2)),
])
def test_the_finding_lands_on_the_reference(tree: str, where: tuple[str, int]) -> None:
    (finding,) = [f for f in container_image_pins.scan(FIXTURE / tree)[0] if f.rule_id == HEYM_STDIO_RULE]
    assert (finding.file_path, finding.line_number) == where
    assert finding.evidence.endswith(f"heym below 0.0.75 ({STDIO_CVE}). Fixed in 0.0.75.")


def test_the_finding_survives_the_full_engine() -> None:
    found = {f.rule_id: f.severity for f in run_scan(FIXTURE / "vulnerable").findings
             if f.rule_id in (HEYM_STDIO_RULE, HEYM_NODE_SSRF_RULE)}
    assert found == {HEYM_STDIO_RULE: Severity.HIGH, HEYM_NODE_SSRF_RULE: Severity.MEDIUM}


@pytest.mark.parametrize(("tag", "fires"), [
    ("0.0.1", True), ("0.0.69", True), ("0.0.72", True), ("0.0.74", True),
    ("v0.0.74", True),      # the git tag's spelling; GHCR tags have no `v`
    ("0.0.73", True),       # no such image, but a 0.0.73 build still spawned on the host
    ("0.0.75", False), ("0.0.76", False), ("0.0.153", False),
    ("0.0", False),         # a two-part tag floats over the line, which has fixed releases
    ("latest", False), (None, False),
])
def test_tags(tmp_path: Path, tag: str | None, fires: bool) -> None:
    ref = HEYM_IMAGE if tag is None else f"{HEYM_IMAGE}:{tag}"
    assert (HEYM_STDIO_RULE in _image_ids(_compose(tmp_path, ref))) is fires


def test_the_compose_files_local_build_states_no_version(tmp_path: Path) -> None:
    """heym's own compose file builds `heym-backend:local` unless HEYM_BACKEND_IMAGE is
    set, so it names no release."""
    root = _compose(tmp_path, "${HEYM_BACKEND_IMAGE:-heym-backend:local}")
    assert _image_ids(root) == set()
    assert "`heym-backend:local` unless `HEYM_BACKEND_IMAGE` is set" in RULES[HEYM_STDIO_RULE].limitations


def test_the_sandbox_opt_out_is_a_stated_limit() -> None:
    """0.0.75's `HEYM_MCP_STDIO_SANDBOX=subprocess` starts stdio commands on the host
    again; the rule reads the tag, so that deployment is not reported, and the text
    says so."""
    assert HEYM_STDIO_RULE not in _image_ids(FIXTURE / "limitation-sandbox-optout")
    assert "`HEYM_MCP_STDIO_SANDBOX=subprocess`" in RULES[HEYM_STDIO_RULE].limitations
    assert "the rule reads the tag, not that variable" in RULES[HEYM_STDIO_RULE].limitations


# ---- the feeds ---------------------------------------------------------------------------------


@pytest.mark.parametrize("cve", [STDIO_CVE, HTTP_NODE_CVE])
def test_nvds_records_map_to_nothing(cve: str) -> None:
    """GitHub's CNA data names `heymrun/heym` with a bare range, no packageURL, and no
    reviewed row or launch row maps it, so `aak update` keeps neither record: the image
    rule is the only thing that reports CVE-2026-67546."""
    vuln = _nvd_record(cve)
    assert vuln["cve"]["id"] == cve
    assert nvd_feed.record_packages(vuln, nvd_feed.load_package_map()) == []
    assert nvd_feed.record_entries(vuln, nvd_feed.load_package_map(), nvd_feed.Tally(),
                                   launch_rows=nvd_feed.load_launch_map()) == []


def test_neither_record_is_bundled() -> None:
    text = advisory_feed.BUNDLED_FEED.read_text(encoding="utf-8")
    assert STDIO_CVE not in text and HTTP_NODE_CVE not in text


# ---- CVE-2026-67545: out of scope --------------------------------------------------------------


def test_the_http_node_record_is_claimed_by_no_rule(tmp_path: Path) -> None:
    """0.0.72, the newest image the HTTP node record affects, gets both heym rules for
    their own flaws, and no finding or rule names CVE-2026-67545."""
    root = _compose(tmp_path, f"{HEYM_IMAGE}:0.0.72")
    findings = run_scan(root).findings
    assert {f.rule_id for f in findings} >= {HEYM_STDIO_RULE, HEYM_NODE_SSRF_RULE}
    assert not [f for f in findings if HTTP_NODE_CVE in f.evidence]
    assert not [r for r in RULES.values() if HTTP_NODE_CVE in r.cve_references]


# ---- the ledger --------------------------------------------------------------------------------


@pytest.mark.parametrize(("cve", "out_of_scope"), [(STDIO_CVE, False), (HTTP_NODE_CVE, True)])
def test_each_record_has_one_ledger_row(cve: str, out_of_scope: bool) -> None:
    rows = [line for line in LEDGER.read_text(encoding="utf-8").splitlines() if line.startswith(f"| {cve} ")]
    assert len(rows) == 1 and rows[0].rstrip().endswith("| not filed |")
    assert ("out of scope" in rows[0].lower()) is out_of_scope
    assert (HEYM_STDIO_RULE in rows[0]) is not out_of_scope
