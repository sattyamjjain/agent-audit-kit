"""2026-11-14 batch, group "misc": #1237, #1246 and two held records, read on 2026-11-14.

Two new image pins. SiYuan (CVE-2026-126393): the MCP `skill` tool's `install` action
downloads past its parse-time SSRF check, on `b3log/siyuan` from v3.7.0 below v3.8.10,
read in the source at each tag. Apache APISIX (CVE-2026-124726): the `openapi-to-mcp`
plugin lets a tool call reach undeclared API paths with the Route's credentials, on
`apache/apisix` 3.19.0, read in the source at the tags and in the 3.19.0 and 3.20.0
images. OpenTelemetry's traceparent ReDoS (CVE-2026-126360) joins the bundled advisory
feed, as anyio's two advisories did, because the MCP Python SDK 2.x requires
`opentelemetry-api` and, by default from 2.0.0b1, extracts trace context from every
request's `params._meta`; the
OSV record is saved unedited under tests/fixtures/cves/cve-2026-126360-opentelemetry/osv.
Opera Neon's MCP Hub (CVE-2026-123139) is out of scope: a browser built-in no project
file declares. NVD's records are saved unedited under tests/fixtures/nvd_cna, as the API
returned them on 2026-11-14. `CHANGELOG.cves.md` holds the reasoning. Nothing here touches
the network.
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
from agent_audit_kit.scanners import container_image_pins
from agent_audit_kit.scanners.known_vulns import scan as known_vulns

SIYUAN_SKILL_PIN = "AAK-MCP-SIYUAN-CVE-2026-126393-001"
SIYUAN_ASSET_PIN = "AAK-MCP-SIYUAN-CVE-2026-116168-001"
SIYUAN_PANIC_PIN = "AAK-MCP-SIYUAN-CVE-2026-123492-001"
APISIX_PIN = "AAK-MCP-APISIX-CVE-2026-124726-001"
KNOWN_VULN_RULE = "AAK-KNOWN-VULN-001"

HERE = Path(__file__).parent
CVES = HERE / "fixtures" / "cves"
NVD_CNA = HERE / "fixtures" / "nvd_cna"
LEDGER = HERE.parent / "CHANGELOG.cves.md"

OPERA = "CVE-2026-123139"
APISIX = "CVE-2026-124726"
OTEL = "CVE-2026-126360"
SIYUAN = "CVE-2026-126393"
OTEL_GHSA = "GHSA-mf5v-w3w3-f6cg"
SIYUAN_GHSA = "GHSA-6pg3-pqxw-jm82"

OTEL_ROOT = CVES / "cve-2026-126360-opentelemetry"


def _image_ids(root: Path) -> set[str]:
    return {f.rule_id for f in container_image_pins.scan(root)[0]}


def _compose(root: Path, image: str) -> set[str]:
    (root / "compose.yaml").write_text(f"services:\n  s:\n    image: {image}\n", encoding="utf-8")
    return _image_ids(root)


def _nvd_record(cve: str) -> dict[str, Any]:
    (vuln,) = json.loads((NVD_CNA / f"{cve}.json").read_text(encoding="utf-8"))["vulnerabilities"]
    return vuln


def _mentions(root: Path, cve: str) -> list[str]:
    return [f.rule_id for f in run_scan(root).findings if cve in f.evidence]


def test_nvd_records_are_the_ones_read() -> None:
    """Each saved record is the CVE it is filed under, with the description quoted in
    the ledger."""
    expected = {
        OPERA: "Improper verification of the source of a communication channel vulnerability in Opera Neon",
        APISIX: "Relative Path Traversal, with Unintended Proxy vulnerability in Apache APISIX.",
        OTEL: "OpenTelemetry Python provides the Python API and SDK for OpenTelemetry. Prior to 1.45.2",
        SIYUAN: "SiYuan before 3.8.10 contains a server-side request forgery vulnerability in the skill-install",
    }
    for cve, opening in expected.items():
        record = _nvd_record(cve)["cve"]
        assert record["id"] == cve
        (text,) = [d["value"] for d in record["descriptions"] if d["lang"] == "en"]
        assert text.startswith(opening)


@pytest.mark.parametrize("cve", [OPERA, APISIX, OTEL, SIYUAN])
def test_no_nvd_record_maps_to_a_package(cve: str) -> None:
    """Opera's and SiYuan's CNA data name a vendor and a product, APISIX's a
    `pkg:software-id` URL and OpenTelemetry's a bare `< 1.45.2`, so `nvd_feed` keeps none
    of them after `aak update`; OpenTelemetry's feed route is OSV's GHSA record."""
    assert nvd_feed.record_packages(_nvd_record(cve), nvd_feed.load_package_map()) == []


# --- SiYuan (CVE-2026-126393): new image pin ---------------------------------------------


def test_siyuan_rule() -> None:
    rule = RULES[SIYUAN_SKILL_PIN]
    assert rule.cve_references == [SIYUAN]
    assert rule.severity is Severity.MEDIUM
    assert rule.category.value == "supply-chain"
    assert rule.owasp_mcp_references == ["MCP04:2025"]
    assert rule.adversa_references == ["ADV-SSRF-02"]
    assert rule.aicm_references == ["IVS-04", "STA-08"]
    assert SIYUAN_GHSA in rule.description and "3e1b977e" in rule.description
    assert "v3.8.9 fires this rule alone" in rule.limitations


def test_siyuan_row() -> None:
    rows = [p for p in container_image_pins._PINS if p.rule_id == SIYUAN_SKILL_PIN]
    assert [(p.image, p.introduced, p.floor, p.cves, p.floating_affected) for p in rows] == [
        ("b3log/siyuan", (3, 7, 0), (3, 8, 10), (SIYUAN,), False),
    ]


def test_siyuan_fixtures_positive_and_negative() -> None:
    root = CVES / "cve-2026-126393-siyuan"
    assert [(f.rule_id, f.file_path, f.line_number) for f in container_image_pins.scan(root / "vulnerable")[0]] == [
        (SIYUAN_SKILL_PIN, "compose.yaml", 3),
    ]
    assert _image_ids(root / "negative") == set()
    found = [f for f in run_scan(root / "vulnerable").findings if f.rule_id == SIYUAN_SKILL_PIN]
    assert [(f.file_path, f.severity) for f in found] == [("compose.yaml", Severity.MEDIUM)]
    assert SIYUAN in found[0].evidence and "Fixed in 3.8.10." in found[0].evidence
    assert SIYUAN_SKILL_PIN not in {f.rule_id for f in run_scan(root / "negative").findings}


@pytest.mark.parametrize(("tag", "ids"), [
    ("v3.6.5", set()),                                                   # no kernel/mcp yet
    ("v3.7.0-rc.1", {SIYUAN_SKILL_PIN, SIYUAN_ASSET_PIN}),              # the skill tool ships
    ("v3.7.0", {SIYUAN_SKILL_PIN, SIYUAN_ASSET_PIN}),
    ("v3.8.0", {SIYUAN_SKILL_PIN, SIYUAN_ASSET_PIN, SIYUAN_PANIC_PIN}),
    ("v3.8.8", {SIYUAN_SKILL_PIN, SIYUAN_PANIC_PIN}),                   # the advisory's release
    ("v3.8.9-rc.1", {SIYUAN_SKILL_PIN}),
    ("v3.8.9", {SIYUAN_SKILL_PIN}),                                     # the last affected release
    ("v3.8.10-alpha.1", set()),                                         # pushed after 3e1b977e
    ("v3.8.10", set()),
    ("latest", set()),                                                  # the v3.8.10 digest on 2026-11-14
])
def test_siyuan_image_tags(tmp_path: Path, tag: str, ids: set[str]) -> None:
    siyuan = {SIYUAN_SKILL_PIN, SIYUAN_ASSET_PIN, SIYUAN_PANIC_PIN}
    assert _compose(tmp_path, f"b3log/siyuan:{tag}") & siyuan == ids


def test_siyuan_untagged_and_docker_io_are_not_read(tmp_path: Path) -> None:
    assert _compose(tmp_path, "b3log/siyuan") == set()
    assert _compose(tmp_path, "docker.io/b3log/siyuan:v3.8.9") == set()


# --- Apache APISIX (CVE-2026-124726): new image pin -------------------------------------


def test_apisix_rule() -> None:
    rule = RULES[APISIX_PIN]
    assert rule.cve_references == [APISIX]
    assert rule.severity is Severity.MEDIUM
    assert rule.category.value == "supply-chain"
    assert rule.owasp_mcp_references == ["MCP04:2025", "MCP07:2025"]
    assert rule.adversa_references == ["ADV-INJECT-06"]
    assert rule.aicm_references == ["AIS-07", "IAM-01", "STA-08"]
    assert "77055643" in rule.description and "allow_encoded_path_separators" in rule.description
    assert "not whether any Route enables `openapi-to-mcp`" in rule.limitations


def test_apisix_row() -> None:
    rows = [p for p in container_image_pins._PINS if p.rule_id == APISIX_PIN]
    assert [(p.image, p.introduced, p.floor, p.cves, p.floating_affected) for p in rows] == [
        ("apache/apisix", (3, 19, 0), (3, 20, 0), (APISIX,), False),
    ]


def test_apisix_fixtures_positive_and_negative() -> None:
    root = CVES / "cve-2026-124726-apisix"
    assert [(f.rule_id, f.file_path, f.line_number) for f in container_image_pins.scan(root / "vulnerable")[0]] == [
        (APISIX_PIN, "compose.yaml", 3),
    ]
    assert _image_ids(root / "negative") == set()
    found = [f for f in run_scan(root / "vulnerable").findings if f.rule_id == APISIX_PIN]
    assert [(f.file_path, f.severity) for f in found] == [("compose.yaml", Severity.MEDIUM)]
    assert APISIX in found[0].evidence and "Fixed in 3.20.0." in found[0].evidence
    assert APISIX_PIN not in {f.rule_id for f in run_scan(root / "negative").findings}


@pytest.mark.parametrize(("tag", "fires"), [
    ("3.18.0-debian", False),       # no openapi-to-mcp plugin yet
    ("3.19.0-debian", True),
    ("3.19.0-ubuntu", True),
    ("3.19.0-redhat", True),
    ("3.20.0-debian", False),       # 77055643
    ("3.20.0-ubuntu", False),
    ("latest", False),              # the 3.20.0-ubuntu build on 2026-11-14
    ("dev", False),                 # states no version
    ("${APISIX_IMAGE_TAG:-3.19.0-debian}", False),   # the apisix-docker example's form
])
def test_apisix_image_tags(tmp_path: Path, tag: str, fires: bool) -> None:
    assert (APISIX_PIN in _compose(tmp_path, f"apache/apisix:{tag}")) is fires


def test_apisix_other_images_are_not_read(tmp_path: Path) -> None:
    """The ingress controller is another image, and the reader matches Docker Hub
    images by the bare name the docs use."""
    assert _compose(tmp_path, "apache/apisix") == set()
    assert _compose(tmp_path, "docker.io/apache/apisix:3.19.0-debian") == set()
    assert _compose(tmp_path, "apache/apisix-ingress-controller:1.8.0") == set()


@pytest.mark.parametrize(("tag_line", "fires"), [
    ("  tag: 3.19.0-debian\n", True),
    ("  tag: 3.20.0-debian\n", False),
    ("  tag: \"\"\n", False),       # the chart's default: its appVersion decides
])
def test_apisix_helm_values(tmp_path: Path, tag_line: str, fires: bool) -> None:
    (tmp_path / "values.yaml").write_text(
        "image:\n  repository: apache/apisix\n  pullPolicy: IfNotPresent\n" + tag_line, encoding="utf-8")
    assert (APISIX_PIN in _image_ids(tmp_path)) is fires


def test_apisix_dockerfile(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM apache/apisix:3.19.0-debian\n", encoding="utf-8")
    assert [(f.rule_id, f.line_number) for f in container_image_pins.scan(tmp_path)[0]] == [(APISIX_PIN, 1)]


# --- OpenTelemetry (CVE-2026-126360): bundled advisory feed -----------------------------


def test_the_bundled_record_is_osvs_unedited() -> None:
    saved = json.loads((OTEL_ROOT / "osv" / f"{OTEL_GHSA}.json").read_text(encoding="utf-8"))
    bundled = json.loads(advisory_feed.BUNDLED_FEED.read_text(encoding="utf-8"))
    (record,) = [r for r in bundled["records"] if r["id"] == OTEL_GHSA]
    assert record == saved
    assert saved["aliases"] == [OTEL]
    assert saved["affected"][0]["package"]["name"] == "opentelemetry-api"
    assert saved["affected"][0]["ranges"] == [
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.45.2"}]}]


def test_the_bundled_record_is_read_without_an_update() -> None:
    feed = advisory_feed.load_feed()
    assert feed.origin == "bundled"
    for version in ("1.28.0", "1.45.1"):     # the MCP SDK's floor, and the last affected release
        assert {a.id for a in feed.match("PyPI", "opentelemetry-api", version)} == {OTEL_GHSA}
    assert feed.match("PyPI", "opentelemetry-api", "1.45.2") == []


def test_otel_fixtures_positive_and_negative() -> None:
    """An MCP server's uv.lock on the SDK 2.3.0 with `opentelemetry-api` 1.45.1 is
    reported once, at MEDIUM from the record's CVSS 3.1 vector; 1.45.2 is not."""
    found = [f for f in run_scan(OTEL_ROOT / "vulnerable").findings if f.rule_id == KNOWN_VULN_RULE]
    assert [(f.file_path, f.line_number, f.severity) for f in found] == [("uv.lock", 24, Severity.MEDIUM)]
    assert OTEL in found[0].evidence and OTEL_GHSA in found[0].evidence
    assert "it is fixed in 1.45.2" in found[0].evidence
    assert _mentions(OTEL_ROOT / "negative", OTEL) == []


def test_otel_requirements_pin(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("mcp==2.3.0\nopentelemetry-api==1.45.1\n", encoding="utf-8")
    assert [(f.rule_id, f.line_number) for f in known_vulns(tmp_path)[0]] == [(KNOWN_VULN_RULE, 2)]


def test_otel_has_no_pin() -> None:
    """The flaw is the tracing library's, so no rule names it; the feed reports it."""
    assert not [r for r in RULES.values() if OTEL in r.cve_references]


# --- Opera Neon (CVE-2026-123139): out of scope ------------------------------------------


def test_opera_claims_nothing(tmp_path: Path) -> None:
    """The MCP Hub is a browser built-in that no project file declares, and npm's
    `mcp-hub` is ravitemer's MCP server manager, another project."""
    (tmp_path / "package.json").write_text('{"dependencies": {"mcp-hub": "4.2.1"}}', encoding="utf-8")
    (tmp_path / ".mcp.json").write_text(json.dumps(
        {"mcpServers": {"hub": {"command": "npx", "args": ["-y", "mcp-hub@4.2.1"]}}}), encoding="utf-8")
    assert _mentions(tmp_path, OPERA) == []
    assert not [r for r in RULES.values() if OPERA in r.cve_references]


# --- the ledger -------------------------------------------------------------------------

ROWS = [
    (OPERA, "#1237", None),
    (APISIX, "#1246", APISIX_PIN),
    (OTEL, "not filed", KNOWN_VULN_RULE),
    (SIYUAN, "not filed", SIYUAN_SKILL_PIN),
]


@pytest.mark.parametrize(("cve", "issue", "rule"), ROWS)
def test_every_record_has_one_ledger_row(cve: str, issue: str, rule: str | None) -> None:
    rows = [line for line in LEDGER.read_text(encoding="utf-8").splitlines() if line.startswith(f"| {cve} ")]
    assert len(rows) == 1 and rows[0].rstrip().endswith(f"| {issue} |")
    assert ("out of scope" in rows[0].lower()) is (rule is None)
    if rule is not None:
        assert rule in rows[0]
