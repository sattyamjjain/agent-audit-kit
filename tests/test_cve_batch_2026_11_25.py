"""2026-11-25 batch: #1258 to #1267, read on 2026-11-25.

Four version pins: the MCP Python SDK's OAuth client (CVE-2026-115563), the AWS Pricing
and Timestream for InfluxDB MCP servers (CVE-2026-126816, CVE-2026-126681) and
code-review-mcp-server (CVE-2026-68934), each range read in the published wheels or
tarballs. Two image pins: REBUILD's MCP QueryRecords tool (CVE-2026-129875), read in the
source at each tag, and GitLab's MCP server (CVE-2026-123142), on the vendor's ranges. Next.js's `use cache` disclosure (CVE-2026-119790) and, for a go.mod
that requires its module, Kubeshark's two CLI flaws (CVE-2026-129235, CVE-2026-129236)
are left to AAK-KNOWN-VULN-001 after `aak update`. The WordPress plugin
(CVE-2026-125771) is out of scope.

NVD's records are saved unedited under tests/fixtures/nvd_cna and OSV's under
tests/fixtures/osv, as the APIs returned them on 2026-11-25. `CHANGELOG.cves.md` holds
the reasoning. Nothing here touches the network.
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

SDK_PIN = "AAK-MCP-SDK-CVE-2026-115563-001"
SDK_MEDIUM_PIN = "AAK-MCP-SDK-CVE-2026-59951-001"
PRICING_PIN = "AAK-MCP-AWSPRICING-CVE-2026-126816-001"
TIMESTREAM_PIN = "AAK-MCP-TIMESTREAM-CVE-2026-126681-001"
CODEREVIEW_PIN = "AAK-MCP-CODEREVIEW-CVE-2026-68934-001"
REBUILD_PIN = "AAK-MCP-REBUILD-CVE-2026-129875-001"
GITLAB_PIN = "AAK-MCP-GITLAB-CVE-2026-123142-001"
KNOWN = "AAK-KNOWN-VULN-001"

HERE = Path(__file__).parent
CVES = HERE / "fixtures" / "cves"
NVD_CNA = HERE / "fixtures" / "nvd_cna"
OSV = HERE / "fixtures" / "osv"
LEDGER = HERE.parent / "CHANGELOG.cves.md"
NOW = datetime(2026, 11, 25, 18, 0, tzinfo=timezone.utc)

SDK, PRICING, TIMESTREAM = "CVE-2026-115563", "CVE-2026-126816", "CVE-2026-126681"
CODEREVIEW, REBUILD, NEXT = "CVE-2026-68934", "CVE-2026-129875", "CVE-2026-119790"
KUBESHARK_FILE, KUBESHARK_ARGV = "CVE-2026-129235", "CVE-2026-129236"
WORDPRESS, GITLAB = "CVE-2026-125771", "CVE-2026-123142"
NEXT_GHSA, KUBESHARK_FILE_GHSA, KUBESHARK_ARGV_GHSA = (
    "GHSA-mfr8-8qww-v76h", "GHSA-gj7r-p794-hhq5", "GHSA-8vf2-hxg5-crqh")

PIN_RULES: dict[str, tuple[str, Severity, str, list[str]]] = {
    SDK_PIN: (SDK, Severity.HIGH, "cve-2026-115563-mcp-sdk-oauth", ["MCP01:2025", "MCP07:2025", "MCP04:2025"]),
    PRICING_PIN: (PRICING, Severity.MEDIUM, "cve-2026-126816-aws-pricing", ["MCP02:2025", "MCP04:2025"]),
    TIMESTREAM_PIN: (TIMESTREAM, Severity.MEDIUM, "cve-2026-126681-timestream-influxdb", ["MCP01:2025", "MCP04:2025"]),
    CODEREVIEW_PIN: (CODEREVIEW, Severity.HIGH, "cve-2026-68934-code-review-mcp", ["MCP05:2025", "MCP04:2025"]),
    REBUILD_PIN: (REBUILD, Severity.HIGH, "cve-2026-129875-rebuild", ["MCP07:2025", "MCP04:2025"]),
    GITLAB_PIN: (GITLAB, Severity.MEDIUM, "cve-2026-123142-gitlab", ["MCP02:2025", "MCP07:2025", "MCP04:2025"]),
}


def _nvd(cve: str) -> dict[str, Any]:
    (vuln,) = json.loads((NVD_CNA / f"{cve}.json").read_text(encoding="utf-8"))["vulnerabilities"]
    return vuln


def _osv(ident: str) -> dict[str, Any]:
    return json.loads((OSV / f"{ident}.json").read_text(encoding="utf-8"))


def _cache(*idents: str) -> None:
    """The cached feed `aak update` writes, holding these OSV records (HOME is per test)."""
    collector = advisory_feed.Collector()
    for ident in idents:
        record = _osv(ident)
        for ecosystem in sorted({a["package"]["ecosystem"] for a in record["affected"]}):
            collector.add(ecosystem, record)
    collector.write(now=NOW)


def _ids(root: Path) -> set[str]:
    return {f.rule_id for f in run_scan(root).findings}


def _pin_ids(root: Path) -> set[str]:
    return {f.rule_id for f in mcp_cve_pins_2026_07.scan(root)[0]}


def _requirements(root: Path, line: str) -> Path:
    (root / "requirements.txt").write_text(line + "\n", encoding="utf-8")
    return root


def _uvx(root: Path, package: str) -> Path:
    (root / ".mcp.json").write_text(json.dumps(
        {"mcpServers": {"s": {"command": "uvx", "args": [package]}}}), encoding="utf-8")
    return root


def _npx(root: Path, package: str) -> Path:
    (root / ".mcp.json").write_text(json.dumps(
        {"mcpServers": {"s": {"command": "npx", "args": ["-y", package]}}}), encoding="utf-8")
    return root


# ---- the saved records ----------------------------------------------------------------------


@pytest.mark.parametrize(("cve", "opening"), [
    (WORDPRESS, "Incorrect Privilege Assignment vulnerability in AtlasAiDev MCP Server for WordPress"),
    (REBUILD, "REBUILD 4.5.0 through 4.5.4 contains an information disclosure vulnerability"),
    (SDK, "The Model Context Protocol Python SDK is the official Python SDK"),
    (KUBESHARK_ARGV, "Kubeshark is an eBPF-powered network observability tool for Kubernetes."),
    (NEXT, "Next.js"),
    (PRICING, "Improper limitation of a pathname to a restricted directory in the cost report generation tool"),
    (KUBESHARK_FILE, "Kubeshark is an eBPF-powered network observability tool for Kubernetes."),
    (TIMESTREAM, "Improper restriction of intended endpoints in the connection configuration handling"),
    (CODEREVIEW, "code-review-mcp-server automates code review"),
    (GITLAB, "GitLab has remediated an issue in GitLab CE/EE"),
])
def test_each_saved_nvd_record_is_the_one_read(cve: str, opening: str) -> None:
    record = _nvd(cve)["cve"]
    assert record["id"] == cve
    (text,) = [d["value"] for d in record["descriptions"] if d["lang"] == "en"]
    assert opening in text


def test_the_saved_osv_records_alias_their_cves() -> None:
    for ident, cve in ((NEXT_GHSA, NEXT), (KUBESHARK_FILE_GHSA, KUBESHARK_FILE), (KUBESHARK_ARGV_GHSA, KUBESHARK_ARGV)):
        record = _osv(ident)
        assert record["id"] == ident and cve in record["aliases"]


# ---- the rules and their fixtures -----------------------------------------------------------


@pytest.mark.parametrize("rule_id", sorted(PIN_RULES))
def test_rule_metadata(rule_id: str) -> None:
    cve, severity, _, mcp = PIN_RULES[rule_id]
    rule = RULES[rule_id]
    assert rule.cve_references == [cve] and rule.severity is severity
    assert rule.category.value == "supply-chain" and rule.owasp_mcp_references == mcp
    assert "ASI04" in rule.owasp_agentic_references and "STA-08" in rule.aicm_references
    assert cve in rule.description and "2026-11-25" in rule.limitations


@pytest.mark.parametrize("rule_id", sorted(PIN_RULES))
def test_fixture_fires_and_its_negative_is_silent(rule_id: str) -> None:
    cve, severity, name, _ = PIN_RULES[rule_id]
    found = [f for f in run_scan(CVES / name / "vulnerable").findings if f.rule_id == rule_id]
    assert len(found) == 1 and found[0].severity is severity and found[0].cve_references == [cve]
    assert found[0].line_number
    assert rule_id not in _ids(CVES / name / "negative")


# ---- MCP Python SDK (CVE-2026-115563) -------------------------------------------------------


@pytest.mark.parametrize(("version", "fires"), [
    ("1.9.0", False),    # no OAuthClientProvider in the wheel
    ("1.9.1", True),     # the provider arrives
    ("1.29.1", True),    # the last 1.x release with no issuer check
    ("1.30.0", False),
    ("2.0.0", True),
    ("2.1.1", True),
    ("2.2.0", False),
    ("2.3.0", False),
])
def test_sdk_versions(tmp_path: Path, version: str, fires: bool) -> None:
    assert (SDK_PIN in _pin_ids(_requirements(tmp_path, f"mcp=={version}"))) is fires


@pytest.mark.parametrize("line", ["mcp", "mcp>=1.30.0,<2", "mcp[cli]==1.30.0", "fastmcp==2.0.0", "mcp-atlassian==0.11.0"])
def test_sdk_unversioned_fixed_and_other_packages_are_silent(tmp_path: Path, line: str) -> None:
    assert SDK_PIN not in _pin_ids(_requirements(tmp_path, line))


def test_sdk_range_that_admits_an_affected_release_fires(tmp_path: Path) -> None:
    assert SDK_PIN in _pin_ids(_requirements(tmp_path, "mcp>=1.20,<2"))


def test_sdk_npm_package_of_the_same_name_is_silent(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"mcp": "1.20.0"}}), encoding="utf-8")
    assert SDK_PIN not in _pin_ids(tmp_path)


def test_every_release_the_sdk_rule_reports_is_in_the_medium_rule_too(tmp_path: Path) -> None:
    """Stated in the limitations: the MEDIUM rule's range contains this one's."""
    for version in ("1.9.1", "1.29.1", "2.0.0", "2.1.1"):
        assert {SDK_PIN, SDK_MEDIUM_PIN} <= _pin_ids(_requirements(tmp_path, f"mcp=={version}"))


# ---- AWS Pricing and cost analysis (CVE-2026-126816) ----------------------------------------


@pytest.mark.parametrize(("package", "fires"), [
    ("awslabs.aws-pricing-mcp-server@1.0.1", True),
    ("awslabs.aws-pricing-mcp-server@1.0.30", True),
    ("awslabs.aws-pricing-mcp-server@1.0.31", False),
    ("awslabs.aws-pricing-mcp-server@1.1.2", False),
    ("awslabs.aws-pricing-mcp-server@latest", False),   # the README's own launch
    ("awslabs.aws-pricing-mcp-server", False),
    ("awslabs.cost-analysis-mcp-server@1.0.5", True),   # its last release
    ("awslabs.cost-analysis-mcp-server@latest", True),
    ("awslabs.cost-analysis-mcp-server", True),
    ("awslabs.cost-explorer-mcp-server@0.0.1", False),  # another server
])
def test_pricing_launches(tmp_path: Path, package: str, fires: bool) -> None:
    assert (PRICING_PIN in _pin_ids(_uvx(tmp_path, package))) is fires


def test_pricing_normalised_spelling_in_a_lockfile(tmp_path: Path) -> None:
    """uv.lock spells the dotted name with hyphens."""
    (tmp_path / "uv.lock").write_text(
        'version = 1\n\n[[package]]\nname = "awslabs-aws-pricing-mcp-server"\nversion = "1.0.30"\n'
        'source = { registry = "https://pypi.org/simple" }\n', encoding="utf-8")
    assert PRICING_PIN in _pin_ids(tmp_path)


# ---- Timestream for InfluxDB (CVE-2026-126681) ----------------------------------------------


@pytest.mark.parametrize(("version", "fires"), [
    ("0.0.11", False),   # the token is the caller's, none is configured
    ("0.0.12", True),
    ("0.0.18", True),
    ("0.0.19", False),
    ("0.1.4", False),
])
def test_timestream_versions(tmp_path: Path, version: str, fires: bool) -> None:
    root = _requirements(tmp_path, f"awslabs.timestream-for-influxdb-mcp-server=={version}")
    assert (TIMESTREAM_PIN in _pin_ids(root)) is fires


def test_timestream_launch_with_no_version_is_silent(tmp_path: Path) -> None:
    assert TIMESTREAM_PIN not in _pin_ids(_uvx(tmp_path, "awslabs.timestream-for-influxdb-mcp-server@latest"))


# ---- code-review-mcp-server (CVE-2026-68934) ------------------------------------------------


@pytest.mark.parametrize(("package", "fires"), [
    ("code-review-mcp-server@1.0.0", True),
    ("code-review-mcp-server@1.4.0-canary.1", True),
    ("code-review-mcp-server@1.5.1", True),
    ("code-review-mcp-server@1.5.3", False),
    ("code-review-mcp-server@latest", False),
    ("code-review-mcp-server", False),
    ("@acme/code-review-mcp-server@1.0.0", False),
    ("mcp-code-review@1.0.0", False),
])
def test_code_review_launches(tmp_path: Path, package: str, fires: bool) -> None:
    assert (CODEREVIEW_PIN in _pin_ids(_npx(tmp_path, package))) is fires


def test_code_review_on_pypi_is_silent(tmp_path: Path) -> None:
    assert CODEREVIEW_PIN not in _pin_ids(_requirements(tmp_path, "code-review-mcp-server==1.0.0"))


# ---- REBUILD (CVE-2026-129875) --------------------------------------------------------------


def test_rebuild_row() -> None:
    rows = [p for p in container_image_pins._PINS if p.rule_id == REBUILD_PIN]
    assert [(p.image, p.introduced, p.floor, p.cves, p.floating_affected) for p in rows] == [
        ("getrebuild/rebuild", (4, 5, 0), (4, 5, 7), (REBUILD,), True),
    ]


@pytest.mark.parametrize(("image", "fires"), [
    ("getrebuild/rebuild:4.4.10", False),   # no QueryRecords tool
    ("getrebuild/rebuild:4.5.0", True),
    ("getrebuild/rebuild:4.5.3", True),
    ("getrebuild/rebuild:4.5.5", True),     # past NVD's 4.5.4, the two files unchanged
    ("getrebuild/rebuild:4.5.7", False),
    ("getrebuild/rebuild:latest", True),    # the 4.5.5 digest on 2026-11-25
    ("getrebuild/rebuild", True),
    ("docker.io/getrebuild/rebuild:4.5.5", False),
    ("acme/getrebuild/rebuild:4.5.5", False),
    ("getrebuild/rebuild:${TAG}", False),
])
def test_rebuild_images(tmp_path: Path, image: str, fires: bool) -> None:
    (tmp_path / "compose.yaml").write_text(f"services:\n  s:\n    image: {image}\n", encoding="utf-8")
    assert (REBUILD_PIN in {f.rule_id for f in container_image_pins.scan(tmp_path)[0]}) is fires


# ---- GitLab (CVE-2026-123142) ---------------------------------------------------------------


def test_gitlab_rows() -> None:
    rows = [p for p in container_image_pins._PINS if p.rule_id == GITLAB_PIN]
    assert {(p.image, p.introduced, p.floor, p.floating_affected) for p in rows} == {
        (image, introduced, floor, False)
        for image in ("gitlab/gitlab-ce", "gitlab/gitlab-ee")
        for introduced, floor in (((18, 4, 0), (19, 3, 9)), ((19, 4, 0), (19, 4, 8)), ((19, 5, 0), (19, 5, 6)))
    }


@pytest.mark.parametrize(("version", "fires"), [
    ("18.3.6", False), ("18.4.0", True), ("19.2.0", True), ("19.3.8", True), ("19.3.9", False), ("19.3.10", False),
    ("19.4.0", True), ("19.4.7", True), ("19.4.8", False), ("19.4.11", False),
    ("19.5.0", True), ("19.5.5", True), ("19.5.6", False), ("19.6.2", False),
])
@pytest.mark.parametrize("edition", ["ce", "ee"])
def test_gitlab_images(tmp_path: Path, edition: str, version: str, fires: bool) -> None:
    (tmp_path / "compose.yaml").write_text(
        f"services:\n  g:\n    image: gitlab/gitlab-{edition}:{version}-{edition}.0\n", encoding="utf-8")
    found = [f for f in container_image_pins.scan(tmp_path)[0] if f.rule_id == GITLAB_PIN]
    assert len(found) == (1 if fires else 0)


@pytest.mark.parametrize("image", [
    "gitlab/gitlab-ce:latest",       # the 19.6.2 digest on 2026-11-25
    "gitlab/gitlab-ee",
    "docker.io/gitlab/gitlab-ce:19.5.5-ce.0",
    "gitlab/gitlab-runner:v18.5.0",  # another image
    "gitlab/gitlab-ce:nightly",
])
def test_gitlab_references_that_are_not_read(tmp_path: Path, image: str) -> None:
    (tmp_path / "compose.yaml").write_text(f"services:\n  g:\n    image: {image}\n", encoding="utf-8")
    assert GITLAB_PIN not in {f.rule_id for f in container_image_pins.scan(tmp_path)[0]}


# ---- left to the advisory feed --------------------------------------------------------------


def _next_lock(root: Path, version: str) -> Path:
    (root / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"next": version}}, "node_modules/next": {"version": version}}}),
        encoding="utf-8")
    return root


@pytest.mark.parametrize(("version", "fires"), [("16.2.0", False), ("16.3.0", True), ("16.4.4", True), ("16.4.5", False)])
def test_next_reaches_the_advisory_feed_rule(tmp_path: Path, version: str, fires: bool) -> None:
    _cache(NEXT_GHSA)
    found = [f for f in run_scan(_next_lock(tmp_path, version)).findings if f.rule_id == KNOWN and NEXT_GHSA in f.evidence]
    assert bool(found) is fires
    assert all(f.severity is Severity.MEDIUM for f in found)


def test_next_is_not_reported_without_aak_update(tmp_path: Path) -> None:
    assert NEXT_GHSA not in advisory_feed.BUNDLED_FEED.read_text(encoding="utf-8")
    assert not [f for f in run_scan(_next_lock(tmp_path, "16.4.4")).findings if NEXT in f.evidence]


@pytest.mark.parametrize(("version", "fires"), [
    ("v0.0.1", False),                                        # the module's only tag
    ("v0.0.2-0.20260519091709-000000000000", True),           # a commit inside the range
    ("v0.0.2-0.20260812200004-a76a1920dc75", False),          # the fix commit
])
def test_kubeshark_in_a_go_mod_reaches_the_advisory_feed_rule(tmp_path: Path, version: str, fires: bool) -> None:
    """OSV ranges the Go module by pseudo-version. The CLI itself is a binary, and its
    release tags (v53.x) are not versions of this module path, so a go.mod is the one
    file that can name it."""
    _cache(KUBESHARK_FILE_GHSA, KUBESHARK_ARGV_GHSA)
    (tmp_path / "go.mod").write_text(
        f"module example.com/x\n\ngo 1.24\n\nrequire github.com/kubeshark/kubeshark {version}\n", encoding="utf-8")
    found = {i for f in run_scan(tmp_path).findings if f.rule_id == KNOWN
             for i in (KUBESHARK_FILE_GHSA, KUBESHARK_ARGV_GHSA) if i in f.evidence}
    assert found == ({KUBESHARK_FILE_GHSA, KUBESHARK_ARGV_GHSA} if fires else set())


def test_kubeshark_mcp_launch_states_no_version(tmp_path: Path) -> None:
    """The documented launch is `kubeshark mcp`, a program on PATH: no pin can read it."""
    (tmp_path / ".mcp.json").write_text(json.dumps(
        {"mcpServers": {"kubeshark": {"command": "kubeshark", "args": ["mcp", "--allow-destructive"]}}}), encoding="utf-8")
    _cache(KUBESHARK_FILE_GHSA, KUBESHARK_ARGV_GHSA)
    assert not [f for f in run_scan(tmp_path).findings if KUBESHARK_ARGV in f.evidence or KUBESHARK_FILE in f.evidence]


# ---- out of scope: nothing is claimed -------------------------------------------------------


@pytest.mark.parametrize("cve", [WORDPRESS, KUBESHARK_FILE, KUBESHARK_ARGV, NEXT])
def test_no_rule_claims_a_record_it_does_not_read(cve: str) -> None:
    assert [r.rule_id for r in RULES.values() if cve in r.cve_references] == []


@pytest.mark.parametrize("cve", [WORDPRESS, REBUILD, SDK, KUBESHARK_ARGV, PRICING, KUBESHARK_FILE, TIMESTREAM, CODEREVIEW, GITLAB])
def test_nvd_record_maps_to_no_package(cve: str) -> None:
    """None of these CNA records names a registry package, so `aak update`'s NVD half
    keeps none of them and the pins above are what reports them."""
    assert nvd_feed.record_packages(_nvd(cve), nvd_feed.load_package_map()) == []


# ---- the ledger -----------------------------------------------------------------------------


@pytest.mark.parametrize(("cve", "issue", "says"), [
    (WORDPRESS, "#1258", "Out of scope"), (REBUILD, "#1259", REBUILD_PIN), (SDK, "#1260", SDK_PIN),
    (KUBESHARK_ARGV, "#1261", "Out of scope"), (NEXT, "#1262", KNOWN), (PRICING, "#1263", PRICING_PIN),
    (KUBESHARK_FILE, "#1264", "Out of scope"), (TIMESTREAM, "#1265", TIMESTREAM_PIN),
    (CODEREVIEW, "#1266", CODEREVIEW_PIN), (GITLAB, "#1267", GITLAB_PIN),
])
def test_every_record_has_one_ledger_row(cve: str, issue: str, says: str) -> None:
    rows = [line for line in LEDGER.read_text(encoding="utf-8").splitlines() if line.startswith(f"| {cve} ")]
    assert len(rows) == 1 and rows[0].rstrip().endswith(f"| {issue} |") and says in rows[0]
