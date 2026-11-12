"""2026-11-12 wave, group "gateway": two held Amazon records for mcp-gateway-registry.

CVE-2026-100307 (missing authorization on the group import route, 1.0.9 to 1.24.7, fixed
in 1.25.0) and CVE-2026-125926 (SSRF through a registered server's address, v1.0.3 to
1.34.0, fixed in 1.35.0) each get an image rule of their own, beside the SQL injection
rule AAK-MCP-GATEWAY-REGISTRY-CVE-2026-14471-001, a different flaw fixed in 1.0.13. The
project is on neither npm nor PyPI; its registry service ships as
`public.ecr.aws/p3v1o3c6/registry` and, up to 1.24.4, as Docker Hub's
`mcpgateway/registry`, whose `latest` is the 1.24.4 build. NVD's records are saved
unedited under tests/fixtures/nvd_cna as the API returned them on 2026-11-12. OSV has no
record for either, so only these rules report them. `CHANGELOG.cves.md` holds the
reasoning. Nothing here touches the network.
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

GROUP_IMPORT_PIN = "AAK-MCP-GATEWAY-REGISTRY-CVE-2026-100307-001"
UPSTREAM_SSRF_PIN = "AAK-MCP-GATEWAY-REGISTRY-CVE-2026-125926-001"
SQLI_RULE = "AAK-MCP-GATEWAY-REGISTRY-CVE-2026-14471-001"
ECR = "public.ecr.aws/p3v1o3c6/registry"
HUB = "mcpgateway/registry"
BOTH = {GROUP_IMPORT_PIN, UPSTREAM_SSRF_PIN}

HERE = Path(__file__).parent
CVES = HERE / "fixtures" / "cves"
NVD_CNA = HERE / "fixtures" / "nvd_cna"
LEDGER = HERE.parent / "CHANGELOG.cves.md"
RECORDS = ("CVE-2026-100307", "CVE-2026-125926")
GHSAS = ("GHSA-rxf3-qgpv-wxvr", "GHSA-fc39-fwh3-wv5r")


def _ids(root: Path) -> set[str]:
    return {f.rule_id for f in container_image_pins.scan(root)[0]} & (BOTH | {SQLI_RULE})


def _compose(root: Path, image: str) -> set[str]:
    (root / "compose.yaml").write_text(f"services:\n  registry:\n    image: {image}\n", encoding="utf-8")
    return _ids(root)


def _nvd_record(cve: str) -> dict[str, Any]:
    (vuln,) = json.loads((NVD_CNA / f"{cve}.json").read_text(encoding="utf-8"))["vulnerabilities"]
    return vuln


@pytest.mark.parametrize(("rule_id", "cves"), [
    (GROUP_IMPORT_PIN, ["CVE-2026-100307"]),
    (UPSTREAM_SSRF_PIN, ["CVE-2026-125926"]),
])
def test_each_rule_carries_its_cve_at_high(rule_id: str, cves: list[str]) -> None:
    rule = RULES[rule_id]
    assert rule.cve_references == cves
    assert rule.severity is Severity.HIGH
    assert rule.category.value == "supply-chain"


def test_the_sql_injection_rule_is_unchanged() -> None:
    """Both fixes sit above its 1.0.13 floor and neither is SQL injection, so it keeps
    its one CVE and does not read images."""
    assert RULES[SQLI_RULE].cve_references == ["CVE-2026-14471"]
    assert not [p for p in container_image_pins._PINS if p.rule_id == SQLI_RULE]


@pytest.mark.parametrize("cve", RECORDS)
def test_what_nvds_records_map_to(cve: str) -> None:
    """The CNA data names the product with a bare version range and no packageURL, and
    no reviewed row maps it, so `nvd_feed` keeps neither record."""
    vuln = _nvd_record(cve)
    assert vuln["cve"]["id"] == cve and vuln["cve"]["sourceIdentifier"] == "ff89ba41-3aa1-4d27-914a-91399e9639e5"
    assert nvd_feed.record_packages(vuln, nvd_feed.load_package_map()) == []


def test_neither_record_is_bundled() -> None:
    text = advisory_feed.BUNDLED_FEED.read_text(encoding="utf-8")
    assert not any(ident in text for ident in RECORDS + GHSAS)


def test_the_image_rows() -> None:
    rows = sorted(
        (p.rule_id, p.image, p.introduced, p.floor, p.cves, p.floating_affected)
        for p in container_image_pins._PINS if p.rule_id in BOTH
    )
    assert rows == [
        (GROUP_IMPORT_PIN, HUB, (1, 0, 9), (1, 25, 0), ("CVE-2026-100307",), True),
        (GROUP_IMPORT_PIN, ECR, (1, 0, 9), (1, 25, 0), ("CVE-2026-100307",), False),
        (UPSTREAM_SSRF_PIN, HUB, (1, 0, 3), (1, 35, 0), ("CVE-2026-125926",), True),
        (UPSTREAM_SSRF_PIN, ECR, (1, 0, 3), (1, 35, 0), ("CVE-2026-125926",), False),
    ]


@pytest.mark.parametrize(("fixture", "vulnerable", "negative"), [
    # 1.24.7 is inside both ranges; 1.25.0 carries the admin check and is still
    # below the SSRF floor.
    ("cve-2026-100307-mcp-gateway-registry", BOTH, {UPSTREAM_SSRF_PIN}),
    ("cve-2026-125926-mcp-gateway-registry", {UPSTREAM_SSRF_PIN}, set()),
])
def test_fixtures_positive_and_negative(fixture: str, vulnerable: set[str], negative: set[str]) -> None:
    root = CVES / fixture
    findings = [f for f in container_image_pins.scan(root / "vulnerable")[0] if f.rule_id in BOTH]
    assert {(f.rule_id, f.file_path, f.line_number) for f in findings} == {
        (rule_id, "compose.yaml", 5) for rule_id in vulnerable
    }
    assert _ids(root / "negative") == negative
    engine = {f.rule_id: f.severity for f in run_scan(root / "vulnerable").findings if f.rule_id in BOTH}
    assert engine == {rule_id: Severity.HIGH for rule_id in vulnerable}


@pytest.mark.parametrize(("tag", "expected"), [
    ("1.0.13", BOTH),            # the oldest version tag on ECR Public
    ("1.0.22-p1", BOTH),
    ("1.23.0", BOTH),
    ("1.24.7", BOTH),            # dbaa1534: no admin check on the import route
    ("1.25.0", {UPSTREAM_SSRF_PIN}),  # 765f35c7: _require_admin (#1333)
    ("1.26.0", {UPSTREAM_SSRF_PIN}),  # literal private addresses refused, no DNS
    ("1.34.0", {UPSTREAM_SSRF_PIN}),  # 8db93ba5
    ("1.35.0", set()),           # 977bb924, the advisory's fix
    ("1.37.0", set()),
    ("1.0", BOTH),               # the 1.0.22 digest
    ("1.24", BOTH),              # the 1.24.7 digest
    ("1.25", {UPSTREAM_SSRF_PIN}),
    ("1.34", {UPSTREAM_SSRF_PIN}),
    ("1.35", set()),
    ("latest", set()),           # the 1.37.0 digest on 2026-11-12
    ("1", set()),                # one part: no version stated
    ("0a038c2ba2c6672ea30568218fe8146314c6396a", set()),  # a commit tag
])
def test_ecr_public_tags(tmp_path: Path, tag: str, expected: set[str]) -> None:
    assert _compose(tmp_path, f"{ECR}:{tag}") == expected


@pytest.mark.parametrize(("tag", "expected"), [
    ("v1.0.0", set()),           # f521376: before the advisory's first release
    ("1.0.0", set()),
    ("v1.0.2", set()),
    ("v1.0.3", {UPSTREAM_SSRF_PIN}),  # f9a3e70d, the first git tag
    ("v1.0.8", {UPSTREAM_SSRF_PIN}),  # no import route yet
    ("v1.0.9", BOTH),            # 0c073153: the import route, no admin check
    ("v1.0.9-patch1", BOTH),
    ("v1.0.12", BOTH),
    ("v1.0.22-p1", BOTH),
    ("1.24.4", BOTH),            # 9fd96af3, Docker Hub's last push
    ("1.0", BOTH),               # the v1.0.12 build
    ("latest", BOTH),            # the 1.24.4 build
    ("1", set()),                # the v1.0.12 build, but one part states no version
    ("sha-9fd96af3", set()),
    ("feature-group-management-apis-165", set()),
])
def test_docker_hub_tags(tmp_path: Path, tag: str, expected: set[str]) -> None:
    assert _compose(tmp_path, f"{HUB}:{tag}") == expected


def test_an_untagged_reference_is_reported_only_for_docker_hub(tmp_path: Path) -> None:
    (tmp_path / "hub").mkdir()
    (tmp_path / "ecr").mkdir()
    assert _compose(tmp_path / "hub", HUB) == BOTH
    assert _compose(tmp_path / "ecr", ECR) == set()


@pytest.mark.parametrize(("name", "content", "expected"), [
    ("values.yaml", f"registry:\n  image:\n    repository: {ECR}\n    tag: 1.24.0\n", BOTH),
    ("values.yaml", f"image:\n  repository: {HUB}\n  tag: v1.0.12\n", BOTH),
    ("Dockerfile", f"FROM {ECR}:1.30.0\n", {UPSTREAM_SSRF_PIN}),
    (".mcp.json", json.dumps({"mcpServers": {"gw": {"command": "docker",
                                                    "args": ["run", "-i", f"{HUB}:1.24.4"]}}}), BOTH),
    # Not this image: the auth server, another name, the `docker.io/` form, a comment.
    ("compose.yaml", "services:\n  a:\n    image: public.ecr.aws/p3v1o3c6/auth-server:1.24.0\n", set()),
    ("compose.yaml", "services:\n  a:\n    image: public.ecr.aws/p3v1o3c6/registry-x:1.24.0\n", set()),
    ("compose.yaml", f"services:\n  a:\n    image: docker.io/{HUB}:1.24.4\n", set()),
    ("compose.yaml", f"services:\n  a:\n    # image: {HUB}:1.24.4\n    image: {ECR}:1.37.0\n", set()),
])
def test_reference_forms(tmp_path: Path, name: str, content: str, expected: set[str]) -> None:
    (tmp_path / name).write_text(content, encoding="utf-8")
    assert _ids(tmp_path) == expected


def test_the_charts_split_form_is_a_stated_limit() -> None:
    """The project's charts name the registry host and the tag in `global.image` and
    the image name alone under `registry.image`, which no mapping pairs with a tag."""
    assert _ids(CVES / "cve-2026-125926-mcp-gateway-registry" / "limitation-chart-values") == set()
    for rule_id in BOTH:
        assert "set the tag in `global.image.tag`" in RULES[rule_id].limitations


def test_the_projects_own_compose_file_is_a_stated_limit(tmp_path: Path) -> None:
    """1.24.7's prebuilt compose file interpolates the namespace and the tag."""
    (tmp_path / "docker-compose.prebuilt.yml").write_text(
        "services:\n  registry:\n    image: ${DOCKERHUB_ORG:-mcpgateway}/registry:${REGISTRY_VERSION:-latest}\n",
        encoding="utf-8")
    assert _ids(tmp_path) == set()
    for rule_id in BOTH:
        assert "its compose file interpolates both" in RULES[rule_id].limitations


def test_a_git_reference_is_read_only_by_the_sql_injection_rule(tmp_path: Path) -> None:
    """The SQL injection rule reads a git reference to the repository; the image rules
    do not, and say so."""
    (tmp_path / "requirements.txt").write_text(
        "mcp-gateway-registry @ git+https://github.com/agentic-community/mcp-gateway-registry@v1.0.12\n",
        encoding="utf-8")
    found = {f.rule_id for f in run_scan(tmp_path).findings} & (BOTH | {SQLI_RULE})
    assert found == {SQLI_RULE}
    for rule_id in BOTH:
        assert f"which {SQLI_RULE} reads, is not read by this rule" in RULES[rule_id].limitations


def test_the_ssrf_rule_says_its_floor_is_the_advisorys() -> None:
    rule = RULES[UPSTREAM_SSRF_PIN]
    assert "The advisory names no fix commit." in rule.description
    assert "The range is the advisory's, v1.0.3 through 1.34.0." in rule.description
    assert "Docker Hub's v1.0.0 to v1.0.2 and `1.0.0` builds predate" in rule.limitations


def test_both_remediations_move_docker_hub_users_to_ecr_public() -> None:
    for rule_id in BOTH:
        assert "Docker Hub's `mcpgateway/registry` has no fixed tag" in RULES[rule_id].remediation


# --- the ledger -------------------------------------------------------------------------


@pytest.mark.parametrize(("cve", "rule_id"), [
    ("CVE-2026-100307", GROUP_IMPORT_PIN),
    ("CVE-2026-125926", UPSTREAM_SSRF_PIN),
])
def test_every_record_has_one_covered_ledger_row(cve: str, rule_id: str) -> None:
    rows = [line for line in LEDGER.read_text(encoding="utf-8").splitlines() if line.startswith(f"| {cve} ")]
    assert len(rows) == 1 and rows[0].rstrip().endswith("| not filed |")
    assert rule_id in rows[0] and "out of scope" not in rows[0].lower()
