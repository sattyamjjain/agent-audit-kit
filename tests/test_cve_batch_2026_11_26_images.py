"""2026-11-26 batch, the self-hosted apps and databases: thirteen records, six new rules.

Each flaw was read in the vendor's source at the git tag on both sides of its range, and
each image's tags on Docker Hub or GHCR on 2026-11-26. Obot's four records share one fix
(v0.27.0) and one rule whose rows name the CVEs a tag has. Pomerium's token endpoint
(v0.34.0), SurrealDB's MCP identifier check (v4.0.0) and LibreChat's MCP OAuth client
(v0.8.8) have one rule each. LibreChat's config dialog joins the last one, and only v0.7.9,
where the source mounts it, names it in the evidence. ArcadeDB's three MCP authorization
gaps (26.11.1) share a rule on its images, with PyPI `arcadedb-embedded` a stated limitation,
and the native builds' read-only bypass is a rule on `-native` tags alone.
SurrealDB's CLI `--help` disclosure (CVE-2026-134289) is not on an MCP surface and is left to
AAK-KNOWN-VULN-001 after `aak update`, which also reads Obot's and Pomerium's Go modules and
SurrealDB's crate.

NVD's records are saved unedited under tests/fixtures/nvd_cna, read on 2026-11-26.
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
from agent_audit_kit.scanners.known_vulns import evidence_cves

OBOT_RULE = "AAK-MCP-OBOT-CVE-2026-130766-001"
OBOT_CRITICAL_RULE = "AAK-MCP-OBOT-CVE-2026-101084-001"
OBOT_STATIC_RULE = "AAK-MCP-OBOT-CVE-2026-105138-001"
POMERIUM_RULE = "AAK-MCP-POMERIUM-CVE-2026-135300-001"
REDIRECT_RULE = "AAK-MCP-LIBRECHAT-CVE-2026-54031-001"
ARCADE_RULE = "AAK-MCP-ARCADEDB-CVE-2026-134327-001"
NATIVE_RULE = "AAK-MCP-ARCADEDB-CVE-2026-134337-001"
SURREAL_RULE = "AAK-MCP-SURREALDB-CVE-2026-134293-001"
KNOWN = "AAK-KNOWN-VULN-001"

HERE = Path(__file__).parent
CVES = HERE / "fixtures" / "cves"
NVD_CNA = HERE / "fixtures" / "nvd_cna"
LEDGER = HERE.parent / "CHANGELOG.cves.md"

OBOT_SSRF, OBOT_RESOURCE, OBOT_HEREDOC, OBOT_EGRESS = (
    "CVE-2026-130764", "CVE-2026-130766", "CVE-2026-130767", "CVE-2026-130768")
SURREAL_HELP, SURREAL_SQL = "CVE-2026-134289", "CVE-2026-134293"
GREMLIN, SCHEMA, EXISTS, NATIVE = (
    "CVE-2026-134324", "CVE-2026-134327", "CVE-2026-134329", "CVE-2026-134337")
POMERIUM, REDIRECT, DIALOG = "CVE-2026-135300", "CVE-2026-54031", "CVE-2026-54032"
ALL_CVES = [OBOT_SSRF, OBOT_RESOURCE, OBOT_HEREDOC, OBOT_EGRESS, SURREAL_HELP, SURREAL_SQL,
            GREMLIN, SCHEMA, EXISTS, NATIVE, POMERIUM, REDIRECT, DIALOG]

NEW_RULES: dict[str, tuple[list[str], Severity, list[str]]] = {
    OBOT_RULE: ([OBOT_RESOURCE, OBOT_SSRF, OBOT_HEREDOC, OBOT_EGRESS], Severity.HIGH,
                ["cve-2026-130766-obot"]),
    POMERIUM_RULE: ([POMERIUM], Severity.HIGH, ["cve-2026-135300-pomerium"]),
    REDIRECT_RULE: ([REDIRECT, DIALOG], Severity.MEDIUM, ["cve-2026-54031-librechat"]),
    ARCADE_RULE: ([SCHEMA, GREMLIN, EXISTS], Severity.MEDIUM, ["cve-2026-134327-arcadedb"]),
    NATIVE_RULE: ([NATIVE], Severity.HIGH, ["cve-2026-134337-arcadedb-native"]),
    SURREAL_RULE: ([SURREAL_SQL], Severity.HIGH, ["cve-2026-134293-surrealdb"]),
}


def _record(cve: str) -> dict[str, Any]:
    (vuln,) = json.loads((NVD_CNA / f"{cve}.json").read_text(encoding="utf-8"))["vulnerabilities"]
    return vuln


def _entries(cve: str) -> list[dict[str, Any]]:
    return nvd_feed.record_entries(_record(cve), nvd_feed.load_package_map(), nvd_feed.Tally())


def _cache(*cves: str) -> None:
    """Write the records to the feed cache as `aak update` converts them (HOME is per test)."""
    entries = [entry for cve in cves for entry in _entries(cve)]
    path = advisory_feed.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"generated_at": "t", "source": "test", "records": [],
                                "nvd": nvd_feed.merged(entries)}), encoding="utf-8")


def _feed(root: Path) -> dict[str, Severity]:
    return {cve: f.severity for f in run_scan(root).findings if f.rule_id == KNOWN
            for cve in evidence_cves(f.evidence)}


def _compose(root: Path, image: str) -> list[Any]:
    (root / "compose.yaml").write_text(f"services:\n  s:\n    image: {image}\n", encoding="utf-8")
    return container_image_pins.scan(root)[0]


def _image_ids(root: Path, image: str) -> set[str]:
    return {f.rule_id for f in _compose(root, image)}


def _evidence(root: Path, image: str, rule_id: str) -> str:
    (finding,) = [f for f in _compose(root, image) if f.rule_id == rule_id]
    return finding.evidence


# ---- the saved records ----------------------------------------------------------------------


@pytest.mark.parametrize(("cve", "opening"), [
    (OBOT_SSRF, "Obot from 0.8.0 before 0.27.0"),
    (OBOT_RESOURCE, "Obot from 0.26.0 before 0.27.0"),
    (OBOT_HEREDOC, "Obot from 0.9.0 before 0.27.0"),
    (OBOT_EGRESS, "Obot from 0.14.0 before 0.27.0"),
    (SURREAL_HELP, "SurrealDB 1.0.0 before 4.0.0 prints SURREAL_PASS"),
    (SURREAL_SQL, "SurrealDB 3.1.0 before 4.0.0"),
    (GREMLIN, "ArcadeDB 26.3.1 before 26.11.1"),
    (SCHEMA, "ArcadeDB before 26.11.1"),
    (EXISTS, "ArcadeDB 26.2.1 before 26.11.1"),
    (NATIVE, "ArcadeDB native-image server builds 26.8.1 before 26.11.1"),
    (POMERIUM, "Pomerium from 0.30.0 before 0.34.0"),
    (REDIRECT, "LibreChat is an enhanced ChatGPT clone"),
    (DIALOG, "LibreChat is an enhanced ChatGPT clone"),
])
def test_each_saved_nvd_record_is_the_one_read(cve: str, opening: str) -> None:
    record = _record(cve)["cve"]
    assert record["id"] == cve
    (text,) = [d["value"] for d in record["descriptions"] if d["lang"] == "en"]
    assert text.startswith(opening)


# ---- the rules and their fixtures -----------------------------------------------------------


@pytest.mark.parametrize("rule_id", sorted(NEW_RULES))
def test_rule_metadata(rule_id: str) -> None:
    cves, severity, _ = NEW_RULES[rule_id]
    rule = RULES[rule_id]
    assert rule.cve_references == cves and rule.severity is severity
    assert rule.category.value == "supply-chain"
    assert "MCP04:2025" in rule.owasp_mcp_references and "ASI04" in rule.owasp_agentic_references
    assert "STA-08" in rule.aicm_references and "2026-11-26" in rule.limitations
    assert all(cve in rule.description for cve in cves)


@pytest.mark.parametrize(("rule_id", "name"), [(r, n) for r, (_, _, names) in NEW_RULES.items() for n in names])
def test_fixture_fires_and_its_negative_is_silent(rule_id: str, name: str) -> None:
    cves, severity, _ = NEW_RULES[rule_id]
    found = [f for f in run_scan(CVES / name / "vulnerable").findings if f.rule_id == rule_id]
    assert len(found) == 1 and found[0].severity is severity and found[0].cve_references == cves
    assert found[0].line_number
    assert rule_id not in {f.rule_id for f in run_scan(CVES / name / "negative").findings}


@pytest.mark.parametrize("image", sorted({p.image for p in container_image_pins._PINS if p.rule_id in NEW_RULES}))
def test_references_the_rules_say_they_do_not_read(tmp_path: Path, image: str) -> None:
    for ref in (f"docker.io/{image}:0.0.0", f"acme/{image}:v0.0.0", f"{image}-extra:v3.2.0",
                f"{image}:${{TAG}}", f"{image}@sha256:{'0' * 64}", f"{image}:main"):
        assert not _image_ids(tmp_path, ref) & set(NEW_RULES), ref


# ---- Obot (CVE-2026-130764, -130766, -130767, -130768) --------------------------------------


@pytest.mark.parametrize(("tag", "cves"), [
    ("v0.7.1", None),                 # no mcpgateway/oauth package
    ("v0.8.0-rc1", [OBOT_SSRF]),
    ("v0.8.0", [OBOT_SSRF]),
    ("0.8", [OBOT_SSRF]),
    ("v0.9.0", [OBOT_SSRF, OBOT_HEREDOC]),
    ("v0.13.0", [OBOT_SSRF, OBOT_HEREDOC]),
    ("v0.14.0", [OBOT_SSRF, OBOT_HEREDOC, OBOT_EGRESS]),
    ("v0.25.6", [OBOT_SSRF, OBOT_HEREDOC, OBOT_EGRESS]),
    ("v0.26.0", [OBOT_RESOURCE, OBOT_SSRF, OBOT_HEREDOC, OBOT_EGRESS]),
    ("v0.26.3", [OBOT_RESOURCE, OBOT_SSRF, OBOT_HEREDOC, OBOT_EGRESS]),
    ("0.26", [OBOT_RESOURCE, OBOT_SSRF, OBOT_HEREDOC, OBOT_EGRESS]),
    ("v0.27.0-rc1", None),            # all four fixes are in it
    ("v0.27.0", None),
    ("0.27", None),
    ("v0.28.2", None),
    ("latest", None),                 # the v0.28.2 digest on 2026-11-26
])
def test_obot_tags_and_the_cves_each_names(tmp_path: Path, tag: str, cves: list[str] | None) -> None:
    ref = f"ghcr.io/obot-platform/obot:{tag}"
    found = [f for f in _compose(tmp_path, ref) if f.rule_id == OBOT_RULE]
    assert len(found) == (0 if cves is None else 1)
    for cve in (OBOT_SSRF, OBOT_RESOURCE, OBOT_HEREDOC, OBOT_EGRESS):
        assert (cve in "".join(f.evidence for f in found)) is (cve in (cves or []))


def test_obot_untagged_and_the_enterprise_image_are_silent(tmp_path: Path) -> None:
    for ref in ("ghcr.io/obot-platform/obot", "ghcr.io/obot-platform/obot-enterprise:v0.26.3"):
        assert OBOT_RULE not in _image_ids(tmp_path, ref)


@pytest.mark.parametrize(("tag", "rules"), [
    ("v0.11.0", {OBOT_RULE, OBOT_CRITICAL_RULE}),
    ("v0.24.2", {OBOT_RULE, OBOT_CRITICAL_RULE, OBOT_STATIC_RULE}),
    ("v0.26.1", {OBOT_RULE, OBOT_STATIC_RULE}),
    ("v0.26.2", {OBOT_RULE}),
    ("v0.27.0", set()),
])
def test_the_three_obot_rules_keep_their_own_floors(tmp_path: Path, tag: str, rules: set[str]) -> None:
    assert _image_ids(tmp_path, f"ghcr.io/obot-platform/obot:{tag}") == rules


# ---- Pomerium (CVE-2026-135300) -------------------------------------------------------------


@pytest.mark.parametrize(("ref", "fires"), [
    ("pomerium/pomerium:v0.29.6", False),    # no internal/mcp
    ("pomerium/pomerium:v0.30.0", True),
    ("pomerium/pomerium:v0.33.6", True),
    ("pomerium/pomerium:v0.33", True),       # floats to v0.33.6
    ("pomerium/pomerium:v0.34", False),
    ("pomerium/pomerium:v0.34.0", False),
    ("pomerium/pomerium:latest", False),     # the v0.34.1 digest on 2026-11-26
    ("pomerium/pomerium", False),
    ("pomerium/pomerium:nonroot-v0.33.6", False),
    ("pomerium/pomerium:debug-v0.33.6", False),
    ("docker.io/pomerium/pomerium:v0.33.6", False),
    ("gcr.io/pomerium-io/pomerium:v0.33.6-cloudrun", True),
    ("gcr.io/pomerium-io/pomerium:v0.34.0-cloudrun", False),
    ("gcr.io/pomerium-io/pomerium:latest-cloudrun", False),
    ("pomerium/ingress-controller:v0.29.6", False),   # its go.mod requires Pomerium v0.29.6
    ("pomerium/ingress-controller:v0.30.0", True),
    ("pomerium/ingress-controller:v0.33.6", True),    # requires v0.33.5
    ("pomerium/ingress-controller:v0.34.0", False),
    ("pomerium/ingress-controller:main", False),
])
def test_pomerium_images(tmp_path: Path, ref: str, fires: bool) -> None:
    assert (POMERIUM_RULE in _image_ids(tmp_path, ref)) is fires


# ---- LibreChat (CVE-2026-54031, CVE-2026-54032) ---------------------------------------------

LIBRECHAT_IMAGES = [
    f"{registry}/{name}"
    for registry in ("ghcr.io/danny-avila", "registry.librechat.ai/danny-avila", "ghcr.io/librechat-ai",
                     "registry.librechat.ai/librechat-ai", "librechat")
    for name in ("librechat", "librechat-api")
]


def test_librechat_rows_cover_the_ten_images() -> None:
    rows = [p for p in container_image_pins._PINS if p.rule_id == REDIRECT_RULE]
    assert {p.image for p in rows} == set(LIBRECHAT_IMAGES) and len(rows) == 30
    assert {p.image for p in rows if p.floating_affected} == {i for i in LIBRECHAT_IMAGES if "/danny-avila/" in i}
    assert {(p.introduced, p.floor) for p in rows if DIALOG in p.cves} == {((0, 7, 9), (0, 8, 0))}


@pytest.mark.parametrize(("tag", "cves"), [
    ("v0.7.8", None),                     # no MCP OAuth client and no dialog
    ("v0.7.9-rc1", [REDIRECT, DIALOG]),   # ui/MCPConfigDialog.tsx, mounted by MCPSelect
    ("v0.7.9", [REDIRECT, DIALOG]),       # ui/MCP/CustomUserVarsSection.tsx
    ("0.7", [REDIRECT, DIALOG]),          # stands for v0.7.9, the newest patch
    ("v0.8.0-rc1", [REDIRECT]),           # nothing imports the dialog file from here on
    ("v0.8.0", [REDIRECT]),
    ("v0.8.5", [REDIRECT]),
    ("v0.8.6-rc1", [REDIRECT]),
    ("v0.8.7", [REDIRECT]),
    ("v0.8.8-rc1", [REDIRECT]),           # pushed before 4d33d8c2
    ("v0.8.8-rc4", [REDIRECT]),
    ("v0.8.8", None),
    ("v0.8.8-rc10", None),                # does not exist; rc1 to rc4 are the ones read
    ("v0.8.9-rc1", None),
    ("v0.8.9", None),
    ("chart-2.0.3", None),
    ("0.8", None),                        # the 0.8 line has fixed releases
])
@pytest.mark.parametrize("image", LIBRECHAT_IMAGES)
def test_librechat_tags_and_the_cves_each_names(
    tmp_path: Path, image: str, tag: str, cves: list[str] | None,
) -> None:
    found = [f for f in _compose(tmp_path, f"{image}:{tag}") if f.rule_id == REDIRECT_RULE]
    assert len(found) == (0 if cves is None else 1)
    for cve in (REDIRECT, DIALOG):
        assert (cve in "".join(f.evidence for f in found)) is (cve in (cves or []))


@pytest.mark.parametrize("suffix", ["", ":latest"])
@pytest.mark.parametrize("image", LIBRECHAT_IMAGES)
def test_librechat_latest_is_affected_under_the_old_namespace_alone(
    tmp_path: Path, image: str, suffix: str,
) -> None:
    """`ghcr.io/danny-avila/librechat:latest` is the v0.8.7 image."""
    found = [f for f in _compose(tmp_path, image + suffix) if f.rule_id == REDIRECT_RULE]
    assert len(found) == (1 if "/danny-avila/" in image else 0)
    assert not [f for f in found if DIALOG in f.evidence]


def test_the_librechat_rule_says_where_the_dialog_is_not_mounted() -> None:
    rule = RULES[REDIRECT_RULE]
    assert "below v0.8.6" in rule.description and "admin" in rule.description
    assert "from v0.8.0-rc1 to v0.8.5 nothing in the source imports" in rule.limitations
    assert [r.rule_id for r in RULES.values() if DIALOG in r.cve_references] == [REDIRECT_RULE]


def test_librechat_images_that_state_no_release_are_silent(tmp_path: Path) -> None:
    for ref in ("registry.librechat.ai/librechat-ai/librechat-dev:latest",
                "ghcr.io/danny-avila/librechat-dev:latest",
                "ghcr.io/danny-avila/librechat-dev-api:e8f3be08623663d4ad7f7241e693c94469b63bb0",
                "docker.io/librechat/librechat:v0.8.5",
                "ghcr.io/danny-avila/librechat-rag-api-dev:v0.8.0"):
        assert _image_ids(tmp_path, ref) == set(), ref


def test_librechat_helm_values(tmp_path: Path) -> None:
    """The chart's own values name the proxy registry and leave the tag empty."""
    values = "image:\n  repository: danny-avila/librechat\n  registry: registry.librechat.ai\n  tag: \"%s\"\n"
    for tag, fires in (("", False), ("v0.8.7", True), ("v0.8.8", False)):
        (tmp_path / "values.yaml").write_text(values % tag, encoding="utf-8")
        assert (REDIRECT_RULE in {f.rule_id for f in container_image_pins.scan(tmp_path)[0]}) is fires


# ---- ArcadeDB (CVE-2026-134324, -134327, -134329, -134337) ----------------------------------


@pytest.mark.parametrize(("image", "tag", "cves"), [
    ("arcadedb", "26.2.2", None),                 # no MCP classes in the server jar
    ("arcadedb", "26.3.1", [SCHEMA, GREMLIN]),
    ("arcadedb", "26.3.2", [SCHEMA, GREMLIN]),
    ("arcadedb", "26.4.1-SNAPSHOT", [SCHEMA, GREMLIN]),
    ("arcadedb", "26.4.2", [SCHEMA, GREMLIN, EXISTS]),
    ("arcadedb", "26.10.2", [SCHEMA, GREMLIN, EXISTS]),
    ("arcadedb", "26.10.2-native", [SCHEMA, GREMLIN, EXISTS]),
    ("arcadedb", "26.10.1-SNAPSHOT", [SCHEMA, GREMLIN, EXISTS]),
    ("arcadedb", "26.11.1", None),
    ("arcadedb", "26.11.1-native", None),
    ("arcadedb", "latest", None),                 # 26.12.1-SNAPSHOT on 2026-11-26
    ("arcadedb", "latest-native", None),
    ("arcadedb-headless", "26.3.1", [SCHEMA]),
    ("arcadedb-headless", "26.4.2", [SCHEMA, EXISTS]),
    ("arcadedb-headless", "26.7.3", [SCHEMA, EXISTS]),
    ("arcadedb-headless", "26.8.1", [SCHEMA, EXISTS, GREMLIN]),   # the upsert tools arrive
    ("arcadedb-headless", "26.10.1", [SCHEMA, EXISTS, GREMLIN]),
    ("arcadedb-headless", "latest", [SCHEMA, EXISTS, GREMLIN]),   # 26.11.1-SNAPSHOT, 2026-10-05
    ("arcadedb-headless", "26.11.1-SNAPSHOT", None),              # the same image; reads as 26.11.1
    ("arcadedb-minimal", "26.2.2", None),
    ("arcadedb-minimal", "26.10.1", [SCHEMA, EXISTS, GREMLIN]),
    ("arcadedb-minimal", "latest", [SCHEMA, EXISTS, GREMLIN]),
])
def test_arcadedb_images_and_the_cves_each_names(
    tmp_path: Path, image: str, tag: str, cves: list[str] | None,
) -> None:
    found = [f for f in _compose(tmp_path, f"arcadedata/{image}:{tag}") if f.rule_id == ARCADE_RULE]
    assert len(found) == (0 if cves is None else 1)
    for cve in (SCHEMA, GREMLIN, EXISTS):
        assert (cve in "".join(f.evidence for f in found)) is (cve in (cves or []))


def test_arcadedb_untagged_references(tmp_path: Path) -> None:
    assert ARCADE_RULE not in _image_ids(tmp_path, "arcadedata/arcadedb")
    for image in ("arcadedata/arcadedb-headless", "arcadedata/arcadedb-minimal"):
        assert "26.11.1" in _evidence(tmp_path, image, ARCADE_RULE)


@pytest.mark.parametrize(("tag", "fires"), [
    ("26.9.1-native", False),             # SqlAstInspector is not there; no such tag either
    ("26.10.1-native", True),
    ("26.10.1-native-arm64", True),
    ("26.10.2-native", True),
    ("26.10.2-native-amd64", True),
    ("26.10.1-SNAPSHOT-native", True),
    ("26.10.2", False),                   # the JVM build
    ("26.10.2-nativeish", False),
    ("26.11.1-native", False),
    ("latest-native", False),
    ("latest", False),
])
def test_arcadedb_native_tags(tmp_path: Path, tag: str, fires: bool) -> None:
    assert (NATIVE_RULE in _image_ids(tmp_path, f"arcadedata/arcadedb:{tag}")) is fires


def test_arcadedb_native_tag_in_a_docker_run_launch(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"g": {
        "command": "docker", "args": ["run", "-i", "--rm", "arcadedata/arcadedb:26.10.2-native"]}}}),
        encoding="utf-8")
    assert NATIVE_RULE in {f.rule_id for f in container_image_pins.scan(tmp_path)[0]}


@pytest.mark.parametrize("line", [
    "arcadedb-embedded==26.2.1",
    "arcadedb-embedded==26.3.1",           # MCP classes inside arcadedb-server
    "arcadedb-embedded==26.10.2",          # an arcadedb-mcp jar
    "arcadedb-embedded==26.10.2.post1",
    "arcadedb-embedded>=26.8,<26.11",
    "arcadedb-embedded",
    "arcadedb==26.11.1.post4",
    "arcadedb-jvm==26.11.1",
])
def test_arcadedb_python_packages_are_not_read(tmp_path: Path, line: str) -> None:
    """Stated in the limitations: the wheels bundle the server jars, and the records name
    Maven packages, so no rule claims the PyPI name, with or without `aak update`."""
    (tmp_path / "requirements.txt").write_text(line + "\n", encoding="utf-8")
    _cache(GREMLIN, SCHEMA, EXISTS, NATIVE)
    assert not {f.rule_id for f in run_scan(tmp_path).findings} & {ARCADE_RULE, NATIVE_RULE, KNOWN}


def test_the_arcadedb_wheel_limitation_fixture_is_silent() -> None:
    root = CVES / "cve-2026-134327-arcadedb" / "limitations"
    assert (root / "requirements.txt").is_file()
    assert ARCADE_RULE not in {f.rule_id for f in run_scan(root).findings}
    assert "arcadedb-embedded" in RULES[ARCADE_RULE].limitations
    assert not [p for p in mcp_cve_pins_2026_07._PINS if any("arcadedb" in n for n in p.names)]


def test_a_maven_coordinate_is_not_read(tmp_path: Path) -> None:
    """Stated in the limitations: no reader opens a JVM manifest for com.arcadedb."""
    (tmp_path / "pom.xml").write_text(
        "<project><dependencies><dependency><groupId>com.arcadedb</groupId>"
        "<artifactId>arcadedb-mcp</artifactId><version>26.10.2</version></dependency>"
        "</dependencies></project>\n", encoding="utf-8")
    _cache(GREMLIN, SCHEMA, EXISTS, NATIVE)
    assert not {f.rule_id for f in run_scan(tmp_path).findings} & {ARCADE_RULE, NATIVE_RULE, KNOWN}


# ---- SurrealDB (CVE-2026-134293) ------------------------------------------------------------


@pytest.mark.parametrize(("ref", "fires"), [
    ("surrealdb/surrealdb:v3.0.5", False),       # no surrealdb/mcp
    ("surrealdb/surrealdb:v3.0", False),
    ("surrealdb/surrealdb:v3.1.0-beta.1", True),
    ("surrealdb/surrealdb:v3.1.0", True),
    ("surrealdb/surrealdb:v3.3.5", True),
    ("surrealdb/surrealdb:v3.3.5-dev", True),
    ("surrealdb/surrealdb:v3.3", True),          # floats to v3.3.5
    ("surrealdb/surrealdb:v3", False),           # one number: the limitation
    ("surrealdb/surrealdb:v4.0.0-beta.1", False),
    ("surrealdb/surrealdb:v4.0.0", False),
    ("surrealdb/surrealdb:latest", False),       # the v4.0.1 digest on 2026-11-26
    ("surrealdb/surrealdb", False),
    ("docker.io/surrealdb/surrealdb:v3.3.5", False),
    ("surrealdb/surrealist:v3.3.5", False),
])
def test_surrealdb_images(tmp_path: Path, ref: str, fires: bool) -> None:
    assert (SURREAL_RULE in _image_ids(tmp_path, ref)) is fires


# ---- `_ImagePin.suffix` ---------------------------------------------------------------------


def test_a_suffix_row_needs_its_suffix_and_never_reads_a_floating_tag() -> None:
    pin = container_image_pins._ImagePin(
        "AAK-TEST", "X", "x/x", (2, 0, 0), "", "", (), introduced=(1, 0, 0), suffix=r"-native(?![a-z])")
    read = container_image_pins._affected
    assert [t for t in ("1.0.0", "1.5.0-native", "1.5-native", "v1.9.9-native-amd64", "2.0.0-native",
                        "0.9.0-native", "native-1.5.0", "latest", "1.5.0-natively") if read(t, pin)] == [
        "1.5.0-native", "1.5-native", "v1.9.9-native-amd64"]
    assert read(None, pin) is False


def test_only_the_two_rules_that_need_a_suffix_set_one() -> None:
    assert {p.rule_id for p in container_image_pins._PINS if p.suffix is not None} == {REDIRECT_RULE, NATIVE_RULE}


# ---- AAK-KNOWN-VULN-001, after `aak update` -------------------------------------------------


@pytest.mark.parametrize(("cve", "package"), [
    (OBOT_SSRF, ("Go", "github.com/obot-platform/obot")),
    (OBOT_RESOURCE, ("Go", "github.com/obot-platform/obot")),
    (OBOT_HEREDOC, ("Go", "github.com/obot-platform/obot")),
    (OBOT_EGRESS, ("Go", "github.com/obot-platform/obot")),
    (POMERIUM, ("Go", "github.com/pomerium/pomerium")),
    (SURREAL_HELP, ("crates.io", "surrealdb")),
    (SURREAL_SQL, ("crates.io", "surrealdb")),
    (GREMLIN, None), (SCHEMA, None), (EXISTS, None), (NATIVE, None), (REDIRECT, None), (DIALOG, None),
])
def test_what_the_nvd_records_map_to(cve: str, package: tuple[str, str] | None) -> None:
    """ArcadeDB's records name Maven packages and LibreChat's none, so no feed entry exists."""
    mapped = [(p[0], p[1]) for p in nvd_feed.record_packages(_record(cve), nvd_feed.load_package_map())]
    assert mapped == ([] if package is None else [package])


def _go_mod(root: Path, module: str, version: str) -> Path:
    (root / "go.mod").write_text(
        f"module example.com/x\n\ngo 1.24\n\nrequire {module} {version}\n", encoding="utf-8")
    return root


@pytest.mark.parametrize(("version", "expected"), [
    ("v0.7.1", set()),
    ("v0.8.0", {OBOT_SSRF}),
    ("v0.14.0", {OBOT_SSRF, OBOT_HEREDOC, OBOT_EGRESS}),
    ("v0.26.3", {OBOT_SSRF, OBOT_RESOURCE, OBOT_HEREDOC, OBOT_EGRESS}),
    ("v0.27.0", set()),
])
def test_a_go_mod_requiring_obot(tmp_path: Path, version: str, expected: set[str]) -> None:
    _cache(OBOT_SSRF, OBOT_RESOURCE, OBOT_HEREDOC, OBOT_EGRESS)
    assert set(_feed(_go_mod(tmp_path, "github.com/obot-platform/obot", version))) == expected


@pytest.mark.parametrize(("version", "fires"), [
    ("v0.29.6", False), ("v0.30.0", True), ("v0.33.6", True), ("v0.34.0", False)])
def test_a_go_mod_requiring_pomerium(tmp_path: Path, version: str, fires: bool) -> None:
    _cache(POMERIUM)
    assert (POMERIUM in _feed(_go_mod(tmp_path, "github.com/pomerium/pomerium", version))) is fires


@pytest.mark.parametrize(("version", "expected"), [
    ("0.9.1", {}),
    ("1.0.0", {SURREAL_HELP: Severity.MEDIUM}),
    ("3.0.5", {SURREAL_HELP: Severity.MEDIUM}),
    ("3.1.0", {SURREAL_HELP: Severity.MEDIUM, SURREAL_SQL: Severity.HIGH}),
    ("3.3.5", {SURREAL_HELP: Severity.MEDIUM, SURREAL_SQL: Severity.HIGH}),
    ("4.0.0", {}),
])
def test_a_cargo_lock_resolving_surrealdb(tmp_path: Path, version: str, expected: dict[str, Severity]) -> None:
    _cache(SURREAL_HELP, SURREAL_SQL)
    (tmp_path / "Cargo.lock").write_text(
        f'version = 4\n\n[[package]]\nname = "surrealdb"\nversion = "{version}"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n', encoding="utf-8")
    assert _feed(tmp_path) == expected


def test_the_help_disclosure_has_no_rule_and_reaches_no_image(tmp_path: Path) -> None:
    """CVE-2026-134289: the CLI's `--help`, not MCP. No rule, and an image tag below the
    MCP rule's range reports nothing."""
    assert [r.rule_id for r in RULES.values() if SURREAL_HELP in r.cve_references] == []
    _cache(SURREAL_HELP, SURREAL_SQL)
    (tmp_path / "compose.yaml").write_text(
        "services:\n  s:\n    image: surrealdb/surrealdb:v3.0.5\n", encoding="utf-8")
    assert not [f for f in run_scan(tmp_path).findings if SURREAL_HELP in f.evidence]


def test_none_of_these_records_is_bundled(tmp_path: Path) -> None:
    """Without `aak update`, the Go and crates.io references above report nothing."""
    bundled = advisory_feed.BUNDLED_FEED.read_text(encoding="utf-8")
    assert not [cve for cve in ALL_CVES if cve in bundled]


# ---- the ledger -----------------------------------------------------------------------------



#: Records the watcher filed as issues on 2026-11-26, before this section landed.
_FILED = {'CVE-2026-134337': '#1281'}

@pytest.mark.parametrize(("cve", "says"), [
    (OBOT_SSRF, OBOT_RULE), (OBOT_RESOURCE, OBOT_RULE), (OBOT_HEREDOC, OBOT_RULE), (OBOT_EGRESS, OBOT_RULE),
    (SURREAL_HELP, KNOWN), (SURREAL_SQL, SURREAL_RULE), (GREMLIN, ARCADE_RULE), (SCHEMA, ARCADE_RULE),
    (EXISTS, ARCADE_RULE), (NATIVE, NATIVE_RULE), (POMERIUM, POMERIUM_RULE), (REDIRECT, REDIRECT_RULE),
    (DIALOG, REDIRECT_RULE),
])
def test_every_record_has_one_ledger_row(cve: str, says: str) -> None:
    rows = [line for line in LEDGER.read_text(encoding="utf-8").splitlines() if line.startswith(f"| {cve} ")]
    assert len(rows) == 1 and rows[0].rstrip().endswith(f"| {_FILED.get(cve, 'not filed')} |") and says in rows[0]
