"""2026-11-26 batch, group `servers`: seventeen records on PyPI, npm and image MCP servers.

Every record is covered by a version pin, most of them read in the published wheels,
tarballs or tagged source at both ends of the range: Document Loader and ECS (AWS Labs),
astro-airflow-mcp, the two Python reference servers (git and fetch), mcp-server-kubernetes,
DBHub (two records), the MSSQL servers built on mssql-mcp-core, obsidian-sync-mcp,
Todoist's server, Jupyter MCP Server, Pydantic AI and its harness, and
three servers that ship as images alone: Tapo's, k8s-mcp-server (reza-gholizade) and
sqlite-mcp (StacklokLabs). Four of the packages ship a container image too and carry an image row on the
same rule.

NVD's records are saved unedited under tests/fixtures/nvd_cna and OSV's under
tests/fixtures/osv, as the APIs returned them on 2026-11-26. `CHANGELOG.cves.md` holds
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
from agent_audit_kit.models import Finding, Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import container_image_pins, mcp_cve_pins_2026_07
from agent_audit_kit.scanners.known_vulns import evidence_cves

TAPO_PIN = "AAK-MCP-TAPO-CVE-2026-77329-001"
DOCLOADER_PIN = "AAK-MCP-AWSDOCLOADER-CVE-2026-130901-001"
ECS_PIN = "AAK-MCP-AWSECS-CVE-2026-135614-001"
AIRFLOW_PIN = "AAK-MCP-ASTROAIRFLOW-CVE-2026-133632-001"
GIT_PIN = "AAK-MCP-SERVERGIT-CVE-2026-134465-001"
FETCH_PIN = "AAK-MCP-SERVERFETCH-CVE-2026-134492-001"
K8S_PIN = "AAK-MCP-K8S-CVE-2026-134817-001"
K8S_CRITICAL_PIN = "AAK-MCP-K8S-CVE-2026-61459-001"
DBHUB_PIN = "AAK-MCP-DBHUB-CVE-2026-134803-001"
DBHUB_ZDI_PIN = "AAK-MCP-DBHUB-CVE-2026-136441-001"
MSSQL_PIN = "AAK-MCP-MSSQL-CVE-2026-63129-001"
OBSIDIAN_PIN = "AAK-MCP-OBSIDIANSYNC-CVE-2026-77283-001"
TODOIST_PIN = "AAK-MCP-TODOIST-CVE-2026-76807-001"
JUPYTER_PIN = "AAK-MCP-JUPYTER-CVE-2026-77318-001"
PYDANTIC_PIN = "AAK-PYDANTICAI-CVE-2026-133505-001"
HARNESS_PIN = "AAK-PYDANTICAI-HARNESS-CVE-2026-133161-001"
K8SGO_PIN = "AAK-MCP-K8SMCPSERVER-CVE-2026-130007-001"
SQLITE_PIN = "AAK-MCP-STACKLOKSQLITE-CVE-2026-130008-001"
KNOWN = "AAK-KNOWN-VULN-001"

HERE = Path(__file__).parent
CVES = HERE / "fixtures" / "cves"
NVD_CNA = HERE / "fixtures" / "nvd_cna"
OSV = HERE / "fixtures" / "osv"
LEDGER = HERE.parent / "CHANGELOG.cves.md"
NOW = datetime(2026, 11, 26, 18, 0, tzinfo=timezone.utc)

TAPO, DOCLOADER, ECS = "CVE-2026-77329", "CVE-2026-130901", "CVE-2026-135614"
AIRFLOW, GIT, FETCH = "CVE-2026-133632", "CVE-2026-134465", "CVE-2026-134492"
K8S, DBHUB, DBHUB_ZDI = "CVE-2026-134817", "CVE-2026-134803", "CVE-2026-136441"
MSSQL, OBSIDIAN, TODOIST = "CVE-2026-63129", "CVE-2026-77283", "CVE-2026-76807"
JUPYTER, JUPYTER_REBIND = "CVE-2026-77318", "CVE-2026-77359"
PYDANTIC, HARNESS = "CVE-2026-133505", "CVE-2026-133161"
K8SGO, SQLITE = "CVE-2026-130007", "CVE-2026-130008"
K8SGO_GHSA, SQLITE_GHSA = "GHSA-m932-63jc-4jqq", "GHSA-q433-mp6c-8v4f"
MSSQL_GHSA, OBSIDIAN_GHSA, TODOIST_GHSA, JUPYTER_GHSA, JUPYTER_REBIND_GHSA = (
    "GHSA-2m9m-6cr5-9x25", "GHSA-mx6p-3fg7-v6pj", "GHSA-833v-v58w-294h",
    "GHSA-24pw-rf5p-mgp7", "GHSA-9x8x-crjq-g64h")

PIN_RULES: dict[str, tuple[str, Severity, str, list[str]]] = {
    TAPO_PIN: (TAPO, Severity.HIGH, "cve-2026-77329-tapo", ["MCP07:2025", "MCP04:2025"]),
    DOCLOADER_PIN: (DOCLOADER, Severity.MEDIUM, "cve-2026-130901-aws-document-loader", ["MCP02:2025", "MCP04:2025"]),
    ECS_PIN: (ECS, Severity.MEDIUM, "cve-2026-135614-aws-ecs", ["MCP01:2025", "MCP10:2025", "MCP04:2025"]),
    AIRFLOW_PIN: (AIRFLOW, Severity.HIGH, "cve-2026-133632-astro-airflow", ["MCP05:2025", "MCP04:2025"]),
    GIT_PIN: (GIT, Severity.MEDIUM, "cve-2026-134465-mcp-server-git", ["MCP02:2025", "MCP04:2025"]),
    FETCH_PIN: (FETCH, Severity.LOW, "cve-2026-134492-mcp-server-fetch", ["MCP05:2025", "MCP04:2025"]),
    K8S_PIN: (K8S, Severity.HIGH, "cve-2026-134817-mcp-kubernetes", ["MCP05:2025", "MCP04:2025"]),
    DBHUB_PIN: (DBHUB, Severity.HIGH, "cve-2026-134803-dbhub", ["MCP02:2025", "MCP05:2025", "MCP04:2025"]),
    DBHUB_ZDI_PIN: (DBHUB_ZDI, Severity.CRITICAL, "cve-2026-136441-dbhub", ["MCP07:2025", "MCP05:2025", "MCP04:2025"]),
    MSSQL_PIN: (MSSQL, Severity.HIGH, "cve-2026-63129-mssql", ["MCP05:2025", "MCP04:2025"]),
    OBSIDIAN_PIN: (OBSIDIAN, Severity.HIGH, "cve-2026-77283-obsidian-sync", ["MCP07:2025", "MCP04:2025"]),
    TODOIST_PIN: (TODOIST, Severity.CRITICAL, "cve-2026-76807-todoist", ["MCP07:2025", "MCP04:2025"]),
    JUPYTER_PIN: (JUPYTER, Severity.HIGH, "cve-2026-77318-jupyter", ["MCP07:2025", "MCP04:2025"]),
    PYDANTIC_PIN: (PYDANTIC, Severity.MEDIUM, "cve-2026-133505-pydantic-ai", []),
    HARNESS_PIN: (HARNESS, Severity.HIGH, "cve-2026-133161-pydantic-ai-harness", []),
    K8SGO_PIN: (K8SGO, Severity.HIGH, "cve-2026-130007-k8s-mcp-server", ["MCP07:2025", "MCP04:2025"]),
    SQLITE_PIN: (SQLITE, Severity.HIGH, "cve-2026-130008-stacklok-sqlite", ["MCP02:2025", "MCP05:2025", "MCP04:2025"]),
}


def _nvd(cve: str) -> dict[str, Any]:
    (vuln,) = json.loads((NVD_CNA / f"{cve}.json").read_text(encoding="utf-8"))["vulnerabilities"]
    return vuln


def _osv(ident: str) -> dict[str, Any]:
    return json.loads((OSV / f"{ident}.json").read_text(encoding="utf-8"))


def _cache_osv(*idents: str) -> None:
    """The cached feed `aak update` writes, holding these OSV records (HOME is per test)."""
    collector = advisory_feed.Collector()
    for ident in idents:
        record = _osv(ident)
        for ecosystem in sorted({a["package"]["ecosystem"] for a in record["affected"]}):
            collector.add(ecosystem, record)
    collector.write(now=NOW)


def _cache_nvd(*cves: str) -> None:
    """The cached feed holding these NVD records as `aak update` converts their CNA data."""
    rows = nvd_feed.load_package_map()
    entries = [e for cve in cves for e in nvd_feed.record_entries(_nvd(cve), rows, nvd_feed.Tally())]
    path = advisory_feed.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"generated_at": "t", "source": "test", "records": [],
                                "nvd": nvd_feed.merged(entries)}), encoding="utf-8")


def _ids(root: Path) -> set[str]:
    return {f.rule_id for f in run_scan(root).findings}


def _pin_ids(root: Path) -> set[str]:
    return {f.rule_id for f in mcp_cve_pins_2026_07.scan(root)[0]}


def _known(root: Path, cve: str) -> list[Finding]:
    return [f for f in run_scan(root).findings if f.rule_id == KNOWN and cve in evidence_cves(f.evidence)]


def _requirements(root: Path, line: str) -> Path:
    (root / "requirements.txt").write_text(line + "\n", encoding="utf-8")
    return root


def _mcp(root: Path, command: str, *args: str) -> Path:
    (root / ".mcp.json").write_text(json.dumps(
        {"mcpServers": {"s": {"command": command, "args": list(args)}}}), encoding="utf-8")
    return root


def _uvx(root: Path, package: str) -> Path:
    return _mcp(root, "uvx", package)


def _npx(root: Path, package: str) -> Path:
    return _mcp(root, "npx", "-y", package)


def _npm_lock(root: Path, **packages: str) -> Path:
    (root / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        f"node_modules/{name}": {"version": version} for name, version in packages.items()}}), encoding="utf-8")
    return root


def _uv_lock(root: Path, name: str, version: str) -> Path:
    (root / "uv.lock").write_text(
        f'version = 1\n\n[[package]]\nname = "{name}"\nversion = "{version}"\n'
        'source = { registry = "https://pypi.org/simple" }\n', encoding="utf-8")
    return root


def _image_ids(root: Path, image: str) -> set[str]:
    (root / "compose.yaml").write_text(f"services:\n  s:\n    image: {image}\n", encoding="utf-8")
    return {f.rule_id for f in container_image_pins.scan(root)[0]}


# ---- the saved records ----------------------------------------------------------------------


@pytest.mark.parametrize(("cve", "opening"), [
    (TAPO, "Tapo provides Rust and Python APIs and an MCP server"),
    (DOCLOADER, "Improper limitation of a pathname to a restricted directory in the file access checks"),
    (ECS, "Improper removal of sensitive information in the troubleshooting tool"),
    (AIRFLOW, "In astro-airflow-mcp 0.5.0 through 0.9.1"),
    (GIT, "In mcp-server-git before 2026.10.28"),
    (FETCH, "In mcp-server-fetch from 2026.10.10 and before 2026.11.11"),
    (K8S, "mcp-server-kubernetes before 4.2.0 contains an argument injection vulnerability"),
    (DBHUB, "DBHub before 1.7.0 contains a read-only mode bypass vulnerability"),
    (DBHUB_ZDI, "Bytebase DBHub MCP Incorrect Authorization Authentication Bypass Vulnerability."),
    (MSSQL, "mssql-mcp-core is the shared library that powers MSSQL MCP servers."),
    (OBSIDIAN, "obsidian-sync-mcp is an MCP server that gives AI agents access to Obsidian vaults."),
    (TODOIST, "Todoist MCP Server provides tools that allow AI agents"),
    (JUPYTER, "Jupyter MCP Server is a Model Context Protocol server for Jupyter."),
    (PYDANTIC, "When message history is serialized and loaded again"),
    (HARNESS, "With `strip_ansi=True`, Pydantic AI Harness's"),
    (K8SGO, "k8s-mcp-server manages Kubernetes clusters through the Model Context Protocol."),
    (SQLITE, "sqlite-mcp is a Model Context Protocol server for SQLite."),
])
def test_each_saved_nvd_record_is_the_one_read(cve: str, opening: str) -> None:
    record = _nvd(cve)["cve"]
    assert record["id"] == cve
    (text,) = [d["value"] for d in record["descriptions"] if d["lang"] == "en"]
    assert opening in text


def test_the_saved_osv_records_alias_their_cves() -> None:
    for ident, cve in ((MSSQL_GHSA, MSSQL), (OBSIDIAN_GHSA, OBSIDIAN), (TODOIST_GHSA, TODOIST),
                       (JUPYTER_GHSA, JUPYTER), (JUPYTER_REBIND_GHSA, JUPYTER_REBIND),
                       (K8SGO_GHSA, K8SGO), (SQLITE_GHSA, SQLITE)):
        record = _osv(ident)
        assert record["id"] == ident and cve in record["aliases"]


@pytest.mark.parametrize(("cve", "packages"), [
    (TAPO, []), (DOCLOADER, []), (ECS, []), (DBHUB_ZDI, []), (MSSQL, []), (OBSIDIAN, []), (TODOIST, []),
    (JUPYTER, []), (K8SGO, []), (SQLITE, []),
    (AIRFLOW, [("PyPI", "astro-airflow-mcp", "collectionURL")]),
    (GIT, [("PyPI", "mcp-server-git", "packageURL")]),
    (FETCH, [("PyPI", "mcp-server-fetch", "packageURL")]),
    (K8S, [("npm", "mcp-server-kubernetes", "packageURL")]),
    (DBHUB, [("npm", "@bytebase/dbhub", "packageURL")]),
    (HARNESS, [("PyPI", "pydantic-ai-harness", "collectionURL")]),
    (PYDANTIC, [("PyPI", "pydantic-ai", "collectionURL"), ("PyPI", "pydantic-ai-slim", "collectionURL")]),
])
def test_which_nvd_records_name_a_package(cve: str, packages: list[tuple[str, str, str]]) -> None:
    assert nvd_feed.record_packages(_nvd(cve), nvd_feed.load_package_map()) == packages


# ---- the rules and their fixtures -----------------------------------------------------------


@pytest.mark.parametrize("rule_id", sorted(PIN_RULES))
def test_rule_metadata(rule_id: str) -> None:
    cve, severity, _, mcp = PIN_RULES[rule_id]
    rule = RULES[rule_id]
    assert rule.cve_references == [cve] and rule.severity is severity
    assert rule.category.value == "supply-chain" and rule.owasp_mcp_references == mcp
    assert "ASI04" in rule.owasp_agentic_references and "STA-08" in rule.aicm_references
    assert cve in rule.description and "2026-11-26" in rule.limitations


@pytest.mark.parametrize("rule_id", sorted(PIN_RULES))
def test_fixture_fires_and_its_negative_is_silent(rule_id: str) -> None:
    cve, severity, name, _ = PIN_RULES[rule_id]
    found = [f for f in run_scan(CVES / name / "vulnerable").findings if f.rule_id == rule_id]
    assert len(found) == 1 and found[0].severity is severity and found[0].cve_references == [cve]
    assert found[0].line_number
    assert rule_id not in _ids(CVES / name / "negative")


# ---- PyPI pins: both ends, unversioned, the other registry ----------------------------------


@pytest.mark.parametrize(("rule_id", "line", "fires"), [
    (DOCLOADER_PIN, "awslabs.document-loader-mcp-server==1.0.9", False),    # no base directory at all
    (DOCLOADER_PIN, "awslabs.document-loader-mcp-server==1.0.10", True),
    (DOCLOADER_PIN, "awslabs.document-loader-mcp-server==1.0.20", True),
    (DOCLOADER_PIN, "awslabs.document-loader-mcp-server==1.0.21", False),
    (DOCLOADER_PIN, "awslabs.document-loader-mcp-server", False),
    (ECS_PIN, "awslabs.ecs-mcp-server==0.1.1", True),                       # the first release
    (ECS_PIN, "awslabs.ecs-mcp-server==0.1.35", True),
    (ECS_PIN, "awslabs.ecs-mcp-server==0.1.36", False),
    (ECS_PIN, "awslabs.ecs-mcp-server", False),
    (ECS_PIN, "awslabs.eks-mcp-server==0.1.1", False),                      # another server
    (AIRFLOW_PIN, "astro-airflow-mcp==0.4.1", False),                       # no telemetry
    (AIRFLOW_PIN, "astro-airflow-mcp==0.5.0", True),
    (AIRFLOW_PIN, "astro-airflow-mcp==0.7.0a1", True),
    (AIRFLOW_PIN, "astro-airflow-mcp==0.9.1", True),
    (AIRFLOW_PIN, "astro-airflow-mcp==0.9.2", False),
    (AIRFLOW_PIN, "astro-airflow-mcp", False),
    (GIT_PIN, "mcp-server-git==0.6.2", True),                               # sorts below the date line
    (GIT_PIN, "mcp-server-git==2025.11.25", True),                          # --repository limits nothing
    (GIT_PIN, "mcp-server-git==2025.12.18", True),                          # the path check arrives
    (GIT_PIN, "mcp-server-git==2026.6.4", True),                            # 6 < 10 as a month, not as text
    (GIT_PIN, "mcp-server-git==2026.10.19", True),
    (GIT_PIN, "mcp-server-git==2026.10.28", False),
    (GIT_PIN, "mcp-server-git==2026.11.4", False),
    (GIT_PIN, "mcp-server-git", False),
    (FETCH_PIN, "mcp-server-fetch==2026.8.18", False),                      # no guard yet
    (FETCH_PIN, "mcp-server-fetch==2026.10.10", True),
    (FETCH_PIN, "mcp-server-fetch==2026.11.4", True),
    (FETCH_PIN, "mcp-server-fetch==2026.11.11", False),
    (FETCH_PIN, "mcp-server-fetch==2026.11.18", False),
    (FETCH_PIN, "mcp-server-fetch", False),
    (JUPYTER_PIN, "jupyter-mcp-server==0.4.0", False),                      # no such route
    (JUPYTER_PIN, "jupyter-mcp-server==0.5.0", True),
    (JUPYTER_PIN, "jupyter-mcp-server==1.0.2", True),
    (JUPYTER_PIN, "jupyter-mcp-server==1.0.3", False),
    (JUPYTER_PIN, "jupyter-mcp-server", False),
    (PYDANTIC_PIN, "pydantic-ai==1.49.0", False),
    (PYDANTIC_PIN, "pydantic-ai==1.50.0", True),
    (PYDANTIC_PIN, "pydantic-ai-slim[openai]==1.107.9", True),
    (PYDANTIC_PIN, "pydantic-ai-slim==1.107.10", False),
    (PYDANTIC_PIN, "pydantic-ai==2.0.0b1", True),
    (PYDANTIC_PIN, "pydantic-ai==2.65.0", True),
    (PYDANTIC_PIN, "pydantic-ai==2.66.0", False),
    (PYDANTIC_PIN, "pydantic-ai", False),
    (PYDANTIC_PIN, "pydantic-ai-harness==0.69.0", False),                   # another package
    (HARNESS_PIN, "pydantic-ai-harness==0.3.0", False),                     # no strip_ansi
    (HARNESS_PIN, "pydantic-ai-harness==0.4.0", True),
    (HARNESS_PIN, "pydantic-ai-harness==0.69.0", True),
    (HARNESS_PIN, "pydantic-ai-harness==0.70.0", False),
    (HARNESS_PIN, "pydantic-ai-harness", False),
    (HARNESS_PIN, "pydantic-ai==0.69.0", False),
])
def test_pypi_versions(tmp_path: Path, rule_id: str, line: str, fires: bool) -> None:
    assert (rule_id in _pin_ids(_requirements(tmp_path, line))) is fires


@pytest.mark.parametrize(("rule_id", "package", "fires"), [
    (DOCLOADER_PIN, "awslabs.document-loader-mcp-server@1.0.20", True),
    (DOCLOADER_PIN, "awslabs.document-loader-mcp-server@latest", False),
    (ECS_PIN, "awslabs.ecs-mcp-server==0.1.35", True),
    (ECS_PIN, "awslabs.ecs-mcp-server@latest", False),
    (GIT_PIN, "mcp-server-git@2026.10.19", True),
    (GIT_PIN, "mcp-server-git", False),
    (FETCH_PIN, "mcp-server-fetch==2026.11.4", True),
    (FETCH_PIN, "mcp-server-fetch", False),
    (AIRFLOW_PIN, "astro-airflow-mcp@0.9.1", True),
    (AIRFLOW_PIN, "astro-airflow-mcp", False),
    (JUPYTER_PIN, "jupyter-mcp-server@1.0.2", True),
    (JUPYTER_PIN, "jupyter-mcp-server@latest", False),
])
def test_uvx_launches(tmp_path: Path, rule_id: str, package: str, fires: bool) -> None:
    assert (rule_id in _pin_ids(_uvx(tmp_path, package))) is fires


@pytest.mark.parametrize(("rule_id", "name", "version"), [
    (GIT_PIN, "mcp-server-git", "2026.10.19"), (FETCH_PIN, "mcp-server-fetch", "2026.11.4"),
    (JUPYTER_PIN, "jupyter-mcp-server", "1.0.2"), (AIRFLOW_PIN, "astro-airflow-mcp", "0.9.1"),
    (PYDANTIC_PIN, "pydantic-ai", "2.65.0"), (HARNESS_PIN, "pydantic-ai-harness", "0.69.0"),
    (ECS_PIN, "awslabs.ecs-mcp-server", "0.1.35"),
    (DOCLOADER_PIN, "awslabs.document-loader-mcp-server", "1.0.20"),
])
def test_an_npm_package_of_the_same_name_is_silent(tmp_path: Path, rule_id: str, name: str, version: str) -> None:
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {name: version}}), encoding="utf-8")
    assert rule_id not in _pin_ids(tmp_path)
    assert rule_id not in _pin_ids(_npx(tmp_path, f"{name}@{version}"))


def test_the_normalised_aws_names_in_a_lockfile(tmp_path: Path) -> None:
    """uv.lock spells the dotted names with hyphens."""
    assert DOCLOADER_PIN in _pin_ids(_uv_lock(tmp_path, "awslabs-document-loader-mcp-server", "1.0.20"))
    assert ECS_PIN in _pin_ids(_uv_lock(tmp_path, "awslabs-ecs-mcp-server", "0.1.35"))


def test_a_range_that_admits_an_affected_release_fires(tmp_path: Path) -> None:
    assert PYDANTIC_PIN in _pin_ids(_requirements(tmp_path, "pydantic-ai>=1.50,<2"))
    assert PYDANTIC_PIN not in _pin_ids(_requirements(tmp_path, "pydantic-ai>=1.107.10,<2"))
    assert PYDANTIC_PIN not in _pin_ids(_requirements(tmp_path, "pydantic-ai>=2.66"))


def test_pydantic_ai_and_slim_in_one_lockfile_are_one_finding(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(
        'version = 1\n\n[[package]]\nname = "pydantic-ai"\nversion = "2.65.0"\n\n'
        '[[package]]\nname = "pydantic-ai-slim"\nversion = "2.65.0"\n', encoding="utf-8")
    assert len([f for f in mcp_cve_pins_2026_07.scan(tmp_path)[0] if f.rule_id == PYDANTIC_PIN]) == 1


# ---- npm pins: both ends, unversioned, other names ------------------------------------------


@pytest.mark.parametrize(("rule_id", "package", "fires"), [
    (K8S_PIN, "mcp-server-kubernetes@0.2.5", False),      # no operand reaches kubectl
    (K8S_PIN, "mcp-server-kubernetes@0.3.0", True),
    (K8S_PIN, "mcp-server-kubernetes@3.9.0", True),       # past the CRITICAL pin's fix
    (K8S_PIN, "mcp-server-kubernetes@4.1.9", True),
    (K8S_PIN, "mcp-server-kubernetes@4.1.10", False),     # 4.2.0's files but for the version
    (K8S_PIN, "mcp-server-kubernetes@4.2.0", False),
    (K8S_PIN, "mcp-server-kubernetes@latest", False),
    (K8S_PIN, "mcp-server-kubernetes", False),
    (K8S_PIN, "@acme/mcp-server-kubernetes@4.1.9", False),
    (DBHUB_PIN, "@bytebase/dbhub@0.17.0", False),         # splits on every `;`
    (DBHUB_PIN, "@bytebase/dbhub@0.18.0", True),
    (DBHUB_PIN, "@bytebase/dbhub@1.6.1", True),
    (DBHUB_PIN, "@bytebase/dbhub@1.7.0", False),
    (DBHUB_PIN, "@bytebase/dbhub@latest", False),
    (DBHUB_PIN, "@bytebase/dbhub", False),
    (DBHUB_PIN, "dbhub@0.2.1", False),                    # another npm project
    (DBHUB_ZDI_PIN, "@bytebase/dbhub@0.4.11", False),     # no splitter
    (DBHUB_ZDI_PIN, "@bytebase/dbhub@0.5.0", True),
    (DBHUB_ZDI_PIN, "@bytebase/dbhub@0.22.5", True),
    (DBHUB_ZDI_PIN, "@bytebase/dbhub@0.22.6", False),
    (DBHUB_ZDI_PIN, "@bytebase/dbhub@2.1.0", False),
    (DBHUB_ZDI_PIN, "@bytebase/dbhub", False),
    (MSSQL_PIN, "@connorbritain/mssql-mcp-server@0.1.0", True),
    (MSSQL_PIN, "@connorbritain/mssql-mcp-server@0.5.2", True),
    (MSSQL_PIN, "@connorbritain/mssql-mcp-server@0.6.0", False),
    (MSSQL_PIN, "@connorbritain/mssql-mcp-core@0.5.0", True),
    (MSSQL_PIN, "@connorbritain/mssql-mcp-core@0.6.0", False),
    (MSSQL_PIN, "@connorbritain/mssql-mcp-reader@0.1.0", True),
    (MSSQL_PIN, "@connorbritain/mssql-mcp-reader@0.4.2", True),
    (MSSQL_PIN, "@connorbritain/mssql-mcp-reader@0.5.0", False),
    (MSSQL_PIN, "@connorbritain/mssql-mcp-writer@0.4.2", True),
    (MSSQL_PIN, "@connorbritain/mssql-mcp-writer@0.5.0", False),
    (MSSQL_PIN, "@connorbritain/mssql-mcp-server@latest", False),
    (MSSQL_PIN, "@connorbritain/mssql-mcp-reader", False),
    (MSSQL_PIN, "mssql-mcp-server@0.1.0", False),         # another npm project
    (OBSIDIAN_PIN, "obsidian-sync-mcp@0.1.0", True),
    (OBSIDIAN_PIN, "obsidian-sync-mcp@0.5.6", True),
    (OBSIDIAN_PIN, "obsidian-sync-mcp@0.5.7", False),
    (OBSIDIAN_PIN, "obsidian-sync-mcp", False),
    (OBSIDIAN_PIN, "@acme/obsidian-sync-mcp@0.1.0", False),
    (TODOIST_PIN, "@doist/todoist-mcp@0.0.1", False),     # an empty placeholder
    (TODOIST_PIN, "@doist/todoist-mcp@9.0.0", True),
    (TODOIST_PIN, "@doist/todoist-mcp@10.3.2", True),
    (TODOIST_PIN, "@doist/todoist-mcp@10.3.3", False),
    (TODOIST_PIN, "@doist/todoist-mcp", False),
    (TODOIST_PIN, "@doist/todoist-ai@7.3.0", False),      # the old name, which the advisory does not name
    (TODOIST_PIN, "@doist/todoist-ai@8.12.3", False),
    (TODOIST_PIN, "@doist/todoist-ai@9.0.0", False),
    (TODOIST_PIN, "@doist/todoist-ai", False),
    (TODOIST_PIN, "@todoist/mcp@15.0.0", False),          # the new name, with the check
    (TODOIST_PIN, "todoist-mcp@1.3.4", False),            # another npm project
])
def test_npx_launches(tmp_path: Path, rule_id: str, package: str, fires: bool) -> None:
    assert (rule_id in _pin_ids(_npx(tmp_path, package))) is fires


@pytest.mark.parametrize(("rule_id", "line"), [
    (K8S_PIN, "mcp-server-kubernetes==0.1.6"),            # PyPI's is another project
    (MSSQL_PIN, "mssql-mcp-server==0.1.2"),
    (OBSIDIAN_PIN, "obsidian-sync-mcp==0.5.6"),           # not on PyPI
    (TODOIST_PIN, "todoist-mcp==0.4.0"),
    (DBHUB_PIN, "dbhub==0.5.2"),
    (DBHUB_ZDI_PIN, "dbhub==0.5.2"),
])
def test_pypi_twins_of_the_npm_names_are_silent(tmp_path: Path, rule_id: str, line: str) -> None:
    assert rule_id not in _pin_ids(_requirements(tmp_path, line))


def test_an_old_kubernetes_server_is_reported_by_both_rules(tmp_path: Path) -> None:
    assert {K8S_PIN, K8S_CRITICAL_PIN} <= _pin_ids(_npx(tmp_path, "mcp-server-kubernetes@3.8.0"))
    assert K8S_CRITICAL_PIN not in _pin_ids(_npx(tmp_path, "mcp-server-kubernetes@3.9.0"))


def test_mssql_lockfile_reports_each_floor_once(tmp_path: Path) -> None:
    """core comes with the server, so they are one row; the reader tier has its own floor."""
    _npm_lock(tmp_path, **{"@connorbritain/mssql-mcp-server": "0.5.2", "@connorbritain/mssql-mcp-core": "0.5.0",
                           "@connorbritain/mssql-mcp-reader": "0.4.2"})
    found = [f for f in mcp_cve_pins_2026_07.scan(tmp_path)[0] if f.rule_id == MSSQL_PIN]
    assert len(found) == 2 and {"0.6.0", "0.5.0"} == {f.evidence.split("fixed in ")[1].split(";")[0] for f in found}


@pytest.mark.parametrize("version", ["7.3.0", "8.12.3", "9.0.0"])
def test_todoists_old_npm_name_is_silent(tmp_path: Path, version: str) -> None:
    """Stated in the limitations: its tarballs carry the same route from 7.3.0, and no
    advisory names it (the 2026-10-17 ruling on `claude-code-sdk`, #1026)."""
    assert "@doist/todoist-ai" in RULES[TODOIST_PIN].limitations
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"@doist/todoist-ai": version}}), encoding="utf-8")
    _npm_lock(tmp_path, **{"@doist/todoist-ai": version})
    assert TODOIST_PIN not in _ids(tmp_path)


def test_a_lockfile_with_the_old_launcher_reports_the_package_it_installs(tmp_path: Path) -> None:
    """@doist/todoist-ai 9.0.0 depends on @doist/todoist-mcp ^9.0.0, and 9.0.0 is npm's only 9.x."""
    _npm_lock(tmp_path, **{"@doist/todoist-ai": "9.0.0", "@doist/todoist-mcp": "9.0.0"})
    (found,) = [f for f in mcp_cve_pins_2026_07.scan(tmp_path)[0] if f.rule_id == TODOIST_PIN]
    assert found.evidence.startswith("@doist/todoist-mcp resolves to 9.0.0")


# ---- images ---------------------------------------------------------------------------------


def test_the_image_rows() -> None:
    rows = {(p.image, p.rule_id): (p.introduced, p.floor, p.cves, p.floating_affected)
            for p in container_image_pins._PINS if p.rule_id in PIN_RULES}
    assert rows == {
        ("ghcr.io/mihai-dinculescu/tapo-mcp", TAPO_PIN): ((0, 3, 1), (0, 5, 0), (TAPO,), False),
        ("flux159/mcp-server-kubernetes", K8S_PIN): ((0, 3, 0), (4, 1, 10), (K8S,), False),
        ("bytebase/dbhub", DBHUB_PIN): ((0, 18, 0), (1, 7, 0), (DBHUB,), False),
        ("bytebase/dbhub", DBHUB_ZDI_PIN): ((0, 5, 0), (0, 22, 6), (DBHUB_ZDI,), False),
        ("ghcr.io/es617/obsidian-sync-mcp", OBSIDIAN_PIN): (None, (0, 5, 7), (OBSIDIAN,), False),
        ("datalayer/jupyter-mcp-server", JUPYTER_PIN): ((0, 5, 0), (1, 0, 3), (JUPYTER,), False),
        ("ginnux/k8s-mcp-server", K8SGO_PIN): ((1, 0, 5), (1, 1, 0), (K8SGO,), False),
        ("ghcr.io/stackloklabs/sqlite-mcp/server", SQLITE_PIN): (None, (0, 1, 2), (SQLITE,), False),
    }


@pytest.mark.parametrize(("rule_id", "image", "fires"), [
    (TAPO_PIN, "ghcr.io/mihai-dinculescu/tapo-mcp:0.3.0", False),   # rmcp's loopback host list applies
    (TAPO_PIN, "ghcr.io/mihai-dinculescu/tapo-mcp:0.3.1", True),
    (TAPO_PIN, "ghcr.io/mihai-dinculescu/tapo-mcp:0.3", True),      # the 0.3.1 digest
    (TAPO_PIN, "ghcr.io/mihai-dinculescu/tapo-mcp:0.4.0", True),
    (TAPO_PIN, "ghcr.io/mihai-dinculescu/tapo-mcp:0.4", True),
    (TAPO_PIN, "ghcr.io/mihai-dinculescu/tapo-mcp:0.5.0", False),
    (TAPO_PIN, "ghcr.io/mihai-dinculescu/tapo-mcp:0.5", False),
    (TAPO_PIN, "ghcr.io/mihai-dinculescu/tapo-mcp:latest", False),  # the 0.7.0 digest
    (TAPO_PIN, "ghcr.io/mihai-dinculescu/tapo-mcp", False),
    (TAPO_PIN, "docker.io/mihai-dinculescu/tapo-mcp:0.4.0", False),
    (K8S_PIN, "flux159/mcp-server-kubernetes:0.2.5", False),
    (K8S_PIN, "flux159/mcp-server-kubernetes:0.3.0", True),
    (K8S_PIN, "flux159/mcp-server-kubernetes:v4.1.9", True),
    (K8S_PIN, "flux159/mcp-server-kubernetes:v4.2.0", False),
    (K8S_PIN, "flux159/mcp-server-kubernetes:latest", False),
    (K8S_PIN, "flux159/mcp-server-kubernetes", False),
    (K8S_PIN, "docker.io/flux159/mcp-server-kubernetes:v4.1.9", False),
    (DBHUB_PIN, "bytebase/dbhub:0.17.0", False),
    (DBHUB_PIN, "bytebase/dbhub:0.18.0", True),
    (DBHUB_PIN, "bytebase/dbhub:1.6.0", True),
    (DBHUB_PIN, "bytebase/dbhub:1.7.1", False),
    (DBHUB_PIN, "bytebase/dbhub:latest", False),
    (DBHUB_PIN, "bytebase/dbhub", False),
    (DBHUB_PIN, "docker.io/bytebase/dbhub:1.6.0", False),
    (DBHUB_ZDI_PIN, "bytebase/dbhub:0.4.11", False),
    (DBHUB_ZDI_PIN, "bytebase/dbhub:0.5.0", True),
    (DBHUB_ZDI_PIN, "bytebase/dbhub:0.22.5", True),
    (DBHUB_ZDI_PIN, "bytebase/dbhub:0.22.6", False),
    (DBHUB_ZDI_PIN, "bytebase/dbhub:latest", False),
    (DBHUB_ZDI_PIN, "docker.io/bytebase/dbhub:0.22.5", False),
    (OBSIDIAN_PIN, "ghcr.io/es617/obsidian-sync-mcp:v0.1.1", True),
    (OBSIDIAN_PIN, "ghcr.io/es617/obsidian-sync-mcp:v0.5.6", True),
    (OBSIDIAN_PIN, "ghcr.io/es617/obsidian-sync-mcp:v0.5.7", False),
    (OBSIDIAN_PIN, "ghcr.io/es617/obsidian-sync-mcp:latest", False),
    (OBSIDIAN_PIN, "ghcr.io/es617/obsidian-sync-mcp", False),
    (OBSIDIAN_PIN, "docker.io/es617/obsidian-sync-mcp:v0.5.6", False),
    (JUPYTER_PIN, "datalayer/jupyter-mcp-server:0.4.0", False),
    (JUPYTER_PIN, "datalayer/jupyter-mcp-server:0.5.0", True),
    (JUPYTER_PIN, "datalayer/jupyter-mcp-server:1.0.1", True),      # an image PyPI has no release for
    (JUPYTER_PIN, "datalayer/jupyter-mcp-server:1.0.2", True),
    (JUPYTER_PIN, "datalayer/jupyter-mcp-server:1.0.3", False),
    (JUPYTER_PIN, "datalayer/jupyter-mcp-server:latest", False),
    (JUPYTER_PIN, "datalayer/jupyter-mcp-server", False),
    (JUPYTER_PIN, "docker.io/datalayer/jupyter-mcp-server:1.0.2", False),
    (K8SGO_PIN, "ginnux/k8s-mcp-server:1.0.4", False),              # stdio only
    (K8SGO_PIN, "ginnux/k8s-mcp-server:1.0.6", True),               # the first image
    (K8SGO_PIN, "ginnux/k8s-mcp-server:1.0.10-rc1", True),
    (K8SGO_PIN, "ginnux/k8s-mcp-server:1.0.25", True),
    (K8SGO_PIN, "ginnux/k8s-mcp-server:1.1.0", False),
    (K8SGO_PIN, "ginnux/k8s-mcp-server:latest", False),             # the 1.1.0 digest
    (K8SGO_PIN, "ginnux/k8s-mcp-server", False),
    (K8SGO_PIN, "docker.io/ginnux/k8s-mcp-server:1.0.25", False),
    (K8SGO_PIN, "acme/k8s-mcp-server:1.0.25", False),
    (SQLITE_PIN, "ghcr.io/stackloklabs/sqlite-mcp/server:0.0.1", True),
    (SQLITE_PIN, "ghcr.io/stackloklabs/sqlite-mcp/server:0.1.1", True),
    (SQLITE_PIN, "ghcr.io/stackloklabs/sqlite-mcp/server:0.1.2", False),
    (SQLITE_PIN, "ghcr.io/stackloklabs/sqlite-mcp/server:latest", False),   # the 0.1.2 digest
    (SQLITE_PIN, "ghcr.io/stackloklabs/sqlite-mcp/server", False),
    (SQLITE_PIN, "ghcr.io/stackloklabs/sqlite-mcp:0.1.1", False),
    (SQLITE_PIN, "docker.io/stackloklabs/sqlite-mcp/server:0.1.1", False),
    (SQLITE_PIN, "mcp/sqlite:0.1.1", False),                        # another project
])
def test_images(tmp_path: Path, rule_id: str, image: str, fires: bool) -> None:
    assert (rule_id in _image_ids(tmp_path, image)) is fires


def test_an_mcp_config_that_runs_an_affected_image(tmp_path: Path) -> None:
    _mcp(tmp_path, "docker", "run", "-i", "--rm", "datalayer/jupyter-mcp-server:1.0.2")
    assert JUPYTER_PIN in {f.rule_id for f in container_image_pins.scan(tmp_path)[0]}


# ---- beside the advisory feed ---------------------------------------------------------------


def test_the_feed_stands_down_where_the_pin_reports_the_record(tmp_path: Path) -> None:
    _cache_osv(TODOIST_GHSA)
    root = _npm_lock(tmp_path, **{"@doist/todoist-mcp": "10.3.2"})
    assert TODOIST_PIN in _ids(root) and _known(root, TODOIST) == []


@pytest.mark.parametrize(("version", "pinned", "fed"), [
    ("0.17.0", False, True), ("1.6.1", True, False), ("1.7.0", False, False),
])
def test_dbhub_before_the_pin_starts_is_left_to_the_feed(tmp_path: Path, version: str, pinned: bool, fed: bool) -> None:
    """The CNA's range has no lower bound; the pin starts where the scanner arrives."""
    _cache_nvd(DBHUB)
    root = _npm_lock(tmp_path, **{"@bytebase/dbhub": version})
    assert (DBHUB_PIN in _ids(root)) is pinned and bool(_known(root, DBHUB)) is fed


@pytest.mark.parametrize(("version", "pinned", "fed"), [
    ("4.1.9", True, False), ("4.1.10", False, True), ("4.2.0", False, False),
])
def test_kubernetes_4_1_10_is_fixed_and_the_feed_still_reports_it(
        tmp_path: Path, version: str, pinned: bool, fed: bool) -> None:
    """Stated in the limitations: the CNA's range ends at 4.2.0."""
    _cache_nvd(K8S)
    root = _npm_lock(tmp_path, **{"mcp-server-kubernetes": version})
    assert (K8S_PIN in _ids(root)) is pinned and bool(_known(root, K8S)) is fed


def test_jupyter_pin_leaves_77359_to_its_own_rule_and_the_feed(tmp_path: Path) -> None:
    """The pin names 77318 alone. A package that only installs 1.0.2 is reported for
    77359 by the feed after `aak update`, at its own severity."""
    assert RULES["AAK-DNS-REBIND-003"].cve_references == [JUPYTER_REBIND]
    assert JUPYTER_REBIND not in RULES[JUPYTER_PIN].cve_references
    _cache_osv(JUPYTER_GHSA, JUPYTER_REBIND_GHSA)
    root = _uv_lock(tmp_path, "jupyter-mcp-server", "1.0.2")
    assert JUPYTER_PIN in _ids(root)
    assert _known(root, JUPYTER) == [] and len(_known(root, JUPYTER_REBIND)) == 1
    assert "AAK-DNS-REBIND-003" not in _ids(root)


def test_the_zdi_record_reaches_no_feed(tmp_path: Path) -> None:
    """Stated in the limitations: the record maps to no package."""
    _cache_nvd(DBHUB_ZDI)
    root = _npm_lock(tmp_path, **{"@bytebase/dbhub": "2.1.0"})
    assert _known(root, DBHUB_ZDI) == [] and DBHUB_ZDI_PIN not in _ids(root)


@pytest.mark.parametrize(("ghsa", "cve", "module", "affected", "fixed"), [
    (K8SGO_GHSA, K8SGO, "github.com/reza-gholizade/k8s-mcp-server", "v1.0.25", "v1.1.0"),
    (SQLITE_GHSA, SQLITE, "github.com/StacklokLabs/sqlite-mcp", "v0.1.1", "v0.1.2"),
])
def test_a_go_mod_that_requires_the_module_is_left_to_the_feed(
        tmp_path: Path, ghsa: str, cve: str, module: str, affected: str, fixed: str) -> None:
    """Stated in the limitations: the two image rules read no Go version."""
    _cache_osv(ghsa)
    for version, fires in ((affected, True), (fixed, False)):
        (tmp_path / "go.mod").write_text(
            f"module example.com/x\n\ngo 1.24\n\nrequire {module} {version}\n", encoding="utf-8")
        assert bool(_known(tmp_path, cve)) is fires
    assert not {K8SGO_PIN, SQLITE_PIN} & _ids(tmp_path)


@pytest.mark.parametrize(("line", "npm"), [("k8s-mcp-server==0.1.0", "k8s-mcp-server@1.0.0"),
                                           ("sqlite-mcp==0.1.0", "sqlite-mcp@0.0.1")])
def test_the_package_twins_of_the_image_servers_are_silent(tmp_path: Path, line: str, npm: str) -> None:
    _requirements(tmp_path, line)
    _npx(tmp_path, npm)
    assert not {K8SGO_PIN, SQLITE_PIN} & _ids(tmp_path)


# ---- the ledger -----------------------------------------------------------------------------



#: Records the watcher filed as issues on 2026-11-26, before this section landed.
_FILED = {'CVE-2026-136441': '#1277', 'CVE-2026-77283': '#1278', 'CVE-2026-77329': '#1279'}

@pytest.mark.parametrize(("cve", "says"), [
    (cve, rule_id) for rule_id, (cve, _, _, _) in sorted(PIN_RULES.items())
])
def test_every_record_has_one_ledger_row(cve: str, says: str) -> None:
    rows = [line for line in LEDGER.read_text(encoding="utf-8").splitlines() if line.startswith(f"| {cve} ")]
    assert len(rows) == 1 and rows[0].rstrip().endswith(f"| {_FILED.get(cve, 'not filed')} |") and says in rows[0]
    assert "out of scope" not in rows[0].lower()
