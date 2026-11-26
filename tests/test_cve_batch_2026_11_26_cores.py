"""2026-11-26 batch, the code-intelligence and execution servers, read on 2026-11-26.

Version pins: Flyto2 Core (CVE-2026-77312 and four more, 2.26.8), codebase-memory-mcp at
two bands (CVE-2026-114494 to 114496 in 0.9.0, CVE-2026-114497 and 114499 in 0.10.0),
mcp-ssh-manager (CVE-2026-129995, CVE-2026-77383) and DOMShell (CVE-2026-75518), each
range read in the published wheels, tarballs or the source at its tags. yt-mcp
(CVE-2026-75612) is read from a reference to its repository and from its image. Gortex
(CVE-2026-62964) is a Go binary and is left to AAK-KNOWN-VULN-001 after `aak update`.

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
from agent_audit_kit.models import Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import container_image_pins, mcp_cve_pins_2026_07

FLYTO_PIN = "AAK-MCP-FLYTO-CVE-2026-77312-001"
FLYTO_HIGH_PIN = "AAK-MCP-FLYTO-CVE-2026-67425-001"
MEMORY_PIN = "AAK-MCP-CODEBASEMEMORY-CVE-2026-114494-001"
STALL_PIN = "AAK-MCP-CODEBASEMEMORY-CVE-2026-114499-001"
SSH_PIN = "AAK-MCP-SSHMANAGER-CVE-2026-129995-001"
DOMSHELL_PIN = "AAK-MCP-DOMSHELL-CVE-2026-75518-001"
YTMCP_PIN = "AAK-MCP-YTMCP-CVE-2026-75612-001"
KNOWN = "AAK-KNOWN-VULN-001"

HERE = Path(__file__).parent
CVES = HERE / "fixtures" / "cves"
NVD_CNA = HERE / "fixtures" / "nvd_cna"
OSV = HERE / "fixtures" / "osv"
LEDGER = HERE.parent / "CHANGELOG.cves.md"
NOW = datetime(2026, 11, 26, 6, 0, tzinfo=timezone.utc)

FLYTO_CVES = ["CVE-2026-77312", "CVE-2026-77313", "CVE-2026-77314", "CVE-2026-77315", "CVE-2026-77316"]
MEMORY_CVES = ["CVE-2026-114494", "CVE-2026-114495", "CVE-2026-114496"]
STALL_CVES = ["CVE-2026-114499", "CVE-2026-114497"]
SSH_CVES = ["CVE-2026-129995", "CVE-2026-77383"]
DOMSHELL, YTMCP, GORTEX = "CVE-2026-75518", "CVE-2026-75612", "CVE-2026-62964"
GORTEX_GHSA, GORTEX_GO, DOMSHELL_GHSA = "GHSA-w42c-h7hr-f67p", "GO-2026-7003", "GHSA-vg83-hcp4-5qcc"
FLYTO_GHSAS = {
    "GHSA-p34x-fmph-9fjx": "CVE-2026-77312", "GHSA-pfg2-w999-497v": "CVE-2026-77313",
    "GHSA-2mr3-rxrq-238c": "CVE-2026-77315", "GHSA-6pm8-6f34-9v3g": "CVE-2026-77316",
}

MCP04 = "MCP04:2025"
PIN_RULES: dict[str, tuple[list[str], Severity, str, list[str]]] = {
    FLYTO_PIN: (FLYTO_CVES, Severity.CRITICAL, "cve-2026-77312-flyto-core", ["MCP05:2025", "MCP02:2025", MCP04]),
    MEMORY_PIN: (MEMORY_CVES, Severity.HIGH, "cve-2026-114494-codebase-memory-mcp", ["MCP05:2025", MCP04]),
    STALL_PIN: (STALL_CVES, Severity.MEDIUM, "cve-2026-114499-codebase-memory-mcp", [MCP04]),
    SSH_PIN: (SSH_CVES, Severity.HIGH, "cve-2026-129995-mcp-ssh-manager", ["MCP05:2025", "MCP02:2025", MCP04]),
    DOMSHELL_PIN: ([DOMSHELL], Severity.MEDIUM, "cve-2026-75518-domshell", ["MCP02:2025", MCP04]),
    YTMCP_PIN: ([YTMCP], Severity.HIGH, "cve-2026-75612-yt-mcp", ["MCP05:2025", MCP04]),
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


def _image_ids(root: Path) -> set[str]:
    return {f.rule_id for f in container_image_pins.scan(root)[0]}


def _requirements(root: Path, line: str) -> Path:
    (root / "requirements.txt").write_text(line + "\n", encoding="utf-8")
    return root


def _launch(root: Path, command: str, *args: str) -> Path:
    (root / ".mcp.json").write_text(json.dumps(
        {"mcpServers": {"s": {"command": command, "args": list(args)}}}), encoding="utf-8")
    return root


def _npx(root: Path, package: str) -> Path:
    return _launch(root, "npx", "-y", package)


def _package(root: Path, name: str, version: str) -> Path:
    (root / "package.json").write_text(json.dumps({"dependencies": {name: version}}), encoding="utf-8")
    return root


# ---- the saved records ----------------------------------------------------------------------


@pytest.mark.parametrize(("cve", "opening", "affected"), [
    ("CVE-2026-77312", "the earlier CVE-2026-67429 remediation applied validate_path_with_env_config()", "< 2.26.8"),
    ("CVE-2026-77313", "validate_url_ssrf in src/core/utils.py resolves and checks a hostname", "< 2.26.8"),
    ("CVE-2026-77314", "the MCP run_recipe tool in src/core/mcp_handler.py", "< 2.26.8"),
    ("CVE-2026-77315", "http.paginate in src/core/modules/atomic/http/paginate.py", "< 2.26.8"),
    ("CVE-2026-77316", "validate_url_ssrf() in src/core/utils.py validates one DNS answer", "< 2.26.8"),
    ("CVE-2026-114494", "the Cypher parser accepted an unbounded number of projection items", "< 0.9.0"),
    ("CVE-2026-114495", "automatic import of a repository's .codebase-memory/ artifact", "< 0.9.0"),
    ("CVE-2026-114496", "the detect_changes tool validated the base_branch argument", "< 0.9.0"),
    ("CVE-2026-114497", "the optional graph UI's POST /api/process-kill route", "< 0.9.1-rc.1"),
    ("CVE-2026-114499", "the indexer's .gitignore matcher", "< 0.10.0"),
    (GORTEX, "resolveFilePath in internal/mcp/tools_fileops.go accepts absolute paths", "< 0.55.0"),
    ("CVE-2026-129995", "ssh_backup_create, ssh_backup_restore, ssh_backup_schedule, and ssh_backup_list", "< 3.8.5"),
    ("CVE-2026-77383", "ssh_db_list, ssh_db_dump, ssh_db_import, and ssh_db_restore", "< 3.6.7"),
    (DOMSHELL, "the DOMShell MCP server classifies the domshell_eval tool", "< 2.0.8"),
    (YTMCP, "add_attachment in src/yt_mcp/tools/attachments.py", "< 1.18.1"),
])
def test_each_saved_nvd_record_is_the_one_read(cve: str, opening: str, affected: str) -> None:
    record = _nvd(cve)["cve"]
    assert record["id"] == cve
    (text,) = [d["value"] for d in record["descriptions"] if d["lang"] == "en"]
    assert opening in text
    (block,) = record["affected"]
    (product,) = block["affectedData"]
    assert [v["version"] for v in product["versions"]] == [affected]


@pytest.mark.parametrize("cve", [*FLYTO_CVES, *MEMORY_CVES, *STALL_CVES, *SSH_CVES, DOMSHELL, YTMCP, GORTEX])
def test_nvd_record_maps_to_no_package(cve: str) -> None:
    """None of these CNA records names a registry package, so `aak update`'s NVD half
    keeps none of them, and the pins above (and OSV's records) are what reports them."""
    assert nvd_feed.record_packages(_nvd(cve), nvd_feed.load_package_map()) == []


def test_the_saved_osv_records_alias_their_cves_and_agree_with_the_floors() -> None:
    for ident, cve in FLYTO_GHSAS.items():
        record = _osv(ident)
        assert record["id"] == ident and cve in record["aliases"]
        (affected,) = record["affected"]
        assert affected["package"]["name"] == "flyto-core" and affected["package"]["ecosystem"] == "PyPI"
        assert affected["ranges"][0]["events"] == [{"introduced": "0"}, {"fixed": "2.26.8"}]
    (domshell,) = _osv(DOMSHELL_GHSA)["affected"]
    assert domshell["package"]["name"] == "@apireno/domshell" and domshell["package"]["ecosystem"] == "npm"
    assert {"fixed": "2.0.8"} in domshell["ranges"][0]["events"]
    for ident in (GORTEX_GHSA, GORTEX_GO):
        record = _osv(ident)
        (affected,) = record["affected"]
        assert GORTEX in record["aliases"] and affected["package"]["name"] == "github.com/zzet/gortex"
        assert affected["ranges"] == [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.55.0"}]}]


# ---- the rules and their fixtures -----------------------------------------------------------


@pytest.mark.parametrize("rule_id", sorted(PIN_RULES))
def test_rule_metadata(rule_id: str) -> None:
    cves, severity, _, mcp = PIN_RULES[rule_id]
    rule = RULES[rule_id]
    assert rule.cve_references == cves and rule.severity is severity
    assert rule.category.value == "supply-chain" and rule.owasp_mcp_references == mcp
    assert "ASI04" in rule.owasp_agentic_references and "STA-08" in rule.aicm_references
    assert all(cve in rule.description for cve in cves) and "2026-11-26" in rule.limitations


@pytest.mark.parametrize("rule_id", sorted(PIN_RULES))
def test_fixture_fires_and_its_negative_is_silent(rule_id: str) -> None:
    cves, severity, name, _ = PIN_RULES[rule_id]
    found = [f for f in run_scan(CVES / name / "vulnerable").findings if f.rule_id == rule_id]
    assert len(found) == 1 and found[0].severity is severity and found[0].cve_references == cves
    assert found[0].line_number
    assert rule_id not in _ids(CVES / name / "negative")


# ---- Flyto2 Core (CVE-2026-77312 to CVE-2026-77316) -----------------------------------------


@pytest.mark.parametrize(("version", "fires", "high"), [
    ("1.0.0", True, True),      # csv_write and file.copy take the path as given
    ("2.17.0", True, True),     # http.paginate arrives
    ("2.26.5", True, True),
    ("2.26.7", True, False),    # past the HIGH rule's 2.26.6 fix, which PyPI never carried
    ("2.26.8", False, False),   # the four modules, load_recipe, the connector, the next link
    ("2.41.0", False, False),   # `latest` on 2026-11-26
])
def test_flyto_versions(tmp_path: Path, version: str, fires: bool, high: bool) -> None:
    ids = _pin_ids(_requirements(tmp_path, f"flyto-core=={version}"))
    assert (FLYTO_PIN in ids) is fires and (FLYTO_HIGH_PIN in ids) is high


def test_flyto_unversioned_is_left_to_the_high_rule(tmp_path: Path) -> None:
    ids = _pin_ids(_requirements(tmp_path, "flyto-core"))
    assert FLYTO_PIN not in ids and FLYTO_HIGH_PIN in ids


@pytest.mark.parametrize(("line", "fires"), [
    ("flyto-core>=2.26", True), ("flyto-core>=2.26.8,<3", False), ("flyto_core==2.26.7", True),
    ("flyto-core-extra==2.26.7", False), ("flyto==2.26.7", False),
])
def test_flyto_ranges_and_names(tmp_path: Path, line: str, fires: bool) -> None:
    assert (FLYTO_PIN in _pin_ids(_requirements(tmp_path, line))) is fires


def test_flyto_uvx_launch_fires_and_an_npm_package_of_the_name_is_silent(tmp_path: Path) -> None:
    assert FLYTO_PIN in _pin_ids(_launch(tmp_path, "uvx", "--from", "flyto-core==2.26.7", "flyto"))
    (tmp_path / ".mcp.json").unlink()
    assert FLYTO_PIN not in _pin_ids(_package(tmp_path, "flyto-core", "2.26.7"))


def test_flyto_lockfile_entry_fires(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(
        'version = 1\n\n[[package]]\nname = "flyto-core"\nversion = "2.26.7"\n'
        'source = { registry = "https://pypi.org/simple" }\n', encoding="utf-8")
    assert FLYTO_PIN in _pin_ids(tmp_path)


# ---- codebase-memory-mcp (CVE-2026-114494 to CVE-2026-114499) -------------------------------


@pytest.mark.parametrize(("package", "memory", "stall"), [
    ("codebase-memory-mcp@0.6.0", True, True),          # npm's first release
    ("codebase-memory-mcp@0.8.1", True, True),
    ("codebase-memory-mcp@0.9.0", False, True),
    ("codebase-memory-mcp@0.9.1-rc.1", False, True),    # no process-kill route, the old matcher
    ("codebase-memory-mcp@0.10.0", False, False),
    ("codebase-memory-mcp@0.12.1", False, False),       # `latest` on 2026-11-26
    ("codebase-memory-mcp@latest", False, False),
    ("codebase-memory-mcp", False, False),
    ("@acme/codebase-memory-mcp@0.8.1", False, False),
    ("codebase-memory@0.8.1", False, False),
])
def test_codebase_memory_npm_launches(tmp_path: Path, package: str, memory: bool, stall: bool) -> None:
    ids = _pin_ids(_npx(tmp_path, package))
    assert (MEMORY_PIN in ids) is memory and (STALL_PIN in ids) is stall


@pytest.mark.parametrize(("line", "memory", "stall"), [
    ("codebase-memory-mcp==0.8.1", True, True),         # PyPI's first release
    ("codebase-memory-mcp==0.9.0", False, True),
    ("codebase-memory-mcp==0.9.1rc1", False, True),     # asks GitHub for a tag that does not exist
    ("codebase-memory-mcp==0.10.0", False, False),
    ("codebase_memory_mcp>=0.8", True, True),
    ("codebase-memory-mcp>=0.10", False, False),
    ("codebase-memory-mcp", False, False),
])
def test_codebase_memory_on_pypi_is_the_same_version_line(
    tmp_path: Path, line: str, memory: bool, stall: bool
) -> None:
    ids = _pin_ids(_requirements(tmp_path, line))
    assert (MEMORY_PIN in ids) is memory and (STALL_PIN in ids) is stall


def test_codebase_memory_run_by_path_states_no_version(tmp_path: Path) -> None:
    ids = _pin_ids(_launch(tmp_path, "/usr/local/bin/codebase-memory-mcp"))
    assert not {MEMORY_PIN, STALL_PIN} & ids


def test_codebase_memory_lockfile_entry_fires(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"codebase-memory-mcp": "0.8.1"}},
        "node_modules/codebase-memory-mcp": {"version": "0.8.1"}}}), encoding="utf-8")
    assert {MEMORY_PIN, STALL_PIN} <= _pin_ids(tmp_path)


# ---- mcp-ssh-manager (CVE-2026-129995, CVE-2026-77383) --------------------------------------


@pytest.mark.parametrize(("package", "fires"), [
    ("mcp-ssh-manager@3.0.0", True),    # npm's first release
    ("mcp-ssh-manager@3.6.6", True),
    ("mcp-ssh-manager@3.6.7", True),    # CVE-2026-77383 fixed, the backup builders are not
    ("mcp-ssh-manager@3.8.4", True),
    ("mcp-ssh-manager@3.8.5", False),
    ("mcp-ssh-manager@4.3.6", False),   # `latest` on 2026-11-26
    ("mcp-ssh-manager@latest", False),
    ("mcp-ssh-manager", False),         # the README's own launch
    ("@acme/mcp-ssh-manager@3.8.4", False),
    ("mcp-ssh@3.8.4", False),
])
def test_ssh_manager_launches(tmp_path: Path, package: str, fires: bool) -> None:
    assert (SSH_PIN in _pin_ids(_npx(tmp_path, package))) is fires


def test_ssh_manager_caret_range_and_pypi_twin(tmp_path: Path) -> None:
    assert SSH_PIN in _pin_ids(_package(tmp_path, "mcp-ssh-manager", "^3.6.7"))
    (tmp_path / "package.json").unlink()
    assert SSH_PIN not in _pin_ids(_requirements(tmp_path, "mcp-ssh-manager==3.8.4"))


# ---- DOMShell (CVE-2026-75518) --------------------------------------------------------------


@pytest.mark.parametrize(("args", "fires"), [
    (["-y", "@apireno/domshell@1.1.0"], True),      # npm's first release
    (["-y", "@apireno/domshell@2.0.7"], True),
    (["-y", "@apireno/domshell@2.0.7", "--allow-write"], True),  # stated: the flags are not read
    (["-y", "-p", "@apireno/domshell@2.0.7", "domshell-proxy", "--port", "3001"], True),
    (["-y", "@apireno/domshell@2.0.8"], False),
    (["-y", "@apireno/domshell@2.0.11"], False),    # `latest` on 2026-11-26
    (["-y", "@apireno/domshell", "--allow-write"], False),       # the README's own launch
    (["-y", "domshell@2.0.7"], False),
    (["-y", "@acme/domshell@2.0.7"], False),
])
def test_domshell_launches(tmp_path: Path, args: list[str], fires: bool) -> None:
    assert (DOMSHELL_PIN in _pin_ids(_launch(tmp_path, "npx", *args))) is fires


def test_domshell_on_pypi_is_silent(tmp_path: Path) -> None:
    assert DOMSHELL_PIN not in _pin_ids(_requirements(tmp_path, "domshell==1.1.0"))


# ---- yt-mcp (CVE-2026-75612): the repository ------------------------------------------------

REPO = "git+https://github.com/velesnitski/yt-mcp"


@pytest.mark.parametrize(("source", "fires"), [
    (f"{REPO}@v1.7.0", True),       # the snapshot write alone
    (f"{REPO}@v1.17.4", True),
    (f"{REPO}@v1.18.0", True),
    (f"{REPO}.git@refs/tags/v1.18.0", True),
    ("git+ssh://git@github.com/velesnitski/yt-mcp@v1.18.0", True),
    (f"{REPO}@v1.18.1", False),
    (f"{REPO}@v1.42.0", False),     # the newest tag on 2026-11-26
    (REPO, False),                  # the README's own launch, the default branch
    (f"{REPO}@main", False),
    (f"{REPO}@af387abd", False),    # a commit names no release
    ("git+https://github.com/crazy-genius/yt-mcp@v1.0.0", False),
    ("git+https://github.com/velesnitski/yt-mcp-extra@v1.0.0", False),
])
def test_ytmcp_launch_sources(tmp_path: Path, source: str, fires: bool) -> None:
    assert (YTMCP_PIN in _pin_ids(_launch(tmp_path, "uvx", "--from", source, "yt-mcp"))) is fires


def test_ytmcp_tag_in_a_key_of_its_own(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "a"\ndependencies = ["yt-mcp"]\n\n[tool.uv.sources]\n'
        'yt-mcp = { git = "https://github.com/velesnitski/yt-mcp", tag = "v1.17.4" }\n', encoding="utf-8")
    found = [f for f in mcp_cve_pins_2026_07.scan(tmp_path)[0] if f.rule_id == YTMCP_PIN]
    assert [f.line_number for f in found] == [6] and "v1.18.1" in found[0].evidence


def test_ytmcp_registry_packages_of_the_name_are_silent(tmp_path: Path) -> None:
    """npm's `yt-mcp` is space-cadet's YouTube server (1.1.2), and PyPI has none."""
    assert YTMCP_PIN not in _pin_ids(_npx(tmp_path, "yt-mcp@1.1.2"))
    assert YTMCP_PIN not in _pin_ids(_package(tmp_path, "yt-mcp", "1.1.2"))
    assert YTMCP_PIN not in _pin_ids(_requirements(tmp_path, "yt-mcp==1.0.0"))


# ---- yt-mcp: the image ----------------------------------------------------------------------


def test_ytmcp_image_row() -> None:
    rows = [p for p in container_image_pins._PINS if p.rule_id == YTMCP_PIN]
    assert [(p.image, p.introduced, p.floor, p.cves, p.floating_affected) for p in rows] == [
        ("velesnitski/yt-mcp", None, (1, 18, 1), (YTMCP,), True),
    ]


@pytest.mark.parametrize(("image", "fires"), [
    ("velesnitski/yt-mcp:1.7.0", True),
    ("velesnitski/yt-mcp:latest", True),    # yt_mcp 1.7.0 inside, pushed 2026-04-10
    ("velesnitski/yt-mcp", True),
    ("velesnitski/yt-mcp:1.18.0", True),    # inside the range, though Docker Hub has no such tag
    ("velesnitski/yt-mcp:1.18.1", False),   # nor this one
    ("docker.io/velesnitski/yt-mcp:1.7.0", False),
    ("acme/velesnitski/yt-mcp:1.7.0", False),
    ("velesnitski/yt-mcp-extra:1.7.0", False),
    ("velesnitski/yt-mcp:${TAG}", False),
])
def test_ytmcp_images(tmp_path: Path, image: str, fires: bool) -> None:
    (tmp_path / "compose.yaml").write_text(f"services:\n  s:\n    image: {image}\n", encoding="utf-8")
    assert (YTMCP_PIN in _image_ids(tmp_path)) is fires


def test_ytmcp_image_fixture_fires_and_its_negative_is_silent() -> None:
    root = CVES / "cve-2026-75612-yt-mcp-image"
    found = [f for f in run_scan(root / "vulnerable").findings if f.rule_id == YTMCP_PIN]
    assert len(found) == 1 and found[0].severity is Severity.HIGH and found[0].line_number == 3
    assert YTMCP_PIN not in _ids(root / "negative")


def test_ytmcp_docker_launch_in_an_mcp_config(tmp_path: Path) -> None:
    """The README's stdio launch, untagged."""
    _launch(tmp_path, "docker", "run", "-i", "--rm", "velesnitski/yt-mcp", "--transport", "stdio")
    assert YTMCP_PIN in _image_ids(tmp_path)


def test_ytmcp_quoted_repository_name_is_read_as_the_image(tmp_path: Path) -> None:
    """Stated in the limitations: Docker Hub and GitHub use the same owner and name."""
    (tmp_path / "mcp-servers.json").write_text(json.dumps([{"repo": "velesnitski/yt-mcp"}]), encoding="utf-8")
    assert YTMCP_PIN in _image_ids(tmp_path)


# ---- Gortex (CVE-2026-62964): left to the advisory feed -------------------------------------

GORTEX_FIXTURE = CVES / "cve-2026-62964-gortex"


def test_gortex_in_a_go_mod_reaches_the_advisory_feed_rule() -> None:
    _cache(GORTEX_GHSA, GORTEX_GO)
    found = [f for f in run_scan(GORTEX_FIXTURE / "vulnerable").findings if f.rule_id == KNOWN]
    assert len(found) == 1 and found[0].severity is Severity.HIGH
    assert GORTEX in found[0].evidence and "0.55.0" in found[0].evidence
    assert not [f for f in run_scan(GORTEX_FIXTURE / "negative").findings if f.rule_id == KNOWN]


@pytest.mark.parametrize(("version", "fires"), [
    ("v0.53.0", True), ("v0.54.1", True), ("v0.55.0", False), ("v0.64.11", False),
])
def test_gortex_go_mod_versions(tmp_path: Path, version: str, fires: bool) -> None:
    _cache(GORTEX_GHSA, GORTEX_GO)
    (tmp_path / "go.mod").write_text(
        f"module example.com/x\n\ngo 1.24\n\nrequire github.com/zzet/gortex {version}\n", encoding="utf-8")
    assert bool([f for f in run_scan(tmp_path).findings if f.rule_id == KNOWN and GORTEX in f.evidence]) is fires


def test_gortex_is_not_reported_without_aak_update() -> None:
    assert "zzet/gortex" not in advisory_feed.BUNDLED_FEED.read_text(encoding="utf-8")
    assert KNOWN not in _ids(GORTEX_FIXTURE / "vulnerable")


def test_gortex_mcp_launch_states_no_version(tmp_path: Path) -> None:
    """The installed client config runs `gortex mcp`, a program on PATH."""
    _cache(GORTEX_GHSA, GORTEX_GO)
    _launch(tmp_path, "gortex", "mcp")
    assert not [f for f in run_scan(tmp_path).findings if GORTEX in f.evidence]


def test_no_rule_names_the_gortex_record() -> None:
    assert [r.rule_id for r in RULES.values() if GORTEX in r.cve_references] == []


# ---- the ledger -----------------------------------------------------------------------------



#: Records the watcher filed as issues on 2026-11-26, before this section landed.
_FILED = {'CVE-2026-129995': '#1280'}

@pytest.mark.parametrize(("cve", "says"), [
    *((cve, FLYTO_PIN) for cve in FLYTO_CVES),
    *((cve, MEMORY_PIN) for cve in MEMORY_CVES),
    *((cve, STALL_PIN) for cve in STALL_CVES),
    *((cve, SSH_PIN) for cve in SSH_CVES),
    (DOMSHELL, DOMSHELL_PIN), (YTMCP, YTMCP_PIN), (GORTEX, KNOWN),
])
def test_every_record_has_one_ledger_row(cve: str, says: str) -> None:
    rows = [line for line in LEDGER.read_text(encoding="utf-8").splitlines() if line.startswith(f"| {cve} ")]
    assert len(rows) == 1 and rows[0].rstrip().endswith(f"| {_FILED.get(cve, 'not filed')} |") and says in rows[0]
