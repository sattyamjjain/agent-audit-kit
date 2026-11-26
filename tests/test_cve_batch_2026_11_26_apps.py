"""2026-11-26 batch, group `apps`: twelve records about agent apps, read on 2026-11-26.

One version pin, the Apache IoTDB MCP Server (CVE-2026-135747), read in the two PyPI wheels.
Four image pins, each read in the source at its release tags: Sim's workflow MCP servers
(CVE-2026-135162), sdcb Chats's MCP assignments (CVE-2026-135432), FlowIntel's chatbot
(CVE-2026-133853) and the AutoGPT Platform (CVE-2026-130178 and CVE-2026-133448, one rule).
NocoDB's password reset (CVE-2026-136133) is not its MCP code, Mattermost's GitLab plugin
(CVE-2026-18399) has no MCP code in the releases affected, and pmo-platform's hooks and eval
viewer (CVE-2026-77350, -77389, -77349, -77390) install from a clone that states no version,
so those six are out of scope.

NVD's records are saved unedited under tests/fixtures/nvd_cna, as the API returned them on
2026-11-26. `CHANGELOG.cves.md` holds the reasoning. Nothing here touches the network.
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

IOTDB_PIN = "AAK-MCP-IOTDB-CVE-2026-135747-001"
SIM_PIN = "AAK-MCP-SIM-CVE-2026-135162-001"
CHATS_PIN = "AAK-MCP-SDCBCHATS-CVE-2026-135432-001"
FLOWINTEL_PIN = "AAK-MCP-FLOWINTEL-CVE-2026-133853-001"
AUTOGPT_PIN = "AAK-AUTOGPT-CVE-2026-130178-001"
KNOWN = "AAK-KNOWN-VULN-001"

HERE = Path(__file__).parent
CVES = HERE / "fixtures" / "cves"
NVD_CNA = HERE / "fixtures" / "nvd_cna"
LEDGER = HERE.parent / "CHANGELOG.cves.md"

IOTDB, SIM, CHATS, FLOWINTEL = "CVE-2026-135747", "CVE-2026-135162", "CVE-2026-135432", "CVE-2026-133853"
AUTOGPT_SSRF, AUTOGPT_CLI = "CVE-2026-130178", "CVE-2026-133448"
NOCODB, MATTERMOST = "CVE-2026-136133", "CVE-2026-18399"
PMO_HOOKS, PMO_VIEWER_XSS = "CVE-2026-77350", "CVE-2026-77349"
PMO_WARN_HOOKS, PMO_VIEWER_FILES = "CVE-2026-77389", "CVE-2026-77390"
OUT_OF_SCOPE = [NOCODB, MATTERMOST, PMO_HOOKS, PMO_VIEWER_XSS, PMO_WARN_HOOKS, PMO_VIEWER_FILES]

PIN_RULES: dict[str, tuple[list[str], Severity, str, list[str]]] = {
    IOTDB_PIN: ([IOTDB], Severity.LOW, "cve-2026-135747-iotdb", ["MCP01:2025", "MCP04:2025"]),
    SIM_PIN: ([SIM], Severity.MEDIUM, "cve-2026-135162-sim", ["MCP02:2025", "MCP07:2025", "MCP04:2025"]),
    CHATS_PIN: ([CHATS], Severity.MEDIUM, "cve-2026-135432-sdcb-chats", ["MCP01:2025", "MCP07:2025", "MCP04:2025"]),
    FLOWINTEL_PIN: ([FLOWINTEL], Severity.MEDIUM, "cve-2026-133853-flowintel",
                    ["MCP01:2025", "MCP07:2025", "MCP04:2025"]),
    AUTOGPT_PIN: ([AUTOGPT_SSRF, AUTOGPT_CLI], Severity.HIGH, "cve-2026-130178-autogpt", []),
}


def _nvd(cve: str) -> dict[str, Any]:
    (vuln,) = json.loads((NVD_CNA / f"{cve}.json").read_text(encoding="utf-8"))["vulnerabilities"]
    return vuln


def _cache(*cves: str) -> None:
    """Write the records to the feed cache as `aak update` converts them (HOME is per test)."""
    entries = [entry for cve in cves
               for entry in nvd_feed.record_entries(_nvd(cve), nvd_feed.load_package_map(), nvd_feed.Tally())]
    path = advisory_feed.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"generated_at": "t", "source": "test", "records": [],
                                "nvd": nvd_feed.merged(entries)}), encoding="utf-8")


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


def _compose(root: Path, image: str) -> Path:
    (root / "compose.yaml").write_text(f"services:\n  s:\n    image: {image}\n", encoding="utf-8")
    return root


def _image_ids(root: Path) -> list[str]:
    return [f.rule_id for f in container_image_pins.scan(root)[0]]


# ---- the saved records ----------------------------------------------------------------------


@pytest.mark.parametrize(("cve", "opening"), [
    (IOTDB, "Apache IoTDB MCP Server logs the IoTDB connection password"),
    (SIM, "Sim 0.5.61 before 0.9.41 contains an incorrect authorization vulnerability"),
    (CHATS, "sdcb Chats 1.10.0 before 1.17.1 contains an incorrect authorization vulnerability"),
    (FLOWINTEL, "FlowIntel's chatbot component used a single shared MCP"),
    (AUTOGPT_SSRF, "an incomplete IPv6 blocklist in AutoGPT's outbound SSRF protection"),
    (AUTOGPT_CLI, "chat and prompt text passed to the Claude Code CLI is pre-processed"),
    (NOCODB, "NocoDB before 2026.10.2 contains a denial of service vulnerability in passwordForgot()"),
    (MATTERMOST, "fail to enforce the configured GitLab group/namespace restriction"),
    (PMO_HOOKS, "core/hooks/block-credential-reads.sh"),
    (PMO_VIEWER_XSS, "release/skills/pmo-skill-refiner/eval-viewer/generate_review.py"),
    (PMO_WARN_HOOKS, "core/hooks/block-fragile-refs.sh"),
    (PMO_VIEWER_FILES, "three security weaknesses in the local evaluation viewer"),
])
def test_each_saved_nvd_record_is_the_one_read(cve: str, opening: str) -> None:
    record = _nvd(cve)["cve"]
    assert record["id"] == cve
    (text,) = [d["value"] for d in record["descriptions"] if d["lang"] == "en"]
    assert opening in text


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


# ---- Apache IoTDB MCP Server (CVE-2026-135747) ----------------------------------------------


@pytest.mark.parametrize(("line", "fires"), [
    ("iotdb-mcp-server==0.2.0", True),       # the one affected release on PyPI
    ("iotdb-mcp-server>=0.2,<0.3", True),
    ("iotdb_mcp_server==0.2.0", True),       # the normalised spelling
    ("iotdb-mcp-server==0.3.0", False),
    ("iotdb-mcp-server", False),
    ("iotdb-mcp-server>=0.3.0", False),
    ("apache-iotdb==0.2.0", False),          # the database client
])
def test_iotdb_requirements(tmp_path: Path, line: str, fires: bool) -> None:
    assert (IOTDB_PIN in _pin_ids(_requirements(tmp_path, line))) is fires


@pytest.mark.parametrize(("package", "fires"), [
    ("iotdb-mcp-server==0.2.0", True),
    ("iotdb-mcp-server@0.2.0", True),
    ("iotdb-mcp-server@latest", False),
    ("iotdb-mcp-server", False),
    ("iotdb-mcp-server==0.3.0", False),
])
def test_iotdb_launches(tmp_path: Path, package: str, fires: bool) -> None:
    assert (IOTDB_PIN in _pin_ids(_uvx(tmp_path, package))) is fires


def test_iotdb_in_an_npm_manifest_is_silent(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"iotdb-mcp-server": "0.2.0"}}), encoding="utf-8")
    assert IOTDB_PIN not in _pin_ids(tmp_path)


def test_iotdb_documented_launch_states_no_version(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"iotdb": {
        "command": "uv", "args": ["--directory", "/srv/iotdb-mcp-server/src/iotdb_mcp_server", "run", "server.py"]}}}),
        encoding="utf-8")
    assert IOTDB_PIN not in _ids(tmp_path)


@pytest.mark.parametrize(("version", "found"), [
    ("0.2.0", [(KNOWN, Severity.MEDIUM), (IOTDB_PIN, Severity.LOW)]),
    ("0.3.0", []),
])
def test_iotdb_after_aak_update_is_reported_twice(
        tmp_path: Path, version: str, found: list[tuple[str, Severity]]) -> None:
    """The CNA record names the PyPI package by packageURL and gives no score, which the feed
    reads as MEDIUM. The pin is LOW, the ASF's rating, so the feed does not stand down for it."""
    _cache(IOTDB)
    findings = run_scan(_requirements(tmp_path, f"iotdb-mcp-server=={version}")).findings
    assert sorted((f.rule_id, f.severity) for f in findings if f.rule_id in (KNOWN, IOTDB_PIN)) == sorted(found)
    assert all(IOTDB in f.evidence for f in findings if f.rule_id == KNOWN)


# ---- Sim (CVE-2026-135162) ------------------------------------------------------------------


def test_sim_rows() -> None:
    rows = [p for p in container_image_pins._PINS if p.rule_id == SIM_PIN]
    assert [(p.image, p.introduced, p.floor, p.cves, p.floating_affected) for p in rows] == [
        ("ghcr.io/simstudioai/simstudio", (0, 5, 61), (0, 9, 41), (SIM,), False),
        ("simstudioai/simstudio", (0, 5, 61), (0, 9, 41), (SIM,), False),
    ]


@pytest.mark.parametrize(("image", "fires"), [
    ("ghcr.io/simstudioai/simstudio:v0.5.59", False),   # no isPublic in the routes
    ("ghcr.io/simstudioai/simstudio:v0.5.61", True),
    ("ghcr.io/simstudioai/simstudio:v0.9.40", True),
    ("ghcr.io/simstudioai/simstudio:v0.9.40-amd64", True),
    ("ghcr.io/simstudioai/simstudio:v0.9.41", False),
    ("ghcr.io/simstudioai/simstudio:v0.9.66", False),
    ("ghcr.io/simstudioai/simstudio:latest", False),    # the v0.9.66 digest on 2026-11-26
    ("ghcr.io/simstudioai/simstudio", False),
    ("ghcr.io/simstudioai/simstudio:staging", False),
    ("ghcr.io/simstudioai/simstudio:${SIM_VERSION:-latest}", False),
    ("ghcr.io/simstudioai/realtime:v0.9.40", False),    # another Sim image
    ("registry.example.com/simstudioai/simstudio:v0.9.40", False),
    ("docker.io/simstudioai/simstudio:v0.9.40", False),
])
def test_sim_images(tmp_path: Path, image: str, fires: bool) -> None:
    assert _image_ids(_compose(tmp_path, image)).count(SIM_PIN) == (1 if fires else 0)


@pytest.mark.parametrize(("tag", "fires"), [('"v0.9.40"', True), ('"v0.9.41"', False), ('""', False), ("latest", False)])
@pytest.mark.parametrize("registry", ["", "        registry: ghcr.io\n"])
def test_sim_helm_values(tmp_path: Path, registry: str, tag: str, fires: bool) -> None:
    """The project's chart sets the registry globally and names the repository without it."""
    (tmp_path / "values.yaml").write_text(
        "app:\n    image:\n" + registry + f"        repository: simstudioai/simstudio\n        tag: {tag}\n",
        encoding="utf-8")
    assert _image_ids(tmp_path).count(SIM_PIN) == (1 if fires else 0)


# ---- sdcb Chats (CVE-2026-135432) -----------------------------------------------------------


def test_chats_row() -> None:
    (row,) = [p for p in container_image_pins._PINS if p.rule_id == CHATS_PIN]
    assert (row.image, row.introduced, row.floor, row.cves, row.floating_affected) == (
        "sdcb/chats", (1, 7, 0), (1, 17, 1), (CHATS,), False)


@pytest.mark.parametrize(("tag", "fires"), [
    (":1.6.9", False),                   # no MCP controller
    (":1.7.0", True),                    # below NVD's 1.10.0, the same endpoint
    (":1.9.1.416", True),
    (":1.10.0", True),
    (":1.16", True),                     # the 1.16.0 digest
    (":1.17.0", True),
    (":1.17.0.772-linux-x64", True),
    (":1.17.0.791-linux-x64", True),     # a build of the fix commit, judged as 1.17.0
    (":1.17.1", False),
    (":1.17.1.799", False),
    (":1.17", False),                    # the 1.17.1 digest on 2026-11-26
    (":1", False),
    (":latest", False),
    ("", False),
    (":r-772", False),
    (":2.0.0.789-linux-x64", False),     # predates the fix, above the floor
    (":${TAG}", False),
])
def test_chats_images(tmp_path: Path, tag: str, fires: bool) -> None:
    assert _image_ids(_compose(tmp_path, "sdcb/chats" + tag)).count(CHATS_PIN) == (1 if fires else 0)


@pytest.mark.parametrize("image", ["docker.io/sdcb/chats:1.17.0", "acme/sdcb/chats:1.17.0", "sdcb/chats-web:1.17.0"])
def test_chats_other_images_are_silent(tmp_path: Path, image: str) -> None:
    assert CHATS_PIN not in _image_ids(_compose(tmp_path, image))


# ---- FlowIntel (CVE-2026-133853) ------------------------------------------------------------


def test_flowintel_row() -> None:
    (row,) = [p for p in container_image_pins._PINS if p.rule_id == FLOWINTEL_PIN]
    assert (row.image, row.introduced, row.floor, row.cves, row.floating_affected) == (
        "ghcr.io/flowintel/flowintel", (3, 2, 0), (4, 1, 0), (FLOWINTEL,), True)


@pytest.mark.parametrize(("image", "fires"), [
    ("ghcr.io/flowintel/flowintel:3.1.0", False),       # no chatbot
    ("ghcr.io/flowintel/flowintel:3.2.0", True),
    ("ghcr.io/flowintel/flowintel:3.3.0", True),
    ("ghcr.io/flowintel/flowintel:4.0.0", True),        # the newest image on 2026-11-26
    ("ghcr.io/flowintel/flowintel:4.1.0", False),       # the record's fix, not published yet
    ("ghcr.io/flowintel/flowintel:latest", True),       # the 4.0.0 digest
    ("ghcr.io/flowintel/flowintel", True),
    ("ghcr.io/flowintel/flowintel:${TAG}", False),
    ("ghcr.io/flowintel/flowintel-mcp:4.0.0", False),
    ("docker.io/flowintel/flowintel:4.0.0", False),
    ("flowintel:latest", False),                        # the local build
])
def test_flowintel_images(tmp_path: Path, image: str, fires: bool) -> None:
    assert _image_ids(_compose(tmp_path, image)).count(FLOWINTEL_PIN) == (1 if fires else 0)


# ---- AutoGPT Platform (CVE-2026-130178, CVE-2026-133448) ------------------------------------


def test_autogpt_row() -> None:
    (row,) = [p for p in container_image_pins._PINS if p.rule_id == AUTOGPT_PIN]
    assert (row.image, row.introduced, row.floor, row.cves, row.floating_affected) == (
        "significantgravitas/autogpt", (0, 7, 1), (0, 9, 0), (AUTOGPT_SSRF, AUTOGPT_CLI), False)


@pytest.mark.parametrize(("image", "fires"), [
    ("significantgravitas/autogpt:v0.7.1", True),       # the oldest release tag on Docker Hub
    ("significantgravitas/autogpt:v0.8.4", True),
    ("significantgravitas/autogpt:v0.9.0", False),
    ("significantgravitas/autogpt:v0.12.0", False),
    ("significantgravitas/autogpt:latest", False),      # the v0.12.0 digest on 2026-11-26
    ("significantgravitas/autogpt", False),
    ("significantgravitas/autogpt:sha-ce4f5929264705bb77260cfccb4b69271823cebc", False),
    ("significantgravitas/auto-gpt:v0.5.1", False),     # AutoGPT Classic
    ("docker.io/significantgravitas/autogpt:v0.8.4", False),
    ("autogpt_platform-backend:latest", False),         # the Compose build
])
def test_autogpt_images(tmp_path: Path, image: str, fires: bool) -> None:
    assert _image_ids(_compose(tmp_path, image)).count(AUTOGPT_PIN) == (1 if fires else 0)


@pytest.mark.parametrize("line", ["agpt==0.2.2", "autogpt==0.0.1"])
def test_autogpt_packages_of_those_names_are_silent(tmp_path: Path, line: str) -> None:
    """PyPI's `agpt` is AutoGPT Classic and its `autogpt` another project."""
    assert AUTOGPT_PIN not in _ids(_requirements(tmp_path, line))


# ---- out of scope: nothing is claimed -------------------------------------------------------


@pytest.mark.parametrize("cve", OUT_OF_SCOPE)
def test_no_rule_claims_a_record_it_does_not_read(cve: str) -> None:
    assert [r.rule_id for r in RULES.values() if cve in r.cve_references] == []


@pytest.mark.parametrize("cve", [SIM, CHATS, FLOWINTEL, AUTOGPT_SSRF, AUTOGPT_CLI, *OUT_OF_SCOPE])
def test_nvd_record_maps_to_no_package(cve: str) -> None:
    """Their CNA records name a GitHub repository or nothing, so `aak update`'s NVD half
    keeps none of them."""
    assert nvd_feed.record_packages(_nvd(cve), nvd_feed.load_package_map()) == []


def test_iotdb_record_maps_to_its_pypi_package() -> None:
    entries = nvd_feed.record_entries(_nvd(IOTDB), nvd_feed.load_package_map(), nvd_feed.Tally())
    assert [(e["ecosystem"], e["name"], e["mapped_by"]) for e in entries] == [
        ("PyPI", "iotdb-mcp-server", "packageURL")]


def test_nocodb_is_not_reported_for_its_password_reset(tmp_path: Path) -> None:
    _cache(NOCODB)
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"nocodb": "0.301.3"}},
        "node_modules/nocodb": {"version": "0.301.3"}}}), encoding="utf-8")
    _compose(tmp_path, "nocodb/nocodb:2026.10.1")
    assert not [f for f in run_scan(tmp_path).findings if NOCODB in f.evidence or NOCODB in f.cve_references]


@pytest.mark.parametrize("image", [
    "mattermost/mattermost-team-edition:11.7.11",
    "mattermost/mattermost-enterprise-edition:11.11.1",
])
def test_mattermost_images_are_not_claimed(tmp_path: Path, image: str) -> None:
    """The GitLab plugin these releases ship (1.12.x, 1.13.0) has no MCP code; its
    `get_projects` tool first ships with server 12.0.0, where the check is in place."""
    claimed = {cve for f in run_scan(_compose(tmp_path, image)).findings for cve in f.cve_references}
    assert MATTERMOST not in claimed


def test_pmo_platform_install_states_no_version(tmp_path: Path) -> None:
    """What `./install.sh` leaves in a workspace: hook registrations with no version, the
    scripts, and a `.version` text file, which AAK does not read."""
    hooks = tmp_path / ".claude" / "hooks"
    hooks.mkdir(parents=True)
    (tmp_path / ".claude" / ".version").write_text("v3.69\n", encoding="utf-8")
    (hooks / "block-egress.sh").write_text('#!/bin/bash\nreadonly JQ="/usr/bin/jq"\nexit 0\n', encoding="utf-8")
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({"hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "/w/.claude/hooks/block-egress.sh"}]}]}}),
        encoding="utf-8")
    claimed = {cve for f in run_scan(tmp_path).findings for cve in f.cve_references}
    assert not claimed & set(OUT_OF_SCOPE)


# ---- the ledger -----------------------------------------------------------------------------


@pytest.mark.parametrize(("cve", "says"), [
    (IOTDB, IOTDB_PIN), (SIM, SIM_PIN), (CHATS, CHATS_PIN), (FLOWINTEL, FLOWINTEL_PIN),
    (AUTOGPT_SSRF, AUTOGPT_PIN), (AUTOGPT_CLI, AUTOGPT_PIN), *((cve, "Out of scope") for cve in OUT_OF_SCOPE),
])
def test_every_record_has_one_ledger_row(cve: str, says: str) -> None:
    rows = [line for line in LEDGER.read_text(encoding="utf-8").splitlines() if line.startswith(f"| {cve} ")]
    assert len(rows) == 1 and rows[0].rstrip().endswith("| not filed |") and says in rows[0]
