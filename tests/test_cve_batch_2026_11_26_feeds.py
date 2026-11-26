"""2026-11-26 batch, the records on packages the pin tables already name.

Three new rules. Flowise's public chatflow route hands out the chatflow's MCP server token
(CVE-2026-130796, npm `flowise` and the `flowiseai/flowise` image from 3.1.3, no fix).
Network-AI's MCP Streamable HTTP server lets localhost origins read its tool catalog on
any bind (CVE-2026-130750). CodeWhale runs programs and scheduled jobs with no approval
prompt (CVE-2026-83816, CVE-2026-83817). Each range was read in the npm tarballs or the
source at its tags.

Sixteen records are off the MCP surface their package's pin reports and are left to
AAK-KNOWN-VULN-001 after `aak update`: six of Next.js's, nine of Better Auth's and one of
LiteLLM's. No floor moves for them.

NVD's records are saved unedited under tests/fixtures/nvd_cna and OSV's under
tests/fixtures/osv, as the APIs returned them on 2026-11-26. `CHANGELOG.cves.md` holds the
reasoning. Nothing here touches the network.
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
from agent_audit_kit.scanners import container_image_pins, known_vulns, mcp_cve_pins_2026_07
from agent_audit_kit.scanners.known_vulns import evidence_cves

FLOWISE_PIN = "AAK-MCP-FLOWISE-CVE-2026-130796-001"
FLOWISE_SANDBOX = "AAK-FLOWISE-CVE-2026-119978-001"
FLOWISE_NODE = "AAK-MCP-FLOWISE-CVE-2026-91931-001"
NETWORKAI_PIN = "AAK-MCP-NETWORKAI-CVE-2026-130750-001"
NETWORKAI_SSE = "AAK-MCP-NETWORKAI-CVE-2026-109332-001"
NETWORKAI_FILES = "AAK-NETWORKAI-CVE-2026-120311-001"
CODEWHALE_PIN = "AAK-CODEWHALE-CVE-2026-83816-001"
CODEWHALE_OLD = "AAK-MCP-CODEWHALE-CVE-2026-75858-001"
NEXTJS = "AAK-MCP-NEXTJS-CVE-2026-94486-001"
BETTER_AUTH = "AAK-MCP-BETTERAUTH-CVE-2026-53512-001"
LITELLM = ("AAK-MCP-LITELLM-CVE-2026-59822-001", "AAK-MCP-LITELLM-CVE-2026-114612-001",
           "AAK-LITELLM-CVE-2026-30623-PIN-001")
KNOWN = "AAK-KNOWN-VULN-001"

HERE = Path(__file__).parent
CVES = HERE / "fixtures" / "cves"
NVD_CNA = HERE / "fixtures" / "nvd_cna"
OSV = HERE / "fixtures" / "osv"
LEDGER = HERE.parent / "CHANGELOG.cves.md"
NOW = datetime(2026, 11, 26, 6, 0, tzinfo=timezone.utc)

FLOWISE, NETWORKAI = "CVE-2026-130796", "CVE-2026-130750"
EXEC_SHELL, AUTOMATION = "CVE-2026-83816", "CVE-2026-83817"
LITELLM_CALLBACKS = "CVE-2026-135287"
NEXT = {  # CVE -> OSV's record of it
    "CVE-2026-119346": "GHSA-f3mh-rxg3-f5g2",
    "CVE-2026-119347": "GHSA-7qx7-33qx-rqx2",
    "CVE-2026-119348": "GHSA-pc58-hwjq-p385",
    "CVE-2026-119349": "GHSA-rhh4-g77r-r9qj",
    "CVE-2026-119350": "GHSA-vvgp-ww4w-46vf",
    "CVE-2026-119351": "GHSA-vc7v-qv4w-wrv8",
}
CODEWHALE_OSV = {EXEC_SHELL: "GHSA-3mgh-93r5-r7jf", AUTOMATION: "GHSA-8hp3-xxrg-v9c8"}
PHONE_UPDATE, OAUTH_EMAIL, SERIAL_ID = "CVE-2026-134311", "CVE-2026-134312", "CVE-2026-134313"
EMAIL_OTP, EMAIL_CHANGE, PADDED_ROLE = "CVE-2026-134314", "CVE-2026-134315", "CVE-2026-134318"
PASSKEY, REVOKED, PHONE_OTP = "CVE-2026-134320", "CVE-2026-134321", "CVE-2026-134322"
BETTER_AUTH_CVES = [PHONE_UPDATE, OAUTH_EMAIL, SERIAL_ID, EMAIL_OTP, EMAIL_CHANGE, PADDED_ROLE,
                    PASSKEY, REVOKED, PHONE_OTP]
FEED_CVES = [*NEXT, *BETTER_AUTH_CVES, LITELLM_CALLBACKS]
PINNED = {FLOWISE: FLOWISE_PIN, NETWORKAI: NETWORKAI_PIN, EXEC_SHELL: CODEWHALE_PIN,
          AUTOMATION: CODEWHALE_PIN}
ALL_CVES = sorted([*FEED_CVES, *PINNED])

PIN_RULES: dict[str, tuple[list[str], Severity, str, list[str]]] = {
    FLOWISE_PIN: ([FLOWISE], Severity.HIGH, "cve-2026-130796-flowise",
                  ["MCP01:2025", "MCP07:2025", "MCP04:2025"]),
    NETWORKAI_PIN: ([NETWORKAI], Severity.MEDIUM, "cve-2026-130750-network-ai",
                    ["MCP07:2025", "MCP04:2025"]),
    CODEWHALE_PIN: ([EXEC_SHELL, AUTOMATION], Severity.HIGH, "cve-2026-83816-codewhale", []),
}


def _nvd(cve: str) -> dict[str, Any]:
    (vuln,) = json.loads((NVD_CNA / f"{cve}.json").read_text(encoding="utf-8"))["vulnerabilities"]
    return vuln


def _entries(cve: str) -> list[dict[str, Any]]:
    return nvd_feed.record_entries(_nvd(cve), nvd_feed.load_package_map(), nvd_feed.Tally())


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
    """The cached feed, holding these records as `aak update` converts them."""
    path = advisory_feed.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"generated_at": "t", "source": "test", "records": [], "nvd": nvd_feed.merged(
        [entry for cve in cves for entry in _entries(cve)])}), encoding="utf-8")


def _npm_lock(root: Path, name: str, version: str) -> Path:
    (root / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {name: version}}, f"node_modules/{name}": {"version": version}}}),
        encoding="utf-8")
    return root


def _uv_lock(root: Path, name: str, version: str) -> Path:
    (root / "uv.lock").write_text(f'version = 1\n\n[[package]]\nname = "{name}"\nversion = "{version}"\n'
                                  'source = { registry = "https://pypi.org/simple" }\n', encoding="utf-8")
    return root


def _package_json(root: Path, name: str, version: str) -> Path:
    (root / "package.json").write_text(json.dumps({"dependencies": {name: version}}), encoding="utf-8")
    return root


def _requirements(root: Path, line: str) -> Path:
    (root / "requirements.txt").write_text(line + "\n", encoding="utf-8")
    return root


def _launch(root: Path, command: str, *args: str) -> Path:
    (root / ".mcp.json").write_text(json.dumps(
        {"mcpServers": {"s": {"command": command, "args": list(args)}}}), encoding="utf-8")
    return root


def _ids(root: Path) -> set[str]:
    return {f.rule_id for f in run_scan(root).findings}


def _pin_ids(root: Path) -> set[str]:
    return {f.rule_id for f in mcp_cve_pins_2026_07.scan(root)[0]}


def _feed(root: Path) -> dict[str, Severity]:
    """What AAK-KNOWN-VULN-001 says of this batch's records, after the engine's passes."""
    return {cve: f.severity for f in run_scan(root).findings if f.rule_id == KNOWN
            for cve in evidence_cves(f.evidence) if cve in ALL_CVES}


def _raw_feed(root: Path) -> set[str]:
    """The same before them, so a finding the engine drops still shows."""
    return {cve for f in known_vulns.scan(root)[0] if f.rule_id == KNOWN
            for cve in evidence_cves(f.evidence) if cve in ALL_CVES}


# ---- the saved records ----------------------------------------------------------------------


@pytest.mark.parametrize(("cve", "opening"), [
    ("CVE-2026-119346", "Next.js is a React framework"),
    ("CVE-2026-119347", "the /_next/image optimizer in self-hosted Next.js deployments"),
    ("CVE-2026-119348", "a response whose declared framing does not match the body"),
    ("CVE-2026-119349", "pass binary arguments, such as Uint8Array or Blob values"),
    ("CVE-2026-119350", "poison a shared fallback shell"),
    ("CVE-2026-119351", "reuse an outer 'use cache' entry across root param values"),
    (PHONE_UPDATE, "the admin plugin's /admin/update-user endpoint"),
    (OAUTH_EMAIL, "treats unverified provider emails as verified"),
    (SERIAL_ID, "a race condition with MySQL or MariaDB serial IDs"),
    (EMAIL_OTP, "a race condition in the emailOTP plugin attempt counter"),
    (EMAIL_CHANGE, "email-change links record the old and new addresses but not the requesting user"),
    (PADDED_ROLE, "a privilege escalation vulnerability in the organization plugin"),
    (PASSKEY, "do not confirm WebAuthn user verification"),
    (REVOKED, "let revoked sessions stay valid"),
    (PHONE_OTP, "save unverified phone numbers"),
    (LITELLM_CALLBACKS, "LiteLLM Proxy 1.62.4 before 1.84.0 contains a callback injection vulnerability"),
    (FLOWISE, "Flowise 3.1.3 through 3.1.4 contains an information disclosure vulnerability"),
    (NETWORKAI, "Network-AI from 5.11.0 before 5.17.2 contains a CORS misconfiguration"),
    (EXEC_SHELL, "Prior to 0.9.0, the ExecShellTool::approval_requirement_for path"),
    (AUTOMATION, "Prior to 0.9.0, DEFAULT_AUTOMATION_AUTO_APPROVE"),
])
def test_each_saved_nvd_record_is_the_one_read(cve: str, opening: str) -> None:
    record = _nvd(cve)["cve"]
    assert record["id"] == cve
    (text,) = [d["value"] for d in record["descriptions"] if d["lang"] == "en"]
    assert opening in text


def test_the_saved_osv_records_alias_their_cves() -> None:
    for cve, ident in {**NEXT, **CODEWHALE_OSV}.items():
        record = _osv(ident)
        assert record["id"] == ident and cve in record["aliases"]


# ---- the rules and their fixtures -----------------------------------------------------------


@pytest.mark.parametrize("rule_id", sorted(PIN_RULES))
def test_rule_metadata(rule_id: str) -> None:
    cves, severity, _, mcp = PIN_RULES[rule_id]
    rule = RULES[rule_id]
    assert rule.cve_references == cves and rule.severity is severity
    assert rule.category.value == "supply-chain" and rule.owasp_mcp_references == mcp
    assert bool(mcp) is rule_id.startswith("AAK-MCP-")
    assert "ASI04" in rule.owasp_agentic_references and "STA-08" in rule.aicm_references
    assert all(cve in rule.description for cve in cves)
    assert rule.limitations.endswith("a lockfile entry keeps its line at any depth.")


@pytest.mark.parametrize("rule_id", sorted(PIN_RULES))
def test_fixture_fires_and_its_negative_is_silent(rule_id: str) -> None:
    cves, severity, name, _ = PIN_RULES[rule_id]
    found = [f for f in run_scan(CVES / name / "vulnerable").findings if f.rule_id == rule_id]
    assert len(found) == 1 and found[0].severity is severity and found[0].cve_references == cves
    assert found[0].line_number
    assert rule_id not in _ids(CVES / name / "negative")


# ---- Flowise (CVE-2026-130796) --------------------------------------------------------------


def test_flowise_rows() -> None:
    (pin,) = [p for p in mcp_cve_pins_2026_07._PINS if p.rule_id == FLOWISE_PIN]
    assert (pin.names, pin.floor, pin.introduced, pin.requires_version, pin.ecosystem) == (
        ("flowise",), None, (3, 1, 3), False, "js")
    rows = [p for p in container_image_pins._PINS if p.rule_id == FLOWISE_PIN]
    assert [(p.image, p.introduced, p.floor, p.cves, p.floating_affected) for p in rows] == [
        ("flowiseai/flowise", (3, 1, 3), (3, 1, 5), (FLOWISE,), True)]


@pytest.mark.parametrize(("version", "fires"), [
    ("3.0.13", False),
    ("3.1.0", False),
    ("3.1.2", False),    # no MCP server, no token
    ("3.1.3", True),     # the MCP server arrives
    ("3.1.4", True),     # the last release
    ("^3.0.0", True),    # admits 3.1.3
    ("~3.1.2", True),
    ("<3.1.3", False),
    ("latest", True),    # installs 3.1.4
    ("*", True),
])
def test_flowise_versions(tmp_path: Path, version: str, fires: bool) -> None:
    assert (FLOWISE_PIN in _pin_ids(_package_json(tmp_path, "flowise", version))) is fires


def test_flowise_launch_with_no_version_fires(tmp_path: Path) -> None:
    assert FLOWISE_PIN in _pin_ids(_launch(tmp_path, "npx", "flowise", "start"))


def test_flowise_lockfile_fires_at_its_line(tmp_path: Path) -> None:
    (finding,) = [f for f in mcp_cve_pins_2026_07.scan(_npm_lock(tmp_path, "flowise", "3.1.3"))[0]
                  if f.rule_id == FLOWISE_PIN]
    assert finding.file_path == "package-lock.json" and "no fixed release" in finding.evidence


def test_flowise_on_pypi_is_silent(tmp_path: Path) -> None:
    """PyPI's `flowise` is FlowiseAI's Python SDK, another package."""
    assert FLOWISE_PIN not in _pin_ids(_requirements(tmp_path, "flowise==3.1.4"))


@pytest.mark.parametrize("name", ["flowise-components", "@acme/flowise"])
def test_flowise_other_npm_names_are_silent(tmp_path: Path, name: str) -> None:
    assert FLOWISE_PIN not in _pin_ids(_package_json(tmp_path, name, "3.1.4"))


def test_flowise_in_a_sub_directory_manifest_is_not_read(tmp_path: Path) -> None:
    sub = tmp_path / "packages" / "app"
    sub.mkdir(parents=True)
    _package_json(sub, "flowise", "3.1.4")
    assert FLOWISE_PIN not in _pin_ids(tmp_path)


@pytest.mark.parametrize(("version", "expected"), [
    ("3.1.2", {FLOWISE_SANDBOX, FLOWISE_NODE}),
    ("3.1.3", {FLOWISE_SANDBOX, FLOWISE_NODE, FLOWISE_PIN}),
    ("3.1.4", {FLOWISE_SANDBOX, FLOWISE_PIN}),
])
def test_flowise_three_rules_name_three_flaws(tmp_path: Path, version: str, expected: set[str]) -> None:
    """The sandbox rule reports from 1.4.6, the Custom MCP node rule below 3.1.4, this from 3.1.3."""
    assert _pin_ids(_package_json(tmp_path, "flowise", version)) == expected


def test_the_older_flowise_rules_point_here_and_claim_nothing() -> None:
    for rule_id in (FLOWISE_SANDBOX, FLOWISE_NODE):
        rule = RULES[rule_id]
        assert FLOWISE_PIN in rule.remediation and FLOWISE not in rule.cve_references


@pytest.mark.parametrize(("image", "fires"), [
    ("flowiseai/flowise:3.1.2", False),
    ("flowiseai/flowise:3.1.3", True),
    ("flowiseai/flowise:3.1.4", True),
    ("flowiseai/flowise:3.1.5", False),     # no such tag: the project ended
    ("flowiseai/flowise:3.1", False),       # a two-part tag, not one the image has
    ("flowiseai/flowise:3.0.13", False),
    ("flowiseai/flowise:latest", True),     # the 3.1.4 build
    ("flowiseai/flowise", True),
    ("flowiseai/flowise:${TAG}", False),
    ("docker.io/flowiseai/flowise:3.1.4", False),
    ("flowiseai/flowise-worker:3.1.4", False),
    ("acme/flowiseai/flowise:3.1.4", False),
])
def test_flowise_images(tmp_path: Path, image: str, fires: bool) -> None:
    (tmp_path / "compose.yaml").write_text(f"services:\n  s:\n    image: {image}\n", encoding="utf-8")
    assert (FLOWISE_PIN in {f.rule_id for f in container_image_pins.scan(tmp_path)[0]}) is fires


def test_flowise_image_fixtures() -> None:
    root = CVES / "cve-2026-130796-flowise"
    found = [f for f in run_scan(root / "vulnerable-image").findings if f.rule_id == FLOWISE_PIN]
    assert [(f.file_path, f.line_number, f.severity) for f in found] == [("compose.yaml", 3, Severity.HIGH)]
    assert FLOWISE_PIN not in _ids(root / "negative-image")


@pytest.mark.parametrize(("version", "feed"), [("3.1.2", False), ("3.1.3", True), ("3.1.4", True)])
def test_flowise_the_feed_stands_down_for_the_rule(tmp_path: Path, version: str, feed: bool) -> None:
    """VulnCheck's record names `pkg:npm/flowise`, so `aak update` reads it too."""
    _cache_nvd(FLOWISE)
    root = _npm_lock(tmp_path, "flowise", version)
    assert (FLOWISE in _raw_feed(root)) is feed
    assert (FLOWISE_PIN in _ids(root)) is feed and _feed(root) == {}


# ---- Network-AI (CVE-2026-130750) -----------------------------------------------------------


@pytest.mark.parametrize(("version", "fires"), [
    ("5.10.2", False),    # no Streamable HTTP transport
    ("5.11.0", True),     # it arrives
    ("5.15.2", True),     # the SSE fix, not this one
    ("5.15.5", True),
    ("5.17.1", True),
    ("5.17.2", False),
    ("6.0.0", False),
    ("6.0.1", False),
    ("^5.11.0", True),
    ("^5.17.2", False),
    ("latest", False),    # 6.0.1 on 2026-11-26
    ("*", False),
])
def test_network_ai_versions(tmp_path: Path, version: str, fires: bool) -> None:
    assert (NETWORKAI_PIN in _pin_ids(_package_json(tmp_path, "network-ai", version))) is fires


@pytest.mark.parametrize(("args", "fires"), [
    (("-y", "-p", "network-ai@5.17.1", "network-ai-server"), True),
    (("-y", "-p", "network-ai@5.17.2", "network-ai-server"), False),
    (("-y", "-p", "network-ai", "network-ai-server"), False),
])
def test_network_ai_launches(tmp_path: Path, args: tuple[str, ...], fires: bool) -> None:
    assert (NETWORKAI_PIN in _pin_ids(_launch(tmp_path, "npx", *args))) is fires


def test_network_ai_on_pypi_is_silent(tmp_path: Path) -> None:
    assert NETWORKAI_PIN not in _pin_ids(_requirements(tmp_path, "network-ai==5.17.1"))


@pytest.mark.parametrize(("version", "expected"), [
    ("5.15.1", {NETWORKAI_PIN, NETWORKAI_SSE, NETWORKAI_FILES}),
    ("5.15.4", {NETWORKAI_PIN, NETWORKAI_FILES}),
    ("5.15.5", {NETWORKAI_PIN}),
    ("5.17.2", set()),
])
def test_network_ai_rules_keep_their_floors(tmp_path: Path, version: str, expected: set[str]) -> None:
    found = {i for i in _pin_ids(_package_json(tmp_path, "network-ai", version)) if i != (
        "AAK-MCP-NETWORKAI-CVE-2026-109331-001")}
    assert found == expected


@pytest.mark.parametrize(("version", "fires"), [("5.10.2", False), ("5.11.0", True), ("5.17.1", True), ("5.17.2", False)])
def test_network_ai_the_feed_stands_down_for_the_rule(tmp_path: Path, version: str, fires: bool) -> None:
    _cache_nvd(NETWORKAI)
    root = _npm_lock(tmp_path, "network-ai", version)
    assert (NETWORKAI in _raw_feed(root)) is fires
    assert (NETWORKAI_PIN in _ids(root)) is fires and _feed(root) == {}


# ---- CodeWhale (CVE-2026-83816, CVE-2026-83817) ---------------------------------------------


@pytest.mark.parametrize(("version", "fires"), [
    ("0.8.41", True),     # the first release under this name
    ("0.8.59", True),     # the automation flaw alone
    ("0.8.60", True),     # the read-only classifier arrives
    ("0.8.64", True),     # the older rule's floor
    ("0.8.67", True),
    ("0.9.0", False),
    ("0.10.4", False),
    ("^0.8.64", True),
    (">=0.8.64", True),
    ("^0.9.0", False),
    ("latest", False),    # 0.10.4 on 2026-11-26
    ("*", False),
])
def test_codewhale_versions(tmp_path: Path, version: str, fires: bool) -> None:
    assert (CODEWHALE_PIN in _pin_ids(_package_json(tmp_path, "codewhale", version))) is fires


@pytest.mark.parametrize(("args", "fires"), [
    (("-y", "codewhale@0.8.67"), True), (("-y", "codewhale@0.9.0"), False), (("-y", "codewhale"), False),
])
def test_codewhale_launches(tmp_path: Path, args: tuple[str, ...], fires: bool) -> None:
    assert (CODEWHALE_PIN in _pin_ids(_launch(tmp_path, "npx", *args))) is fires


def test_codewhale_on_pypi_is_silent(tmp_path: Path) -> None:
    assert CODEWHALE_PIN not in _pin_ids(_requirements(tmp_path, "codewhale==0.8.67"))


@pytest.mark.parametrize("name", ["codewhale-tui", "@acme/codewhale", "codewhaler"])
def test_codewhale_other_npm_names_are_silent(tmp_path: Path, name: str) -> None:
    assert CODEWHALE_PIN not in _pin_ids(_package_json(tmp_path, name, "0.8.67"))


def test_the_old_name_is_the_older_rule_s(tmp_path: Path) -> None:
    """`deepseek-tui` is in neither advisory: the limitation says so."""
    assert _pin_ids(_package_json(tmp_path, "deepseek-tui", "0.8.39")) == {CODEWHALE_OLD}
    assert "`deepseek-tui`" in RULES[CODEWHALE_PIN].limitations


@pytest.mark.parametrize(("version", "expected"), [
    ("0.8.63", {CODEWHALE_PIN, CODEWHALE_OLD}), ("0.8.64", {CODEWHALE_PIN}), ("0.9.0", set()),
])
def test_the_older_codewhale_floor_stays(tmp_path: Path, version: str, expected: set[str]) -> None:
    assert _pin_ids(_package_json(tmp_path, "codewhale", version)) == expected


@pytest.mark.parametrize(("version", "fires"), [("0.8.41", True), ("0.8.67", True), ("0.9.0", False)])
def test_codewhale_the_feed_stands_down_for_the_rule(tmp_path: Path, version: str, fires: bool) -> None:
    """OSV carries both advisories for npm, so `aak update` reads them as well."""
    _cache_osv(*CODEWHALE_OSV.values())
    root = _npm_lock(tmp_path, "codewhale", version)
    assert _raw_feed(root) == (set(CODEWHALE_OSV) if fires else set())
    assert (CODEWHALE_PIN in _ids(root)) is fires and _feed(root) == {}


@pytest.mark.parametrize(("version", "fires"), [("0.8.67", True), ("0.9.0", False)])
def test_the_crate_is_the_feed_s(tmp_path: Path, version: str, fires: bool) -> None:
    """The limitation: a Cargo.lock that resolves `codewhale-tui` is read after `aak update`."""
    (tmp_path / "Cargo.lock").write_text(
        f'version = 4\n\n[[package]]\nname = "codewhale-tui"\nversion = "{version}"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n', encoding="utf-8")
    assert _feed(tmp_path) == {}
    _cache_osv(*CODEWHALE_OSV.values())
    assert _feed(tmp_path) == (dict.fromkeys(CODEWHALE_OSV, Severity.HIGH) if fires else {})
    assert CODEWHALE_PIN not in _ids(tmp_path)


# ---- Next.js: the advisory feed after `aak update` ------------------------------------------

_BOTH_LINES = {"CVE-2026-119346", "CVE-2026-119347", "CVE-2026-119348"}
_SIXTEEN = {"CVE-2026-119349"}


@pytest.mark.parametrize(("version", "expected"), [
    ("9.5.5", {"CVE-2026-119348"}),                        # its record starts at the first release
    ("14.2.35", {"CVE-2026-119348"}),
    ("15.0.0", _BOTH_LINES),
    ("15.5.28", _BOTH_LINES),
    ("15.5.29", set()),                                    # the 15.x fix
    ("16.0.0", _BOTH_LINES | _SIXTEEN),
    ("16.1.7", _BOTH_LINES | _SIXTEEN),
    ("16.2.0", _BOTH_LINES | _SIXTEEN | {"CVE-2026-119351"}),
    ("16.3.8", _BOTH_LINES | _SIXTEEN | {"CVE-2026-119351"}),
    ("16.4.0", set(NEXT)),
    ("16.4.4", set(NEXT)),
    ("16.4.5", set()),                                     # the 16.x fix
    ("16.4.6", set()),                                     # latest on 2026-11-26
])
def test_next_ranges(tmp_path: Path, version: str, expected: set[str]) -> None:
    _cache_osv(*NEXT.values())
    found = _feed(_npm_lock(tmp_path, "next", version))
    assert set(found) == expected
    assert set(found.values()) <= {Severity.MEDIUM}


@pytest.mark.parametrize(("cve", "below", "first", "last", "fixed"), [
    ("CVE-2026-119346", None, "15.0.0", "15.5.28", "15.5.29"),
    ("CVE-2026-119346", "15.5.29", "16.0.0", "16.4.4", "16.4.5"),
    ("CVE-2026-119347", None, "15.0.0", "15.5.28", "15.5.29"),
    ("CVE-2026-119347", "15.5.29", "16.0.0", "16.4.4", "16.4.5"),
    ("CVE-2026-119348", None, "9.5.5", "15.5.28", "15.5.29"),
    ("CVE-2026-119348", "15.5.29", "16.0.0", "16.4.4", "16.4.5"),
    ("CVE-2026-119349", "15.5.28", "16.0.0", "16.4.4", "16.4.5"),
    ("CVE-2026-119350", "16.3.8", "16.4.0", "16.4.4", "16.4.5"),
    ("CVE-2026-119351", "16.1.7", "16.2.0", "16.4.4", "16.4.5"),
])
def test_each_next_record_alone_at_both_ends(tmp_path: Path, cve: str, below: str | None, first: str, last: str,
                                             fixed: str) -> None:
    _cache_osv(NEXT[cve])
    for version, fires in ((below, False), (first, True), (last, True), (fixed, False)):
        if version is not None:
            assert (cve in _feed(_npm_lock(tmp_path, "next", version))) is fires, version


def test_next_is_not_reported_without_aak_update(tmp_path: Path) -> None:
    """The bundled feed holds none of the six, and no pin reports 16.4.4."""
    text = advisory_feed.BUNDLED_FEED.read_text(encoding="utf-8")
    assert [i for pair in NEXT.items() for i in pair if i in text] == []
    root = _npm_lock(tmp_path, "next", "16.4.4")
    assert _feed(root) == {} and NEXTJS not in _ids(root)


def test_next_dev_server_pin_stays_and_makes_no_claim() -> None:
    (pin,) = [p for p in mcp_cve_pins_2026_07._PINS if p.rule_id == NEXTJS]
    assert (pin.introduced, pin.floor) == ((16, 0, 0), (16, 3, 8))


# ---- Better Auth: the advisory feed after `aak update` --------------------------------------

#: (record, package, a release at the low end of the CNA's range, the npm release below it).
_BA_STARTS: list[tuple[str, str, str, str | None]] = [
    (PHONE_UPDATE, "better-auth", "1.3.0", "1.2.12"),
    (OAUTH_EMAIL, "better-auth", "0.4.9", "0.4.8"),
    (SERIAL_ID, "better-auth", "0.4.8", None),  # its range starts at the first release
    (SERIAL_ID, "@better-auth/kysely-adapter", "1.5.0-beta.9", None),   # npm's first release
    (SERIAL_ID, "@better-auth/drizzle-adapter", "1.5.0-beta.9", None),  # the same
    (EMAIL_OTP, "better-auth", "1.3.7", "1.3.6"),
    (EMAIL_CHANGE, "better-auth", "1.4.0", "1.4.0-beta.28"),
    (PADDED_ROLE, "better-auth", "1.5.5", "1.5.4"),
    (PASSKEY, "@better-auth/passkey", "1.4.0-beta.16", None),  # npm's first release
    (REVOKED, "better-auth", "0.8.1-beta.5", "0.8.1-beta.4"),
    (REVOKED, "@better-auth/passkey", "1.6.25", "1.6.24"),
    (PHONE_OTP, "better-auth", "0.4.12-beta.7", "0.4.12-beta.6"),
]
_BA_SEVERITY = {PHONE_OTP: Severity.HIGH}


@pytest.mark.parametrize(("cve", "package", "first", "below"), _BA_STARTS)
def test_better_auth_at_both_ends(tmp_path: Path, cve: str, package: str, first: str, below: str | None) -> None:
    _cache_nvd(cve)
    cases = [(first, True), ("1.6.35", True), ("1.7.15", True), ("1.7.16", False), ("1.7.28", False),
             ("1.8.0-beta.0", True), ("1.8.0-beta.4", True), ("1.8.0-beta.5", False), ("1.8.0-beta.11", False)]
    for version, fires in cases + ([(below, False)] if below else []):
        found = _feed(_npm_lock(tmp_path, package, version))
        assert (cve in found) is fires, version
        if fires:
            assert found[cve] is _BA_SEVERITY.get(cve, Severity.MEDIUM)


@pytest.mark.parametrize(("version", "fires"), [
    ("1.2.0-beta.18", True), ("1.3.34", True), ("1.4.0", False), ("1.7.15", False),
])
def test_the_passkey_plugin_left_better_auth_in_1_4_0(tmp_path: Path, version: str, fires: bool) -> None:
    _cache_nvd(PASSKEY)
    assert (PASSKEY in _feed(_npm_lock(tmp_path, "better-auth", version))) is fires


def test_better_auth_1_6_35_carries_every_record(tmp_path: Path) -> None:
    """The newest 1.6 release (2026-11-19) has none of the fixes. PASSKEY's is another package's."""
    _cache_nvd(*BETTER_AUTH_CVES)
    root = _npm_lock(tmp_path, "better-auth", "1.6.35")
    assert set(_feed(root)) == set(BETTER_AUTH_CVES) - {PASSKEY}
    assert BETTER_AUTH not in _ids(root)  # above its 1.6.13 floor


def test_below_the_pin_s_floor_both_speak(tmp_path: Path) -> None:
    _cache_nvd(*BETTER_AUTH_CVES)
    root = _npm_lock(tmp_path, "better-auth", "1.6.12")
    assert BETTER_AUTH in _ids(root) and set(_feed(root)) == set(BETTER_AUTH_CVES) - {PASSKEY}


@pytest.mark.parametrize(("package", "version"), [
    ("better-auth", "1.7.15"), ("@better-auth/passkey", "1.7.15"), ("@better-auth/kysely-adapter", "1.7.15"),
    ("@better-auth/drizzle-adapter", "1.7.15"),
])
def test_better_auth_is_not_reported_without_aak_update(tmp_path: Path, package: str, version: str) -> None:
    root = _npm_lock(tmp_path, package, version)
    assert _feed(root) == {} and BETTER_AUTH not in _ids(root)


def test_better_auth_s_oauth_provider_is_in_none_of_the_records() -> None:
    """The pin reports the OAuth provider an MCP server runs. No record names its package."""
    packages = {entry["name"] for cve in BETTER_AUTH_CVES for entry in _entries(cve)}
    assert packages == {"better-auth", "@better-auth/passkey", "@better-auth/kysely-adapter",
                        "@better-auth/drizzle-adapter"}
    (pin,) = [p for p in mcp_cve_pins_2026_07._PINS if p.rule_id == BETTER_AUTH]
    assert pin.floor == (1, 6, 13)


# ---- LiteLLM: the advisory feed after `aak update` ------------------------------------------


@pytest.mark.parametrize(("version", "fires"), [
    ("1.62.1", False), ("1.62.4", True), ("1.83.14", True), ("1.84.0rc1", True), ("1.84.0", False),
    ("1.84.4", False), ("1.111.0", False),
])
def test_litellm_range(tmp_path: Path, version: str, fires: bool) -> None:
    _cache_nvd(LITELLM_CALLBACKS)
    found = _feed(_uv_lock(tmp_path, "litellm", version))
    assert found == ({LITELLM_CALLBACKS: Severity.MEDIUM} if fires else {})


def test_litellm_below_the_mcp_rule_s_floor_both_speak(tmp_path: Path) -> None:
    """Every affected release is below 1.84.0, the MCP rule's floor, which reports other flaws."""
    _cache_nvd(LITELLM_CALLBACKS)
    root = _uv_lock(tmp_path, "litellm", "1.83.14")
    assert LITELLM[0] in _ids(root) and set(_feed(root)) == {LITELLM_CALLBACKS}


def test_litellm_is_not_reported_without_aak_update(tmp_path: Path) -> None:
    root = _uv_lock(tmp_path, "litellm", "1.83.14")
    assert _feed(root) == {} and LITELLM[0] in _ids(root)


# ---- what no rule claims --------------------------------------------------------------------


@pytest.mark.parametrize("cve", FEED_CVES)
def test_no_rule_claims_a_record_it_does_not_read(cve: str) -> None:
    assert [r.rule_id for r in RULES.values() if cve in r.cve_references] == []


@pytest.mark.parametrize("cve", ALL_CVES)
def test_each_pinned_record_has_one_rule(cve: str) -> None:
    named = [r.rule_id for r in RULES.values() if cve in r.cve_references]
    assert named == ([PINNED[cve]] if cve in PINNED else [])


@pytest.mark.parametrize("cve", ALL_CVES)
def test_the_bundled_feed_holds_none_of_the_records(cve: str) -> None:
    """The bundled feed is held to the pins (tests/test_pin_floors_vs_advisories.py)."""
    assert cve not in advisory_feed.BUNDLED_FEED.read_text(encoding="utf-8")


@pytest.mark.parametrize("cve", [*NEXT, EXEC_SHELL, AUTOMATION])
def test_the_github_cna_records_map_to_no_package(cve: str) -> None:
    """They name `vercel/next.js` and `codewhale-hq/CodeWhale`, no package, so OSV's record is
    what `aak update` reads for them."""
    assert nvd_feed.record_packages(_nvd(cve), nvd_feed.load_package_map()) == []


@pytest.mark.parametrize(("cve", "packages"), [
    (PHONE_UPDATE, {"better-auth"}), (OAUTH_EMAIL, {"better-auth"}),
    (SERIAL_ID, {"better-auth", "@better-auth/kysely-adapter", "@better-auth/drizzle-adapter"}),
    (EMAIL_OTP, {"better-auth"}), (EMAIL_CHANGE, {"better-auth"}), (PADDED_ROLE, {"better-auth"}),
    (PASSKEY, {"better-auth", "@better-auth/passkey"}), (REVOKED, {"better-auth", "@better-auth/passkey"}),
    (PHONE_OTP, {"better-auth"}), (LITELLM_CALLBACKS, {"litellm"}), (FLOWISE, {"flowise"}),
    (NETWORKAI, {"network-ai"}),
])
def test_the_vulncheck_records_name_their_packages(cve: str, packages: set[str]) -> None:
    assert {name for _, name, _ in nvd_feed.record_packages(_nvd(cve), nvd_feed.load_package_map())} == packages


# ---- the ledger -----------------------------------------------------------------------------


@pytest.mark.parametrize("cve", ALL_CVES)
def test_every_record_has_one_ledger_row(cve: str) -> None:
    rows = [line for line in LEDGER.read_text(encoding="utf-8").splitlines() if line.startswith(f"| {cve} ")]
    assert len(rows) == 1 and rows[0].rstrip().endswith("| not filed |")
    assert PINNED.get(cve, KNOWN) in rows[0] and "out of scope" not in rows[0].lower()
