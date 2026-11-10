"""CVE-2026-111768, CVE-2026-11624 and anyio's two advisories, read on 2026-11-07.

None was filed by the watcher. `CHANGELOG.cves.md` holds the reasoning.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_audit_kit import advisory_feed
from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import mcp_cve_pins_2026_07, mcp_toolbox_hosts
from agent_audit_kit.scanners.known_vulns import _exact_parents
from agent_audit_kit.scanners.known_vulns import scan as known_vulns

TSSDK = "AAK-MCP-TSSDK-CVE-2026-111768-001"
TASKS = "AAK-MCP-TSSDK-CVE-2026-111767-001"
TOOLBOX = "AAK-MCP-TOOLBOX-HOSTS-001"
ANYIO = ["GHSA-82r6-8w77-94w6", "GHSA-5p39-cfhj-2xmp"]


def _pins(root: Path) -> set[str]:
    return {f.rule_id for f in mcp_cve_pins_2026_07.scan(root)[0]}


def _package_json(root: Path, name: str, version: str) -> Path:
    (root / "package.json").write_text(json.dumps({"dependencies": {name: version}}))
    return root


@pytest.mark.parametrize("name,version,fires", [
    ("@modelcontextprotocol/sdk", "1.2.0", False),
    ("@modelcontextprotocol/sdk", "1.3.0", True),
    ("@modelcontextprotocol/sdk", "1.31.0", True),
    ("@modelcontextprotocol/sdk", "1.32.0", False),
    ("@modelcontextprotocol/server", "2.0.0", True),
    ("@modelcontextprotocol/server", "2.2.0", True),
    ("@modelcontextprotocol/server", "2.3.0", False),
    ("@modelcontextprotocol/sdk", "latest", False),
])
def test_the_sdk_pin_reads_both_packages(tmp_path: Path, name: str, version: str, fires: bool) -> None:
    assert (TSSDK in _pins(_package_json(tmp_path, name, version))) is fires


def test_1_31_0_fires_with_the_task_store_pin(tmp_path: Path) -> None:
    assert {TSSDK, TASKS} <= _pins(_package_json(tmp_path, "@modelcontextprotocol/sdk", "1.31.0"))


def test_the_sdk_rule_says_upgrading_alone_changes_nothing() -> None:
    rule = RULES[TSSDK]
    assert rule.severity is Severity.HIGH and rule.cve_references == ["CVE-2026-111768"]
    assert "upgrading alone changes nothing" in rule.remediation and "maxToolInputElements" in rule.remediation


@pytest.mark.parametrize("version,fires", [("0.21.0", True), ("0.24.1", True), ("0.25.0", False), ("latest", False)])
def test_the_toolbox_pin(tmp_path: Path, version: str, fires: bool) -> None:
    assert (TOOLBOX in _pins(_package_json(tmp_path, "@toolbox-sdk/server", version))) is fires


def _launch(root: Path, args: list[str], command: str = "npx", name: str = ".mcp.json") -> list[str]:
    (root / name).write_text(json.dumps({"mcpServers": {"db": {"command": command, "args": args}}}))
    return [f.evidence for f in mcp_toolbox_hosts.scan(root)[0]]


BOTH = ["--allowed-hosts", "mcp.example.com", "--allowed-origins=https://app.example.com"]
PKG = ["-y", "@toolbox-sdk/server"]


def test_a_launch_with_both_flags_naming_real_hosts_does_not_fire(tmp_path: Path) -> None:
    assert _launch(tmp_path, [*PKG, *BOTH]) == []


@pytest.mark.parametrize("args,names", [
    ([], ["--allowed-hosts (unset", "--allowed-origins (unset"]),
    (["--allowed-origins=https://a.example.com"], ["--allowed-hosts (unset"]),
    (["--allowed-hosts", "a.example.com"], ["--allowed-origins (unset"]),
    (["--allowed-hosts=*", "--allowed-origins=https://a.example.com"], ["--allowed-hosts=*"]),
    (["--allowed-hosts", "*,a.example.com", "--allowed-origins", "https://a.example.com"], ["--allowed-hosts=*"]),
], ids=["neither", "no-hosts", "no-origins", "wildcard", "wildcard-in-a-list"])
def test_an_open_flag_fires_and_is_named(tmp_path: Path, args: list[str], names: list[str]) -> None:
    (evidence,) = _launch(tmp_path, [*PKG, *args])
    assert all(name in evidence for name in names) and "CVE-2026-11624" in evidence


def test_the_binary_by_name_fires(tmp_path: Path) -> None:
    assert len(_launch(tmp_path, ["--config", "t.yaml"], command="/usr/local/bin/toolbox")) == 1


def test_stdio_has_no_listener(tmp_path: Path) -> None:
    assert _launch(tmp_path, [*PKG, "--stdio"]) == []


def test_another_package_is_not_read(tmp_path: Path) -> None:
    assert _launch(tmp_path, ["-y", "@toolbox-sdk/other"]) == []


def test_a_release_below_the_fix_is_left_to_the_pin(tmp_path: Path) -> None:
    args = ["-y", "@toolbox-sdk/server@0.24.1"]
    assert _launch(tmp_path, args) == []
    assert TOOLBOX in {f.rule_id for f in run_scan(tmp_path).findings}
    assert len(_launch(tmp_path, ["-y", "@toolbox-sdk/server@0.25.0"])) == 1


def test_a_sub_directory_and_a_vscode_map_are_read(tmp_path: Path) -> None:
    sub = tmp_path / "svc"
    sub.mkdir()
    (sub / "db.mcp.json").write_text(json.dumps({"servers": {"db": {"command": "npx", "args": PKG}}}))
    (finding,) = mcp_toolbox_hosts.scan(tmp_path)[0]
    assert finding.file_path == "svc/db.mcp.json"


# ---- anyio ----------------------------------------------------------------------------


UV = 'version = 1\n\n[[package]]\nname = "anyio"\nversion = "%s"\nsource = { registry = "https://pypi.org/simple" }\n'


def test_a_uv_lock_on_4_12_1_fires_for_both_records(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(UV % "4.12.1")
    findings = known_vulns(tmp_path)[0]
    assert {a: f.severity for a in ANYIO for f in findings if a in f.evidence} == {
        ANYIO[0]: Severity.CRITICAL, ANYIO[1]: Severity.MEDIUM}
    assert all("it is fixed in 4.14.2" in f.evidence for f in findings)


def test_a_uv_lock_on_4_14_2_does_not_fire(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(UV % "4.14.2")
    assert known_vulns(tmp_path)[0] == []


def test_the_project_s_own_exact_pin_is_named(tmp_path: Path) -> None:
    """browser-use's own uv.lock: the project requires anyio==4.12.1."""
    root = ('\n[[package]]\nname = "browser-use"\nversion = "0.13.14"\nsource = { editable = "." }\n'
            '\n[package.metadata]\nrequires-dist = [\n    { name = "anyio", specifier = "==4.12.1" },\n]\n')
    (tmp_path / "uv.lock").write_text(UV % "4.12.1" + root)
    findings = known_vulns(tmp_path)[0]
    assert findings and all("browser-use, this project, pins anyio ==4.12.1 exactly" in f.evidence for f in findings)


def test_a_poetry_parent_s_exact_pin_says_the_upgrade_needs_an_override(tmp_path: Path) -> None:
    lock = ('[[package]]\nname = "anyio"\nversion = "4.12.1"\n\n'
            '[[package]]\nname = "browser-use"\nversion = "0.13.14"\n\n[package.dependencies]\nanyio = "==4.12.1"\n'
            'httpx = ">=0.27"\n\n[package.extras]\nanyio = ["x"]\n')
    (tmp_path / "poetry.lock").write_text(lock)
    findings = known_vulns(tmp_path)[0]
    assert findings and all("browser-use pins anyio ==4.12.1 exactly, so the upgrade needs an override" in f.evidence
                            and "override-dependencies" in f.evidence for f in findings)


def test_a_range_or_another_release_is_not_an_exact_parent() -> None:
    lock = ('[[package]]\nname = "p"\nversion = "1"\n\n[package.dependencies]\nanyio = ">=4.0"\nsniffio = "1.3.1"\n'
            'x = {version = "==2.0", optional = true}\n')
    assert _exact_parents(lock, "poetry.lock") == {("sniffio", "1.3.1"): ("p", False), ("x", "2.0"): ("p", False)}
    assert _exact_parents(lock, "package-lock.json") == {}


def test_a_plain_lockfile_says_nothing_about_parents(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(UV % "4.12.1")
    assert not any("exactly" in f.evidence for f in known_vulns(tmp_path)[0])


def test_the_bundled_records_are_read_without_an_update() -> None:
    feed = advisory_feed.load_feed()
    assert feed.origin == "bundled"
    assert {a.id for a in feed.match("PyPI", "anyio", "4.12.1")} == set(ANYIO)
    assert feed.match("PyPI", "anyio", "4.14.2") == []


@pytest.mark.parametrize("cve,rule", [("CVE-2026-111768", TSSDK), ("CVE-2026-11624", TOOLBOX),
                                      ("CVE-2026-63374", "AAK-KNOWN-VULN-001"),
                                      ("CVE-2026-64847", "AAK-KNOWN-VULN-001")])
def test_every_cve_has_a_ledger_row_naming_its_rule(cve: str, rule: str) -> None:
    ledger = Path(__file__).resolve().parent.parent / "CHANGELOG.cves.md"
    (row,) = [line for line in ledger.read_text().splitlines() if line.startswith(f"| {cve} ")]
    assert rule in row and row.rstrip().endswith("| not filed |")
