"""AAK-MCP-KOTLINSDK-CVE-2026-108714-001 — CVE-2026-108714 (#974).

MCP Kotlin SDK from 0.7.3: `Application.mcpWebSocket` installs Ktor `WebSockets`
with no `maxFrameSize`, so a client can declare a frame near 2 GiB and force the
allocation. There is no fixed release.

The boundaries were checked in the source and on Maven Central, not inferred:
`kotlin-sdk-server/.../WebSocketMcpKtorServerExtensions.kt` has no
`Application.mcpWebSocket` at 0.7.2 and has it from 0.7.3 to 0.15.0, the newest
release. The extension is in the server module, which the `kotlin-sdk` umbrella
pulls in (its 0.15.0 POM depends on `kotlin-sdk-server`), so the client and core
artifacts are not matched.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import jvm_mcp_sdk_pins as jvm

RULE = "AAK-MCP-KOTLINSDK-CVE-2026-108714-001"
STDIO_RULE = "AAK-MCP-STDIO-UNBOUNDED-BUFFER-001"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cves" / "cve-2026-108714-mcp-kotlin-sdk-ws"


def _ids(root: Path) -> set[str]:
    return {f.rule_id for f in jvm.scan(root)[0]}


def _write(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    return tmp_path


def test_rule_metadata() -> None:
    r = RULES[RULE]
    assert r.severity.value == "high"            # NVD 7.5
    assert r.category.value == "supply-chain"
    assert r.cve_references == ["CVE-2026-108714"]
    assert r.aicm_references


def test_rule_says_it_reads_versions_not_code() -> None:
    assert "It reads versions, not code" in RULES[RULE].limitations


def test_vulnerable_fixture_fires_on_gradle_and_maven() -> None:
    findings = [f for f in jvm.scan(FIXTURES / "vulnerable")[0] if f.rule_id == RULE]
    assert {f.file_path for f in findings} == {"build.gradle.kts", "pom.xml"}
    ev = {f.file_path: f.evidence for f in findings}
    assert "kotlin-sdk-server` resolves to 0.15.0" in ev["build.gradle.kts"]
    assert "kotlin-sdk-jvm` resolves to 0.14.0" in ev["pom.xml"]


def test_negative_and_pre_range_fixtures_are_silent() -> None:
    assert _ids(FIXTURES / "negative") == set()
    assert _ids(FIXTURES / "pre-range") == set()


@pytest.mark.parametrize("version,fires", [
    ("0.7.2", False),   # the extension is not there yet
    ("0.7.3", True),    # Application.mcpWebSocket arrives
    ("0.12.0", True),
    ("0.15.0", True),   # the newest release
    ("0.16.0", True),   # does not exist; no fixed release, so no floor yet
])
def test_version_boundaries(tmp_path: Path, version: str, fires: bool) -> None:
    root = _write(tmp_path, "build.gradle",
                  f"dependencies {{\n  implementation 'io.modelcontextprotocol:kotlin-sdk-server:{version}'\n}}\n")
    assert (RULE in _ids(root)) is fires


@pytest.mark.parametrize("artifact,fires", [
    ("kotlin-sdk-server", True),
    ("kotlin-sdk-server-jvm", True),
    ("kotlin-sdk", True),          # the umbrella depends on kotlin-sdk-server
    ("kotlin-sdk-jvm", True),
    ("kotlin-sdk-core", False),    # no server extension
    ("kotlin-sdk-client", False),
])
def test_artifacts(tmp_path: Path, artifact: str, fires: bool) -> None:
    root = _write(tmp_path, "build.gradle.kts",
                  f'dependencies {{\n  implementation("io.modelcontextprotocol:{artifact}:0.15.0")\n}}\n')
    assert (RULE in _ids(root)) is fires


def test_catalog_version_ref_resolves(tmp_path: Path) -> None:
    root = _write(tmp_path, "gradle/libs.versions.toml",
                  '[versions]\nmcp = "0.14.0"\n\n[libraries]\n'
                  'mcp-server = { module = "io.modelcontextprotocol:kotlin-sdk-server", version.ref = "mcp" }\n')
    assert RULE in _ids(root)


def test_the_two_pins_report_independently(tmp_path: Path) -> None:
    """0.12.0 of the umbrella carries both CVEs: one finding each, not one for
    the file. 0.13.0 fixed the stdio buffer and not the frame size."""
    root = _write(tmp_path, "build.gradle.kts",
                  'dependencies {\n  implementation("io.modelcontextprotocol:kotlin-sdk:0.12.0")\n}\n')
    assert sorted(f.rule_id for f in jvm.scan(root)[0]) == sorted([RULE, STDIO_RULE])
    root2 = _write(tmp_path / "b", "build.gradle.kts",
                   'dependencies {\n  implementation("io.modelcontextprotocol:kotlin-sdk:0.13.0")\n}\n')
    assert _ids(root2) == {RULE}


def test_a_file_naming_two_server_artifacts_reports_once(tmp_path: Path) -> None:
    root = _write(tmp_path, "build.gradle.kts",
                  'dependencies {\n'
                  '  implementation("io.modelcontextprotocol:kotlin-sdk:0.15.0")\n'
                  '  implementation("io.modelcontextprotocol:kotlin-sdk-server:0.15.0")\n'
                  '}\n')
    assert len([f for f in jvm.scan(root)[0] if f.rule_id == RULE]) == 1


def test_a_dynamic_version_is_not_reported(tmp_path: Path) -> None:
    root = _write(tmp_path, "build.gradle",
                  "dependencies {\n  implementation 'io.modelcontextprotocol:kotlin-sdk-server:0.+'\n}\n")
    assert RULE not in _ids(root)


def test_rule_fires_through_run_scan() -> None:
    from agent_audit_kit.engine import run_scan
    result = run_scan(FIXTURES / "vulnerable")
    assert RULE in {f.rule_id for f in result.findings}
