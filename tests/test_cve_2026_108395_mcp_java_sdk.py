"""AAK-MCP-JAVASDK-CVE-2026-108395-001 — CVE-2026-108395 (#999).

The MCP Java SDK's Servlet SSE, Streamable HTTP and Stateless server transports
read a POST body line by line into a `StringBuilder` with no size limit, so an
unauthenticated client can exhaust the heap.

The boundaries were checked in the source and on Maven Central, not inferred:
`HttpServletSseServerTransportProvider` arrives in 0.8.0 (0.7.0 has only the older
`HttpServletSseServerTransport`, which reads the same way but is outside the
record), the transports move from `mcp` to `mcp-core` at 0.13.0, and the `mcp`
bundle's POM depends on `mcp-core` at its own version from then on. The unbounded
`readLine()` loop is in all three transports at 0.12.1, 0.13.0, 0.18.3, 1.0.0-RC3,
1.0.2, 1.1.3, 2.0.0-M1, 2.0.0-RC1 and 2.0.0, and 0.18.4, 1.1.4 and 2.0.1 read
through a bounded `readBody`. 1.0.x has no fixed release. The quickstart at v1.1.3
declares `mcp` with no version and imports `mcp-bom` 1.1.0, which is the
vulnerable fixture.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import jvm_mcp_sdk_pins as jvm

RULE = "AAK-MCP-JAVASDK-CVE-2026-108395-001"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cves" / "cve-2026-108395-mcp-java-sdk"


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
    assert r.cve_references == ["CVE-2026-108395"]
    assert r.aicm_references


def test_the_quickstart_fires_through_the_bom_on_maven_and_gradle() -> None:
    findings = [f for f in jvm.scan(FIXTURES / "vulnerable")[0] if f.rule_id == RULE]
    assert {(f.file_path, f.line_number) for f in findings} == {("pom.xml", 25), ("build.gradle", 5)}
    for f in findings:
        assert "`io.modelcontextprotocol.sdk:mcp` resolves to 1.1.0 through `mcp-bom`" in f.evidence


def test_the_fixed_boms_are_silent() -> None:
    assert _ids(FIXTURES / "negative") == set()


@pytest.mark.parametrize("version,fires", [
    ("0.7.0", False),       # the record starts at 0.8.0
    ("0.8.0", True),        # HttpServletSseServerTransportProvider arrives
    ("0.12.1", True),       # the last release with the transports in `mcp` itself
    ("0.13.0", True),       # `mcp` now depends on `mcp-core` 0.13.0
    ("0.18.3", True),
    ("0.18.4", False),      # the 0.18.x fix
    ("1.0.0-RC3", True),    # reads as 1.0.0; its source has the same loop
    ("1.0.2", True),        # 1.0.x has no fix
    ("1.1.3", True),
    ("1.1.4", False),       # the 1.1.x fix
    ("1.1.5", False),
    ("2.0.0-M1", True),     # reads as 2.0.0; affected per the record and the source
    ("2.0.0", True),
    ("2.0.1", False),       # the 2.0.x fix
    ("2.1.0", False),       # the newest release on 2026-10-15
])
def test_version_boundaries(tmp_path: Path, version: str, fires: bool) -> None:
    root = _write(tmp_path, "build.gradle",
                  f'dependencies {{\n    implementation "io.modelcontextprotocol.sdk:mcp:{version}"\n}}\n')
    assert (RULE in _ids(root)) is fires


@pytest.mark.parametrize("artifact,fires", [
    ("mcp", True),
    ("mcp-core", True),
    ("mcp-json-jackson2", False),   # no transports
    ("mcp-spring-webmvc", False),   # pulls `mcp` in; transitive versions are not read
    ("mcp-test", False),
])
def test_artifacts(tmp_path: Path, artifact: str, fires: bool) -> None:
    root = _write(tmp_path, "build.gradle.kts",
                  f'dependencies {{\n    implementation("io.modelcontextprotocol.sdk:{artifact}:1.1.3")\n}}\n')
    assert (RULE in _ids(root)) is fires


def test_the_kotlin_group_is_not_the_java_group(tmp_path: Path) -> None:
    """`io.modelcontextprotocol:mcp` is not a Java SDK coordinate, and the Kotlin
    pins do not read `io.modelcontextprotocol.sdk`."""
    root = _write(tmp_path, "build.gradle.kts",
                  'dependencies {\n'
                  '    implementation("io.modelcontextprotocol:mcp-core:1.1.3")\n'
                  '    implementation("io.modelcontextprotocol.sdk:kotlin-sdk:0.12.0")\n'
                  '}\n')
    assert _ids(root) == set()


def test_an_explicit_version_overrides_the_bom(tmp_path: Path) -> None:
    root = _write(tmp_path, "build.gradle",
                  'dependencies {\n'
                  '    implementation platform("io.modelcontextprotocol.sdk:mcp-bom:1.1.0")\n'
                  '    implementation "io.modelcontextprotocol.sdk:mcp-core:1.1.4"\n'
                  '}\n')
    assert RULE not in _ids(root)


def test_an_unresolved_version_is_not_replaced_by_the_bom(tmp_path: Path) -> None:
    """`$mcpVersion` set in another file decides the build, not the BOM."""
    root = _write(tmp_path, "build.gradle",
                  'dependencies {\n'
                  '    implementation platform("io.modelcontextprotocol.sdk:mcp-bom:1.1.0")\n'
                  '    implementation "io.modelcontextprotocol.sdk:mcp-core:$mcpVersion"\n'
                  '}\n')
    assert RULE not in _ids(root)


def test_a_bom_without_the_sdk_is_not_reported(tmp_path: Path) -> None:
    root = _write(tmp_path, "build.gradle",
                  'dependencies {\n'
                  '    implementation platform("io.modelcontextprotocol.sdk:mcp-bom:1.1.0")\n'
                  '}\n')
    assert RULE not in _ids(root)


def test_maven_property_and_catalog_forms_resolve(tmp_path: Path) -> None:
    pom = _write(tmp_path / "maven", "pom.xml",
                 "<project>\n  <properties>\n    <mcp.version>0.17.2</mcp.version>\n  </properties>\n"
                 "  <dependencies>\n    <dependency>\n"
                 "      <groupId>io.modelcontextprotocol.sdk</groupId>\n"
                 "      <artifactId>mcp-core</artifactId>\n"
                 "      <version>${mcp.version}</version>\n"
                 "    </dependency>\n  </dependencies>\n</project>\n")
    assert RULE in _ids(pom)
    catalog = _write(tmp_path / "catalog", "gradle/libs.versions.toml",
                     '[versions]\nmcp = "1.0.1"\n\n[libraries]\n'
                     'mcp-bom = { module = "io.modelcontextprotocol.sdk:mcp-bom", version.ref = "mcp" }\n'
                     'mcp = { module = "io.modelcontextprotocol.sdk:mcp" }\n')
    findings = [f for f in jvm.scan(catalog)[0] if f.rule_id == RULE]
    assert [(f.line_number, "through `mcp-bom`" in f.evidence) for f in findings] == [(6, True)]


def test_a_dynamic_version_is_not_reported(tmp_path: Path) -> None:
    root = _write(tmp_path, "build.gradle",
                  'dependencies {\n    implementation "io.modelcontextprotocol.sdk:mcp:1.0.+"\n}\n')
    assert RULE not in _ids(root)


def test_the_finding_is_placed_on_the_dependency_not_the_first_mention(tmp_path: Path) -> None:
    """The project name contains `mcp`; the finding goes on the coordinate's line."""
    root = _write(tmp_path, "pom.xml",
                  "<project>\n  <artifactId>my-mcp-server</artifactId>\n  <dependencies>\n"
                  "    <dependency>\n      <groupId>io.modelcontextprotocol.sdk</groupId>\n"
                  "      <artifactId>mcp</artifactId>\n      <version>0.10.0</version>\n"
                  "    </dependency>\n  </dependencies>\n</project>\n")
    [finding] = [f for f in jvm.scan(root)[0] if f.rule_id == RULE]
    assert finding.line_number == 6


def test_rule_fires_through_run_scan() -> None:
    from agent_audit_kit.engine import run_scan
    result = run_scan(FIXTURES / "vulnerable")
    assert RULE in {f.rule_id for f in result.findings}
