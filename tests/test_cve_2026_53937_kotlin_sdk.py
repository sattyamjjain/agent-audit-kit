"""AAK-MCP-STDIO-UNBOUNDED-BUFFER-001 — CVE-2026-53937 (#705).

MCP Kotlin SDK 0.7.0–0.12.0: `ReadBuffer.append` writes every stdio chunk into a
`kotlinx.io.Buffer` with no size cap and only frames on `\\n`, so a peer that
never sends a newline OOM-kills the JVM. Fixed 0.13.0.

This is the first JVM entry in the pin surface, so the manifest forms are the
substance of the tests rather than the boundary arithmetic. A JVM coordinate
rarely carries its version inline any more: Gradle KTS puts it in a `val`, the
version catalog puts it behind a `version.ref`, and Maven puts it in
`<properties>`. All three are asserted, in both directions.

The version boundaries were checked against Maven Central rather than inferred:
`kotlin-sdk-core` publishes 0.7.0 first — which is why NVD's range starts there,
a module-split boundary rather than the commit that introduced the defect — and
0.13.0, 0.14.0, 0.15.0 exist above the fix.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import jvm_mcp_sdk_pins as jvm

RULE = "AAK-MCP-STDIO-UNBOUNDED-BUFFER-001"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cves" / "cve-2026-53937-mcp-kotlin-sdk"


def _ids(root: Path) -> set[str]:
    return {f.rule_id for f in jvm.scan(root)[0]}


def _write(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    return tmp_path


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def test_rule_is_registered() -> None:
    assert RULE in RULES


def test_rule_metadata() -> None:
    r = RULES[RULE]
    assert r.severity.value == "medium"          # NVD 6.2
    assert r.category.value == "supply-chain"    # every sibling version-pin rule
    assert r.cve_references == ["CVE-2026-53937"]


def test_rule_carries_aicm_tags() -> None:
    """The overlay in `_AICM_TAGS` is what puts a rule on the AICM crosswalk. A
    pin with no tags silently drops out of the compliance output."""
    assert RULES[RULE].aicm_references


def test_rule_states_it_is_a_manifest_pin_not_a_source_detector() -> None:
    assert "does not detect the unbounded-buffer shape in first-party code" in RULES[RULE].limitations


# ---------------------------------------------------------------------------
# Fixtures — the three manifest forms, both directions
# ---------------------------------------------------------------------------

def test_vulnerable_fixture_fires_on_every_manifest_form() -> None:
    findings = jvm.scan(FIXTURES / "vulnerable")[0]
    files = {f.file_path for f in findings}
    assert files == {"build.gradle.kts", "pom.xml", "gradle/libs.versions.toml"}, files
    assert all(f.rule_id == RULE for f in findings)


def test_patched_fixture_is_silent() -> None:
    assert _ids(FIXTURES / "patched") == set()


def test_pre_range_fixture_is_silent() -> None:
    """0.6.1 predates `kotlin-sdk-core`, which is where the buffer lives — and is
    why NVD starts the range at 0.7.0 rather than at 0.1.0."""
    assert _ids(FIXTURES / "pre-range") == set()


def test_evidence_names_the_resolved_version_not_the_reference() -> None:
    """The version comes from a `val`, a `version.ref` or a `<properties>` entry.
    Reporting the reference name instead of what it resolved to would make the
    finding unactionable."""
    ev = {f.file_path: f.evidence for f in jvm.scan(FIXTURES / "vulnerable")[0]}
    assert "0.12.0" in ev["build.gradle.kts"]           # val mcpVersion
    assert "0.11.1" in ev["pom.xml"]                    # ${mcp.sdk.version}
    assert "0.7.0" in ev["gradle/libs.versions.toml"]   # version.ref = "mcp"


# ---------------------------------------------------------------------------
# Boundaries
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("version,fires", [
    ("0.6.1", False),   # below the range: kotlin-sdk-core does not exist yet
    ("0.7.0", True),    # first affected, and first release of kotlin-sdk-core
    ("0.9.0", True),
    ("0.11.1", True),
    ("0.12.0", True),   # last affected
    ("0.13.0", False),  # the vendor fix
    ("0.15.0", False),  # current line at ship time
])
def test_floor_boundaries(tmp_path: Path, version: str, fires: bool) -> None:
    root = _write(tmp_path, "build.gradle",
                  f"dependencies {{\n  implementation 'io.modelcontextprotocol:kotlin-sdk:{version}'\n}}\n")
    assert (RULE in _ids(root)) is fires


@pytest.mark.parametrize("artifact", ["kotlin-sdk", "kotlin-sdk-core", "kotlin-sdk-jvm"])
def test_all_three_artifact_names_are_matched(tmp_path: Path, artifact: str) -> None:
    """Three artifacts publish the same code; Gradle resolves `-jvm` from the
    plain name. Matching only one would miss a real dependent."""
    root = _write(tmp_path, "build.gradle.kts",
                  f'dependencies {{\n  implementation("io.modelcontextprotocol:{artifact}:0.12.0")\n}}\n')
    assert RULE in _ids(root)


def test_a_file_naming_two_artifacts_reports_once(tmp_path: Path) -> None:
    """A multiplatform project that names both `kotlin-sdk` and `kotlin-sdk-core`
    has one dependency, not two. Reporting twice is noise, not coverage — the
    lesson the MCPHub pin recorded when it collapsed eight advisories into one."""
    root = _write(tmp_path, "build.gradle.kts",
                  'dependencies {\n'
                  '  implementation("io.modelcontextprotocol:kotlin-sdk:0.12.0")\n'
                  '  implementation("io.modelcontextprotocol:kotlin-sdk-core:0.12.0")\n'
                  '}\n')
    assert len([f for f in jvm.scan(root)[0] if f.rule_id == RULE]) == 1


# ---------------------------------------------------------------------------
# Negatives that keep this narrow
# ---------------------------------------------------------------------------

def test_an_unrelated_group_with_the_same_artifact_name_is_silent(tmp_path: Path) -> None:
    root = _write(tmp_path, "build.gradle.kts",
                  'dependencies {\n  implementation("com.example.fork:kotlin-sdk:0.12.0")\n}\n')
    assert RULE not in _ids(root)


def test_a_dynamic_version_is_not_reported(tmp_path: Path) -> None:
    """`0.+` may well resolve into the affected range, but this rule reports what
    it resolved, not what it might resolve to. Saying otherwise would be a claim
    the scanner cannot support — stated in the rule's `limitations`."""
    root = _write(tmp_path, "build.gradle",
                  "dependencies {\n  implementation 'io.modelcontextprotocol:kotlin-sdk:0.+'\n}\n")
    assert RULE not in _ids(root)


def test_an_unresolvable_version_ref_is_not_reported(tmp_path: Path) -> None:
    root = _write(tmp_path, "gradle/libs.versions.toml",
                  '[libraries]\n'
                  'mcp = { module = "io.modelcontextprotocol:kotlin-sdk", version.ref = "absent" }\n')
    assert RULE not in _ids(root)


def test_a_manifest_without_the_group_is_silent(tmp_path: Path) -> None:
    root = _write(tmp_path, "pom.xml",
                  "<project><dependencies><dependency>"
                  "<groupId>io.ktor</groupId><artifactId>ktor-client-core</artifactId>"
                  "<version>3.0.0</version></dependency></dependencies></project>")
    assert RULE not in _ids(root)


def test_scanner_is_silent_on_this_repository() -> None:
    """This repo has no JVM manifests, but the VS Code extension subtree and the
    fixture corpus both carry files a loose matcher could reach."""
    repo = Path(__file__).resolve().parents[1]
    findings, _ = jvm.scan(repo / "agent_audit_kit")
    assert findings == []


# ---------------------------------------------------------------------------
# The full engine sees it, not just the module in isolation
# ---------------------------------------------------------------------------

def test_rule_fires_through_run_scan() -> None:
    from agent_audit_kit.engine import run_scan
    result = run_scan(FIXTURES / "vulnerable")
    assert RULE in {f.rule_id for f in result.findings}
