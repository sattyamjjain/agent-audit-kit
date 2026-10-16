"""AAK-MCP-INSPECTOR-CVE-2026-23744-001: an installed or vendored MCPJam Inspector.

CVE-2026-23744 (GHSA-232v-j27c-5pp6) is npm `@mcpjam/inspector` 1.4.2 and
earlier; 1.4.3 binds 127.0.0.1. The published package keeps its server in
`dist/server/index.js` and only a `bin/` shim outside `dist/` (1.4.2, 1.4.3 and
3.16.1 alike), so the rule used to read the shim alone and report every install,
a patched one included. It now reads the copy's own package.json version.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_audit_kit.scanners.mcp_inspector_cve import scan

RULE = "AAK-MCP-INSPECTOR-CVE-2026-23744-001"
NPM = "node_modules/@mcpjam/inspector"
_JS = "module.exports = {};\n"


def _project(tmp_path: Path, files: dict[str, str]) -> list:
    for rel, text in files.items():
        dest = tmp_path / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text, encoding="utf-8")
    return [f for f in scan(tmp_path)[0] if f.rule_id == RULE]


def _manifest(version: str, name: str = "@mcpjam/inspector") -> str:
    return json.dumps({"name": name, "version": version, "bin": "bin/start.js"}, indent=2) + "\n"


@pytest.mark.parametrize("folder", ["dist/server", "build", "out"])
def test_code_in_a_build_folder_of_a_vulnerable_install_fires(tmp_path: Path, folder: str) -> None:
    """dist/, build/ and out/ were skipped inside the package, so a copy whose
    code sits only there was never read."""
    findings = _project(tmp_path, {
        f"{NPM}/package.json": _manifest("1.4.2"),
        f"{NPM}/{folder}/index.js": _JS,
    })
    assert len(findings) == 1
    assert findings[0].file_path == f"{NPM}/package.json"
    assert findings[0].line_number == 3   # the "version" line
    assert "1.4.2" in findings[0].evidence


@pytest.mark.parametrize("version", ["1.4.3", "1.5.17", "3.16.1"])
def test_a_patched_install_is_quiet(tmp_path: Path, version: str) -> None:
    """Every install fired, at CRITICAL, whatever its version."""
    assert _project(tmp_path, {
        f"{NPM}/package.json": _manifest(version),
        f"{NPM}/bin/start.js": _JS,
        f"{NPM}/dist/server/index.js": _JS,
    }) == []


@pytest.mark.parametrize("version", ["1.4.2", "1.0.0", "0.9.8"])
def test_a_vulnerable_install_fires_once(tmp_path: Path, version: str) -> None:
    files = {f"{NPM}/package.json": _manifest(version), f"{NPM}/bin/start.js": _JS}
    files.update({f"{NPM}/dist/client/chunk-{i}.js": _JS for i in range(30)})
    findings = _project(tmp_path, files)
    assert len(findings) == 1, "one install is one finding, not one per file"
    assert version in findings[0].evidence


def test_an_install_with_no_readable_version_fires_on_its_first_file(tmp_path: Path) -> None:
    findings = _project(tmp_path, {
        f"{NPM}/dist/server/index.js": _JS,
        f"{NPM}/bin/start.js": _JS,
    })
    assert [(f.file_path, f.line_number) for f in findings] == [(f"{NPM}/bin/start.js", 1)]


def test_a_vendored_copy_is_judged_by_its_package_json(tmp_path: Path) -> None:
    base = "vendor/mcpjam-inspector"
    assert len(_project(tmp_path / "old", {
        f"{base}/package.json": _manifest("1.4.2"), f"{base}/dist/server.js": _JS,
    })) == 1
    assert _project(tmp_path / "new", {
        f"{base}/package.json": _manifest("1.4.3"), f"{base}/dist/server.js": _JS,
    }) == []


def test_a_renamed_fork_states_no_inspector_version(tmp_path: Path) -> None:
    """A fork's own version number is not MCPJam's, so it cannot clear the copy."""
    findings = _project(tmp_path, {
        "vendor/mcpjam-inspector/package.json": _manifest("9.0.0", name="acme-inspector"),
        "vendor/mcpjam-inspector/src/server.ts": _JS,
    })
    assert [f.file_path for f in findings] == ["vendor/mcpjam-inspector/src/server.ts"]


def test_a_different_mcpjam_package_is_not_the_inspector(tmp_path: Path) -> None:
    """`@mcpjam/inspector-v1` (0.2.8, a Next.js app) is another package, and
    CVE-2026-23744 names `@mcpjam/inspector` only."""
    assert _project(tmp_path, {
        "node_modules/@mcpjam/inspector-v1/package.json": _manifest("0.2.8", "@mcpjam/inspector-v1"),
        "node_modules/@mcpjam/inspector-v1/bin/start.js": _JS,
    }) == []


def test_a_copy_inside_a_skipped_folder_stays_skipped(tmp_path: Path) -> None:
    assert _project(tmp_path, {"dist/vendor/mcpjam-inspector/server.js": _JS}) == []


def test_the_call_shape_outside_a_copy_still_fires_per_file(tmp_path: Path) -> None:
    findings = _project(tmp_path, {
        "src/app.ts": "const a = 1;\ninspectorServer.handle(req, res);\n",
        "src/other.ts": _JS,
    })
    assert [(f.file_path, f.line_number) for f in findings] == [("src/app.ts", 2)]


def test_an_unparseable_package_json_counts_as_no_version(tmp_path: Path) -> None:
    findings = _project(tmp_path, {
        f"{NPM}/package.json": '{"name": "@mcpjam/inspector", "version": ',
        f"{NPM}/bin/start.js": _JS,
    })
    assert [f.file_path for f in findings] == [f"{NPM}/bin/start.js"]


def test_an_unversioned_copy_is_reported_on_its_call_site(tmp_path: Path) -> None:
    """The vendored-fork fixture's finding sat on its `inspectorServer.handle(`
    line before copies were read as a whole, and still does."""
    findings = _project(tmp_path, {
        "vendor/mcpjam-inspector/a.ts": _JS,
        "vendor/mcpjam-inspector/server.ts": "import x from 'y';\n\ninspectorServer.handle(a, b);\n",
    })
    assert [(f.file_path, f.line_number) for f in findings] == [("vendor/mcpjam-inspector/server.ts", 3)]


def test_a_file_named_after_the_inspector_is_not_a_copy(tmp_path: Path) -> None:
    """Outside a copy only the call shape is read, as the limitation says: a file
    whose name holds `mcpjam-inspector` was reported at CRITICAL for its name."""
    assert _project(tmp_path / "named", {"src/mcpjam-inspector.ts": "export const x = 1;\n"}) == []
    findings = _project(tmp_path / "calls", {
        "src/mcpjam-inspector.ts": "export const x = 1;\ninspectorServer.handle(req, res);\n",
    })
    assert [(f.file_path, f.line_number) for f in findings] == [("src/mcpjam-inspector.ts", 2)]
    assert "call shape" in findings[0].evidence
