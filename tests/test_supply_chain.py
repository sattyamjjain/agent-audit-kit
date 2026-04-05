from __future__ import annotations

import json
from pathlib import Path

from agent_audit_kit.scanners.supply_chain import scan, _version_in_range


def test_supply_chain_mcp_unpinned(tmp_path: Path) -> None:
    """AAK-SUPPLY-001: MCP server packages without version pins."""
    config = {
        "mcpServers": {
            "unpinned": {
                "command": "npx",
                "args": ["@modelcontextprotocol/server-filesystem", "/data"]
            }
        }
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(config))
    findings, _ = scan(tmp_path)
    supply001 = [f for f in findings if f.rule_id == "AAK-SUPPLY-001"]
    assert len(supply001) > 0, "Unpinned MCP package should be detected"


def test_supply_chain_pinned_not_flagged(tmp_path: Path) -> None:
    """Pinned packages should NOT trigger AAK-SUPPLY-001."""
    config = {
        "mcpServers": {
            "pinned": {
                "command": "npx",
                "args": ["@modelcontextprotocol/server-filesystem@2025.1.1", "/data"]
            }
        }
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(config))
    findings, _ = scan(tmp_path)
    supply001 = [f for f in findings if f.rule_id == "AAK-SUPPLY-001"]
    assert len(supply001) == 0, "Pinned packages should not be flagged"


def test_known_vulnerable_package(tmp_path: Path) -> None:
    """AAK-SUPPLY-002: Known vulnerable packages in lockfile."""
    lockfile = {
        "name": "test-project",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "node_modules/axios": {
                "version": "1.7.2",
                "resolved": "https://registry.npmjs.org/axios/-/axios-1.7.2.tgz"
            }
        }
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lockfile))
    (tmp_path / "package.json").write_text('{"name":"test","version":"1.0.0"}')
    findings, _ = scan(tmp_path)
    supply002 = [f for f in findings if f.rule_id == "AAK-SUPPLY-002"]
    assert len(supply002) > 0, "Known vulnerable axios version should be detected"


def test_dangerous_install_scripts(project_with_package_risks: Path) -> None:
    """AAK-SUPPLY-003: Dangerous install scripts in package.json."""
    findings, _ = scan(project_with_package_risks)
    supply003 = [f for f in findings if f.rule_id == "AAK-SUPPLY-003"]
    assert len(supply003) > 0, "Dangerous install scripts should be detected"


def test_no_lockfile(tmp_path: Path) -> None:
    """AAK-SUPPLY-004: Missing lockfile."""
    (tmp_path / "package.json").write_text('{"name":"test","version":"1.0.0"}')
    findings, _ = scan(tmp_path)
    supply004 = [f for f in findings if f.rule_id == "AAK-SUPPLY-004"]
    assert len(supply004) > 0, "Missing lockfile should be detected"


def test_excessive_dependencies(tmp_path: Path) -> None:
    """AAK-SUPPLY-005: Excessive dependency count."""
    packages = {f"node_modules/pkg-{i}": {"version": "1.0.0"} for i in range(250)}
    lockfile = {
        "name": "test",
        "lockfileVersion": 3,
        "packages": packages
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lockfile))
    (tmp_path / "package.json").write_text('{"name":"test","version":"1.0.0"}')
    findings, _ = scan(tmp_path)
    supply005 = [f for f in findings if f.rule_id == "AAK-SUPPLY-005"]
    assert len(supply005) > 0, "Excessive dependencies should be detected"


def test_version_in_range() -> None:
    """Test version comparison logic."""
    assert _version_in_range("1.7.2", ">=1.7.0 <1.7.4") is True
    assert _version_in_range("1.7.0", ">=1.7.0 <1.7.4") is True
    assert _version_in_range("1.7.4", ">=1.7.0 <1.7.4") is False
    assert _version_in_range("1.6.9", ">=1.7.0 <1.7.4") is False
    assert _version_in_range("2.0.0", "<2.1.0") is True
    assert _version_in_range("2.1.0", "<2.1.0") is False


def test_clean_project_no_supply_chain_findings(tmp_path: Path) -> None:
    """A project with proper lockfile and pinned deps should have no findings."""
    (tmp_path / "package.json").write_text('{"name":"test","version":"1.0.0"}')
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "name": "test",
        "lockfileVersion": 3,
        "packages": {
            "node_modules/safe-pkg": {"version": "1.0.0"}
        }
    }))
    findings, _ = scan(tmp_path)
    assert len(findings) == 0, f"Clean project should have no supply chain findings, got: {[f.rule_id for f in findings]}"


# ---------------------------------------------------------------------------
# Python dependency scanning (_scan_python_deps)
# ---------------------------------------------------------------------------


def test_python_requirements_vulnerable_dep(tmp_path: Path) -> None:
    """AAK-SUPPLY-002: A requirements.txt with a known vulnerable Python package."""
    (tmp_path / "requirements.txt").write_text("openclaw==2.0.0\nrequests==2.31.0\n")
    findings, _ = scan(tmp_path)
    supply002 = [f for f in findings if f.rule_id == "AAK-SUPPLY-002"]
    assert len(supply002) > 0, "Vulnerable Python package in requirements.txt should be detected"
    assert any("openclaw" in f.evidence for f in supply002)


def test_python_pyproject_missing_lockfile(tmp_path: Path) -> None:
    """AAK-SUPPLY-004: pyproject.toml without a lockfile triggers missing lockfile finding."""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "test"\nversion = "1.0.0"\n'
        'dependencies = ["openclaw==2.0.0"]\n'
    )
    findings, _ = scan(tmp_path)
    supply004 = [f for f in findings if f.rule_id == "AAK-SUPPLY-004"]
    assert len(supply004) > 0, "Missing lockfile for pyproject.toml should be detected"


def test_python_requirements_safe_dep(tmp_path: Path) -> None:
    """Safe Python packages should NOT trigger AAK-SUPPLY-002."""
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nflask==3.0.0\n")
    findings, _ = scan(tmp_path)
    supply002 = [f for f in findings if f.rule_id == "AAK-SUPPLY-002"]
    assert len(supply002) == 0, "Safe Python packages should not trigger AAK-SUPPLY-002"


def test_python_requirements_no_version(tmp_path: Path) -> None:
    """Python packages without version specifiers should not trigger AAK-SUPPLY-002."""
    (tmp_path / "requirements.txt").write_text("openclaw\nrequests\n")
    findings, _ = scan(tmp_path)
    supply002 = [f for f in findings if f.rule_id == "AAK-SUPPLY-002"]
    assert len(supply002) == 0, "Packages without versions should not trigger vulnerable dep check"


def test_python_requirements_with_extras(tmp_path: Path) -> None:
    """Python packages with extras should be parsed correctly."""
    (tmp_path / "requirements.txt").write_text("openclaw[full]==2.0.0\n")
    findings, _ = scan(tmp_path)
    supply002 = [f for f in findings if f.rule_id == "AAK-SUPPLY-002"]
    assert len(supply002) > 0, "Vulnerable package with extras should still be detected"


# ---------------------------------------------------------------------------
# Rust dependency scanning (_scan_rust_deps)
# ---------------------------------------------------------------------------


def test_rust_cargo_missing_lockfile(tmp_path: Path) -> None:
    """AAK-SUPPLY-004: Cargo.toml without Cargo.lock triggers missing lockfile."""
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "test"\nversion = "0.1.0"\n'
    )
    findings, _ = scan(tmp_path)
    supply004 = [f for f in findings if f.rule_id == "AAK-SUPPLY-004"]
    assert len(supply004) > 0, "Missing Cargo.lock should be detected"


def test_rust_cargo_lock_clean(tmp_path: Path) -> None:
    """Cargo.lock with only safe crates should produce no AAK-SUPPLY-002 findings."""
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "test"\nversion = "0.1.0"\n'
    )
    (tmp_path / "Cargo.lock").write_text(
        '[[package]]\nname = "safe-crate"\nversion = "1.0.0"\n'
    )
    findings, _ = scan(tmp_path)
    supply002 = [f for f in findings if f.rule_id == "AAK-SUPPLY-002"]
    assert len(supply002) == 0, "Clean Cargo.lock should not trigger AAK-SUPPLY-002"


def test_rust_cargo_lock_excessive_deps(tmp_path: Path) -> None:
    """AAK-SUPPLY-005: Cargo.lock with >200 packages triggers excessive deps."""
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "test"\nversion = "0.1.0"\n'
    )
    lines = []
    for i in range(210):
        lines.append(f'[[package]]\nname = "crate-{i}"\nversion = "1.0.0"\n')
    (tmp_path / "Cargo.lock").write_text("\n".join(lines))
    findings, _ = scan(tmp_path)
    supply005 = [f for f in findings if f.rule_id == "AAK-SUPPLY-005"]
    assert len(supply005) > 0, "Excessive Rust dependencies should be detected"


# ---------------------------------------------------------------------------
# npm lockfile scanning
# ---------------------------------------------------------------------------


def test_npm_lockfile_excessive_deps(tmp_path: Path) -> None:
    """AAK-SUPPLY-005: package-lock.json with >200 deps triggers excessive deps."""
    packages = {f"node_modules/pkg-{i}": {"version": "1.0.0"} for i in range(250)}
    lockfile = {
        "name": "test",
        "lockfileVersion": 3,
        "packages": packages,
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lockfile))
    (tmp_path / "package.json").write_text('{"name":"test","version":"1.0.0"}')
    findings, _ = scan(tmp_path)
    supply005 = [f for f in findings if f.rule_id == "AAK-SUPPLY-005"]
    assert len(supply005) > 0, "Excessive npm dependencies should be detected"
    assert any("250" in f.evidence for f in supply005)


def test_npm_lockfile_v1_format(tmp_path: Path) -> None:
    """npm lockfile v1 uses 'dependencies' key instead of 'packages'."""
    lockfile = {
        "name": "test",
        "lockfileVersion": 1,
        "dependencies": {
            "axios": {"version": "1.7.2"},
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lockfile))
    (tmp_path / "package.json").write_text('{"name":"test","version":"1.0.0"}')
    findings, _ = scan(tmp_path)
    supply002 = [f for f in findings if f.rule_id == "AAK-SUPPLY-002"]
    assert len(supply002) > 0, "Vulnerable axios in v1 lockfile should be detected"


def test_npm_lockfile_typosquat_detection(tmp_path: Path) -> None:
    """Typosquat patterns in package names should trigger AAK-SUPPLY-002."""
    lockfile = {
        "name": "test",
        "lockfileVersion": 3,
        "packages": {
            "node_modules/@modlecontextprotocol/something": {"version": "1.0.0"},
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lockfile))
    (tmp_path / "package.json").write_text('{"name":"test","version":"1.0.0"}')
    findings, _ = scan(tmp_path)
    supply002 = [f for f in findings if f.rule_id == "AAK-SUPPLY-002"]
    assert len(supply002) > 0, "Typosquat package should be detected"
    assert any("typosquat" in f.evidence.lower() for f in supply002)


# ---------------------------------------------------------------------------
# Pipfile.lock scanning
# ---------------------------------------------------------------------------


def test_pipfile_missing_lockfile(tmp_path: Path) -> None:
    """AAK-SUPPLY-004: Pipfile without Pipfile.lock triggers missing lockfile."""
    (tmp_path / "Pipfile").write_text("[packages]\nrequests = '*'\n")
    findings, _ = scan(tmp_path)
    supply004 = [f for f in findings if f.rule_id == "AAK-SUPPLY-004"]
    assert len(supply004) > 0, "Missing Pipfile.lock should be detected"


def test_pipfile_lock_vulnerable_dep(tmp_path: Path) -> None:
    """AAK-SUPPLY-002: Vulnerable package in Pipfile.lock."""
    pipfile_lock = {
        "_meta": {"hash": {"sha256": "abc123"}},
        "default": {
            "openclaw": {"version": "==2.0.0"},
        },
        "develop": {},
    }
    (tmp_path / "Pipfile").write_text("[packages]\nopenclaw = '*'\n")
    (tmp_path / "Pipfile.lock").write_text(json.dumps(pipfile_lock))
    findings, _ = scan(tmp_path)
    supply002 = [f for f in findings if f.rule_id == "AAK-SUPPLY-002"]
    assert len(supply002) > 0, "Vulnerable package in Pipfile.lock should be detected"


# ---------------------------------------------------------------------------
# Scanned files tracking
# ---------------------------------------------------------------------------


def test_scanned_files_includes_relevant_files(tmp_path: Path) -> None:
    """The scan function should track which files were scanned."""
    (tmp_path / "package.json").write_text('{"name":"test","version":"1.0.0"}')
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    _, scanned = scan(tmp_path)
    assert "package.json" in scanned
    assert "requirements.txt" in scanned
