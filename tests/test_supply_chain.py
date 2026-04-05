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
