from __future__ import annotations

import json
from pathlib import Path

import pytest

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
# Closes #18: targeted boundary coverage for _scan_python_deps + _scan_rust_deps.
# ---------------------------------------------------------------------------


def test_python_requirements_dev_files_picked_up(tmp_path: Path) -> None:
    """`requirements*.txt` glob should also catch requirements-dev.txt
    and requirements-test.txt, not just requirements.txt."""
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    (tmp_path / "requirements-dev.txt").write_text("openclaw==2.0.0\n")
    (tmp_path / "requirements-test.txt").write_text("flask==3.0.0\n")
    findings, scanned = scan(tmp_path)
    supply002 = [f for f in findings if f.rule_id == "AAK-SUPPLY-002"]
    assert any(f.file_path == "requirements-dev.txt" for f in supply002), (
        "Vulnerable pin in requirements-dev.txt must be detected via glob"
    )
    assert "requirements-dev.txt" in scanned
    assert "requirements-test.txt" in scanned


def test_version_in_range_boundary_below() -> None:
    """A version exactly at the lower bound of the affected range
    must be flagged; one tick below must not."""
    affected = ">=1.7.0 <1.7.4"
    assert _version_in_range("1.7.0", affected), "1.7.0 is the lower bound — must trip"
    assert _version_in_range("1.7.3", affected), "1.7.3 is inside the range — must trip"
    assert not _version_in_range("1.6.99", affected), "1.6.99 is below — must pass"


def test_version_in_range_boundary_above() -> None:
    """A version at or above the upper bound must NOT be flagged."""
    affected = ">=1.7.0 <1.7.4"
    assert not _version_in_range("1.7.4", affected), "1.7.4 is the patched version — must pass"
    assert not _version_in_range("1.8.0", affected), "1.8.0 is well above — must pass"
    assert not _version_in_range("2.0.0", affected), "2.0.0 is well above — must pass"


def test_python_version_range_lower_bound_trips(tmp_path: Path) -> None:
    """End-to-end version-range check: pin exactly at the lower bound
    of an affected range must produce AAK-SUPPLY-002."""
    # axios >=1.7.0 <1.7.4 is the seeded range in KNOWN_VULNERABLE_PACKAGES
    # but axios is npm-only. Use openclaw which is in python's table.
    (tmp_path / "requirements.txt").write_text("openclaw==1.5.0\n")  # below patched 2.1.0
    findings, _ = scan(tmp_path)
    supply002 = [f for f in findings if f.rule_id == "AAK-SUPPLY-002"]
    assert any("openclaw" in f.evidence and "1.5.0" in f.evidence for f in supply002)


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


# ---------------------------------------------------------------------------
# AAK-SUPPLY-001 reads the package spec, not every argument
# ---------------------------------------------------------------------------
#
# The rule used to report every argument that did not start with `-` and count any
# text after `@` as a version. A port, a server URL, an exact `==` pin and a commit
# were reported; `@latest` and `@^1` passed as pinned.

GIT_HTTPS = "gi" + "t+https://github.com/org/repo"


def _supply001(tmp_path: Path, server: dict) -> list[str]:
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"srv": server}}))
    findings, _ = scan(tmp_path)
    return [f.evidence for f in findings if f.rule_id == "AAK-SUPPLY-001"]


@pytest.mark.parametrize("server", [
    {"command": "npx", "args": ["-y", "some-mcp-server@1.0.0", "--port", "3000"]},
    {"command": "npx", "args": ["-y", "mcp-remote@0.1.30", "https://example.test/mcp"]},
    {"command": "uvx", "args": ["some-mcp-server==1.2.3"]},
    {"command": "uvx", "args": ["some-mcp-server@1.2.3"]},
    {"command": "npx", "args": ["-y", "github:org/repo#abc1234def"]},
    {"command": "uvx", "args": [GIT_HTTPS + "@0123456789abcdef"]},
    {"command": "uvx", "args": ["--from", "some-mcp-server==1.0.0", "some-mcp-server"]},
    {"command": "uvx", "args": ["--python", "3.12", "some-mcp-server==1.0.0"]},
    {"command": "npx", "args": ["-p", "@scope/pkg@1.2.3", "pkg-bin", "--flag"]},
    {"command": "npx", "args": ["-y", "./local-server"]},
])
def test_a_pinned_spec_and_the_servers_own_arguments_are_not_reported(
    tmp_path: Path, server: dict
) -> None:
    assert _supply001(tmp_path, server) == []


@pytest.mark.parametrize(("server", "reason"), [
    ({"command": "npx", "args": ["-y", "some-mcp-server@latest"]}, "floating tag `latest`"),
    ({"command": "npx", "args": ["-y", "some-mcp-server@^1.0.0"]}, "version range `^1.0.0`"),
    ({"command": "npx", "args": ["some-mcp-server@~1.2"]}, "version range `~1.2`"),
    ({"command": "npx", "args": ["some-mcp-server@1"]}, "version range `1`"),
    ({"command": "uvx", "args": ["some-mcp-server@latest"]}, "floating tag `latest`"),
    ({"command": "uvx", "args": ["some-mcp-server>=1.0"]}, "version range `>=1.0`"),
    ({"command": "uvx", "args": ["some-mcp-server==1.2.*"]}, "version range `==1.2.*`"),
    ({"command": "npx", "args": ["-y", "github:org/repo#v1.2.3"]},
     "a git or URL reference without a commit"),
    ({"command": "npx -y some-mcp-server"}, "no version pin"),
    ({"command": "bunx", "args": ["@scope/pkg"]}, "no version pin"),
])
def test_an_unpinned_spec_is_reported_once_with_its_reason(
    tmp_path: Path, server: dict, reason: str
) -> None:
    evidence = _supply001(tmp_path, server)
    assert len(evidence) == 1, evidence
    assert f"({reason})" in evidence[0]


def test_every_package_an_invocation_fetches_is_judged(tmp_path: Path) -> None:
    """`--with` and a repeated `-p` add packages; the command after them is not one."""
    uvx = {"command": "uvx", "args": ["--with", "requests", "some-mcp-server==1.0.0"]}
    assert _supply001(tmp_path, uvx) == ["Server 'srv' arg: requests (no version pin)"]
    npx = {"command": "npx", "args": ["-p", "a", "-p", "b@2.0.0", "the-command"]}
    assert _supply001(tmp_path, npx) == ["Server 'srv' arg: a (no version pin)"]


def test_the_value_of_a_credential_option_is_never_read_as_the_package(tmp_path: Path) -> None:
    """npm reads `--api-key VALUE` as an option and its value. Read as a flag, the
    key became the package, and the finding quoted it."""
    server = {"command": "npx", "args": ["--api-key", "k-5e3c9a1f", "some-mcp-server"]}
    assert _supply001(tmp_path, server) == ["Server 'srv' arg: some-mcp-server (no version pin)"]


# ---------------------------------------------------------------------------
# AAK-SUPPLY-001 reads VS Code's `servers` map too
# ---------------------------------------------------------------------------

_UNPINNED = {"command": "npx", "args": ["-y", "some-mcp-server"]}


def _supply001_in(tmp_path: Path, rel: str, config: object) -> list[str]:
    target = tmp_path / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(config))
    findings, _ = scan(tmp_path)
    return [f.evidence for f in findings if f.rule_id == "AAK-SUPPLY-001"]


def test_vscode_servers_map_is_read(tmp_path: Path) -> None:
    """VS Code keeps its servers under `servers`; the rule read `mcpServers` only."""
    evidence = _supply001_in(tmp_path, ".vscode/mcp.json", {"servers": {"c": _UNPINNED}})
    assert evidence == ["Server 'c' arg: some-mcp-server (no version pin)"]


def test_both_maps_are_read_each_on_its_own(tmp_path: Path) -> None:
    config = {"mcpServers": {"a": _UNPINNED}, "servers": {"a": _UNPINNED}}
    assert len(_supply001_in(tmp_path, ".mcp.json", config)) == 2


@pytest.mark.parametrize("config", [
    {"servers": [{"name": "listing", "command": "npx", "args": ["some-mcp-server"]}]},
    {"mcp": {"servers": {"c": _UNPINNED}}},
    {"servers": {"c": "npx -y some-mcp-server", "d": ["npx"], "e": None}},
    ["npx", "-y", "some-mcp-server"],
    "npx -y some-mcp-server",
])
def test_only_top_level_object_maps_of_object_entries_are_read(
    tmp_path: Path, config: object
) -> None:
    """A registry listing (`servers` array), a nested map, a non-object entry and a
    non-object config are not server maps, and none of them raises."""
    assert _supply001_in(tmp_path, ".vscode/mcp.json", config) == []


def test_a_blank_command_does_not_raise(tmp_path: Path) -> None:
    assert _supply001_in(tmp_path, ".mcp.json", {"mcpServers": {"a": {"command": "   "}}}) == []
