from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_audit_kit.cli import cli
from agent_audit_kit.engine import _drop_launches_supply_chain_reports, run_scan
from agent_audit_kit.models import Severity
from agent_audit_kit.scanners import mcp_config, supply_chain
from agent_audit_kit.scanners._launchers import launch_evidence, launch_subject
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


@pytest.fixture
def python_table(monkeypatch: pytest.MonkeyPatch) -> str:
    """A stand-in PyPI entry for the reader's tests; returns its name.

    The PyPI table is empty. Its one entry, `openclaw`, named an unrelated PyPI
    project (an installer for the cmdop CLI), not OpenClaw, which ships on npm.
    """
    from agent_audit_kit.scanners import supply_chain

    monkeypatch.setitem(supply_chain.KNOWN_VULNERABLE_PACKAGES, "python", {
        "vulnerable-pkg": {"affected": "<2.1.0", "description": "test entry"},
    })
    return "vulnerable-pkg"


def test_python_requirements_vulnerable_dep(tmp_path: Path, python_table: str) -> None:
    """AAK-SUPPLY-002: A requirements.txt with a known vulnerable Python package."""
    (tmp_path / "requirements.txt").write_text(f"{python_table}==2.0.0\nrequests==2.31.0\n")
    findings, _ = scan(tmp_path)
    supply002 = [f for f in findings if f.rule_id == "AAK-SUPPLY-002"]
    assert len(supply002) > 0, "Vulnerable Python package in requirements.txt should be detected"
    assert any(python_table in f.evidence for f in supply002)


def test_the_pypi_openclaw_is_not_reported(tmp_path: Path) -> None:
    """PyPI's `openclaw` (2.0.1, 2.0.2) installs the cmdop CLI and is not OpenClaw,
    which ships on npm only; the table reported it as 104 OpenClaw CVEs."""
    (tmp_path / "requirements.txt").write_text("openclaw==2.0.2\n")
    (tmp_path / "Pipfile.lock").write_text(
        json.dumps({"default": {"openclaw": {"version": "==2.0.2"}}})
    )
    findings, _ = scan(tmp_path)
    assert not [f for f in findings if f.rule_id == "AAK-SUPPLY-002"]


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


def test_python_requirements_no_version(tmp_path: Path, python_table: str) -> None:
    """Python packages without version specifiers should not trigger AAK-SUPPLY-002."""
    (tmp_path / "requirements.txt").write_text(f"{python_table}\nrequests\n")
    findings, _ = scan(tmp_path)
    supply002 = [f for f in findings if f.rule_id == "AAK-SUPPLY-002"]
    assert len(supply002) == 0, "Packages without versions should not trigger vulnerable dep check"


def test_python_requirements_with_extras(tmp_path: Path, python_table: str) -> None:
    """Python packages with extras should be parsed correctly."""
    (tmp_path / "requirements.txt").write_text(f"{python_table}[full]==2.0.0\n")
    findings, _ = scan(tmp_path)
    supply002 = [f for f in findings if f.rule_id == "AAK-SUPPLY-002"]
    assert len(supply002) > 0, "Vulnerable package with extras should still be detected"


# ---------------------------------------------------------------------------
# Closes #18: targeted boundary coverage for _scan_python_deps + _scan_rust_deps.
# ---------------------------------------------------------------------------


def test_python_requirements_dev_files_picked_up(tmp_path: Path, python_table: str) -> None:
    """`requirements*.txt` glob should also catch requirements-dev.txt
    and requirements-test.txt, not just requirements.txt."""
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    (tmp_path / "requirements-dev.txt").write_text(f"{python_table}==2.0.0\n")
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


def test_python_version_range_lower_bound_trips(tmp_path: Path, python_table: str) -> None:
    """End-to-end version-range check: pin exactly at the lower bound
    of an affected range must produce AAK-SUPPLY-002."""
    # axios >=1.7.0 <1.7.4 is the seeded range in KNOWN_VULNERABLE_PACKAGES
    # but axios is npm-only, and the PyPI table is empty: use the stand-in.
    (tmp_path / "requirements.txt").write_text(f"{python_table}==1.5.0\n")  # below 2.1.0
    findings, _ = scan(tmp_path)
    supply002 = [f for f in findings if f.rule_id == "AAK-SUPPLY-002"]
    assert any(python_table in f.evidence and "1.5.0" in f.evidence for f in supply002)


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


def test_pipfile_lock_vulnerable_dep(tmp_path: Path, python_table: str) -> None:
    """AAK-SUPPLY-002: Vulnerable package in Pipfile.lock."""
    pipfile_lock = {
        "_meta": {"hash": {"sha256": "abc123"}},
        "default": {
            python_table: {"version": "==2.0.0"},
        },
        "develop": {},
    }
    (tmp_path / "Pipfile").write_text(f"[packages]\n{python_table} = '*'\n")
    (tmp_path / "Pipfile.lock").write_text(json.dumps(pipfile_lock))
    findings, _ = scan(tmp_path)
    supply002 = [f.evidence for f in findings if f.rule_id == "AAK-SUPPLY-002"]
    assert supply002 == [f"{python_table}==2.0.0 — test entry"], supply002


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


# ---------------------------------------------------------------------------
# Large lockfiles
#
# package-lock.json, Pipfile.lock and Cargo.lock over 1,000,000 characters were
# skipped without a finding, a silent all-clear on the projects with the most
# dependencies: a lockfileVersion 3 package-lock.json passes 1 MB at about 2,200
# packages, which is also where AAK-SUPPLY-005 has the most to say. Lockfiles are
# now read up to MAX_LOCKFILE_BYTES (32 MiB), checked with stat() before reading.
# ---------------------------------------------------------------------------


def _write_padded_package_lock(path: Path, minimum_bytes: int, packages: dict) -> None:
    """A lockfileVersion 3 package-lock.json over `minimum_bytes`, holding
    `packages` among filler entries shaped like real ones."""
    entry = {
        "version": "1.0.0",
        "resolved": "https://registry.npmjs.org/filler/-/filler-1.0.0.tgz",
        "integrity": "sha512-" + "A" * 86 + "==",
    }
    count = minimum_bytes // len(json.dumps(entry)) + 1
    filled: dict = {"": {"name": "app", "version": "1.0.0"}}
    filled.update({f"node_modules/filler-{i}": entry for i in range(count)})
    filled.update(packages)
    lockfile = {"name": "app", "lockfileVersion": 3, "packages": filled}
    path.write_text(json.dumps(lockfile), encoding="utf-8")
    assert path.stat().st_size > minimum_bytes


def test_a_package_lock_over_1mb_is_read(tmp_path: Path) -> None:
    _write_padded_package_lock(
        tmp_path / "package-lock.json", 1_100_000, {"node_modules/axios": {"version": "1.7.2"}}
    )
    findings, _ = scan(tmp_path)
    supply002 = [f.evidence for f in findings if f.rule_id == "AAK-SUPPLY-002"]
    assert any(e.startswith("axios@1.7.2") for e in supply002), supply002
    assert [f for f in findings if f.rule_id == "AAK-SUPPLY-005"], "the count was skipped too"


def test_a_cargo_lock_over_1mb_is_counted(tmp_path: Path) -> None:
    block = (
        '[[package]]\nname = "crate-{i}"\nversion = "1.0.0"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        'checksum = "' + "0" * 64 + '"\n\n'
    )
    count = 1_100_000 // len(block) + 1
    lock = tmp_path / "Cargo.lock"
    packages = "".join(block.replace("{i}", str(i)) for i in range(count))
    lock.write_text("version = 3\n\n" + packages, encoding="utf-8")
    assert lock.stat().st_size > 1_100_000
    findings, _ = scan(tmp_path)
    supply005 = [f.evidence for f in findings if f.rule_id == "AAK-SUPPLY-005"]
    assert supply005 == [f"{count} dependencies (threshold: 200)"]


def test_a_lockfile_over_the_limit_is_not_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The stated limitation, at a size a test can write: the size is checked
    before the file is read, and a lockfile over it yields nothing."""
    from agent_audit_kit.scanners import supply_chain

    _write_padded_package_lock(
        tmp_path / "package-lock.json", 60_000, {"node_modules/axios": {"version": "1.7.2"}}
    )
    rules = ("AAK-SUPPLY-002", "AAK-SUPPLY-005")
    assert {f.rule_id for f in scan(tmp_path)[0]} >= set(rules), "the file is reportable"
    monkeypatch.setattr(supply_chain, "MAX_LOCKFILE_BYTES", 50_000)
    assert not [f for f in scan(tmp_path)[0] if f.rule_id in rules]


def test_the_lockfile_index_reads_each_format() -> None:
    """One pass a lockfile, every package in it, by the name its registry compares."""
    from agent_audit_kit.scanners.supply_chain import _lockfile_index

    yarn_v1 = (
        "# yarn lockfile v1\n\n"
        '"@scope/pkg@^1.0.0", "@scope/pkg@^1.1.0":\n  version "1.2.0"\n'
        '  resolved "https://registry.yarnpkg.com/@scope/pkg/-/pkg-1.2.0.tgz"\n\n'
        "next@^15.0.0:\n  version \"15.0.0\"\n  dependencies:\n    react \"^18.0.0\"\n\n"
        'next@^16.1.0:\n  version "16.1.0"\n'
    )
    assert _lockfile_index(yarn_v1, "yarn.lock") == {
        "@scope/pkg": [(1, 2, 0)], "next": [(15, 0, 0), (16, 1, 0)],
    }
    yarn_berry = '__metadata:\n  version: 6\n\n"next@npm:^16.1.0":\n  version: 16.1.0\n'
    assert _lockfile_index(yarn_berry, "yarn.lock") == {}
    pnpm = (
        "packages:\n  /next@16.1.0:\n    resolution: {integrity: a}\n"
        "  '@next/eslint-plugin-next@16.2.0':\n    resolution: {integrity: b}\n"
        "snapshots:\n  next@16.1.0(react@18.0.0):\n    dependencies: {}\n"
    )
    assert _lockfile_index(pnpm, "pnpm-lock.yaml") == {
        "next": [(16, 1, 0)], "@next/eslint-plugin-next": [(16, 2, 0)], "react": [(18, 0, 0)],
    }
    package_lock_v1 = json.dumps({"lockfileVersion": 1, "dependencies": {
        "axios": {"version": "1.7.2", "dependencies": {"follow-redirects": {"version": "1.15.0"}}},
    }})
    assert _lockfile_index(package_lock_v1, "package-lock.json") == {
        "axios": [(1, 7, 2)], "follow-redirects": [(1, 15, 0)],
    }
    uv_lock = 'version = 1\n\n[[package]]\nname = "Awslabs.Healthlake_MCP-Server"\nversion = "0.0.5"\n'
    assert _lockfile_index(uv_lock, "uv.lock") == {"awslabs-healthlake-mcp-server": [(0, 0, 5)]}
    pipfile_lock = json.dumps({"default": {"litellm": {"version": "==1.83.0"}}, "develop": []})
    assert _lockfile_index(pipfile_lock, "pipfile.lock") == {"litellm": [(1, 83, 0)]}
    assert _lockfile_index("[not json", "package-lock.json") == {}
    assert _lockfile_index("[1, 2]", "pipfile.lock") == {}


def _blank_run_toml_lock() -> str:
    """A package block of 300,000 blank lines and no keys, then a readable one."""
    return "[[package]]\n" + "\n" * 300_000 + '[[package]]\nname = "a"\nversion = "1.0.0"\n'


_CRAFTED_LOCKFILES = {
    # `^\s*name` crossed newlines, so in a block without the key every line start
    # of a blank run rescanned the rest of the run: 300,000 blank lines took 71 s.
    "uv.lock": _blank_run_toml_lock,
    "poetry.lock": _blank_run_toml_lock,
    # If a name character could precede a name, every position of a run of them
    # would start a match and read up to 214 characters: about ten seconds here.
    "pnpm-lock.yaml": lambda: "~" * 9_000_000 + " next@16.1.0\n",
}


@pytest.mark.parametrize("filename", sorted(_CRAFTED_LOCKFILES))
def test_a_crafted_lockfile_indexes_in_linear_time(filename: str) -> None:
    """A lockfile is read up to 32 MiB now, so its parsing must stay linear. The
    bound is loose for slow CI runners; the linear version takes milliseconds."""
    import time

    from agent_audit_kit.scanners.supply_chain import _lockfile_index

    text = _CRAFTED_LOCKFILES[filename]()
    started = time.perf_counter()
    index = _lockfile_index(text, filename)
    assert time.perf_counter() - started < 10.0
    assert index, "the crafted file still holds one readable entry"


def test_a_pypi_launch_is_not_looked_up_in_the_npm_table(tmp_path: Path) -> None:
    """uvx reads `openclaw@2.0.0` as the PyPI project (the cmdop CLI installer);
    npx reads it as OpenClaw, which the npm table lists."""
    def supply006(command: str) -> list[str]:
        config = {"mcpServers": {"x": {"command": command, "args": ["openclaw@2.0.0"]}}}
        (tmp_path / ".mcp.json").write_text(json.dumps(config))
        return [f.evidence for f in scan(tmp_path)[0] if f.rule_id == "AAK-SUPPLY-006"]

    assert supply006("uvx") == []
    assert supply006("uv tool run") == []
    hits = supply006("npx")
    assert len(hits) == 1 and hits[0].startswith("Server 'x' uses openclaw@2.0.0"), hits


# ---------------------------------------------------------------------------
# AAK-MCP-007 stands down where AAK-SUPPLY-001 reports the same launch
# ---------------------------------------------------------------------------
#
# Both rules report an unpinned package launch: AAK-SUPPLY-001 (MEDIUM) reads the
# launcher's grammar, AAK-MCP-007 (LOW) every argument without an `@`. On a config
# both read, `engine.run_scan` keeps AAK-SUPPLY-001 and drops AAK-MCP-007, after
# the rule and path filters, so selecting or excluding a rule still works.

_LAUNCH_RULES = ("AAK-MCP-007", "AAK-SUPPLY-001")
_NPX = {"command": "npx", "args": ["-y", "@scope/pkg"]}
_NPX_EVIDENCE = "Server 'fs' arg: @scope/pkg (no version pin)"


def _write(root: Path, rel: str, config: object) -> None:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(config, indent=2))


def _launches(root: Path, **kwargs: object) -> list[tuple[str, str, str]]:
    result = run_scan(root, **kwargs)  # type: ignore[arg-type]
    return sorted(
        (f.rule_id, f.severity.value, f.evidence)
        for f in result.findings
        if f.rule_id in _LAUNCH_RULES
    )


def _launch_files(root: Path, **kwargs: object) -> list[tuple[str, str]]:
    result = run_scan(root, **kwargs)  # type: ignore[arg-type]
    return sorted((f.rule_id, f.file_path) for f in result.findings if f.rule_id in _LAUNCH_RULES)


def test_a_launch_both_rules_report_is_reported_once(tmp_path: Path) -> None:
    _write(tmp_path, ".mcp.json", {"mcpServers": {"fs": _NPX}})
    by_scanner = mcp_config.scan(tmp_path)[0] + supply_chain.scan(tmp_path)[0]
    assert sorted(
        (f.rule_id, f.line_number, f.evidence) for f in by_scanner if f.rule_id in _LAUNCH_RULES
    ) == [("AAK-MCP-007", 7, _NPX_EVIDENCE), ("AAK-SUPPLY-001", 7, _NPX_EVIDENCE)]
    assert _launches(tmp_path) == [("AAK-SUPPLY-001", "medium", _NPX_EVIDENCE)]


def test_the_vscode_servers_shape_is_reported_once(tmp_path: Path) -> None:
    server = {"type": "stdio", **_NPX}
    _write(tmp_path, ".vscode/mcp.json", {"servers": {"fs": server}})
    assert _launches(tmp_path) == [("AAK-SUPPLY-001", "medium", _NPX_EVIDENCE)]
    # mcp_config reads only `mcpServers` on this branch. Its per-server check does
    # not care which map an entry came from, so build the AAK-MCP-007 finding it
    # reports for this entry and check the engine drops it beside AAK-SUPPLY-001.
    raw = (tmp_path / ".vscode" / "mcp.json").read_text()
    mcp007 = [
        f for f in mcp_config._check_server("fs", server, ".vscode/mcp.json", raw)
        if f.rule_id == "AAK-MCP-007"
    ]
    supply001 = [f for f in supply_chain.scan(tmp_path)[0] if f.rule_id == "AAK-SUPPLY-001"]
    assert [f.evidence for f in mcp007] == [_NPX_EVIDENCE]
    assert _drop_launches_supply_chain_reports(mcp007 + supply001) == supply001


@pytest.mark.parametrize(("server", "supply_reason"), [
    ({"command": "uvx", "args": ["some-mcp-server>=1.0"]}, "version range `>=1.0`"),
    ({"command": "npx", "args": ["-y", "github:org/repo"]},
     "a git or URL reference without a commit"),
])
def test_the_same_launch_is_matched_whatever_reason_each_rule_gives(
    tmp_path: Path, server: dict, supply_reason: str
) -> None:
    """AAK-MCP-007 says "no version pin" for a range or a git reference too, so
    the launch is matched on the server and the spec, not on the whole evidence."""
    _write(tmp_path, ".mcp.json", {"mcpServers": {"s": server}})
    found = _launches(tmp_path)
    assert [(rule, sev) for rule, sev, _ in found] == [("AAK-SUPPLY-001", "medium")]
    assert found[0][2].endswith(f"({supply_reason})")
    assert [rule for rule, _, _ in _launches(tmp_path, rules=["AAK-MCP-007"])] == ["AAK-MCP-007"]


def test_selecting_aak_mcp_007_alone_still_reports_it(tmp_path: Path) -> None:
    _write(tmp_path, ".mcp.json", {"mcpServers": {"fs": _NPX}})
    assert _launches(tmp_path, rules=["AAK-MCP-007"]) == [("AAK-MCP-007", "low", _NPX_EVIDENCE)]


def test_excluding_aak_supply_001_brings_aak_mcp_007_back(tmp_path: Path) -> None:
    _write(tmp_path, ".mcp.json", {"mcpServers": {"fs": _NPX}})
    assert _launches(tmp_path, exclude_rules=["AAK-SUPPLY-001"]) == [
        ("AAK-MCP-007", "low", _NPX_EVIDENCE)
    ]


@pytest.mark.parametrize("how", ["--rules", "--exclude-rules", "config file"])
def test_the_cli_keeps_aak_mcp_007_when_aak_supply_001_is_not_reported(
    tmp_path: Path, how: str
) -> None:
    _write(tmp_path, ".mcp.json", {"mcpServers": {"fs": _NPX}})
    args = ["scan", str(tmp_path), "--format", "json"]
    if how == "--rules":
        args += ["--rules", "AAK-MCP-007"]
    elif how == "--exclude-rules":
        args += ["--exclude-rules", "AAK-SUPPLY-001"]
    else:
        (tmp_path / ".agent-audit-kit.yml").write_text("exclude-rules:\n  - AAK-SUPPLY-001\n")
    result = CliRunner().invoke(cli, args)
    rule_ids = {f["ruleId"] for f in json.loads(result.output)["findings"]}
    assert "AAK-MCP-007" in rule_ids and "AAK-SUPPLY-001" not in rule_ids, rule_ids


def test_an_ignored_path_takes_only_its_own_findings(tmp_path: Path) -> None:
    """AAK-SUPPLY-001 reads the root config; AAK-MCP-007 reads both. A launch is
    matched within one file, so ignoring the root does not take the other's."""
    _write(tmp_path, ".mcp.json", {"mcpServers": {"fs": _NPX}})
    _write(tmp_path, "deploy/mcp.json", {"mcpServers": {"fs": _NPX}})
    assert _launch_files(tmp_path) == [
        ("AAK-MCP-007", "deploy/mcp.json"), ("AAK-SUPPLY-001", ".mcp.json"),
    ]
    assert _launch_files(tmp_path, ignore_paths=[".mcp.json"]) == [
        ("AAK-MCP-007", "deploy/mcp.json"),
    ]
    assert _launch_files(tmp_path, ignore_paths=["deploy"]) == [("AAK-SUPPLY-001", ".mcp.json")]


def test_a_config_only_aak_mcp_007_reads_keeps_it(tmp_path: Path) -> None:
    _write(tmp_path, ".windsurf/mcp.json", {"mcpServers": {"fs": _NPX}})
    assert _launches(tmp_path) == [("AAK-MCP-007", "low", _NPX_EVIDENCE)]


def test_the_same_spec_under_another_server_is_another_launch(tmp_path: Path) -> None:
    """Server `b` passes `some-mcp-server` as an argument to a pinned package, so
    AAK-SUPPLY-001 does not report it there. Both findings name the first line that
    holds the spec, which is why the line is not what a launch is matched on."""
    _write(tmp_path, ".mcp.json", {"mcpServers": {
        "a": {"command": "npx", "args": ["-y", "some-mcp-server"]},
        "b": {"command": "npx", "args": ["-y", "other-mcp-server@1.0.0", "some-mcp-server"]},
    }})
    result = run_scan(tmp_path)
    found = sorted(
        (f.rule_id, f.line_number, f.evidence)
        for f in result.findings
        if f.rule_id in _LAUNCH_RULES
    )
    assert found == [
        ("AAK-MCP-007", 7, "Server 'b' arg: some-mcp-server (no version pin)"),
        ("AAK-SUPPLY-001", 7, "Server 'a' arg: some-mcp-server (no version pin)"),
    ]


def test_aak_mcp_007_never_gives_way_to_a_lower_severity(tmp_path: Path) -> None:
    _write(tmp_path, ".mcp.json", {"mcpServers": {"fs": _NPX}})
    mcp007 = [f for f in mcp_config.scan(tmp_path)[0] if f.rule_id == "AAK-MCP-007"]
    supply001 = [f for f in supply_chain.scan(tmp_path)[0] if f.rule_id == "AAK-SUPPLY-001"]
    lowered = [dataclasses.replace(f, severity=Severity.INFO) for f in supply001]
    assert _drop_launches_supply_chain_reports(mcp007 + lowered) == mcp007 + lowered
    assert _drop_launches_supply_chain_reports(mcp007 + supply001) == supply001


def test_launch_subject_reads_back_what_launch_evidence_wrote() -> None:
    evidence = launch_evidence("it's", "pkg (beta)", "version range `^1`")
    assert launch_subject(evidence) == "Server 'it's' arg: pkg (beta)"
    assert launch_subject("Server 'a' arg: pkg") is None


@pytest.mark.parametrize(("rel", "config"), [
    (".mcp.json", {"mcpServers": {"fs": _NPX}}),
    (".vscode/mcp.json", {"servers": {"fs": {"type": "stdio", **_NPX}}}),
])
def test_fail_on_high_passes_an_unpinned_npx_launch(
    tmp_path: Path, rel: str, config: dict
) -> None:
    """`npx -y pkg` is how VS Code's docs start a server. AAK-SUPPLY-001 is MEDIUM,
    so the launch fails `--fail-on medium` and no longer fails `--fail-on high`."""
    _write(tmp_path, rel, config)
    passed = CliRunner().invoke(cli, ["scan", str(tmp_path), "--fail-on", "high"])
    assert passed.exit_code == 0, passed.output
    failed = CliRunner().invoke(cli, ["scan", str(tmp_path), "--fail-on", "medium"])
    assert failed.exit_code == 1, failed.output


@pytest.mark.parametrize(("name", "content"), [
    # No operator after the name: two `\s*` split the blank run every way.
    ("requirements.txt", "litellm" + " " * 990_000 + "x\n"),
    ("requirements.txt", "semantic-kernel" + " " * 990_000 + "x\n"),
    # Every `git+https://` in one long token read to the token's end.
    ("package-lock.json", '{"x": "' + "git+https://" * 82_000 + '"}'),
    ("package.json", '{"dependencies": {"docsgpt": "' + "git+https://" * 82_000 + '"}}'),
])
def test_a_crafted_manifest_scans_in_linear_time(tmp_path: Path, name: str, content: str) -> None:
    """About 1 MB. Before, 40,000 blanks after `litellm` took 5 seconds and
    80 KB of `git+https://` 2.7, and both grew with the square. The bound is loose for slow CI runners."""
    import time

    (tmp_path / name).write_text(content, encoding="utf-8")
    started = time.perf_counter()
    scan(tmp_path)
    assert time.perf_counter() - started < 5.0


@pytest.mark.parametrize(("requirement", "fires"), [
    ("litellm==1.83.6", True),
    ("litellm >= 1.83.6", True),
    ("litellm\t1.83.6", True),
    ("litellm==1.83.7", False),
])
def test_litellm_pin_keeps_its_version(tmp_path: Path, requirement: str, fires: bool) -> None:
    (tmp_path / "requirements.txt").write_text(requirement + "\n", encoding="utf-8")
    rule_ids = {f.rule_id for f in scan(tmp_path)[0]}
    assert any("LITELLM" in r for r in rule_ids) is fires


# ---------------------------------------------------------------------------
# AAK-SUPPLY-006 reads .vscode/mcp.json and VS Code's `servers` map
# ---------------------------------------------------------------------------

_SUPPLY_006_VSCODE = Path(__file__).parent / "fixtures" / "vscode_servers" / "supply-006"


def _supply_006(root: Path) -> list[tuple[str, str]]:
    return [(f.file_path, f.evidence) for f in scan(root)[0] if f.rule_id == "AAK-SUPPLY-006"]


def test_supply_006_reads_a_vscode_servers_map() -> None:
    [(path, evidence)] = _supply_006(_SUPPLY_006_VSCODE / "detecting")
    assert path == str(Path(".vscode") / "mcp.json")
    assert evidence.startswith("Server 'claw' uses openclaw@2.0.0")


def test_supply_006_passes_a_fixed_release_in_a_vscode_servers_map() -> None:
    assert _supply_006(_SUPPLY_006_VSCODE / "clean") == []


def test_supply_006_reads_both_maps_of_the_root_config(tmp_path: Path) -> None:
    config = {
        "mcpServers": {"a": {"command": "npx", "args": ["openclaw@2.0.0"]}},
        "servers": {"b": {"command": "npx", "args": ["axios@1.7.2"]}},
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(config), encoding="utf-8")
    hits = [evidence.split(" — ")[0] for _, evidence in _supply_006(tmp_path)]
    assert hits == ["Server 'a' uses openclaw@2.0.0", "Server 'b' uses axios@1.7.2"]
