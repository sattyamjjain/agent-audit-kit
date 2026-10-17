from __future__ import annotations

import dataclasses
import json
import re
from pathlib import Path
from typing import Any

import yaml

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import (
    find_line_number,
    find_line_numbers,
    in_skip_dir,
    CONFIG_MAX_BYTES,
    iter_mcp_servers,
    load_yaml,
    loads_json,
    loads_jsonc,
    make_finding,
    read_text_capped,
)
from agent_audit_kit.scanners._launchers import (
    Launched,
    _shell_split,
    _shell_syntax,
    basename,
    invocation,
    invocation_packages,
    launch_evidence,
    launched_packages,
    npm_spec,
    pin_problem,
    shell_tokens,
    starts_with_launcher,
)
from agent_audit_kit.scanners._manifest_deps import (
    MAX_LOCKFILE_BYTES,
    MAX_MANIFEST_BYTES,
    Declaration,
    _argv,
    _command_entries,
    declarations,
)
from agent_audit_kit.scanners._versions import parse_range, parse_version

# Known vulnerable packages: ecosystem -> name -> affected version range
# Covers npm, Python (PyPI), and Rust (crates.io)
KNOWN_VULNERABLE_PACKAGES: dict[str, dict[str, dict[str, str]]] = {
    "npm": {
        "axios": {
            "affected": ">=1.7.0 <1.7.4",
            "description": "Claude Code supply chain compromise (March 31 2026)",
        },
        # No `openclaw` entry. It listed `<2.1.0` as "104 CVEs catalogued by
        # Adversa AI", but OpenClaw publishes calendar versions on npm (2026.1.29
        # on), so the range matched only `openclaw@0.0.1`, an empty placeholder
        # published the day before the first. OpenClaw's CVEs are pinned with
        # the ranges NVD gives them, in mcp_cve_pins_2026_07.
    },
    # No PyPI entry. The table listed `openclaw` here too, but OpenClaw ships on
    # npm only, and the PyPI project of that name (2.0.1 and 2.0.2) is an
    # unrelated installer for the cmdop CLI, so `openclaw==2.0.2` was reported as
    # 104 OpenClaw CVEs. The reader below stays for entries a PyPI package earns.
    "python": {},
    "rust": {},
}

# Typosquat patterns for popular MCP server packages: misspellings of the
# official scope, each one edit from `modelcontextprotocol`. Neither matches a
# package on npm (checked 2026-10-17). A third pattern, the name shape
# `mcp-server-<word>-<word>`, matched real servers (`mcp-server-code-runner`,
# `@baidumap/mcp-server-baidu-map`: 37 of the first 1,000 packages npm's search
# returns for "mcp-server"), so it reported published packages at HIGH as
# potential typosquats and was dropped.
TYPOSQUAT_PATTERNS = [
    re.compile(r"modelcontextprotocal", re.IGNORECASE),  # typo of "protocol"
    re.compile(r"@modlecontextprotocol", re.IGNORECASE),  # typo of "model"
]

# Install script keys in package.json
INSTALL_SCRIPTS = {"preinstall", "postinstall", "prepare", "install"}

# Network commands in install scripts. `https` joined `http`: as a whole word
# `http` matched neither `require('https')` nor an `https://` URL.
NETWORK_IN_SCRIPTS = re.compile(
    r"\b(curl|wget|fetch|nc|ncat|ssh|https?|axios|request)\b", re.IGNORECASE
)

# The build tools a command of an install script may run to pass AAK-SUPPLY-003,
# by program name (`node_modules/.bin/tsc` is `tsc`). They were matched as a text
# prefix of the command, so `tscripts/setup.sh`, `vite-installer` and, through
# `node`, `NODE_ENV=production sh ./evil.sh` passed. `npx` was a prefix too, so
# any package given to it passed: a launcher is judged by the package it runs
# instead (`_launch_is_local`). `node-gyp` and `node-gyp-build` passed as
# prefixes of `node` and stay: npm itself runs `node-gyp rebuild` for a package
# with a binding.gyp and no install script, and node-gyp-build builds the
# package's own sources or loads the prebuilds it ships, fetching nothing.
# `node-pre-gyp` and `prebuild-install`, which download a prebuilt binary from
# a host the package.json names, are not on the list. `ts-node`, `tsx` and
# `vite-node` run a TypeScript script as `node` runs a JavaScript one, and
# `node <script>` passes, so they pass too; `node_modules/.bin/ts-node` passed
# as a prefix of `node`, and `vite-node` as a prefix of `vite`.
_SAFE_SCRIPT_TOOLS = frozenset({
    "tsc", "node", "node-gyp", "node-gyp-build", "ts-node", "tsx", "vite-node",
    "webpack", "rollup", "esbuild", "vite",
})
# A shell variable assignment before a command (`NODE_ENV=production webpack`).
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
# The scripts `npm run` may name to pass: `build`, or `build:<name>`.
_BUILD_SCRIPT = re.compile(r"build(?::.+)?")
# How deep command substitutions nested in each other are judged; one nested
# deeper is reported unread.
_MAX_SUBSTITUTION_DEPTH = 4
# Words and operator runs, for a line the shell splitter gives up on.
_FALLBACK_WORD = re.compile(r"[();<>|&]+|[^ \t\r\n();<>|&]+")
# What ends a word for sh, so a `#` after one of these starts a comment.
_WORD_BREAKS = frozenset(" \t\r\n;&|()<>")
# Launchers that run a package from node_modules when it is installed and fetch
# it only when it is not. `pnpm dlx`, `pnpx` and `yarn dlx` always fetch.
_LOCAL_FIRST_LAUNCHERS = frozenset({"npx", "npm exec", "npm x", "bunx", "bun x"})
# Fallbacks that run nothing (`node install.js || true`), skipped after the
# first command unless they redirect into a file.
_NO_OP_COMMANDS = frozenset({"true", "false", ":", "exit", "echo"})
# The longest of 3,171 install scripts read from npm manifests and GitHub repos
# (2026-10-17) was 578 characters. A script over this is reported without being
# split into commands, which bounds what one crafted script costs the scan.
_MAX_JUDGED_SCRIPT = 4096
_SHELL_PUNCTUATION = frozenset("();<>|&")

# Package fetchers for MCP config
PACKAGE_FETCHERS = frozenset({"npx", "uvx", "bunx", "pnpx"})

# The client configs AAK-SUPPLY-001 and AAK-SUPPLY-006 read, at the project root.
# AAK-SUPPLY-006 kept a list of its own, .mcp.json and .vscode/mcp.json, so a
# vulnerable launch in Cursor's, Amazon Q's or the root mcp.json was never looked
# up, though AAK-SUPPLY-001 judged its pin in all five.
_MCP_CONFIGS = (".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".amazonq/mcp.json", "mcp.json")


_find_line_number = find_line_number
_make_finding = make_finding


def _version_in_range(version: str, affected: str) -> bool:
    """Simple version range check. Handles >=X.Y.Z <A.B.C and <X.Y.Z patterns."""
    try:
        parts = affected.split()
        ver_tuple = tuple(int(x) for x in version.split("."))

        i = 0
        while i < len(parts):
            token = parts[i]
            if token.startswith(">="):
                min_ver = tuple(int(x) for x in token[2:].split("."))
                if ver_tuple < min_ver:
                    return False
            elif token.startswith(">"):
                min_ver = tuple(int(x) for x in token[1:].split("."))
                if ver_tuple <= min_ver:
                    return False
            elif token.startswith("<="):
                max_ver = tuple(int(x) for x in token[2:].split("."))
                if ver_tuple > max_ver:
                    return False
            elif token.startswith("<"):
                max_ver = tuple(int(x) for x in token[1:].split("."))
                if ver_tuple >= max_ver:
                    return False
            i += 1
        return True
    except (ValueError, IndexError):
        return False


def _scan_mcp_configs_for_supply_chain(project_root: Path) -> list[Finding]:
    """Check MCP configs for unpinned packages (AAK-SUPPLY-001)."""
    findings: list[Finding] = []
    for mcp_path in (project_root / name for name in _MCP_CONFIGS):
        if not mcp_path.is_file():
            continue
        try:
            raw = read_text_capped(mcp_path, CONFIG_MAX_BYTES, errors="replace")
            data = loads_jsonc(raw, mcp_path)
        except (json.JSONDecodeError, UnicodeDecodeError, OSError):
            continue

        rel_path = str(mcp_path.relative_to(project_root))
        unplaced: list[tuple[Finding, str]] = []
        # Both server maps: VS Code keeps its servers under `servers` in
        # .vscode/mcp.json, and reading `mcpServers` alone never judged one.
        for server_name, server_cfg in iter_mcp_servers(data):
            command = server_cfg.get("command", "")
            args = server_cfg.get("args", [])

            # `command` is a string per the MCP schema, but a malformed config
            # can make it a list and `.strip()` then raises (issue #743). The
            # wrong type is reported by AAK-MCP-CONFIG-MALFORMED-001; there is
            # no package fetcher to identify here, so skip it.
            if not isinstance(command, str):
                continue
            # A blank command has no first word; indexing one raised.
            argv = command.split()
            if not argv or argv[0] not in PACKAGE_FETCHERS:
                continue

            # Only the package specs are judged: the first positional argument
            # (or the `--from` / `-p` value that names the package, plus any
            # `--with` / extra `-p`), read with the launcher's option values
            # skipped. Every other argument belongs to the server. The inline
            # form (`"command": "npx -y pkg"`) carries its spec in `command`.
            if isinstance(args, list):
                argv += [str(a) for a in args
                         if isinstance(a, (str, int, float)) and not isinstance(a, bool)]
            for launched in invocation_packages(argv):
                problem = pin_problem(launched)
                if problem is not None:
                    unplaced.append((_make_finding(
                        "AAK-SUPPLY-001", rel_path,
                        launch_evidence(server_name, launched.spec, problem),
                    ), launched.spec))
        # Every launch's line in one pass over the file, not one search of it per launch.
        lines = find_line_numbers(raw, (spec for _, spec in unplaced))
        for finding, spec in unplaced:
            finding.line_number = lines[spec]
            findings.append(finding)
    return findings


def _scan_npm_lockfile(project_root: Path) -> list[Finding]:
    """Check package-lock.json for known vulnerable packages (AAK-SUPPLY-002)."""
    findings: list[Finding] = []
    lockfile = project_root / "package-lock.json"
    if not lockfile.is_file():
        return findings

    try:
        if lockfile.stat().st_size > MAX_LOCKFILE_BYTES:
            return findings
        raw = read_text_capped(lockfile, MAX_LOCKFILE_BYTES, errors="replace")
        data = loads_json(raw, lockfile)
    except (json.JSONDecodeError, OSError):
        return findings
    # npm writes an object, its package table as an object and each version as
    # a string. A value of another type raised here and took the whole scanner
    # down; npm cannot install from such a file, so it is read as far as it
    # has the right shape.
    if not isinstance(data, dict):
        return findings

    rel_path = str(lockfile.relative_to(project_root))

    # Check packages in lockfile v2/v3 format
    packages = data.get("packages")
    if isinstance(packages, dict) and packages:
        dep_count = sum(1 for key, info in packages.items() if _is_npm_dependency(key, info))
    else:
        # Try lockfile v1 format, which has no entry for the root package
        packages = data.get("dependencies")
        if not isinstance(packages, dict):
            packages = {}
        dep_count = len(packages)
    # Every typosquat's line in one pass over the file, not one search of it per
    # package: a lockfile may name thousands of packages under a misspelt scope.
    names = (p.split("node_modules/")[-1] if "node_modules/" in p else p for p in packages if isinstance(p, str))
    find_line_numbers(raw, (name for name in names if any(p.search(name) for p in TYPOSQUAT_PATTERNS)))

    for pkg_path, pkg_info in packages.items():
        if not isinstance(pkg_info, dict):
            continue
        # Extract package name from path (e.g., "node_modules/axios" -> "axios")
        pkg_name = pkg_path.split("node_modules/")[-1] if "node_modules/" in pkg_path else pkg_path
        if not pkg_name:
            continue

        version = pkg_info.get("version", "")
        npm_vulns = KNOWN_VULNERABLE_PACKAGES.get("npm", {})
        if pkg_name in npm_vulns and isinstance(version, str) and version:
            vuln_info = npm_vulns[pkg_name]
            if _version_in_range(version, vuln_info["affected"]):
                findings.append(_make_finding(
                    "AAK-SUPPLY-002", rel_path,
                    f"{pkg_name}@{version} — {vuln_info['description']}",
                    _find_line_number(raw, f'"{pkg_name}"'),
                ))

        # Check for typosquats
        for pattern in TYPOSQUAT_PATTERNS:
            if pattern.search(pkg_name):
                findings.append(_make_finding(
                    "AAK-SUPPLY-002", rel_path,
                    f"Potential typosquat: {pkg_name}",
                    _find_line_number(raw, pkg_name),
                ))

    # AAK-SUPPLY-005: Excessive dependencies
    if dep_count > 200:
        findings.append(_make_finding(
            "AAK-SUPPLY-005", rel_path,
            f"{dep_count} dependencies (threshold: 200)",
        ))

    return findings


def _is_npm_dependency(key: str, info: object) -> bool:
    """Is a lockfile v2/v3 `packages` entry a dependency (AAK-SUPPLY-005)?

    The entries are keyed by install path. The root package is the `""` entry,
    and a workspace member is a folder entry (`packages/web`) with a `link` to it
    under node_modules; each is the project's own package, not a dependency.
    Counting them reported 200 dependencies as 201, so a lockfile with exactly
    200 crossed the threshold. A package installed under a member
    (`packages/web/node_modules/x`) is a dependency like any other.
    """
    return "node_modules/" in key and not (isinstance(info, dict) and info.get("link") is True)


def _scan_package_json(project_root: Path) -> list[Finding]:
    """Check package.json for install scripts (AAK-SUPPLY-003)."""
    findings: list[Finding] = []
    pkg_json = project_root / "package.json"
    if not pkg_json.is_file():
        return findings

    try:
        raw = read_text_capped(pkg_json, MAX_MANIFEST_BYTES, errors="replace")
        data = loads_json(raw, pkg_json)
    except (json.JSONDecodeError, OSError):
        return findings
    if not isinstance(data, dict):
        return findings

    rel_path = str(pkg_json.relative_to(project_root))
    scripts = data.get("scripts", {})
    if isinstance(scripts, dict):
        declared = _declared_packages(data)
        for script_name, script_cmd in scripts.items():
            if script_name in INSTALL_SCRIPTS and isinstance(script_cmd, str):
                if _install_script_reported(script_cmd, declared):
                    findings.append(_make_finding(
                        "AAK-SUPPLY-003", rel_path,
                        f"scripts.{script_name}: {script_cmd}",
                        _find_line_number(raw, script_name),
                    ))

    return findings


def _install_script_reported(script: str, declared: set[str], depth: int = 0) -> bool:
    """Does an install script run something AAK-SUPPLY-003 reports?

    A script that names a network word is reported, as is one too long to
    split. Otherwise every command it runs is judged (`_command_passes`), not
    only the first: `tsc && sh ./evil.sh` passed because it started with `tsc`.
    A command after the first that runs nothing (`|| true`, `&& echo done`) is
    not judged, unless it redirects into a file, but every command substitution,
    `$(...)` or backticks, is judged wherever it sits, as a script of its own:
    `tsc && echo "$(sh ./evil.sh)"` hid one inside the quoted argument of a
    command that runs nothing. Inside a substitution a command that runs
    nothing is not judged in any position (`node $(echo build.js)`); one nested
    deeper than `_MAX_SUBSTITUTION_DEPTH` is reported unread.
    """
    if NETWORK_IN_SCRIPTS.search(script) or len(script) > _MAX_JUDGED_SCRIPT:
        return True
    text, substitutions = _shell_parts(script)
    for inner in substitutions:
        if depth >= _MAX_SUBSTITUTION_DEPTH or _install_script_reported(inner, declared, depth + 1):
            return True
    for index, (words, redirected) in enumerate(_script_commands(text)):
        program = _without_assignments(words)
        if (index or depth) and not redirected and program and program[0] in _NO_OP_COMMANDS:
            continue
        if not _command_passes(program, declared):
            return True
    return False


def _without_assignments(words: list[str]) -> list[str]:
    """The command after any leading `NAME=value` words."""
    i = 0
    while i < len(words) and _ASSIGNMENT.match(words[i]):
        i += 1
    return words[i:]


def _command_passes(words: list[str], declared: set[str]) -> bool:
    """Does one command of an install script run only what AAK-SUPPLY-003 allows?

    The command is read after its variable assignments, which run nothing, so a
    command that is only assignments does not pass. It passes when its program
    is a build tool on the safe list, by name (`node_modules/.bin/tsc` is
    `tsc`), when it is `npm run build` or `npm run build:<name>`, or when it is
    a launcher running packages the project installs (`_launch_is_local`). The
    safe list was matched as a prefix of the command text, so
    `tscripts/setup.sh`, `vite-installer`, `npm run build-and-setup` and,
    through `node`, `NODE_ENV=production sh ./evil.sh` passed. The
    package.json controls a `build:css` script exactly as much as `build`, and
    neither script is read, so the `build:<name>` family (npm-run-all's naming)
    passes as `build` does. When an option named the
    launcher's package (`npx -p pkg cmd`, `npm exec --package=pkg -- cmd`), the
    command it then runs is judged in turn, unless it is that package's own
    (`npx -p husky husky`): `npx -p husky sh ./evil.sh` passed because only
    husky was looked at.
    """
    while words and starts_with_launcher(words):
        packages, command = invocation(words)
        if not packages or not all(_launch_is_local(one, declared) for one in packages):
            return False
        if not command or basename(command[0]) in {npm_spec(one.spec).name for one in packages}:
            return True
        words = _without_assignments(command)
    if not words:
        return False
    if basename(words[0]).lower() in _SAFE_SCRIPT_TOOLS:
        return True
    return (
        basename(words[0]).lower() == "npm"
        and words[1:2] == ["run"]
        and _BUILD_SCRIPT.fullmatch(words[2] if len(words) > 2 else "") is not None
    )


def _launch_is_local(launched: Launched, declared: set[str]) -> bool:
    """Does a launcher in an install script run a package the project installs?

    `npx`, `npm exec` and `bunx` run a package from node_modules when one is
    installed and fetch it from the registry when it is not, so `npx husky
    install` with husky declared runs the project's own husky, while `npx
    some-remote-package` fetches whatever the registry serves and runs it during
    install. `npx` used to pass whatever it was given. A build tool on the safe
    list passes under them too (`npx tsc`), as it does alone. Only a bare name
    or a registry version passes: `npx husky@github:attacker/evil` and `npx
    husky@npm:evil-installer` name a declared package and fetch another, and a
    tag (`husky@latest`) can name a release the project does not install.
    `pnpm dlx`, `pnpx` and `yarn dlx` fetch the package even when it is
    installed.
    """
    if launched.launcher not in _LOCAL_FIRST_LAUNCHERS or launched.ecosystem != "js":
        return False
    spec = npm_spec(launched.spec)
    if spec.kind != "registry" or (spec.version and parse_range(spec.version, "npm") is None):
        return False
    return spec.name in declared or spec.name.lower() in _SAFE_SCRIPT_TOOLS


def _script_commands(script: str) -> list[tuple[list[str], bool]]:
    """The commands a script runs, each with whether it redirects into a file.

    A line is split at `&&`, `||`, `;`, `|`, `&` and parentheses; a newline
    ends a command too. A line the shell splitter gives up on (an unclosed
    quote) is split at whitespace and those operators: it fell back to
    whitespace alone, so the `#'` of `tsc&&sh ./evil.sh #'` left `tsc&&sh` one
    word, though sh reads `#'` as a comment (dropped first, in `_shell_parts`). A redirection and its target are dropped from
    the words (`node build.js > build.log`), so the target is not read as a
    command.
    """
    commands: list[tuple[list[str], bool]] = []
    syntax = _shell_syntax("();<>|&", " \t\r\n", "")
    for line in script.splitlines():
        tokens = _shell_split(line, syntax)
        if tokens is None:
            tokens = _FALLBACK_WORD.findall(line)
        words: list[str] = []
        redirected = skip = False
        for token in tokens:
            if skip:
                skip = False
            elif token and set(token) <= _SHELL_PUNCTUATION:
                if token[0] in "<>" or token.startswith("&>"):
                    redirected = skip = True
                    continue
                if words:
                    commands.append((words, redirected))
                words, redirected = [], False
            else:
                words.append(token)
        if words:
            commands.append((words, redirected))
    return commands


def _shell_parts(script: str) -> tuple[str, list[str]]:
    """A script as sh reads it: its text without comments, and the text of
    each outermost command substitution, `$(...)` or backticks, in it.

    A comment starts at a `#` that begins a word outside quotes and runs to the
    end of its line; a `#` inside a word (`github:org/repo#sha`, `$#`) is part
    of it. Quotes are followed across lines, as sh follows them, so a `#` on a
    line inside a quoted string does not hide the lines after it. sh runs a
    substitution outside single quotes, inside double quotes too, so a single
    quote within double quotes (`"it's $(cmd)"`) does not hide one, and a `#`
    inside one does not end the line around it. An ANSI-C string (`$'...'`),
    whose backslash escapes a quote, is replaced by an empty string, which the
    shell splitter reads as sh does.
    """
    kept: list[str] = []
    substitutions: list[str] = []
    quote = ""
    word_start = True
    i = start = 0
    n = len(script)
    while i < n:
        char = script[i]
        if quote == "'":
            if char == "'":
                quote = ""
            i += 1
            continue
        if char == "\\":
            i += 2
            word_start = False
            continue
        if char == "`" or (char == "$" and script.startswith("(", i + 1)):
            if char == "`":
                end = i + 1
                while end < n and script[end] != "`":
                    end += 2 if script[end] == "\\" else 1
                substitutions.append(script[i + 1:end])
            else:
                end = _closing_paren(script, i + 2)
                substitutions.append(script[i + 2:end])
            i = end + 1
            word_start = False
            continue
        if quote:
            if char == '"':
                quote = ""
        elif char == "$" and script.startswith("'", i + 1):
            end = i + 2
            while end < n and script[end] != "'":
                end += 2 if script[end] == "\\" else 1
            kept.append(script[start:i])
            kept.append("''")
            i = start = end + 1
            word_start = False
            continue
        elif char in "'\"":
            quote = char
            word_start = False
        elif char == "#" and word_start:
            kept.append(script[start:i])
            end = script.find("\n", i)
            i = start = n if end == -1 else end
            continue
        else:
            word_start = char in _WORD_BREAKS
        i += 1
    kept.append(script[start:])
    return "".join(kept), substitutions


def _closing_paren(text: str, i: int) -> int:
    """The index of the `)` that closes a `(` just before `i`, or the end."""
    depth, quote, n = 1, "", len(text)
    while i < n:
        char = text[i]
        if char == "\\" and quote != "'":
            i += 2
            continue
        if quote:
            if char == quote:
                quote = ""
        elif char in "'\"":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n


def _declared_packages(data: dict[str, Any]) -> set[str]:
    """Every package a package.json declares, in any dependency section."""
    declared: set[str] = set()
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(section)
        if isinstance(deps, dict):
            declared.update(str(name) for name in deps)
    return declared


def _check_lockfile_exists(project_root: Path) -> list[Finding]:
    """AAK-SUPPLY-004: Check that lockfiles exist for package manifests."""
    findings: list[Finding] = []

    npm_manifest = project_root / "package.json"
    if npm_manifest.is_file():
        # Bun 1.2 and later writes the text bun.lock; earlier releases wrote the
        # binary bun.lockb. Only bun.lockb was accepted, so a current Bun project
        # was reported as having no lockfile.
        has_lock = any(
            (project_root / lf).is_file()
            for lf in ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"]
        )
        if not has_lock:
            findings.append(_make_finding(
                "AAK-SUPPLY-004",
                str(npm_manifest.relative_to(project_root)),
                "package.json exists but no lockfile found",
            ))

    pyproject = project_root / "pyproject.toml"
    if pyproject.is_file():
        has_lock = any(
            (project_root / lf).is_file()
            for lf in ["poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock"]
        )
        if not has_lock:
            findings.append(_make_finding(
                "AAK-SUPPLY-004",
                str(pyproject.relative_to(project_root)),
                "pyproject.toml exists but no lockfile found",
            ))

    pipfile = project_root / "Pipfile"
    if pipfile.is_file() and not (project_root / "Pipfile.lock").is_file():
        findings.append(_make_finding(
            "AAK-SUPPLY-004",
            str(pipfile.relative_to(project_root)),
            "Pipfile exists but no Pipfile.lock found",
        ))

    cargo_toml = project_root / "Cargo.toml"
    if cargo_toml.is_file() and not (project_root / "Cargo.lock").is_file():
        findings.append(_make_finding(
            "AAK-SUPPLY-004",
            str(cargo_toml.relative_to(project_root)),
            "Cargo.toml exists but no Cargo.lock found",
        ))

    return findings


def _extract_python_package_version(line: str) -> tuple[str, str]:
    """Extract (package_name, version) from a requirements.txt line like 'axios==1.7.2'."""
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("-"):
        return ("", "")
    for sep in ["==", ">=", "<=", "~=", "!="]:
        if sep in line:
            parts = line.split(sep, 1)
            name = parts[0].strip().lower()
            version = parts[1].strip().split(",")[0].strip() if len(parts) > 1 else ""
            # Strip extras like package[extra]==1.0
            if "[" in name:
                name = name.split("[")[0]
            return (name, version)
    # No version specifier
    name = line.split("[")[0].strip().lower()
    return (name, "")


def _scan_python_deps(project_root: Path) -> list[Finding]:
    """Check Python dependency files for known vulnerable packages (AAK-SUPPLY-002)."""
    findings: list[Finding] = []
    python_vulns = KNOWN_VULNERABLE_PACKAGES.get("python", {})
    if not python_vulns:
        return findings

    # Scan requirements*.txt files
    for req_file in project_root.glob("requirements*.txt"):
        if not req_file.is_file():
            continue
        try:
            if req_file.stat().st_size > MAX_MANIFEST_BYTES:
                continue
            raw = read_text_capped(req_file, MAX_MANIFEST_BYTES, errors="replace")
        except OSError:
            continue
        rel_path = str(req_file.relative_to(project_root))
        for line in raw.splitlines():
            pkg_name, version = _extract_python_package_version(line)
            if pkg_name in python_vulns and version:
                vuln_info = python_vulns[pkg_name]
                if _version_in_range(version, vuln_info["affected"]):
                    findings.append(_make_finding(
                        "AAK-SUPPLY-002", rel_path,
                        f"{pkg_name}=={version} — {vuln_info['description']}",
                        _find_line_number(raw, pkg_name),
                    ))

    # Scan Pipfile.lock
    pipfile_lock = project_root / "Pipfile.lock"
    if pipfile_lock.is_file():
        try:
            if pipfile_lock.stat().st_size <= MAX_LOCKFILE_BYTES:
                raw = read_text_capped(pipfile_lock, MAX_LOCKFILE_BYTES, errors="replace")
                data = loads_json(raw, pipfile_lock)
                rel_path = str(pipfile_lock.relative_to(project_root))
                for section in ["default", "develop"]:
                    # A top level that is not an object, or a version that is
                    # not a string, raised here (see `_scan_npm_lockfile`).
                    pkgs = data.get(section, {}) if isinstance(data, dict) else None
                    if not isinstance(pkgs, dict):
                        continue
                    for pkg_name, pkg_info in pkgs.items():
                        stated = pkg_info.get("version", "") if isinstance(pkg_info, dict) else None
                        if not isinstance(stated, str):
                            continue
                        version = stated.lstrip("=")
                        name_lower = pkg_name.lower()
                        if name_lower in python_vulns and version:
                            vuln_info = python_vulns[name_lower]
                            if _version_in_range(version, vuln_info["affected"]):
                                findings.append(_make_finding(
                                    "AAK-SUPPLY-002", rel_path,
                                    f"{pkg_name}=={version} — {vuln_info['description']}",
                                    _find_line_number(raw, pkg_name),
                                ))
        except (json.JSONDecodeError, OSError):
            pass

    return findings


def _scan_rust_deps(project_root: Path) -> list[Finding]:
    """Check Cargo.lock for known vulnerable packages (AAK-SUPPLY-002) and
    count them (AAK-SUPPLY-005).

    A Cargo.toml without a Cargo.lock is `_check_lockfile_exists`'s to report
    (AAK-SUPPLY-004). This ended with that check too, but it returns early when
    there is no Cargo.lock, so the check could never fire here.

    Only a package with a `source` (a registry or a git repository) counts as a
    dependency. Cargo.lock lists the root crate as a `[[package]]` too, without
    one, and counting it reported 200 dependencies as 201. Workspace members and
    path dependencies have no `source` either: they are the project's own crates.
    """
    findings: list[Finding] = []
    rust_vulns = KNOWN_VULNERABLE_PACKAGES.get("rust", {})

    cargo_lock = project_root / "Cargo.lock"
    if not cargo_lock.is_file():
        return findings

    try:
        if cargo_lock.stat().st_size > MAX_LOCKFILE_BYTES:
            return findings
        raw = read_text_capped(cargo_lock, MAX_LOCKFILE_BYTES, errors="replace")
    except OSError:
        return findings

    rel_path = str(cargo_lock.relative_to(project_root))

    # Parse TOML-style Cargo.lock: [[package]] blocks
    current_name = ""
    current_version = ""
    current_has_source = False
    dep_count = 0
    for line in raw.splitlines():
        line = line.strip()
        if line == "[[package]]":
            # Check previous package
            if current_name and current_version and current_name in rust_vulns:
                vuln_info = rust_vulns[current_name]
                if _version_in_range(current_version, vuln_info["affected"]):
                    findings.append(_make_finding(
                        "AAK-SUPPLY-002", rel_path,
                        f"{current_name}@{current_version} — {vuln_info['description']}",
                        _find_line_number(raw, current_name),
                    ))
            if current_has_source:
                dep_count += 1
            current_name = ""
            current_version = ""
            current_has_source = False
        elif line.startswith('name = "'):
            current_name = line.split('"')[1]
        elif line.startswith('version = "'):
            current_version = line.split('"')[1]
        elif line.startswith("source = "):
            current_has_source = True

    # Check last package
    if current_name and current_version and current_name in rust_vulns:
        vuln_info = rust_vulns[current_name]
        if _version_in_range(current_version, vuln_info["affected"]):
            findings.append(_make_finding(
                "AAK-SUPPLY-002", rel_path,
                f"{current_name}@{current_version} — {vuln_info['description']}",
                _find_line_number(raw, current_name),
            ))
    if current_has_source:
        dep_count += 1

    # AAK-SUPPLY-005 for Rust
    if dep_count > 200:
        findings.append(_make_finding(
            "AAK-SUPPLY-005", rel_path,
            f"{dep_count} dependencies (threshold: 200)",
        ))

    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    # Track which files exist and were scanned
    for candidate in [
        *_MCP_CONFIGS,
        "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock",
        "Cargo.toml", "Cargo.lock",
    ]:
        p = project_root / candidate
        if p.is_file():
            scanned_files.add(candidate)

    for req_file in project_root.glob("requirements*.txt"):
        if req_file.is_file():
            scanned_files.add(str(req_file.relative_to(project_root)))

    findings.extend(_scan_mcp_configs_for_supply_chain(project_root))
    findings.extend(_scan_npm_lockfile(project_root))
    findings.extend(_scan_package_json(project_root))
    findings.extend(_scan_python_deps(project_root))
    findings.extend(_scan_rust_deps(project_root))
    findings.extend(_check_lockfile_exists(project_root))
    findings.extend(_check_mcp_specific_vulns(project_root))
    findings.extend(_check_doris_mcp_pin(project_root, scanned_files))
    findings.extend(_check_mcp_gateway_registry_pin(project_root, scanned_files))
    findings.extend(_check_serena_pin(project_root, scanned_files))
    findings.extend(_check_excel_mcp_pin(project_root, scanned_files))
    findings.extend(_check_azure_mcp_auth(project_root, scanned_files))
    findings.extend(_check_astro_mcp_pin(project_root, scanned_files))
    findings.extend(_scan_astro_mcp_query_concat(project_root, scanned_files))
    findings.extend(_check_litellm_pin(project_root, scanned_files))
    findings.extend(_check_chatgpt_mcp_pin(project_root, scanned_files))
    findings.extend(_check_docsgpt_mcp_pin(project_root, scanned_files))
    findings.extend(_check_gpt_researcher_mcp_pin(project_root, scanned_files))
    findings.extend(_check_agent_zero_pin(project_root, scanned_files))
    findings.extend(_check_claudecode_pin(project_root, scanned_files))
    findings.extend(_check_semantic_kernel_pin(project_root, scanned_files))
    findings.extend(_check_mcp_calculate_server_pin(project_root, scanned_files))
    return findings, scanned_files


# ---------------------------------------------------------------------------
# AAK-DORIS-001 — apache-doris-mcp-server < 0.6.1 (CVE-2025-66335).
# Published 2026-04-20. Context-neutralization bypass reached via crafted
# tool arguments. Separate pin-check because the Python lockfile scanner
# above operates on a fixed KNOWN_VULNERABLE_PACKAGES table and we want
# this check to run even if that table hasn't been extended yet.
# ---------------------------------------------------------------------------

# A requirement's version after its name: blanks, an optional operator with its
# own trailing blanks, then the version. The operator used to sit between two
# `\s*`, so with no operator a blank run after the name was split between them
# every possible way, and a crafted requirements file grew with the square of
# the run. The same text matches, with the same version.
_PY_VERSION_TAIL = r"\s*(?:(?:==|>=|~=|<=|<|>)\s*)?([0-9][\w.\-]*)"

_DORIS_PATCHED = (0, 6, 1)


def _semver3(spec: str) -> tuple[int, int, int] | None:
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", str(spec))
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


# Lockfiles pin a *resolved* graph — the package name and its version are not
# adjacent, so a manifest regex reads them as "unpinned" and a version-pin rule
# fires even after a correct upgrade. Resolve the actual locked version so the
# fix the rule recommends can actually clear it (otherwise users suppress the
# CVE rule and go future-blind).
_LOCKFILES = frozenset({
    "uv.lock", "poetry.lock", "pipfile.lock",
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
})


def _lockfile_over_limit(path: Path) -> bool:
    """Is ``path`` a lockfile over MAX_LOCKFILE_BYTES?

    The older per-CVE checks read lockfiles among the manifests, and read them
    whole, however large: a crafted one costs the scan what it likes. The pin
    table skips a lockfile over the limit unread, and so do they, stating it in
    their limitations. ``stat`` raises OSError, as the read it guards does.
    """
    return path.name.lower() in _LOCKFILES and path.stat().st_size > MAX_LOCKFILE_BYTES


def _read_capped(path: Path) -> str:
    """A pin source's text: a lockfile up to MAX_LOCKFILE_BYTES and any other
    manifest or config up to MAX_MANIFEST_BYTES, the pin table's limits, and
    only a regular file (see `read_text_capped`). The older checks gated only
    lockfiles, so a `requirements*.txt` symlinked to a FIFO held the scan and
    a 200 MB pyproject.toml was read whole."""
    cap = MAX_LOCKFILE_BYTES if path.name.lower() in _LOCKFILES else MAX_MANIFEST_BYTES
    return read_text_capped(path, cap, errors="replace")


def _resolve_lockfile_versions(
    text: str, filename: str, names: tuple[str, ...], path: Path | None = None
) -> list[tuple[int, int, int]]:
    """Every resolved version of any of ``names`` in a lockfile, lowest first.

    A lockfile can resolve one package to several versions: pnpm and Yarn keep
    one entry per distinct range that resolved differently, and uv one per
    marker fork. Judging only the lowest misses an affected version above it
    whenever the lowest sits below a pin's `introduced` bound, which is the
    "first match decides" mistake the manifest reader stopped making.
    """
    return _lockfile_lookup(_lockfile_index(text, filename, path), filename, names)


def _lockfile_canon(name: str, filename: str) -> str:
    """A name as the lockfile's registry compares it.

    PyPI lockfiles compare names as PEP 503 normalises them: uv.lock records
    `awslabs-healthlake-mcp-server` for the package published as
    `awslabs.healthlake-mcp-server`, and the dotted name never matched it.
    """
    lowered = name.lower()
    if filename in ("uv.lock", "poetry.lock", "pipfile.lock"):
        return re.sub(r"[-_.]+", "-", lowered)
    return lowered


def _lockfile_lookup(
    index: dict[str, list[tuple[int, int, int]]], filename: str, names: tuple[str, ...]
) -> list[tuple[int, int, int]]:
    """The versions `index` holds for any of `names`, lowest first."""
    return sorted({v for n in names for v in index.get(_lockfile_canon(n, filename), ())})


# One resolved entry in a pnpm lockfile, any package: `/next@16.2.0:`,
# `next@16.2.0(react@18.0.0)`, `'@scope/name@1.2.3'`. Bounded on the left,
# because a name must not be read out of a longer one: unbounded,
# `eslint-config-next@16.2.0` and `@next/eslint-plugin-next@16.2.0` read as
# `next@16.2.0`, so a plugin left behind reported an upgraded `next` as
# unpatched, and `@vercel/next@4.4.0` (from the `vercel` CLI) hid a vulnerable
# one below the pin's `introduced`. A `/` still opens the v6 key form
# (`/next@16.2.0:`), but not after a scope name. A name is at most 214
# characters, npm's own limit, and no character a name can hold may precede
# one, so a match starts only where a run of name characters starts and the
# scan stays linear on a crafted lockfile of any size.
_PNPM_ENTRY_RE = re.compile(
    r"(?<![\w.\-~@])(?<!\w/)(@[\w.\-~]{1,214}/[\w.\-~]{1,214}|[\w.\-~]{1,214})@([0-9][\w.\-]*)"
)
# A Yarn 1 `version "1.2.3"` line. Yarn 2+ writes `version: 1.2.3`, which this
# does not read.
_YARN_VERSION_RE = re.compile(r'\s+version\s+"([0-9][\w.\-]*)"')


def _yarn_entries(text: str) -> list[tuple[str, str]]:
    """(name, version) for each Yarn 1 block: a header line, then its version line."""
    entries: list[tuple[str, str]] = []
    current: str | None = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            first = line.split(",", 1)[0].strip().rstrip(":").strip('"')
            at = first.find("@", 1)
            current = first[:at] if at > 0 else None
            continue
        if current is not None:
            m = _YARN_VERSION_RE.match(line)
            if m:
                entries.append((current, m.group(1)))
                current = None
    return entries


def _lockfile_index(text: str, filename: str, path: Path | None = None) -> dict[str, list[tuple[int, int, int]]]:
    """Every package a lockfile resolves, by canonical name, to its versions.

    One pass over the file, so a pin table of a hundred rows reads a large
    lockfile once instead of once per row. Absent or unparseable content yields
    an empty index, so a correct upgrade and re-lock clears a pin instead of
    forcing a suppression.
    """
    found: dict[str, list[str]] = {}

    def add(name: object, version: object) -> None:
        if isinstance(name, str) and version:
            found.setdefault(_lockfile_canon(name, filename), []).append(str(version))

    if filename in ("uv.lock", "poetry.lock"):
        # TOML keeps a key and its value on one line, so only spaces and tabs
        # are skipped. `^\s*` also crossed newlines, and on a run of blank lines
        # every line start rescanned the rest of the run: quadratic in a file
        # that is now read up to MAX_LOCKFILE_BYTES.
        for block in re.split(r"(?=^\[\[package\]\])", text, flags=re.MULTILINE):
            nm = re.search(r'^[ \t]*name[ \t]*=[ \t]*["\']([^"\'\n]+)["\']', block, re.MULTILINE)
            vm = re.search(r'^[ \t]*version[ \t]*=[ \t]*["\']([0-9][\w.\-]*)', block, re.MULTILINE)
            if nm and vm:
                add(nm.group(1), vm.group(1))
    elif filename in ("pipfile.lock", "package-lock.json"):
        try:
            data = loads_json(text, path)
        except ValueError:
            data = {}
        if not isinstance(data, dict):
            data = {}
        if filename == "pipfile.lock":
            for section in ("default", "develop"):
                packages = data.get(section)
                for pkg, meta in (packages.items() if isinstance(packages, dict) else ()):
                    if isinstance(meta, dict):
                        add(pkg, str(meta.get("version", "")).lstrip("="))
        else:
            packages = data.get("packages")
            for key, meta in (packages.items() if isinstance(packages, dict) else ()):
                if isinstance(meta, dict):
                    add(str(key).rsplit("node_modules/", 1)[-1], meta.get("version"))
            stack = [data.get("dependencies")]
            while stack:
                deps = stack.pop()
                if not isinstance(deps, dict):
                    continue
                for pkg, meta in deps.items():
                    if isinstance(meta, dict):
                        add(pkg, meta.get("version"))
                        stack.append(meta.get("dependencies"))
    elif filename == "pnpm-lock.yaml":
        for m in _PNPM_ENTRY_RE.finditer(text):
            add(m.group(1), m.group(2))
    elif filename == "yarn.lock":
        for name, version in _yarn_entries(text):
            add(name, version)

    return {
        name: sorted({v for v in (_semver3(x) for x in versions) if v})
        for name, versions in found.items()
    }


# ---------------------------------------------------------------------------
# How the Doris, gateway-registry, Serena, Excel and LiteLLM pins read a file.
#
# They read the first number after the package name, so an upper bound read as
# the version: `litellm<1.83.7`, which admits only affected releases, read as
# 1.83.7 and passed, and `<2.0.0,>=1.0.0` passed where `>=1.0.0,<2.0.0` fired.
# A comment that named the package with a number decided the file, as the first
# mention decided the gateway-registry and Serena checks. A lockfile, where the
# name and its version sit on separate lines, read as unpinned or not at all.
# They now read a file the way the CVE pin table does: a lockfile on the
# versions it resolves, any other file on the declarations it makes in its own
# format (`_manifest_deps`), each judged by the releases its range admits
# (`_versions`) with the pin table's own judge.
# ---------------------------------------------------------------------------

def _read_pin_candidate(path: Path) -> str | None:
    """A candidate file's text, or None when it is unreadable, not a regular
    file or over its limit.

    A lockfile is read up to MAX_LOCKFILE_BYTES and any other file up to
    MAX_MANIFEST_BYTES, the pin table's limits (`_read_capped`). A stat()
    before the read was not enough: a FIFO reports a size of 0, so a
    `requirements*.txt` symlinked to one held the scan.
    """
    try:
        return _read_capped(path)
    except OSError:
        return None


def _affected_pin(
    path: Path,
    text: str,
    names: tuple[str, ...],
    floor: tuple[int, int, int],
    *,
    requires_version: bool = False,
) -> str | None:
    """How `path` takes a release of `names` below `floor`, or None when it does not.

    Args:
        path: The candidate file; its name selects how it is read.
        text: The file's contents.
        names: The package's names, compared as its registry compares them.
        floor: The first fixed release.
        requires_version: Report only a declaration that states a version.

    Returns:
        The version as the file states it: a lockfile's resolved version, or a
        declaration's specifier (`<0.6.1`, with a lone `==` dropped), "" for a
        declaration that states none, and None when nothing in the file admits
        a release below `floor`.
    """
    filename = path.name.lower()
    if filename in _LOCKFILES:
        affected = [v for v in _resolve_lockfile_versions(text, filename, names, path) if v < floor]
        return ".".join(str(x) for x in affected[0]) if affected else None
    # Imported here: the pin table imports this module's lockfile readers.
    from agent_audit_kit.scanners.mcp_cve_pins_2026_07 import _Pin, _deciding_declaration

    pin = _Pin(rule_id="", display=names[0], names=names, floor=floor,
               requires_version=requires_version)
    found = [_with_vcs_version(d) for d in declarations(path, text)]
    declaration = _deciding_declaration(pin, found)
    return None if declaration is None else _stated_version(declaration.version)


def _with_vcs_version(declaration: Declaration) -> Declaration:
    """A git requirement with the release its tag names, as `==<tag>`.

    `git+https://github.com/oraios/serena@v1.5.2#egg=serena-agent` declares no
    version, but its tag names the release it installs. Read as unversioned,
    it made the gateway-registry and Serena checks, which report an unpinned
    reference, report the patched tag, and the other three, which report only
    a stated version, miss a tag below the fix. A branch, a commit or a tag
    with no dot names no release, so such a requirement stays unversioned.
    """
    if declaration.version or declaration.dialect != "pep440":
        return declaration
    tag = _vcs_tag_version(declaration.text)
    return declaration if tag is None else dataclasses.replace(declaration, version="==" + tag)


# A release tag: dotted numbers after an optional `v` (`v1.5.2`, `1.83.7-stable`).
_RELEASE_TAG_RE = re.compile(r"[vV]?[0-9]+(?:\.[0-9]+)+")
# A commit id, short or full. It has no dot, so it is never a release tag, but
# it can begin with digits.
_COMMIT_ID_RE = re.compile(r"[0-9a-fA-F]{7,40}")


def _vcs_tag_version(requirement: str) -> str | None:
    """The version a VCS requirement's ref names, or None.

    pip takes the ref after the last `@` of the URL's last path segment, so the
    `git@` of an ssh URL is never read as one; the `#egg=` fragment and an
    environment marker are not part of it. Only a dotted release tag names a
    version: the version parser alone read a commit id that begins with digits
    as a release (`@1a2b3c4` as 1.0.0, `@0e1f2a3` as 0.0.0), so a pin reported
    a commit-pinned requirement as below its fix. A tag with no dot (`@v2`)
    names no release either.
    """
    url = requirement.split(";", 1)[0].partition("#")[0].strip()
    if "://" not in url:
        return None
    segment = url.rsplit("/", 1)[-1]
    if "@" not in segment:
        return None
    ref = segment.rsplit("@", 1)[1]
    if _COMMIT_ID_RE.fullmatch(ref) or not _RELEASE_TAG_RE.match(ref):
        return None
    ref = ref[1:] if ref[:1] in ("v", "V") else ref
    return ref if parse_version(ref) is not None else None


def _stated_version(spec: str) -> str:
    """A specifier as the evidence quotes it: `==0.5.0` as `0.5.0`, any other as written."""
    text = spec.strip()
    exact = text[2:].strip()
    if text.startswith("==") and not text.startswith("===") and exact and not any(
        c in exact for c in " ,;<>=!~^*|"
    ):
        return exact
    return text


def _check_doris_mcp_pin(project_root: Path, scanned_files: set[str]) -> list[Finding]:
    findings: list[Finding] = []

    def _fire(rel: str, raw: str) -> None:
        findings.append(make_finding(
            "AAK-DORIS-001",
            rel,
            f"apache-doris-mcp-server pinned at {raw!r} — CVE-2025-66335 "
            "SQL injection is patched in 0.6.1.",
        ))

    candidates: list[Path] = []
    candidates.extend(project_root.glob("requirements*.txt"))
    for name in ("pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock"):
        p = project_root / name
        if p.is_file():
            candidates.append(p)

    for path in candidates:
        text = _read_pin_candidate(path)
        if text is None:
            continue
        raw = _affected_pin(path, text, ("apache-doris-mcp-server",), _DORIS_PATCHED,
                            requires_version=True)
        if raw is not None:
            rel = str(path.relative_to(project_root))
            scanned_files.add(rel)
            _fire(rel, raw)
    return findings


# ---------------------------------------------------------------------------
# AAK-MCP-GATEWAY-REGISTRY-CVE-2026-14471-001 — Amazon mcp-gateway-registry
# < 1.0.13 (CVE-2026-14471, HIGH 7.x/8.1). SQL injection in the metrics-service
# retention-policy component: a crafted `table_name` is interpolated into SQL in
# identifier position (CWE-89). Fixed in 1.0.13.
# ---------------------------------------------------------------------------

_MCP_GATEWAY_REGISTRY_PATCHED = (1, 0, 13)
_MCP_GATEWAY_REGISTRY_NAMES = ("mcp-gateway-registry",)
# The project's repository, read as Serena's is (`_SERENA_REPO_RE`): a git URL
# or an image under it carries its version in its tag.
_MCP_GATEWAY_REGISTRY_REPO_RE = re.compile(
    r"(?<![\w-])agentic-community/mcp-gateway-registry(?![\w-])", re.IGNORECASE
)


def _command_lines(path: Path, text: str) -> list[list[str]]:
    """The command lines an MCP config's entries or a package.json's scripts run."""
    name = path.name.lower()
    try:
        if name == "package.json":
            data = loads_json(text, path)
            scripts = data.get("scripts") if isinstance(data, dict) else None
            if not isinstance(scripts, dict):
                return []
            return [shell_tokens(line) for line in scripts.values() if isinstance(line, str)]
        if name.endswith((".yaml", ".yml")):
            # `_command_entries` reads each container once, so a document that
            # contains itself ends there and is read, not refused.
            data = load_yaml(text, path, cycles_ok=True)
        elif name.endswith(".json"):
            data = loads_jsonc(text, path)
        else:
            return []
    except (ValueError, yaml.YAMLError, RecursionError):
        return []
    return [_argv(entry)[0] for entry, _where in _command_entries(data)]


def _runs_unversioned(path: Path, text: str, names: tuple[str, ...]) -> bool:
    """Does `path` run one of `names` that no launcher fetches, so at a version
    nothing in the file states?

    `uv run --directory ../serena serena-mcp-server` runs the entry point of a
    checkout of unknown version, and a declaration cannot see it: `uv run`
    fetches nothing. A command line that fetches the package it runs is
    skipped, because the command it then runs is that package's (`uvx --from
    <spec> serena`), and the declarations judge `<spec>`. A package `--with`
    adds is not the one that runs, so `uv run --with requests --directory
    ../serena serena-mcp-server`, skipped for fetching `requests`, is read
    again. This replaces reading every mention of the name in the text, which
    would report the command of a patched `uvx --from x==1.0.13 x` as
    unpinned, and a server merely named `x`.
    """
    wanted = {n.lower() for n in names}
    for argv in _command_lines(path, text):
        if any(not launched.extra for launched in launched_packages(argv)):
            continue
        words = [w for token in argv
                 for w in (shell_tokens(token) if any(c.isspace() for c in token) else [token])]
        if any(basename(word).lower() in wanted for word in words):
            return True
    return False


def _check_mcp_gateway_registry_pin(project_root: Path, scanned_files: set[str]) -> list[Finding]:
    findings: list[Finding] = []

    def _fire(rel: str, raw: str | None) -> None:
        shown = f"{raw!r}" if raw else "unpinned"
        findings.append(make_finding(
            "AAK-MCP-GATEWAY-REGISTRY-CVE-2026-14471-001",
            rel,
            f"Amazon mcp-gateway-registry referenced at {shown} — CVE-2026-14471 "
            "SQL injection (crafted table_name interpolated into an SQL "
            "identifier in the metrics-service retention policy) is fixed in "
            "1.0.13; pin >= 1.0.13.",
        ))

    candidates: list[Path] = []
    candidates.extend(project_root.glob("requirements*.txt"))
    for name in (
        "pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock",
        "package.json", "package-lock.json",
        ".mcp.json", "mcp.json", "claude_desktop_config.json",
    ):
        p = project_root / name
        if p.is_file():
            candidates.append(p)
    candidates.extend(project_root.glob("*.mcp.yaml"))
    candidates.extend(project_root.glob("*.mcp.yml"))

    for path in candidates:
        text = _read_pin_candidate(path)
        if text is None:
            continue
        raw = _affected_pin(path, text, _MCP_GATEWAY_REGISTRY_NAMES, _MCP_GATEWAY_REGISTRY_PATCHED)
        if raw is None and path.name.lower() not in _LOCKFILES:
            raw = _repository_reference_below(
                text, _MCP_GATEWAY_REGISTRY_REPO_RE, _MCP_GATEWAY_REGISTRY_PATCHED
            )
            if raw is None and _runs_unversioned(path, text, _MCP_GATEWAY_REGISTRY_NAMES):
                raw = ""
        if raw is not None:
            rel = str(path.relative_to(project_root))
            scanned_files.add(rel)
            _fire(rel, raw)
    return findings


# ---------------------------------------------------------------------------
# AAK-MCP-SERENA-CVE-2026-49471-001 — Serena MCP toolkit < 1.5.2.
# Unauthenticated Flask dashboard + DNS rebinding -> agent-memory write ->
# RCE via execute_shell_command(shell=True). Fixed in serena-agent 1.5.2.
# ---------------------------------------------------------------------------

_SERENA_PATCHED = (1, 5, 2)
_SERENA_NAMES = ("serena-agent", "serena-mcp-server")
# Serena's repository, which uvx, pip and docker take it from
# (`uvx --from git+https://github.com/oraios/serena serena`,
# `ghcr.io/oraios/serena`). Such a reference declares no package, so the text is
# read for it, every reference and not the first: its tag is its version, and
# one with no tag is unpinned. Bounded, so `oraios/serena-x` is another repo.
_SERENA_REPO_RE = re.compile(r"(?<![\w-])oraios/serena(?![\w-])", re.IGNORECASE)
# A reference's version, `@v1.5.2` or `:1.5.2`, read in a fixed window after it.
# A git URL may end the repository in `.git` before its tag (`serena.git@v1.5.2`),
# which read as a reference with no tag.
_REFERENCE_VERSION_RE = re.compile(r"(?:\.git)?\s*(?:[@:]\s*)?v?([0-9][\w.\-]*)?")


def _repository_reference_below(
    text: str, pattern: re.Pattern[str], floor: tuple[int, int, int]
) -> str | None:
    """The version of the first reference that is unpinned or below `floor`
    ("" when it carries none), or None when every reference is patched."""
    for m in pattern.finditer(text):
        after = _REFERENCE_VERSION_RE.match(text, m.end(), m.end() + 64)
        raw = after.group(1) if after else None
        version = _semver3(raw) if raw else None
        if version is None or version < floor:
            return raw or ""
    return None


def _check_serena_pin(project_root: Path, scanned_files: set[str]) -> list[Finding]:
    findings: list[Finding] = []

    def _fire(rel: str, raw: str | None) -> None:
        shown = f"{raw!r}" if raw else "unpinned"
        findings.append(make_finding(
            "AAK-MCP-SERENA-CVE-2026-49471-001",
            rel,
            f"Serena MCP toolkit referenced at {shown} — CVE-2026-49471 "
            "(unauthenticated dashboard + DNS rebinding -> agent-memory write -> "
            "RCE via execute_shell_command shell=True) is fixed in 1.5.2; pin "
            "serena-agent >= 1.5.2.",
        ))

    candidates: list[Path] = []
    candidates.extend(project_root.glob("requirements*.txt"))
    for name in (
        "pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock",
        "package.json", "package-lock.json",
        ".mcp.json", "mcp.json", "claude_desktop_config.json",
    ):
        p = project_root / name
        if p.is_file():
            candidates.append(p)
    candidates.extend(project_root.glob("*.mcp.yaml"))
    candidates.extend(project_root.glob("*.mcp.yml"))

    for path in candidates:
        text = _read_pin_candidate(path)
        if text is None:
            continue
        # A lockfile resolves a version, so a correct upgrade and re-lock clears
        # the finding; elsewhere the repository and a checkout's entry point
        # count as references too.
        raw = _affected_pin(path, text, _SERENA_NAMES, _SERENA_PATCHED)
        if raw is None and path.name.lower() not in _LOCKFILES:
            raw = _repository_reference_below(text, _SERENA_REPO_RE, _SERENA_PATCHED)
            if raw is None and _runs_unversioned(path, text, _SERENA_NAMES):
                raw = ""
        if raw is not None:
            rel = str(path.relative_to(project_root))
            scanned_files.add(rel)
            _fire(rel, raw)
    return findings


# ---------------------------------------------------------------------------
# AAK-EXCEL-MCP-001 — excel-mcp-server <= 0.1.7 (CVE-2026-40576).
# Path-traversal in get_excel_path(). Fixed in 0.1.8.
# ---------------------------------------------------------------------------

_EXCEL_FIRST_PATCHED = (0, 1, 8)


def _check_excel_mcp_pin(project_root: Path, scanned_files: set[str]) -> list[Finding]:
    findings: list[Finding] = []

    def _fire(rel: str, raw: str) -> None:
        findings.append(make_finding(
            "AAK-EXCEL-MCP-001",
            rel,
            f"excel-mcp-server pinned at {raw!r} — CVE-2026-40576 path "
            "traversal is patched in 0.1.8.",
        ))

    candidates: list[Path] = []
    candidates.extend(project_root.glob("requirements*.txt"))
    for name in ("pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock"):
        p = project_root / name
        if p.is_file():
            candidates.append(p)

    for path in candidates:
        text = _read_pin_candidate(path)
        if text is None:
            continue
        raw = _affected_pin(path, text, ("excel-mcp-server",), _EXCEL_FIRST_PATCHED,
                            requires_version=True)
        if raw is not None:
            rel = str(path.relative_to(project_root))
            scanned_files.add(rel)
            _fire(rel, raw)
    return findings


# ---------------------------------------------------------------------------
# AAK-AZURE-MCP-001 — Azure MCP server consumed without authentication
# (CVE-2026-32211). Server-side default ships with no auth on the MCP
# endpoint; consumer-side check is "your .mcp.json points at it without
# Authorization / mTLS / Azure-AD token exchange".
# ---------------------------------------------------------------------------

_AZURE_MCP_HOST_RE = re.compile(
    r"""
    (?:
        \.azure\.com
      | \.azurewebsites\.net
      | \.cognitiveservices\.azure\.com
      | \.openai\.azure\.com
      | azure[-_]?mcp
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)
_AUTH_HINT_RE = re.compile(
    r"""
    (?:
        Authorization
      | client_certificate
      | client[_-]?cert
      | mtls
      | api[_-]?key
      | x-functions-key
      | DefaultAzureCredential
      | ManagedIdentity
      | WorkloadIdentity
      | azure[_-]?ad
      | bearer_token
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _check_azure_mcp_auth(
    project_root: Path, scanned_files: set[str]
) -> list[Finding]:
    findings: list[Finding] = []
    candidates: list[Path] = []
    for name in (
        ".mcp.json",
        ".cursor/mcp.json",
        ".vscode/mcp.json",
        ".amazonq/mcp.json",
        "mcp.json",
    ):
        p = project_root / name
        if p.is_file():
            candidates.append(p)
    az_dir = project_root / ".azure-mcp"
    if az_dir.is_dir():
        for p in az_dir.rglob("*.json"):
            if p.is_file():
                candidates.append(p)

    for path in candidates:
        try:
            text = _read_capped(path)
        except OSError:
            continue
        if not _AZURE_MCP_HOST_RE.search(text):
            continue
        if _AUTH_HINT_RE.search(text):
            continue
        rel = str(path.relative_to(project_root))
        scanned_files.add(rel)
        findings.append(make_finding(
            "AAK-AZURE-MCP-001",
            rel,
            "Azure MCP endpoint configured without an Authorization "
            "header, mTLS client certificate, or Azure-AD token. "
            "CVE-2026-32211: the server-side default ships with no "
            "auth on the MCP endpoint.",
            line_number=find_line_number(text, "azure")
            or find_line_number(text, "azurewebsites"),
        ))
    return findings


def _check_mcp_specific_vulns(project_root: Path) -> list[Finding]:
    """AAK-SUPPLY-006: Check MCP server packages against vuln DB.

    Reads the configs AAK-SUPPLY-001 reads (`_MCP_CONFIGS`), both server maps of
    each through `iter_mcp_servers`: VS Code keeps its servers under `servers`.
    """
    findings: list[Finding] = []
    try:
        from agent_audit_kit.vuln_db import load_database
        db = load_database()
    except ImportError:
        return findings

    npm_vulns = db.get("npm", {})
    for name in _MCP_CONFIGS:
        mcp_path = project_root / name
        if not mcp_path.is_file():
            continue
        try:
            data = loads_jsonc(read_text_capped(mcp_path, CONFIG_MAX_BYTES, errors="replace"), mcp_path)
        except (json.JSONDecodeError, UnicodeDecodeError, OSError):
            continue
        rel_path = str(mcp_path.relative_to(project_root))
        for server_name, cfg in iter_mcp_servers(data):
            findings.extend(_vulnerable_launches(rel_path, server_name, cfg, npm_vulns))
    return findings


def _vulnerable_launches(
    rel_path: str, server_name: str, cfg: dict[str, Any], npm_vulns: dict[str, Any]
) -> list[Finding]:
    """AAK-SUPPLY-006 for one server: each `package@version` in its args that the
    npm section of the vulnerability database lists as affected."""
    findings: list[Finding] = []
    args = cfg.get("args", [])
    if not isinstance(args, list):
        return findings
    # The table is npm's, so a PyPI launch is not looked up in it: uvx reads
    # `openclaw@2.0.2` as the PyPI `openclaw`, an unrelated installer for the
    # cmdop CLI, not as OpenClaw.
    command = cfg.get("command")
    argv = command.split() if isinstance(command, str) else []
    argv += [a for a in args if isinstance(a, str)]
    launches = invocation_packages(argv)
    if launches and all(launched.ecosystem == "py" for launched in launches):
        return findings
    for arg in args:
        if not isinstance(arg, str) or arg.startswith("-"):
            continue
        # Extract package name and version from arg like @org/pkg@1.2.3
        pkg_name = arg
        version = ""
        if arg.startswith("@") and "@" in arg[1:]:
            parts = arg.split("@")
            pkg_name = f"@{parts[1]}"
            version = parts[2] if len(parts) > 2 else ""
        elif "@" in arg and not arg.startswith("@"):
            pkg_name, version = arg.split("@", 1)
        if pkg_name in npm_vulns and version:
            vuln_info = npm_vulns[pkg_name]
            if _version_in_range(version, vuln_info["affected"]):
                findings.append(_make_finding(
                    "AAK-SUPPLY-006", rel_path,
                    f"Server '{server_name}' uses {pkg_name}@{version} — {vuln_info['description']}",
                ))
    return findings


# ---------------------------------------------------------------------------
# AAK-ASTROMCP-SQLI-CVE-2026-7591-001 — astro-mcp-server <= 1.1.1.
# CVE-2026-7591 (NVD 2026-05-01): SQL injection in src/index.ts via
# request.params.arguments at the MCP-tool query-construction path.
# Latest npm publish (TimBroddin/astro-mcp-server) is 1.1.1 — the same
# version flagged as the vulnerable ceiling — so no upstream patch
# exists yet; pin-check fires whenever the package is present at any
# version. The TS / JS source detector fires when files importing the
# package build queries via string concatenation or untagged template
# literals; tagged-template SQL helpers (sql/drizzle/prisma/postgres-js)
# encode interpolation safely and are intentionally not matched.
# ---------------------------------------------------------------------------

# `None` means "no fix released yet — every version is vulnerable".
_ASTRO_MCP_PATCHED: tuple[int, int, int] | None = None
_ASTRO_MCP_PACKAGE_JSON_RE = re.compile(
    r'"astro-mcp-server"\s*:\s*"([~^>=<\s]*[0-9][\w.\-]*)"',
    re.IGNORECASE,
)
# yarn.lock / pnpm-lock.yaml / package-lock.json shape:
#   "astro-mcp-server@1.1.1" or astro-mcp-server@^1.1.0:
_ASTRO_MCP_LOCKLINE_RE = re.compile(
    r'\bastro-mcp-server@([~^>=<\s]*[0-9][\w.\-]*)',
    re.IGNORECASE,
)


def _check_astro_mcp_pin(project_root: Path, scanned_files: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()

    def _fire(rel: str, raw: str) -> None:
        if rel in seen:
            return
        seen.add(rel)
        findings.append(make_finding(
            "AAK-ASTROMCP-SQLI-CVE-2026-7591-001",
            rel,
            f"astro-mcp-server pinned at {raw!r} — CVE-2026-7591 SQL "
            "injection (NVD 2026-05-01); no upstream patch published "
            "as of the AAK ship date — every version <=1.1.1 is "
            "vulnerable.",
        ))

    candidates: list[Path] = []
    for name in ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
        p = project_root / name
        if p.is_file():
            candidates.append(p)

    for path in candidates:
        try:
            if _lockfile_over_limit(path):
                continue
            text = _read_capped(path)
        except OSError:
            continue
        if "astro-mcp-server" not in text:
            continue
        rel = str(path.relative_to(project_root))
        m = _ASTRO_MCP_PACKAGE_JSON_RE.search(text)
        if m:
            version = _semver3(m.group(1))
            if _ASTRO_MCP_PATCHED is None or version is None or version < _ASTRO_MCP_PATCHED:
                scanned_files.add(rel)
                _fire(rel, m.group(1).strip())
                continue
        m2 = _ASTRO_MCP_LOCKLINE_RE.search(text)
        if m2:
            version = _semver3(m2.group(1))
            if _ASTRO_MCP_PATCHED is None or version is None or version < _ASTRO_MCP_PATCHED:
                scanned_files.add(rel)
                _fire(rel, m2.group(1).strip())
    return findings


_ASTRO_MCP_IMPORT_RE = re.compile(
    r"""(?x)
    (?:
        \bfrom\s+['"]astro-mcp-server['"]
      | \bimport\s+['"]astro-mcp-server['"]
      | \brequire\(\s*['"]astro-mcp-server['"]\s*\)
    )
    """,
)
# Concatenation: db.query("SELECT ... " + x) or
# untagged template literal: db.query(`SELECT ... ${x}`).
# Tagged template form (sql`...`, drizzle`...`) is intentionally NOT
# matched because it escapes interpolations safely.
_ASTRO_MCP_CONCAT_RE = re.compile(
    r"""(?xs)
    \b(?:db|client|conn|connection|pool|cursor|database|sqlite|knex)
    \.(?:query|execute|run|all|get|exec|prepare)\s*\(\s*
    (?:
        ['"][^'"]*\b(?:select|insert|update|delete|create|drop|alter)\b[^'"]*['"]\s*\+\s*\w+
      | `[^`]*\b(?:select|insert|update|delete|create|drop|alter)\b[^`]*\$\{\s*[^}]+\s*\}[^`]*`
    )
    """,
    re.IGNORECASE,
)


def _scan_astro_mcp_query_concat(
    project_root: Path, scanned_files: set[str]
) -> list[Finding]:
    findings: list[Finding] = []
    skip_dirs = {"node_modules", ".git", "dist", "build", ".next", "coverage"}
    suffixes = {".ts", ".tsx", ".js", ".mjs", ".cjs"}
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if in_skip_dir(path, project_root, skip_dirs):
            continue
        if path.suffix not in suffixes:
            continue
        try:
            text = read_text_capped(path, 1_000_000, errors="replace")
        except OSError:
            continue
        if len(text) > 1_000_000:
            continue
        if not _ASTRO_MCP_IMPORT_RE.search(text):
            continue
        rel = str(path.relative_to(project_root))
        for m in _ASTRO_MCP_CONCAT_RE.finditer(text):
            scanned_files.add(rel)
            line_no = text.count("\n", 0, m.start()) + 1
            evidence = m.group(0).replace("\n", " ").strip()
            if len(evidence) > 100:
                evidence = evidence[:97] + "..."
            findings.append(make_finding(
                "AAK-ASTROMCP-SQLI-CVE-2026-7591-001",
                rel,
                f"Unsafe SQL construction in astro-mcp-server context "
                f"(CVE-2026-7591): {evidence}",
                line_number=line_no,
            ))
    return findings


# ---------------------------------------------------------------------------
# AAK-LITELLM-CVE-2026-30623-PIN-001 — litellm < 1.83.7 (CVE-2026-30623).
# BerriAI/litellm published v1.83.7 on 2026-04-30 with the patch. This
# pin-only rule complements AAK-MCP-STDIO-CMD-INJ-001 (which catches the
# source-side shape) by surfacing a discrete finding when the manifest
# pins a pre-patch version, even if the source uses the SDK safely.
# Wired into `aak fix --cve` so the auto-fixer can rewrite the manifest.
# ---------------------------------------------------------------------------

_LITELLM_PATCHED = (1, 83, 7)


# ---------------------------------------------------------------------------
# AAK-CHATGPT-MCP-CVE-2026-7061-PIN-001 — Toowiredd/chatgpt-mcp-server
# <=0.1.0 (CVE-2026-7061, HIGH 7.3). OS command injection in
# `src/services/docker.service.ts` of the MCP/HTTP component. Package
# is NOT published to npm — consumers install via a git+https URL in
# package.json. No upstream patch as of ship date; every version
# <=0.1.0 is vulnerable. The architectural class is also caught by
# AAK-MCP-STDIO-CMD-INJ-002 (TS taint sink); this pin-only rule is
# the named-CVE companion that surfaces a discrete finding for
# downstream consumers running pin-check mode and need an actionable
# manifest fix (i.e., remove the dep until upstream ships a patch).
# Closes #80.
# ---------------------------------------------------------------------------

_CHATGPT_MCP_PACKAGE_RE = re.compile(
    r'"chatgpt-mcp-server"\s*:\s*"([^"]+)"',
    re.IGNORECASE,
)
# git+https / git+ssh / GitHub shorthand pinned via package.json:
# "chatgpt-mcp-server": "github:Toowiredd/chatgpt-mcp-server"
# "chatgpt-mcp-server": "git+https://github.com/Toowiredd/chatgpt-mcp-server.git"
#
# Here and in the agent-zero, DocsGPT and gpt-researcher patterns below, the URL
# is read up to the next `git+https://` rather than to the end of the token:
# with `[^"\s]*`, every `git+https://` in a long token with no repository after
# it read to the token's end, so a crafted lockfile grew with the square of the
# token. A file matches exactly when it did; only the quoted evidence of a token
# that holds two `git+` prefixes can differ.
_CHATGPT_MCP_GIT_RE = re.compile(
    r'(?:github:|git\+https?://(?:(?!git\+https?://)[^"\s])*)?Toowiredd/chatgpt-mcp-server',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# AAK-AGENT-ZERO-CVE-2026-30624-PIN-001 — Agent Zero 0.9.8 (HIGH 8.6).
#
# The External MCP Servers feature takes a JSON config carrying arbitrary
# `command` / `args` and executes them when the config is applied, with no
# validation — a malicious MCP config is RCE with the Agent Zero process's
# privileges. NVD's CPE scopes this to exactly `agent-zero:agent-zero:0.9.8`
# with no versionEndExcluding, and the only reference is the OX advisory; no
# vendor fix version is published.
#
# Three things the 2026-05 roadmap row got wrong, corrected here:
#
#   1. The repo moved. `frdel/agent-zero` now redirects to `agent0ai/agent-zero`.
#      Both spellings are matched — existing manifests still carry the old one.
#   2. `agent-zero` DOES resolve on PyPI, but it is an unrelated project ("AI
#      outbound voice agent framework", 0.1.2, different author). Matching the
#      bare distribution name would fire on an innocent package, so this pin is
#      git-reference-only — the roadmap's "GitHub-only" conclusion was right even
#      though the PyPI name is now taken.
#   3. The version scheme jumped 0.9.8 -> 0.9.8.1/.2/.3 -> v1.1 (2026-03-26) and
#      is now at v2.x. Since NVD names no fixed release, the floor is set at the
#      1.x line: the 0.9.8 series is what NVD marks affected, and everything from
#      1.0 on postdates the CVE's disclosure. `_semver3` collapses 0.9.8.3 to
#      (0, 9, 8), so the whole 0.9.8 patch line is treated as affected — the
#      conservative reading, since no advisory says which of those carries a fix.
# ---------------------------------------------------------------------------

# Git reference only — deliberately NOT the bare `agent-zero` distribution name.
# The trailing boundary keeps sibling repos under the same org out: without it,
# `agent0ai/agent-zero-plugins` and `agent0ai/agent-zero-clone` both match the
# prefix and get flagged as the vulnerable project.
_AGENT_ZERO_REPO = r'(?:frdel|agent0ai)/agent-zero(?![\w-])'
_AGENT_ZERO_GIT_RE = re.compile(
    r'(?:github:|git\+(?:https?|ssh)://(?:(?!git\+(?:https?|ssh)://)[^"\s])*)?' + _AGENT_ZERO_REPO,
    re.IGNORECASE,
)
# A version-ish ref hanging off that git URL: `...agent-zero@v0.9.8`,
# `...agent-zero.git@0.9.8.3`, `...agent-zero#v1.1`.
_AGENT_ZERO_REF_RE = re.compile(
    _AGENT_ZERO_REPO + r'(?:\.git)?[@#]v?(\d+(?:\.\d+)*)',
    re.IGNORECASE,
)
_AGENT_ZERO_PATCHED = (1, 0, 0)


def _check_agent_zero_pin(project_root: Path, scanned_files: set[str]) -> list[Finding]:
    """Agent Zero git dependency at the 0.9.8 line, or unpinned (CVE-2026-30624)."""
    findings: list[Finding] = []

    def _fire(rel: str, raw: str, why: str, line: int | None) -> None:
        findings.append(make_finding(
            "AAK-AGENT-ZERO-CVE-2026-30624-PIN-001",
            rel,
            f"Agent Zero referenced at {raw!r} — {why}. CVE-2026-30624 (HIGH, "
            "CVSS 8.6): the External MCP Servers feature executes the `command` "
            "and `args` of a user-supplied JSON MCP config without validation, so "
            "a malicious config is remote code execution with the Agent Zero "
            "process's privileges. NVD scopes the CVE to 0.9.8 and names no fixed "
            "release; the project has since moved to the 1.x/2.x line. Move to a "
            "1.0+ tag and do not accept MCP server configs from untrusted sources.",
            line_number=line,
        ))

    candidates: list[Path] = []
    for name in (
        "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock",
        ".mcp.json", "mcp.json", "claude_desktop_config.json",
    ):
        p = project_root / name
        if p.is_file():
            candidates.append(p)
    candidates.extend(sorted(project_root.glob("requirements*.txt")))

    for path in candidates:
        try:
            if _lockfile_over_limit(path):
                continue
            text = _read_capped(path)
        except OSError:
            continue
        if not _AGENT_ZERO_GIT_RE.search(text):
            continue
        rel = str(path.relative_to(project_root))

        ref = _AGENT_ZERO_REF_RE.search(text)
        if ref is None:
            scanned_files.add(rel)
            _fire(
                rel,
                _AGENT_ZERO_GIT_RE.search(text).group(0).strip(),  # type: ignore[union-attr]
                "the git reference carries no tag, so it resolves to whatever "
                "HEAD serves — including the affected 0.9.8 line",
                find_line_number(text, "agent-zero"),
            )
            continue

        version = _semver3(ref.group(1))
        if version is not None and version >= _AGENT_ZERO_PATCHED:
            continue
        scanned_files.add(rel)
        _fire(
            rel,
            ref.group(0).strip(),
            f"pinned at {ref.group(1)}, at or below the affected 0.9.8 line",
            find_line_number(text, ref.group(0)),
        )
    return findings


def _check_chatgpt_mcp_pin(project_root: Path, scanned_files: set[str]) -> list[Finding]:
    findings: list[Finding] = []

    def _fire(rel: str, raw: str) -> None:
        findings.append(make_finding(
            "AAK-CHATGPT-MCP-CVE-2026-7061-PIN-001",
            rel,
            f"chatgpt-mcp-server pinned at {raw!r} — CVE-2026-7061 "
            "(HIGH 7.3) OS command injection in docker.service.ts; no "
            "upstream patch released as of the AAK ship date.",
        ))

    candidates: list[Path] = []
    for name in ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
        p = project_root / name
        if p.is_file():
            candidates.append(p)

    for path in candidates:
        try:
            if _lockfile_over_limit(path):
                continue
            text = _read_capped(path)
        except OSError:
            continue
        if "chatgpt-mcp-server" not in text and "Toowiredd/chatgpt-mcp-server" not in text:
            continue
        rel = str(path.relative_to(project_root))
        # Try JSON-shape pin first (any value — including git URL — is vulnerable
        # because the package has no published patched version).
        m = _CHATGPT_MCP_PACKAGE_RE.search(text)
        if m:
            scanned_files.add(rel)
            _fire(rel, m.group(1).strip())
            continue
        # Fall back to git URL / shorthand match in lockfiles.
        m2 = _CHATGPT_MCP_GIT_RE.search(text)
        if m2:
            scanned_files.add(rel)
            _fire(rel, m2.group(0).strip())
    return findings


# ---------------------------------------------------------------------------
# AAK-DOCSGPT-MCP-STDIO-MITM-001 — arc53/DocsGPT MCP-server STDIO
# command-injection via transport-flip MITM (OX 2026-05-01 disclosure;
# CVE-2026-26015 in the OX MCP-STDIO family).
#
# Two detector arms:
#   1) pin-check on the npm `docsgpt` package + GitHub `arc53/DocsGPT`
#      git refs in package.json / lockfiles + `pip install`-style
#      pyproject.toml / requirements*.txt (DocsGPT is published on
#      both registries — npm latest was vulnerable until vendor fix).
#   2) Source detector → see scanners/docsgpt_transport_flip.py for
#      the server-config arm (`transports: ["sse"]` configs that don't
#      reject `transport=stdio` overrides post-handshake).
#
# Architectural class is already covered by AAK-MCP-STDIO-CMD-INJ-001/
# 002/003/004 + AAK-STDIO-001 (shipped in v0.3.6, see _OX_MCP_STDIO_CVES);
# this rule adds the product-named pin row consumers expect when
# grepping CHANGELOG.cves.md for "DocsGPT".
# Closes the OX MCP 2026-05-01 batch carry-list item from v0.3.12.
# ---------------------------------------------------------------------------

# DocsGPT npm latest at OX-disclosure time was 0.6.3; vendor fix lands
# in 0.6.4+. We pin-fire below the patched floor; if the package isn't
# present at all we silently pass.
_DOCSGPT_PATCHED: tuple[int, int, int] = (0, 6, 4)
_DOCSGPT_PACKAGE_JSON_RE = re.compile(
    r'"docsgpt(?:-mcp)?"\s*:\s*"([^"]+)"',
    re.IGNORECASE,
)
_DOCSGPT_LOCKLINE_RE = re.compile(
    r'\bdocsgpt(?:-mcp)?@([~^>=<\s]*[0-9][\w.\-]*)',
    re.IGNORECASE,
)
_DOCSGPT_GIT_RE = re.compile(
    r'(?:github:|git\+https?://(?:(?!git\+https?://)[^"\s])*)?arc53/DocsGPT',
    re.IGNORECASE,
)
_DOCSGPT_PYTHON_RE = re.compile(
    r"\bdocsgpt(?:-mcp)?" + _PY_VERSION_TAIL,
    re.IGNORECASE,
)


def _check_docsgpt_mcp_pin(project_root: Path, scanned_files: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()

    def _fire(rel: str, raw: str) -> None:
        if rel in seen:
            return
        seen.add(rel)
        findings.append(make_finding(
            "AAK-DOCSGPT-MCP-STDIO-MITM-001",
            rel,
            f"docsgpt pinned at {raw!r} — OX MCP 2026-05-01 disclosure "
            f"(CVE-2026-26015 family); patched in >=0.6.4. Class also "
            f"covered by AAK-MCP-STDIO-CMD-INJ-001..004.",
        ))

    # npm manifests
    for name in ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
        p = project_root / name
        if not p.is_file():
            continue
        try:
            if _lockfile_over_limit(p):
                continue
            text = _read_capped(p)
        except OSError:
            continue
        if "docsgpt" not in text.lower() and "arc53/DocsGPT" not in text:
            continue
        rel = str(p.relative_to(project_root))
        # Git-URL / GitHub-shorthand wins first — every git ref to
        # arc53/DocsGPT is unpatched until the user explicitly tracks
        # a tagged release post-0.6.4.
        m3 = _DOCSGPT_GIT_RE.search(text)
        if m3:
            scanned_files.add(rel)
            _fire(rel, m3.group(0).strip())
            continue
        m = _DOCSGPT_PACKAGE_JSON_RE.search(text)
        if m:
            raw = m.group(1).strip()
            # Strip any leading semver-range operator (^, ~, >=, etc.)
            # before parsing so safe pins like "^0.6.4" don't fail the
            # _semver3 regex and false-fire.
            stripped = re.sub(r"^[~^>=<\s]+", "", raw)
            version = _semver3(stripped)
            if version is not None and version < _DOCSGPT_PATCHED:
                scanned_files.add(rel)
                _fire(rel, raw)
                continue
        m2 = _DOCSGPT_LOCKLINE_RE.search(text)
        if m2:
            raw = m2.group(1).strip()
            stripped = re.sub(r"^[~^>=<\s]+", "", raw)
            version = _semver3(stripped)
            if version is not None and version < _DOCSGPT_PATCHED:
                scanned_files.add(rel)
                _fire(rel, raw)

    # Python manifests (DocsGPT ships an MCP server bridge as a Python pkg too)
    candidates: list[Path] = list(project_root.glob("requirements*.txt"))
    for name in ("pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock"):
        p = project_root / name
        if p.is_file():
            candidates.append(p)
    for path in candidates:
        try:
            if _lockfile_over_limit(path):
                continue
            text = _read_capped(path)
        except OSError:
            continue
        if "docsgpt" not in text.lower():
            continue
        rel = str(path.relative_to(project_root))
        m = _DOCSGPT_PYTHON_RE.search(text)
        if m:
            raw = m.group(1).strip()
            version = _semver3(raw)
            if version is None or version < _DOCSGPT_PATCHED:
                scanned_files.add(rel)
                _fire(rel, raw)
    return findings


# ---------------------------------------------------------------------------
# AAK-MCPCALC-CVE-2026-44717-PIN-001 — MCP Calculate Server <0.1.1
# (CVE-2026-44717, CRITICAL CVSS 9.8). Tool handler routes
# user-supplied math expressions through `eval()` (SymPy-backed
# without `local_dict`/`global_dict` pinning), reaching RCE.
# Patched in 0.1.1 (latest at AAK ship time: 1.0.0). Pin-only arm;
# a source-detector for `eval()` inside MCP `@tool` handlers
# generally was scoped for v0.3.19 and never written. Recorded as a
# known gap rather than a pending version: this pin catches the
# package, not the shape, so another single-author MCP server with
# the same `eval()` handler is not covered by it.
# Disclosed by NVD on 2026-05-15.
# ---------------------------------------------------------------------------

_MCP_CALC_PATCHED = (0, 1, 1)
_MCP_CALC_PYTHON_RE = re.compile(
    r"\bmcp[-_]calculate[-_]server" + _PY_VERSION_TAIL,
    re.IGNORECASE,
)


def _check_mcp_calculate_server_pin(project_root: Path, scanned_files: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()

    def _fire(rel: str, raw: str) -> None:
        if rel in seen:
            return
        seen.add(rel)
        findings.append(make_finding(
            "AAK-MCPCALC-CVE-2026-44717-PIN-001",
            rel,
            f"mcp-calculate-server pinned at {raw!r} — CVE-2026-44717 "
            f"eval() RCE in MCP tool handler (CVSS 9.8 CRITICAL); "
            f"patched in 0.1.1 (NVD 2026-05-15).",
        ))

    candidates: list[Path] = list(project_root.glob("requirements*.txt"))
    for name in ("pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock"):
        p = project_root / name
        if p.is_file():
            candidates.append(p)

    for path in candidates:
        try:
            if _lockfile_over_limit(path):
                continue
            text = _read_capped(path)
        except OSError:
            continue
        low = text.lower()
        if "mcp-calculate-server" not in low and "mcp_calculate_server" not in low:
            continue
        rel = str(path.relative_to(project_root))
        m = _MCP_CALC_PYTHON_RE.search(text)
        if m:
            raw = m.group(1).strip()
            stripped = re.sub(r"^[~^>=<\s]+", "", raw)
            version = _semver3(stripped)
            if version is not None and version < _MCP_CALC_PATCHED:
                scanned_files.add(rel)
                _fire(rel, raw)
    return findings


# ---------------------------------------------------------------------------
# AAK-SK-INMEMORY-VECTORSTORE-FILTER-CVE-2026-26030-PIN-001 — Microsoft
# Semantic Kernel Python SDK <1.39.4 (CVE-2026-26030, CRITICAL CVSS 9.9).
# RCE via the InMemoryVectorStore filter functionality. Patched in
# `python-1.39.4`. The companion .NET CVE (CVE-2026-25592, file-write
# in SessionsPythonPlugin, patched in .NET 1.71.0) is OUT OF SCOPE
# for AAK — we don't currently scan NuGet manifests; only the Python
# pin shape is actionable here.
#
# MSRC disclosure: 2026-05-07. AAK rule shipped: 2026-05-10 — three days
# for the Python SDK arm. A dated measurement, not a service level: this
# project publishes no CVE-response SLA (retired in PR #432; see the note
# at the top of CHANGELOG.cves.md). Current latency is published, and
# recomputed, on the coverage page.
# ---------------------------------------------------------------------------

_SEMANTIC_KERNEL_PATCHED = (1, 39, 4)
_SEMANTIC_KERNEL_PYTHON_RE = re.compile(
    r"\bsemantic[-_]kernel" + _PY_VERSION_TAIL,
    re.IGNORECASE,
)


def _check_semantic_kernel_pin(project_root: Path, scanned_files: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()

    def _fire(rel: str, raw: str) -> None:
        if rel in seen:
            return
        seen.add(rel)
        findings.append(make_finding(
            "AAK-SK-INMEMORY-VECTORSTORE-FILTER-CVE-2026-26030-PIN-001",
            rel,
            f"semantic-kernel pinned at {raw!r} — CVE-2026-26030 RCE in "
            f"InMemoryVectorStore filter functionality (CVSS 9.9 CRITICAL); "
            f"patched in 1.39.4 (MSRC 2026-05-07).",
        ))

    candidates: list[Path] = list(project_root.glob("requirements*.txt"))
    for name in ("pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock"):
        p = project_root / name
        if p.is_file():
            candidates.append(p)

    for path in candidates:
        try:
            if _lockfile_over_limit(path):
                continue
            text = _read_capped(path)
        except OSError:
            continue
        if "semantic-kernel" not in text.lower() and "semantic_kernel" not in text.lower():
            continue
        rel = str(path.relative_to(project_root))
        m = _SEMANTIC_KERNEL_PYTHON_RE.search(text)
        if m:
            raw = m.group(1).strip()
            stripped = re.sub(r"^[~^>=<\s]+", "", raw)
            version = _semver3(stripped)
            if version is not None and version < _SEMANTIC_KERNEL_PATCHED:
                scanned_files.add(rel)
                _fire(rel, raw)
    return findings


# ---------------------------------------------------------------------------
# AAK-CLAUDECODE-CVE-2026-40068-PIN-001 — Anthropic Claude Code <2.1.84
# (CVE-2026-40068, HIGH). Folder-trust determination uses the git
# worktree `commondir` file without validating its contents — a
# malicious repo with a crafted `commondir` pointing to a previously-
# trusted path bypasses the trust prompt. Vendor patched in 2.1.84
# (GHSA-q5hj-mxqh-vv77, affected from 2.1.63; this pin said 2.1.83 until
# 2026-10-16); named pin row was pre-allocated in the v0.3.15 triage of #181.
# Pin-arm only — Claude Code is a binary product, not a source shape
# we statically scan. Closes the v0.3.15 deferral.
#
# Floor raised 2.1.83 -> 2.1.129 on 2026-10-08 for CVE-2026-103435 (HIGH,
# CVSS 4.0 7.7, GHSA-5j29-h97v-84ch): the write path re-resolved a file that
# the permission check had placed inside the project, so a symlink swapped in
# between redirected the write outside it. Same package and severity, a higher
# fix, so the floor moves.
#
# Floor raised 2.1.129 -> 2.1.179 on 2026-10-16 for CVE-2026-86063 (HIGH, CVSS
# 4.0 7.5, GHSA-pq7j-f95f-qfcv): the plugin install flow checked out a
# marketplace-pinned commit without checking that HEAD then equalled the pinned
# SHA, so a branch named after that SHA installed its own tip. Commit pins
# arrived in 2.1.14 (the CHANGELOG's "Added support for pinning plugins to
# specific git commit SHAs"), so every release from the old floor up is
# affected. The evidence names each bug only in the range it applies to.
# ---------------------------------------------------------------------------

_CLAUDECODE_PATCHED = (2, 1, 179)
_CLAUDECODE_SYMLINK_PATCHED = (2, 1, 129)
_CLAUDECODE_TRUST_INTRODUCED = (2, 1, 63)
_CLAUDECODE_TRUST_PATCHED = (2, 1, 84)
_CLAUDECODE_PLUGIN_PIN_INTRODUCED = (2, 1, 14)
# Scoped npm package name. Both the JSON-shape (package.json /
# package-lock.json `packages` map keys) and the lockfile-line shape
# (yarn.lock / pnpm-lock.yaml) handle the `@anthropic-ai/claude-code`
# slug — including the lockfile-key form `node_modules/@anthropic-ai/
# claude-code`.
_CLAUDECODE_PACKAGE_JSON_RE = re.compile(
    r'"@anthropic-ai/claude-code"\s*:\s*"([^"]+)"',
    re.IGNORECASE,
)
_CLAUDECODE_LOCKLINE_RE = re.compile(
    r'@anthropic-ai/claude-code@([~^>=<\s]*[0-9][\w.\-]*)',
    re.IGNORECASE,
)


def _check_claudecode_pin(project_root: Path, scanned_files: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()

    def _fire(rel: str, raw: str, version: tuple[int, int, int]) -> None:
        if rel in seen:
            return
        seen.add(rel)
        defects: list[str] = []
        if _CLAUDECODE_TRUST_INTRODUCED <= version < _CLAUDECODE_TRUST_PATCHED:
            defects.append(
                "CVE-2026-40068 folder-trust bypass via git worktree commondir "
                "(fixed in 2.1.84)"
            )
        if version < _CLAUDECODE_SYMLINK_PATCHED:
            defects.append(
                "CVE-2026-103435 write-time symlink following (fixed in 2.1.129)"
            )
        if version >= _CLAUDECODE_PLUGIN_PIN_INTRODUCED:
            defects.append(
                "CVE-2026-86063 plugin commit-pin bypass (fixed in 2.1.179)"
            )
        # Below the floor a release is either below 2.1.129 or has commit pins,
        # so the list is never empty.
        listed = defects[-1] if len(defects) == 1 else (
            ", ".join(defects[:-1]) + " and " + defects[-1]
        )
        findings.append(make_finding(
            "AAK-CLAUDECODE-CVE-2026-40068-PIN-001",
            rel,
            f"@anthropic-ai/claude-code pinned at {raw!r} — {listed}.",
        ))

    for name in ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
        p = project_root / name
        if not p.is_file():
            continue
        try:
            if _lockfile_over_limit(p):
                continue
            text = _read_capped(p)
        except OSError:
            continue
        if "@anthropic-ai/claude-code" not in text:
            continue
        rel = str(p.relative_to(project_root))
        m = _CLAUDECODE_PACKAGE_JSON_RE.search(text)
        if m:
            raw = m.group(1).strip()
            stripped = re.sub(r"^[~^>=<\s]+", "", raw)
            version = _semver3(stripped)
            if version is not None and version < _CLAUDECODE_PATCHED:
                scanned_files.add(rel)
                _fire(rel, raw, version)
                continue
        m2 = _CLAUDECODE_LOCKLINE_RE.search(text)
        if m2:
            raw = m2.group(1).strip()
            stripped = re.sub(r"^[~^>=<\s]+", "", raw)
            version = _semver3(stripped)
            if version is not None and version < _CLAUDECODE_PATCHED:
                scanned_files.add(rel)
                _fire(rel, raw, version)
    return findings


# ---------------------------------------------------------------------------
# AAK-GPTRESEARCHER-MCP-STDIO-MITM-001 — assafelovic/gpt-researcher (CVE-
# 2025-65720, OX 2026-05-01 disclosure batch). Python-first project; npm
# / git refs also valid surfaces. Latest PyPI release at the time of
# the disclosure is 0.14.8 (2026-03-13), pre-disclosure — vendor has
# not shipped a post-disclosure fix as of the AAK ship date. Same
# `patched_in: None` posture as astro-mcp / chatgpt-mcp.
#
# Pairs with `agent_audit_kit/scanners/gpt_researcher_transport_flip.py`
# for the config-side transport-flip detection arm. The architectural
# class is already covered by AAK-MCP-STDIO-CMD-INJ-001 (Python).
# Closes Phase 2 / row GPT-Researcher of the OX MCP 2026-05-01 batch
# (issue #159).
# ---------------------------------------------------------------------------

# `None` means "no fix released yet — every published version is in scope".
_GPT_RESEARCHER_PATCHED: tuple[int, int, int] | None = None
_GPT_RESEARCHER_PACKAGE_JSON_RE = re.compile(
    r'"gpt-researcher(?:-mcp)?"\s*:\s*"([^"]+)"',
    re.IGNORECASE,
)
_GPT_RESEARCHER_LOCKLINE_RE = re.compile(
    r'\bgpt-researcher(?:-mcp)?@([~^>=<\s]*[0-9][\w.\-]*)',
    re.IGNORECASE,
)
_GPT_RESEARCHER_GIT_RE = re.compile(
    r'(?:github:|git\+https?://(?:(?!git\+https?://)[^"\s])*)?assafelovic/gpt-researcher',
    re.IGNORECASE,
)
_GPT_RESEARCHER_PYTHON_RE = re.compile(
    r"\bgpt[-_]researcher(?:-mcp)?" + _PY_VERSION_TAIL,
    re.IGNORECASE,
)


def _check_gpt_researcher_mcp_pin(project_root: Path, scanned_files: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()

    def _fire(rel: str, raw: str) -> None:
        if rel in seen:
            return
        seen.add(rel)
        findings.append(make_finding(
            "AAK-GPTRESEARCHER-MCP-STDIO-MITM-001",
            rel,
            f"gpt-researcher pinned at {raw!r} — OX MCP 2026-05-01 "
            f"disclosure (CVE-2025-65720); no upstream patch published "
            f"as of the AAK ship date. Class also covered by "
            f"AAK-MCP-STDIO-CMD-INJ-001.",
        ))

    # Python manifests — primary surface (gpt-researcher is on PyPI).
    candidates: list[Path] = list(project_root.glob("requirements*.txt"))
    for name in ("pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock"):
        p = project_root / name
        if p.is_file():
            candidates.append(p)
    for path in candidates:
        try:
            if _lockfile_over_limit(path):
                continue
            text = _read_capped(path)
        except OSError:
            continue
        if "gpt-researcher" not in text.lower() and "gpt_researcher" not in text.lower():
            continue
        rel = str(path.relative_to(project_root))
        m = _GPT_RESEARCHER_PYTHON_RE.search(text)
        if m:
            raw = m.group(1).strip()
            stripped = re.sub(r"^[~^>=<\s]+", "", raw)
            version = _semver3(stripped)
            if _GPT_RESEARCHER_PATCHED is None or (version is not None and version < _GPT_RESEARCHER_PATCHED):
                scanned_files.add(rel)
                _fire(rel, raw)

    # npm manifests (less common but valid — gpt-researcher-mcp wrapper)
    for name in ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
        p = project_root / name
        if not p.is_file():
            continue
        try:
            if _lockfile_over_limit(p):
                continue
            text = _read_capped(p)
        except OSError:
            continue
        low = text.lower()
        if "gpt-researcher" not in low and "assafelovic/gpt-researcher" not in text:
            continue
        rel = str(p.relative_to(project_root))
        m3 = _GPT_RESEARCHER_GIT_RE.search(text)
        if m3:
            scanned_files.add(rel)
            _fire(rel, m3.group(0).strip())
            continue
        m = _GPT_RESEARCHER_PACKAGE_JSON_RE.search(text)
        if m:
            raw = m.group(1).strip()
            stripped = re.sub(r"^[~^>=<\s]+", "", raw)
            version = _semver3(stripped)
            if _GPT_RESEARCHER_PATCHED is None or (version is not None and version < _GPT_RESEARCHER_PATCHED):
                scanned_files.add(rel)
                _fire(rel, raw)
                continue
        m2 = _GPT_RESEARCHER_LOCKLINE_RE.search(text)
        if m2:
            raw = m2.group(1).strip()
            stripped = re.sub(r"^[~^>=<\s]+", "", raw)
            version = _semver3(stripped)
            if _GPT_RESEARCHER_PATCHED is None or (version is not None and version < _GPT_RESEARCHER_PATCHED):
                scanned_files.add(rel)
                _fire(rel, raw)
    return findings


def _check_litellm_pin(project_root: Path, scanned_files: set[str]) -> list[Finding]:
    findings: list[Finding] = []

    def _fire(rel: str, raw: str) -> None:
        findings.append(make_finding(
            "AAK-LITELLM-CVE-2026-30623-PIN-001", rel,
            f"litellm pinned at {raw!r} — CVE-2026-30623 patched in "
            "1.83.7 (BerriAI/litellm 2026-04-30).",
        ))

    candidates: list[Path] = []
    candidates.extend(project_root.glob("requirements*.txt"))
    for name in ("pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock"):
        p = project_root / name
        if p.is_file():
            candidates.append(p)

    for path in candidates:
        text = _read_pin_candidate(path)
        if text is None:
            continue
        raw = _affected_pin(path, text, ("litellm",), _LITELLM_PATCHED, requires_version=True)
        if raw is not None:
            rel = str(path.relative_to(project_root))
            scanned_files.add(rel)
            _fire(rel, raw)
    return findings
