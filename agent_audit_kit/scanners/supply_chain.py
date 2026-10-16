from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import (
    find_line_number,
    in_skip_dir,
    iter_mcp_servers,
    loads_jsonc,
    make_finding,
)
from agent_audit_kit.scanners._launchers import invocation_packages, launch_evidence, pin_problem
from agent_audit_kit.scanners._manifest_deps import MAX_LOCKFILE_BYTES, MAX_MANIFEST_BYTES

# Known vulnerable packages: ecosystem -> name -> affected version range
# Covers npm, Python (PyPI), and Rust (crates.io)
KNOWN_VULNERABLE_PACKAGES: dict[str, dict[str, dict[str, str]]] = {
    "npm": {
        "axios": {
            "affected": ">=1.7.0 <1.7.4",
            "description": "Claude Code supply chain compromise (March 31 2026)",
        },
        "openclaw": {
            "affected": "<2.1.0",
            "description": "104 CVEs catalogued by Adversa AI",
        },
    },
    # No PyPI entry. The table listed `openclaw` here too, but OpenClaw ships on
    # npm only, and the PyPI project of that name (2.0.1 and 2.0.2) is an
    # unrelated installer for the cmdop CLI, so `openclaw==2.0.2` was reported as
    # 104 OpenClaw CVEs. The reader below stays for entries a PyPI package earns.
    "python": {},
    "rust": {},
}

# Typosquat patterns for popular MCP server packages
TYPOSQUAT_PATTERNS = [
    re.compile(r"modelcontextprotocal", re.IGNORECASE),  # typo of "protocol"
    re.compile(r"mcp-server-[a-z]+-[a-z]+", re.IGNORECASE),  # suspicious double-hyphen patterns
    re.compile(r"@modlecontextprotocol", re.IGNORECASE),  # typo of "model"
]

# Install script keys in package.json
INSTALL_SCRIPTS = {"preinstall", "postinstall", "prepare", "install"}

# Network commands in install scripts
NETWORK_IN_SCRIPTS = re.compile(
    r"\b(curl|wget|fetch|nc|ncat|ssh|http|axios|request)\b", re.IGNORECASE
)

# Package fetchers for MCP config
PACKAGE_FETCHERS = frozenset({"npx", "uvx", "bunx", "pnpx"})


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
    mcp_files = [
        project_root / ".mcp.json",
        project_root / ".cursor" / "mcp.json",
        project_root / ".vscode" / "mcp.json",
        project_root / ".amazonq" / "mcp.json",
        project_root / "mcp.json",
    ]

    for mcp_path in mcp_files:
        if not mcp_path.is_file():
            continue
        try:
            raw = mcp_path.read_text(encoding="utf-8")
            data = loads_jsonc(raw)
        except (json.JSONDecodeError, UnicodeDecodeError, OSError):
            continue

        rel_path = str(mcp_path.relative_to(project_root))
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
                    findings.append(_make_finding(
                        "AAK-SUPPLY-001", rel_path,
                        launch_evidence(server_name, launched.spec, problem),
                        _find_line_number(raw, launched.spec),
                    ))
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
        raw = lockfile.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (json.JSONDecodeError, OSError):
        return findings

    rel_path = str(lockfile.relative_to(project_root))

    # Check packages in lockfile v2/v3 format
    packages = data.get("packages", {})
    if not packages:
        # Try lockfile v1 format
        packages = data.get("dependencies", {})

    dep_count = len(packages)

    for pkg_path, pkg_info in packages.items():
        if not isinstance(pkg_info, dict):
            continue
        # Extract package name from path (e.g., "node_modules/axios" -> "axios")
        pkg_name = pkg_path.split("node_modules/")[-1] if "node_modules/" in pkg_path else pkg_path
        if not pkg_name:
            continue

        version = pkg_info.get("version", "")
        npm_vulns = KNOWN_VULNERABLE_PACKAGES.get("npm", {})
        if pkg_name in npm_vulns and version:
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


def _scan_package_json(project_root: Path) -> list[Finding]:
    """Check package.json for install scripts (AAK-SUPPLY-003)."""
    findings: list[Finding] = []
    pkg_json = project_root / "package.json"
    if not pkg_json.is_file():
        return findings

    try:
        raw = pkg_json.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (json.JSONDecodeError, OSError):
        return findings

    rel_path = str(pkg_json.relative_to(project_root))
    scripts = data.get("scripts", {})
    if isinstance(scripts, dict):
        for script_name, script_cmd in scripts.items():
            if script_name in INSTALL_SCRIPTS and isinstance(script_cmd, str):
                if NETWORK_IN_SCRIPTS.search(script_cmd) or not _is_safe_script(script_cmd):
                    findings.append(_make_finding(
                        "AAK-SUPPLY-003", rel_path,
                        f"scripts.{script_name}: {script_cmd}",
                        _find_line_number(raw, script_name),
                    ))

    return findings


def _is_safe_script(cmd: str) -> bool:
    """Check if an install script is likely safe (build tools only)."""
    safe_patterns = {"tsc", "node", "npm run build", "npx", "webpack", "rollup", "esbuild", "vite"}
    cmd_lower = cmd.strip().lower()
    return any(cmd_lower.startswith(p) for p in safe_patterns)


def _check_lockfile_exists(project_root: Path) -> list[Finding]:
    """AAK-SUPPLY-004: Check that lockfiles exist for package manifests."""
    findings: list[Finding] = []

    npm_manifest = project_root / "package.json"
    if npm_manifest.is_file():
        has_lock = any(
            (project_root / lf).is_file()
            for lf in ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"]
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
            raw = req_file.read_text(encoding="utf-8")
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
                raw = pipfile_lock.read_text(encoding="utf-8")
                data = json.loads(raw)
                rel_path = str(pipfile_lock.relative_to(project_root))
                for section in ["default", "develop"]:
                    pkgs = data.get(section, {})
                    if not isinstance(pkgs, dict):
                        continue
                    for pkg_name, pkg_info in pkgs.items():
                        if not isinstance(pkg_info, dict):
                            continue
                        version = pkg_info.get("version", "").lstrip("=")
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
    """Check Cargo.lock for known vulnerable packages (AAK-SUPPLY-002)."""
    findings: list[Finding] = []
    rust_vulns = KNOWN_VULNERABLE_PACKAGES.get("rust", {})

    cargo_lock = project_root / "Cargo.lock"
    if not cargo_lock.is_file():
        return findings

    try:
        if cargo_lock.stat().st_size > MAX_LOCKFILE_BYTES:
            return findings
        raw = cargo_lock.read_text(encoding="utf-8")
    except OSError:
        return findings

    rel_path = str(cargo_lock.relative_to(project_root))

    # Parse TOML-style Cargo.lock: [[package]] blocks
    current_name = ""
    current_version = ""
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
            current_name = ""
            current_version = ""
            dep_count += 1
        elif line.startswith('name = "'):
            current_name = line.split('"')[1]
        elif line.startswith('version = "'):
            current_version = line.split('"')[1]

    # Check last package
    if current_name and current_version and current_name in rust_vulns:
        vuln_info = rust_vulns[current_name]
        if _version_in_range(current_version, vuln_info["affected"]):
            findings.append(_make_finding(
                "AAK-SUPPLY-002", rel_path,
                f"{current_name}@{current_version} — {vuln_info['description']}",
                _find_line_number(raw, current_name),
            ))

    # AAK-SUPPLY-005 for Rust
    if dep_count > 200:
        findings.append(_make_finding(
            "AAK-SUPPLY-005", rel_path,
            f"{dep_count} dependencies (threshold: 200)",
        ))

    # Also check Cargo.toml lockfile existence
    cargo_toml = project_root / "Cargo.toml"
    if cargo_toml.is_file() and not cargo_lock.is_file():
        findings.append(_make_finding(
            "AAK-SUPPLY-004",
            str(cargo_toml.relative_to(project_root)),
            "Cargo.toml exists but no Cargo.lock found",
        ))

    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    # Track which files exist and were scanned
    for candidate in [
        ".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".amazonq/mcp.json", "mcp.json",
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
    findings.extend(_check_kong_konnect_mcp_pin(project_root, scanned_files))
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
_DORIS_VERSION_RE = re.compile(
    r"apache-doris-mcp-server" + _PY_VERSION_TAIL,
    re.IGNORECASE,
)


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


def _resolve_lockfile_version(
    text: str, filename: str, names: tuple[str, ...]
) -> tuple[int, int, int] | None:
    """Lowest resolved version of any of ``names`` in a lockfile, or None if the
    package is absent / unparseable (conservative — a `None` result means the
    pin does not fire on this lockfile)."""
    resolved = _resolve_lockfile_versions(text, filename, names)
    return min(resolved) if resolved else None


def _resolve_lockfile_versions(
    text: str, filename: str, names: tuple[str, ...]
) -> list[tuple[int, int, int]]:
    """Every resolved version of any of ``names`` in a lockfile, lowest first.

    A lockfile can resolve one package to several versions: pnpm and Yarn keep
    one entry per distinct range that resolved differently, and uv one per
    marker fork. Judging only the lowest misses an affected version above it
    whenever the lowest sits below a pin's `introduced` bound, which is the
    "first match decides" mistake the manifest reader stopped making.
    """
    return _lockfile_lookup(_lockfile_index(text, filename), filename, names)


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


def _lockfile_index(text: str, filename: str) -> dict[str, list[tuple[int, int, int]]]:
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
            data = json.loads(text)
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
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _DORIS_VERSION_RE.finditer(text):
            version = _semver3(m.group(1))
            if version is None or version < _DORIS_PATCHED:
                rel = str(path.relative_to(project_root))
                scanned_files.add(rel)
                _fire(rel, m.group(1))
                break  # one finding per file is enough
    return findings


# ---------------------------------------------------------------------------
# AAK-MCP-KONG-CVE-2026-13341-001 — Kong Konnect MCP server < 1.0.0.
# Indirect prompt injection (CVE-2026-13341, HIGH 7.4, published 2026-07-03):
# untrusted content the server relays carries instructions the agent acts on,
# issuing unintended Konnect/Admin API requests. Fixed in 1.0.0. Detected as a
# version pin across dependency manifests AND MCP config files (the server is
# commonly launched from `.mcp.json` / `claude_desktop_config.json`).
# ---------------------------------------------------------------------------

_KONG_KONNECT_PATCHED = (1, 0, 0)
# Match the Konnect MCP package/command with an optional adjacent version.
_KONG_KONNECT_MCP_RE = re.compile(
    r"(?:@kong/|kong[-_/])?konnect[-_]?mcp(?:[-_]server)?"
    r"\s*(?:==|>=|~=|<=|<|>|@|:|\"?\s*version\"?\s*[:=])?\s*v?([0-9][\w.\-]*)?",
    re.IGNORECASE,
)


def _check_kong_konnect_mcp_pin(project_root: Path, scanned_files: set[str]) -> list[Finding]:
    findings: list[Finding] = []

    def _fire(rel: str, raw: str | None) -> None:
        shown = f"{raw!r}" if raw else "unpinned"
        findings.append(make_finding(
            "AAK-MCP-KONG-CVE-2026-13341-001",
            rel,
            f"Kong Konnect MCP server referenced at {shown} — CVE-2026-13341 "
            "indirect prompt injection (unintended Konnect/Admin API requests) "
            "is fixed in 1.0.0; pin >= 1.0.0.",
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
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        m = _KONG_KONNECT_MCP_RE.search(text)
        if not m:
            continue
        raw = m.group(1)
        version = _semver3(raw) if raw else None
        # Fire when the version is below 1.0.0, or when it cannot be proven
        # to be >= 1.0.0 (unpinned reference).
        if version is None or version < _KONG_KONNECT_PATCHED:
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
_MCP_GATEWAY_REGISTRY_RE = re.compile(
    r"mcp-gateway-registry"
    r"\s*(?:==|>=|~=|<=|<|>|@|:|\"?\s*version\"?\s*[:=])?\s*v?([0-9][\w.\-]*)?",
    re.IGNORECASE,
)


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
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        m = _MCP_GATEWAY_REGISTRY_RE.search(text)
        if not m:
            continue
        raw = m.group(1)
        version = _semver3(raw) if raw else None
        if version is None or version < _MCP_GATEWAY_REGISTRY_PATCHED:
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
_SERENA_RE = re.compile(
    r"(?:serena-agent|serena-mcp-server|oraios/serena)"
    r"\s*(?:==|>=|~=|<=|<|>|@|:|\"?\s*version\"?\s*[:=])?\s*v?([0-9][\w.\-]*)?",
    re.IGNORECASE,
)


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
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(project_root))
        if path.name.lower() in _LOCKFILES:
            # Resolve the locked version; fire only when it is below the fix
            # floor, so a correct upgrade + re-lock clears the finding.
            resolved = _resolve_lockfile_version(
                text, path.name.lower(), ("serena-agent", "serena-mcp-server")
            )
            if resolved is not None and resolved < _SERENA_PATCHED:
                scanned_files.add(rel)
                _fire(rel, ".".join(str(x) for x in resolved))
            continue
        m = _SERENA_RE.search(text)
        if not m:
            continue
        raw = m.group(1)
        version = _semver3(raw) if raw else None
        if version is None or version < _SERENA_PATCHED:
            scanned_files.add(rel)
            _fire(rel, raw)
    return findings


# ---------------------------------------------------------------------------
# AAK-EXCEL-MCP-001 — excel-mcp-server <= 0.1.7 (CVE-2026-40576).
# Path-traversal in get_excel_path(). Fixed in 0.1.8.
# ---------------------------------------------------------------------------

_EXCEL_FIRST_PATCHED = (0, 1, 8)
_EXCEL_VERSION_RE = re.compile(
    r"excel-mcp-server" + _PY_VERSION_TAIL,
    re.IGNORECASE,
)


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
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _EXCEL_VERSION_RE.finditer(text):
            version = _semver3(m.group(1))
            if version is None or version < _EXCEL_FIRST_PATCHED:
                rel = str(path.relative_to(project_root))
                scanned_files.add(rel)
                _fire(rel, m.group(1))
                break
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
            text = path.read_text(encoding="utf-8", errors="replace")
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


# The configs AAK-SUPPLY-006 reads: the root .mcp.json, and VS Code's
# .vscode/mcp.json, which keeps its servers under `servers`. Until both maps were
# read through `iter_mcp_servers` the rule saw only `mcpServers` in .mcp.json, so
# a vulnerable package launched from VS Code was never looked up.
_SUPPLY_006_CONFIGS = (".mcp.json", ".vscode/mcp.json")


def _check_mcp_specific_vulns(project_root: Path) -> list[Finding]:
    """AAK-SUPPLY-006: Check MCP server packages against vuln DB."""
    findings: list[Finding] = []
    try:
        from agent_audit_kit.vuln_db import load_database
        db = load_database()
    except ImportError:
        return findings

    npm_vulns = db.get("npm", {})
    for name in _SUPPLY_006_CONFIGS:
        mcp_path = project_root / name
        if not mcp_path.is_file():
            continue
        try:
            data = loads_jsonc(mcp_path.read_text(encoding="utf-8"))
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
            text = path.read_text(encoding="utf-8", errors="replace")
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
            text = path.read_text(encoding="utf-8", errors="replace")
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
_LITELLM_VERSION_RE = re.compile(
    r"(?<![\w-])litellm" + _PY_VERSION_TAIL,
    re.IGNORECASE,
)


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
            text = path.read_text(encoding="utf-8", errors="replace")
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
            text = path.read_text(encoding="utf-8", errors="replace")
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
            text = p.read_text(encoding="utf-8", errors="replace")
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
            text = path.read_text(encoding="utf-8", errors="replace")
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
            text = path.read_text(encoding="utf-8", errors="replace")
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
            text = path.read_text(encoding="utf-8", errors="replace")
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
            text = p.read_text(encoding="utf-8", errors="replace")
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
            text = path.read_text(encoding="utf-8", errors="replace")
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
            text = p.read_text(encoding="utf-8", errors="replace")
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
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _LITELLM_VERSION_RE.finditer(text):
            version = _semver3(m.group(1))
            if version is None or version < _LITELLM_PATCHED:
                rel = str(path.relative_to(project_root))
                scanned_files.add(rel)
                _fire(rel, m.group(1))
                break  # one finding per file is enough
    return findings
