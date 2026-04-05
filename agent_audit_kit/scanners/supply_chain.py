from __future__ import annotations

import json
import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding

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
    "python": {
        "openclaw": {
            "affected": "<2.1.0",
            "description": "104 CVEs catalogued by Adversa AI",
        },
    },
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
            data = json.loads(raw)
        except (json.JSONDecodeError, OSError):
            continue

        rel_path = str(mcp_path.relative_to(project_root))
        servers = data.get("mcpServers", {})
        if not isinstance(servers, dict):
            continue

        for server_name, server_cfg in servers.items():
            if not isinstance(server_cfg, dict):
                continue
            command = server_cfg.get("command", "")
            args = server_cfg.get("args", [])

            if not command or command.strip().split()[0] not in PACKAGE_FETCHERS:
                continue

            if isinstance(args, list):
                for arg in args:
                    if isinstance(arg, str) and not arg.startswith("-"):
                        # Skip path-like arguments (filesystem paths, not package names)
                        if arg.startswith("/") or arg.startswith("./") or arg.startswith("../"):
                            continue
                        has_version = False
                        if arg.startswith("@"):
                            # Scoped package: @org/pkg@version
                            parts = arg.split("@")
                            has_version = len(parts) >= 3 and bool(parts[2])
                        elif "@" in arg:
                            has_version = True
                        if not has_version:
                            findings.append(_make_finding(
                                "AAK-SUPPLY-001", rel_path,
                                f"Server '{server_name}' arg: {arg} (no version pin)",
                                _find_line_number(raw, arg),
                            ))
    return findings


def _scan_npm_lockfile(project_root: Path) -> list[Finding]:
    """Check package-lock.json for known vulnerable packages (AAK-SUPPLY-002)."""
    findings: list[Finding] = []
    lockfile = project_root / "package-lock.json"
    if not lockfile.is_file():
        return findings

    try:
        raw = lockfile.read_text(encoding="utf-8")
        if len(raw) > 1_000_000:
            return findings
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
            raw = req_file.read_text(encoding="utf-8")
            if len(raw) > 1_000_000:
                continue
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
            raw = pipfile_lock.read_text(encoding="utf-8")
            if len(raw) <= 1_000_000:
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
        raw = cargo_lock.read_text(encoding="utf-8")
        if len(raw) > 1_000_000:
            return findings
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
    return findings, scanned_files


def _check_mcp_specific_vulns(project_root: Path) -> list[Finding]:
    """AAK-SUPPLY-006: Check MCP server packages against vuln DB."""
    findings: list[Finding] = []
    try:
        from agent_audit_kit.vuln_db import load_database
        db = load_database()
    except ImportError:
        return findings

    mcp_path = project_root / ".mcp.json"
    if not mcp_path.is_file():
        return findings
    try:
        data = json.loads(mcp_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return findings

    rel_path = str(mcp_path.relative_to(project_root))
    npm_vulns = db.get("npm", {})
    servers = data.get("mcpServers", {})
    if not isinstance(servers, dict):
        return findings

    for server_name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        args = cfg.get("args", [])
        if not isinstance(args, list):
            continue
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
