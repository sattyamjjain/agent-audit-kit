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
    findings.extend(_check_doris_mcp_pin(project_root, scanned_files))
    findings.extend(_check_excel_mcp_pin(project_root, scanned_files))
    findings.extend(_check_azure_mcp_auth(project_root, scanned_files))
    findings.extend(_check_astro_mcp_pin(project_root, scanned_files))
    findings.extend(_scan_astro_mcp_query_concat(project_root, scanned_files))
    findings.extend(_check_litellm_pin(project_root, scanned_files))
    return findings, scanned_files


# ---------------------------------------------------------------------------
# AAK-DORIS-001 — apache-doris-mcp-server < 0.6.1 (CVE-2025-66335).
# Published 2026-04-20. Context-neutralization bypass reached via crafted
# tool arguments. Separate pin-check because the Python lockfile scanner
# above operates on a fixed KNOWN_VULNERABLE_PACKAGES table and we want
# this check to run even if that table hasn't been extended yet.
# ---------------------------------------------------------------------------

_DORIS_PATCHED = (0, 6, 1)
_DORIS_VERSION_RE = re.compile(
    r"apache-doris-mcp-server\s*(?:==|>=|~=|<=|<|>)?\s*([0-9][\w.\-]*)",
    re.IGNORECASE,
)


def _semver3(spec: str) -> tuple[int, int, int] | None:
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", str(spec))
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


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
# AAK-EXCEL-MCP-001 — excel-mcp-server <= 0.1.7 (CVE-2026-40576).
# Path-traversal in get_excel_path(). Fixed in 0.1.8.
# ---------------------------------------------------------------------------

_EXCEL_FIRST_PATCHED = (0, 1, 8)
_EXCEL_VERSION_RE = re.compile(
    r"excel-mcp-server\s*(?:==|>=|~=|<=|<|>)?\s*([0-9][\w.\-]*)",
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
        if any(part in skip_dirs for part in path.parts):
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
    r"(?<![\w-])litellm\s*(?:==|>=|~=|<=|<|>)?\s*([0-9][\w.\-]*)",
    re.IGNORECASE,
)


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
