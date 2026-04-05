from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, SKIP_DIRS as _SKIP_DIRS

# Patterns for secret-like keys in MCP server env blocks
SECRET_KEY_PATTERNS = re.compile(
    r"(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|API_KEY|ANTHROPIC|OPENAI|AWS_)", re.IGNORECASE
)

# Shell metacharacters indicating shell expansion risk
SHELL_METACHARACTERS = re.compile(r"[|;&`$()]")
SHELL_WRAPPERS = ("sh -c", "bash -c", "cmd /c", "cmd.exe /c")

# npx-like package fetchers
PACKAGE_FETCHERS = ("npx", "uvx", "bunx", "pnpx")

# Well-known binaries that are acceptable without absolute paths
KNOWN_BINARIES = frozenset({
    "node", "python", "python3", "npx", "uvx", "bunx", "pnpx",
    "docker", "deno", "bun", "cargo", "go", "java", "ruby",
})

# Internal / localhost patterns
INTERNAL_URL_PATTERNS = re.compile(
    r"(localhost|127\.0\.0\.1|0\.0\.0\.0|::1|10\.\d+\.\d+\.\d+|"
    r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|\.local\b)",
    re.IGNORECASE,
)

MCP_CONFIG_FILES = [
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".amazonq/mcp.json",
    ".windsurf/mcp.json",
    ".continue/config.json",
    ".roo/mcp.json",
    ".kiro/mcp.json",
    "mcp.json",
]

# Config files that use a different key structure or format
_YAML_CONFIG_FILES = [
    ".config/goose/config.yaml",
]

# Gemini uses a settings.json that may contain MCP config
_SETTINGS_CONFIG_FILES = [
    ".gemini/settings.json",
]


def _find_mcp_configs(project_root: Path, include_user_config: bool = False) -> list[Path]:
    found: list[Path] = []
    for name in MCP_CONFIG_FILES:
        p = project_root / name
        if p.is_file():
            found.append(p)
    # Check settings-style configs (Gemini)
    for name in _SETTINGS_CONFIG_FILES:
        p = project_root / name
        if p.is_file() and p not in found:
            found.append(p)
    # Check YAML configs (Goose)
    for name in _YAML_CONFIG_FILES:
        p = project_root / name
        if p.is_file() and p not in found:
            found.append(p)
    # Recursively search for any *mcp*.json from project root
    for p in project_root.rglob("*mcp*.json"):
        if any(part in _SKIP_DIRS for part in p.relative_to(project_root).parts):
            continue
        if p.is_file() and p not in found:
            found.append(p)
    if include_user_config:
        user_claude = Path.home() / ".claude.json"
        if user_claude.is_file():
            found.append(user_claude)
    return found


_find_line_number = find_line_number
_make_finding = make_finding


def _check_server(
    server_name: str, server_cfg: dict[str, Any], file_path: str, raw_text: str
) -> list[Finding]:
    findings: list[Finding] = []

    url = server_cfg.get("url", "")
    command = server_cfg.get("command", "")
    args = server_cfg.get("args", [])
    env = server_cfg.get("env", {})
    headers_helper = server_cfg.get("headersHelper", "")

    # AAK-MCP-001: Remote server without auth
    if url:
        headers = server_cfg.get("headers", {})
        has_auth = any(
            k.lower() in ("authorization", "x-api-key", "api-key", "bearer")
            for k in headers.keys()
        ) if isinstance(headers, dict) else False
        if not has_auth:
            findings.append(_make_finding(
                "AAK-MCP-001", file_path,
                f"Server '{server_name}' URL: {url} — no authentication headers",
                _find_line_number(raw_text, url),
            ))

    # AAK-MCP-002: Shell expansion in command
    if command:
        has_shell_meta = bool(SHELL_METACHARACTERS.search(command))
        has_shell_wrapper = any(command.strip().startswith(sw) for sw in SHELL_WRAPPERS)
        if has_shell_meta or has_shell_wrapper:
            findings.append(_make_finding(
                "AAK-MCP-002", file_path,
                f"Server '{server_name}' command: {command}",
                _find_line_number(raw_text, command),
            ))

    # AAK-MCP-003: Hardcoded secrets in env
    if isinstance(env, dict):
        for key, value in env.items():
            if SECRET_KEY_PATTERNS.search(key) and isinstance(value, str):
                # Allow variable references like ${VAR}
                if not re.match(r"^\$\{.+\}$", value) and value:
                    findings.append(_make_finding(
                        "AAK-MCP-003", file_path,
                        f"Server '{server_name}' env.{key} = (hardcoded value)",
                        _find_line_number(raw_text, key),
                    ))

    # AAK-MCP-005: npx/uvx package fetcher
    if command and command.strip().split()[0] in PACKAGE_FETCHERS:
        findings.append(_make_finding(
            "AAK-MCP-005", file_path,
            f"Server '{server_name}' command: {command}",
            _find_line_number(raw_text, command),
        ))

    # AAK-MCP-006: Relative path command
    if command:
        cmd_bin = command.strip().split()[0]
        is_absolute = cmd_bin.startswith("/")
        is_known = cmd_bin in KNOWN_BINARIES
        if not is_absolute and not is_known and cmd_bin:
            findings.append(_make_finding(
                "AAK-MCP-006", file_path,
                f"Server '{server_name}' command: {cmd_bin}",
                _find_line_number(raw_text, cmd_bin),
            ))

    # AAK-MCP-007: Unpinned package version in args
    if command and command.strip().split()[0] in PACKAGE_FETCHERS and isinstance(args, list):
        for arg in args:
            if isinstance(arg, str) and not arg.startswith("-"):
                # Skip path-like arguments
                if arg.startswith("/") or arg.startswith("./") or arg.startswith("../"):
                    continue
                # Check if it looks like a package name without @version
                if arg and "@" not in arg:
                    findings.append(_make_finding(
                        "AAK-MCP-007", file_path,
                        f"Server '{server_name}' arg: {arg} (no version pin)",
                        _find_line_number(raw_text, arg),
                    ))
                elif arg and "@" in arg:
                    # Has @ but check if it's scoped package without version
                    # e.g. @org/pkg has @ but no version; @org/pkg@1.0.0 is fine
                    parts = arg.split("@")
                    # Scoped: ['', 'org/pkg'] or ['', 'org/pkg', '1.0.0']
                    # Unscoped with version: ['pkg', '1.0.0']
                    if arg.startswith("@"):
                        # Scoped package
                        if len(parts) < 3 or not parts[2]:
                            findings.append(_make_finding(
                                "AAK-MCP-007", file_path,
                                f"Server '{server_name}' arg: {arg} (no version pin)",
                                _find_line_number(raw_text, arg),
                            ))

    # AAK-MCP-008: headersHelper
    if headers_helper:
        findings.append(_make_finding(
            "AAK-MCP-008", file_path,
            f"Server '{server_name}' headersHelper: {headers_helper}",
            _find_line_number(raw_text, "headersHelper"),
        ))

    # AAK-MCP-009: Internal/localhost URL
    if url and INTERNAL_URL_PATTERNS.search(url):
        findings.append(_make_finding(
            "AAK-MCP-009", file_path,
            f"Server '{server_name}' URL: {url}",
            _find_line_number(raw_text, url),
        ))

    # AAK-MCP-010: Filesystem root access
    if isinstance(args, list):
        for arg in args:
            if isinstance(arg, str) and arg in ("/", "~", "/home", "/Users", "/etc", "/var"):
                findings.append(_make_finding(
                    "AAK-MCP-010", file_path,
                    f"Server '{server_name}' grants access to '{arg}'",
                    _find_line_number(raw_text, arg),
                ))

    return findings


def scan(project_root: Path, include_user_config: bool = False) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned_files: set[str] = set()
    configs = _find_mcp_configs(project_root, include_user_config)

    for config_path in configs:
        try:
            raw_text = config_path.read_text(encoding="utf-8")
            if len(raw_text) > 1_000_000:
                continue
            data = json.loads(raw_text)
        except (json.JSONDecodeError, OSError):
            continue

        rel_path = str(config_path.relative_to(project_root)) if config_path.is_relative_to(project_root) else str(config_path)
        scanned_files.add(rel_path)
        servers = data.get("mcpServers", {})
        if not isinstance(servers, dict):
            continue

        # AAK-MCP-004: Excessive server count
        if len(servers) > 10:
            findings.append(_make_finding(
                "AAK-MCP-004", rel_path,
                f"{len(servers)} MCP servers declared (threshold: 10)",
                _find_line_number(raw_text, "mcpServers"),
            ))

        for server_name, server_cfg in servers.items():
            if isinstance(server_cfg, dict):
                findings.extend(_check_server(server_name, server_cfg, rel_path, raw_text))

    return findings, scanned_files
