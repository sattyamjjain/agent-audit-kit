from __future__ import annotations

import json
import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding

# Patterns for API URL override env vars
API_URL_PATTERNS = re.compile(
    r"(_BASE_URL|_API_URL|_ENDPOINT)$", re.IGNORECASE
)

# Wildcard/broad permission patterns
BROAD_PERMISSION_PATTERNS = re.compile(
    r"^(\*+|mcp__\*|Bash\(\*\)|Edit\(\*\*\)|Read\(\*\*\)|Write\(\*\*\))$"
)

SETTINGS_FILES = [
    ".claude/settings.json",
    ".claude/settings.local.json",
]


def _find_settings(project_root: Path, include_user_config: bool = False) -> list[Path]:
    found: list[Path] = []
    for name in SETTINGS_FILES:
        p = project_root / name
        if p.is_file():
            found.append(p)
    if include_user_config:
        user_settings = Path.home() / ".claude" / "settings.json"
        if user_settings.is_file():
            found.append(user_settings)
    return found


_find_line_number = find_line_number
_make_finding = make_finding


def scan(project_root: Path, include_user_config: bool = False) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned_files: set[str] = set()
    settings_files = _find_settings(project_root, include_user_config)

    for settings_path in settings_files:
        try:
            raw_text = settings_path.read_text(encoding="utf-8")
            if len(raw_text) > 1_000_000:
                continue
            data = json.loads(raw_text)
        except (json.JSONDecodeError, OSError):
            continue

        rel_path = str(settings_path.relative_to(project_root)) if settings_path.is_relative_to(project_root) else str(settings_path)
        scanned_files.add(rel_path)

        # AAK-TRUST-001: enableAllProjectMcpServers
        if data.get("enableAllProjectMcpServers") is True:
            findings.append(_make_finding(
                "AAK-TRUST-001", rel_path,
                "enableAllProjectMcpServers: true",
                _find_line_number(raw_text, "enableAllProjectMcpServers"),
            ))

        # AAK-TRUST-002: ANTHROPIC_BASE_URL override
        env = data.get("env", {})
        if isinstance(env, dict):
            anthropic_url = env.get("ANTHROPIC_BASE_URL", "")
            if anthropic_url and isinstance(anthropic_url, str):
                if "anthropic.com" not in anthropic_url.lower():
                    findings.append(_make_finding(
                        "AAK-TRUST-002", rel_path,
                        f"ANTHROPIC_BASE_URL = {anthropic_url}",
                        _find_line_number(raw_text, "ANTHROPIC_BASE_URL"),
                    ))

            # AAK-TRUST-005: Custom API base URL for any provider
            for key, value in env.items():
                if key == "ANTHROPIC_BASE_URL":
                    continue  # Already handled by AAK-TRUST-002
                if API_URL_PATTERNS.search(key) and isinstance(value, str) and value:
                    findings.append(_make_finding(
                        "AAK-TRUST-005", rel_path,
                        f"{key} = {value}",
                        _find_line_number(raw_text, key),
                    ))

        # Check permissions
        permissions = data.get("permissions", {})
        if isinstance(permissions, dict):
            allow_list = permissions.get("allow", [])
            deny_list = permissions.get("deny", [])

            # AAK-TRUST-003: Wildcard permissions
            if isinstance(allow_list, list):
                for pattern in allow_list:
                    if isinstance(pattern, str) and BROAD_PERMISSION_PATTERNS.match(pattern):
                        findings.append(_make_finding(
                            "AAK-TRUST-003", rel_path,
                            f"Broad permission allow: {pattern}",
                            _find_line_number(raw_text, pattern),
                        ))

            # AAK-TRUST-004: No deny rules
            if allow_list and (not deny_list or deny_list == []):
                findings.append(_make_finding(
                    "AAK-TRUST-004", rel_path,
                    "permissions.allow has entries but permissions.deny is empty/missing",
                    _find_line_number(raw_text, "allow"),
                ))

            # AAK-TRUST-006: Project settings may override user denys
            if isinstance(allow_list, list) and len(allow_list) > 0:
                # Check for potentially shadow-capable allows
                has_tool_allows = any(
                    isinstance(p, str) and ("Bash" in p or "Edit" in p or "Write" in p or "Read" in p or "mcp__" in p)
                    for p in allow_list
                )
                if has_tool_allows and not deny_list:
                    findings.append(_make_finding(
                        "AAK-TRUST-006", rel_path,
                        f"Project allows tool access ({len(allow_list)} rules) with no deny rules to prevent override",
                        _find_line_number(raw_text, "allow"),
                    ))

        # AAK-TRUST-007: No MCP server allowlist configured
        if not data.get("enabledMcpjsonServers") and data.get("enableAllProjectMcpServers") is not True:
            # Only flag if there's an .mcp.json in the project (servers exist to allowlist)
            mcp_json = project_root / ".mcp.json"
            if mcp_json.is_file():
                findings.append(_make_finding(
                    "AAK-TRUST-007", rel_path,
                    "No enabledMcpjsonServers allowlist configured",
                    _find_line_number(raw_text, "enabledMcpjsonServers") or 1,
                ))

    return findings, scanned_files
