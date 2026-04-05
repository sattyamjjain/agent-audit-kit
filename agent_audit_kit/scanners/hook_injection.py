from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding

# Network-capable commands
NETWORK_COMMANDS = re.compile(
    r"\b(curl|wget|nc|ncat|ssh|scp|rsync|ftp)\b|"
    r"python\s+-c\s+.*import\s+requests|"
    r"node\s+-e\s+.*fetch\(",
    re.IGNORECASE,
)

# Credential environment variables
CREDENTIAL_VARS = re.compile(
    r"\$(ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|"
    r"AWS_ACCESS_KEY_ID|HOME|PATH)|"
    r"(env\s*\|\s*curl|printenv\s*\|\s*nc|echo\s+\$\w+\s*\|\s*base64)",
    re.IGNORECASE,
)

# Paths outside project directory
EXTERNAL_PATHS = re.compile(
    r"(/tmp/|~/|/etc/|/var/|/usr/|/home/)",
)

# Allowed formatting/linting binaries
FORMATTING_ALLOWLIST = frozenset({
    "prettier", "eslint", "black", "ruff", "mypy", "tsc",
    "cargo fmt", "cargo-fmt", "clippy", "rustfmt", "gofmt",
    "isort", "autopep8", "yapf", "biome", "dprint",
})

# Sensitive lifecycle events
SENSITIVE_EVENTS = frozenset({
    "PreToolUse", "PostToolUse", "SessionStart", "UserPromptSubmit",
})

# Base64 operations
BASE64_PATTERNS = re.compile(
    r"\b(base64|btoa|atob|b64encode|b64decode)\b", re.IGNORECASE
)

# Privilege escalation
PRIVILEGE_PATTERNS = re.compile(
    r"\b(sudo|doas|pkexec)\b|chmod\s+\+x",
)

# Obfuscation indicators
OBFUSCATION_PATTERNS = re.compile(
    r"(\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|sh\s+-c\s+.*sh\s+-c)",
)

# Source file references
_SOURCE_FILE_PATTERNS = re.compile(
    r"\b(cat|head|tail|less|more|grep|sed|awk)\s+.+\.(py|js|ts|go|rs|java|rb|c|cpp|h)\b|"
    r"<\s+\S+\.(py|js|ts|go|rs|java|rb|c|cpp|h)\b",
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


def _extract_hook_commands(hooks_data: Any) -> list[tuple[str, str]]:
    """Extract (event_name, command_string) pairs from hooks config.

    Hooks can be structured as:
      hooks: { "EventName": [{ "command": "..." }] }
    or
      hooks: { "EventName": { "command": "..." } }
    or
      hooks: [{ "event": "EventName", "command": "..." }]
    """
    results: list[tuple[str, str]] = []
    if isinstance(hooks_data, dict):
        for event_name, hook_entries in hooks_data.items():
            if isinstance(hook_entries, list):
                for entry in hook_entries:
                    if isinstance(entry, dict):
                        cmd = entry.get("command", "")
                        if isinstance(cmd, str) and cmd:
                            results.append((event_name, cmd))
            elif isinstance(hook_entries, dict):
                cmd = hook_entries.get("command", "")
                if isinstance(cmd, str) and cmd:
                    results.append((event_name, cmd))
    elif isinstance(hooks_data, list):
        for entry in hooks_data:
            if isinstance(entry, dict):
                event = entry.get("event", "unknown")
                cmd = entry.get("command", "")
                if isinstance(cmd, str) and cmd:
                    results.append((event, cmd))
    return results


def _is_formatting_tool(command: str) -> bool:
    cmd_lower = command.strip().lower()
    return any(tool in cmd_lower for tool in FORMATTING_ALLOWLIST)


def _count_hooks(hooks_data: Any) -> int:
    if isinstance(hooks_data, dict):
        count = 0
        for entries in hooks_data.values():
            if isinstance(entries, list):
                count += len(entries)
            else:
                count += 1
        return count
    elif isinstance(hooks_data, list):
        return len(hooks_data)
    return 0


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
        hooks = data.get("hooks", {})
        if not hooks:
            continue

        hook_commands = _extract_hook_commands(hooks)

        # AAK-HOOK-007: Excessive hook count
        hook_count = _count_hooks(hooks)
        if hook_count > 15:
            findings.append(_make_finding(
                "AAK-HOOK-007", rel_path,
                f"{hook_count} hooks defined (threshold: 15)",
                _find_line_number(raw_text, "hooks"),
            ))

        for event_name, command in hook_commands:
            # AAK-HOOK-001: Network-capable command
            if NETWORK_COMMANDS.search(command):
                findings.append(_make_finding(
                    "AAK-HOOK-001", rel_path,
                    f"Event '{event_name}': {command}",
                    _find_line_number(raw_text, command.split()[0] if command.split() else command),
                ))

            # AAK-HOOK-002: Credential exfiltration
            if CREDENTIAL_VARS.search(command):
                findings.append(_make_finding(
                    "AAK-HOOK-002", rel_path,
                    f"Event '{event_name}': {command}",
                    _find_line_number(raw_text, command.split()[0] if command.split() else command),
                ))

            # AAK-HOOK-003: Write outside project
            if EXTERNAL_PATHS.search(command):
                findings.append(_make_finding(
                    "AAK-HOOK-003", rel_path,
                    f"Event '{event_name}': {command}",
                    _find_line_number(raw_text, command.split()[0] if command.split() else command),
                ))

            # AAK-HOOK-004: Suspicious lifecycle hook
            if event_name in SENSITIVE_EVENTS and not _is_formatting_tool(command):
                findings.append(_make_finding(
                    "AAK-HOOK-004", rel_path,
                    f"Event '{event_name}': {command}",
                    _find_line_number(raw_text, event_name),
                ))

            # AAK-HOOK-005: Base64 operations
            if BASE64_PATTERNS.search(command):
                findings.append(_make_finding(
                    "AAK-HOOK-005", rel_path,
                    f"Event '{event_name}': {command}",
                    _find_line_number(raw_text, "base64"),
                ))

            # AAK-HOOK-006: Privilege escalation
            if PRIVILEGE_PATTERNS.search(command):
                findings.append(_make_finding(
                    "AAK-HOOK-006", rel_path,
                    f"Event '{event_name}': {command}",
                    _find_line_number(raw_text, command.split()[0] if command.split() else command),
                ))

            # AAK-HOOK-008: Obfuscated payload
            has_hex = bool(OBFUSCATION_PATTERNS.search(command))
            is_very_long = len(command) > 500
            if has_hex or is_very_long:
                findings.append(_make_finding(
                    "AAK-HOOK-008", rel_path,
                    f"Event '{event_name}': {command[:200]}{'...' if len(command) > 200 else ''}",
                    _find_line_number(raw_text, event_name),
                ))

            # AAK-HOOK-009: Hook references source files
            if _SOURCE_FILE_PATTERNS.search(command):
                findings.append(_make_finding(
                    "AAK-HOOK-009", rel_path,
                    f"Event '{event_name}': {command}",
                    _find_line_number(raw_text, command.split()[0] if command.split() else command),
                ))

    return findings, scanned_files
