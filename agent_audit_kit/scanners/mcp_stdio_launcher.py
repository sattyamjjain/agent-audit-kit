"""MCP stdio launcher-injection scanner — CVE-2026-40933 class.

Flags MCP **stdio** server definitions (`command` + `args` inside a
`mcpServers` / `servers` block) that either:

  1. launch a shell-style interpreter (`npx`, `node`, `bash`, `sh`,
     `python`) with a code-execution flag (`-c`, `-e`, `--eval`), or
  2. carry a template / interpolation token (`${...}` embedded in a larger
     string, `{{...}}`, `%s`) in the argv that is not a pinned static literal.

Either shape makes the launched process an arbitrary-code sink. This is the
**CVE-2026-40933** class: Flowise < 3.1.0 unsafely serialised stdio commands
in its MCP adapter, so an authenticated actor could register a stdio server
whose allowlisted launcher (e.g. `npx`) was combined with `-c` to run
arbitrary OS commands (CWE-78, CVSS 9.9).

This is a **config-level** detector. It is deliberately distinct from:
  - ``AAK-MCP-002`` (mcp_config.py) — inspects only the ``command`` *string*
    for ``sh -c``/``bash -c`` wrappers and shell metacharacters; never ``args``.
  - ``AAK-MCP-STDIO-CMD-INJ-001..004`` (mcp_stdio_params.py / stdio_injection.py)
    — source-code taint on ``StdioServerParameters(command=tainted)``.
A standalone env reference (``${VAR}``) is treated as pinned and does not fire.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, SKIP_DIRS

_RULE_ID = "AAK-MCP-STDIO-LAUNCHER-INJECT-001"

# Standard MCP config file names (mirrors mcp_config.py / tool_poisoning.py).
_MCP_CONFIG_FILES: tuple[str, ...] = (
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".amazonq/mcp.json",
    ".windsurf/mcp.json",
    ".roo/mcp.json",
    "mcp.json",
)

# Shell-style interpreters that execute code passed on the command line.
_SHELL_LAUNCHERS = frozenset({"npx", "node", "bash", "sh", "python", "python3"})

# Code-execution flags for those interpreters.
_EXEC_FLAGS = frozenset({"-c", "-e", "-eval", "--eval"})

# A standalone env reference is considered "pinned" (host-resolved), e.g.
# "${GITHUB_TOKEN}" — safe, does not fire the interpolation arm.
_STANDALONE_ENV_RE = re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*\}$")


def _find_mcp_configs(project_root: Path) -> list[Path]:
    """Discover MCP configuration files in the project."""
    found: list[Path] = []
    for name in _MCP_CONFIG_FILES:
        p = project_root / name
        if p.is_file() and p not in found:
            found.append(p)
    for p in project_root.rglob("*mcp*.json"):
        try:
            rel_parts = p.relative_to(project_root).parts
        except ValueError:
            continue
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if p.is_file() and p not in found:
            found.append(p)
    return found


def _server_blocks(data: Any) -> list[tuple[str, dict[str, Any]]]:
    """Return (server_name, server_cfg) for every MCP server entry.

    Supports both the ``mcpServers`` (Claude/Cursor/…) and ``servers``
    (VS Code) container keys.
    """
    out: list[tuple[str, dict[str, Any]]] = []
    if not isinstance(data, dict):
        return out
    for container_key in ("mcpServers", "servers"):
        servers = data.get(container_key)
        if isinstance(servers, dict):
            for name, cfg in servers.items():
                if isinstance(cfg, dict):
                    out.append((str(name), cfg))
    return out


def _argv_tokens(cfg: dict[str, Any]) -> tuple[str, list[str]]:
    """Return (launcher_basename, remaining_tokens) for a server cfg.

    ``command`` may be a string ("npx" or "npx -c ...") or a list. The
    launcher is the basename of the first token; remaining command tokens are
    merged with ``args`` so the split form `{"command":"npx","args":["-c",…]}`
    and the inline form `{"command":"npx -c …"}` are handled identically.
    """
    command = cfg.get("command")
    if isinstance(command, list):
        cmd_tokens = [str(t) for t in command]
    elif isinstance(command, str):
        cmd_tokens = command.split()
    else:
        cmd_tokens = []

    if not cmd_tokens:
        return "", []

    launcher = os.path.basename(cmd_tokens[0])
    rest = cmd_tokens[1:]

    raw_args = cfg.get("args")
    if isinstance(raw_args, list):
        rest = rest + [str(a) for a in raw_args if isinstance(a, (str, int, float))]
    return launcher, rest


def _interpolation_hit(token: str) -> bool:
    """True if a token carries a non-pinned template/interpolation token."""
    if "{{" in token and "}}" in token:
        return True
    if "%s" in token:
        return True
    if "${" in token:
        # A standalone env reference (the whole token is exactly ${VAR}) is
        # host-resolved and treated as pinned; anything else (embedded in a
        # larger string, multiple refs, expressions) fires.
        return not _STANDALONE_ENV_RE.match(token.strip())
    return False


def _evaluate_server(launcher: str, tokens: list[str]) -> str | None:
    """Return a reason string if the server cfg is risky, else None."""
    # Arm 1: shell-style launcher + a code-execution flag.
    if launcher in _SHELL_LAUNCHERS:
        for tok in tokens:
            if tok in _EXEC_FLAGS:
                return (
                    f"launcher '{launcher}' invoked with execution flag "
                    f"'{tok}' — arbitrary code sink"
                )
    # Arm 2: a non-pinned interpolation token anywhere in the argv.
    for tok in tokens:
        if _interpolation_hit(tok):
            return (
                f"argv carries a non-pinned interpolation token "
                f"({tok!r}) — value is not a static literal"
            )
    return None


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan MCP config files for stdio launcher-injection shapes.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    for config_path in _find_mcp_configs(project_root):
        try:
            raw_text = config_path.read_text(encoding="utf-8", errors="ignore")
            if len(raw_text) > 1_000_000:
                continue
            data = json.loads(raw_text)
        except (json.JSONDecodeError, OSError):
            continue

        rel_path = (
            str(config_path.relative_to(project_root))
            if config_path.is_relative_to(project_root)
            else str(config_path)
        )
        scanned_files.add(rel_path)

        for server_name, cfg in _server_blocks(data):
            # stdio transport only: an entry with a `url` (and no `command`)
            # is an HTTP/SSE server — out of scope for launcher injection.
            if not cfg.get("command"):
                continue
            launcher, tokens = _argv_tokens(cfg)
            if not launcher:
                continue
            reason = _evaluate_server(launcher, tokens)
            if reason is None:
                continue
            findings.append(make_finding(
                _RULE_ID,
                rel_path,
                (
                    f"MCP stdio server '{server_name}': {reason} — "
                    f"CVE-2026-40933 class. Pin command to a concrete "
                    f"executable and pass only static literal args."
                ),
                find_line_number(raw_text, server_name),
            ))

    return findings, scanned_files
