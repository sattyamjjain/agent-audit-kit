"""AAK-MCP-TOOLBOX-HOSTS-001: MCP Toolbox for Databases on a network listener with an open host check.

CVE-2026-11624 (GHSA-76g7-m3xw-x9gr): before 0.25.0 the server had no way to validate
the `Host` a request names, so a page in a browser could rebind a name to its listener
(CWE-346). 0.25.0 added `--allowed-hosts` beside `--allowed-origins`. Both still default
to `*`, and the server only warns at startup, so an upgrade closes nothing by itself. The
release rule of the fix is the `_Pin` row of the same id in `mcp_cve_pins_2026_07`, which
reads `@toolbox-sdk/server` below 0.25.0. This module reads the launch: an MCP config that
starts the server on a network listener with either flag unset or `*`.

A launch with `--stdio` has no listener and is not read. `--allowed-hosts` and
`--allowed-origins` are read as the server's flag parser takes them, `--flag value` or
`--flag=value`, a comma list either way. A launch stating a release below 0.25.0 is left to
the pin, which names the upgrade it needs first.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from agent_audit_kit.models import Finding

from ._helpers import CONFIG_MAX_BYTES, SKIP_DIRS, iter_mcp_servers, loads_jsonc, make_finding, read_text_capped
from ._launchers import basename, invocation_packages, npm_spec
from ._versions import parse_version

RULE = "AAK-MCP-TOOLBOX-HOSTS-001"
_PACKAGE = "@toolbox-sdk/server"
_FIXED = (0, 25, 0)
_FLAGS = ("--allowed-hosts", "--allowed-origins")
_CONFIG_NAMES = frozenset({".mcp.json", "mcp.json", "claude_desktop_config.json"})


def _argv(server: dict[str, Any]) -> list[str]:
    command = server.get("command")
    args = server.get("args")
    argv = command.split() if isinstance(command, str) else []
    if isinstance(args, list):
        argv += [a for a in args if isinstance(a, str)]
    return argv


def _is_toolbox(argv: list[str]) -> tuple[bool, str]:
    """Does this launch start the server? The second value is the version it states,
    empty when it names none. npm's package runs the binary of its own version, and
    the binary is called `toolbox`."""
    if not argv:
        return False, ""
    if basename(argv[0]).lower() == "toolbox":
        return True, ""
    for launched in invocation_packages(argv):
        if launched.ecosystem == "js":
            spec = npm_spec(launched.spec)
            if spec.kind == "registry" and spec.name == _PACKAGE:
                return True, spec.version
    return False, ""


def _flag_values(argv: list[str], flag: str) -> list[str]:
    """Every value given for a flag, each comma list split. An empty list means unset."""
    values: list[str] = []
    for index, arg in enumerate(argv):
        raw = None
        if arg == flag and index + 1 < len(argv):
            raw = argv[index + 1]
        elif arg.startswith(flag + "="):
            raw = arg[len(flag) + 1:]
        if raw is not None:
            values.extend(part.strip() for part in raw.split(",") if part.strip())
    return values


def _open_flags(argv: list[str]) -> list[str]:
    """The flags left at their open default or given `*`, as `--flag (unset)` or `--flag=*`."""
    found: list[str] = []
    for flag in _FLAGS:
        values = _flag_values(argv, flag)
        if not values:
            found.append(f"{flag} (unset, so `*`)")
        elif "*" in values:
            found.append(f"{flag}=*")
    return found


def _config_findings(path: Path, rel: str) -> list[Finding]:
    try:
        data = loads_jsonc(read_text_capped(path, CONFIG_MAX_BYTES, errors="replace"), path)
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return []
    findings: list[Finding] = []
    for name, server in iter_mcp_servers(data):
        argv = _argv(server)
        is_toolbox, version = _is_toolbox(argv)
        if not is_toolbox or "--stdio" in argv:
            continue
        stated = parse_version(version) if version else None
        if stated is not None and stated < _FIXED:
            continue  # the pin row reports it, with the upgrade it needs first
        gaps = _open_flags(argv)
        if gaps:
            findings.append(make_finding(
                RULE, rel,
                f"Server '{name}' starts MCP Toolbox on a network listener with {' and '.join(gaps)}, so a page in a "
                "browser can rebind a name to it (CVE-2026-11624). Name your hosts and origins in both flags.",
            ))
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Report MCP Toolbox launches on a network listener with an open host or origin check.

    Args:
        project_root: The root directory of the project.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(project_root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            lowered = name.lower()
            if lowered not in _CONFIG_NAMES and not lowered.endswith(".mcp.json"):
                continue
            path = Path(dirpath) / name
            rel = path.relative_to(project_root).as_posix()
            found = _config_findings(path, rel)
            if found:
                scanned.add(rel)
                findings.extend(found)
    return findings, scanned


__all__ = ["RULE", "scan"]
