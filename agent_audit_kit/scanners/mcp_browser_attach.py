"""AAK-MCP-BROWSER-ATTACH-001: a browser-automation MCP server with the user's own browser in reach.

Attaching over CDP to a Chrome on this machine, pointing at the real profile, or importing its
cookies hands the model every session that browser is signed in to. `--no-sandbox` takes away the
renderer's sandbox, on a browser that is about to load whatever the model chose. The flags are the
ones Playwright MCP and chrome-devtools-mcp document, read from a config's `args` and `env`.

What the rule reads, and where it stops, is in the registry's limitations.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from agent_audit_kit.models import Finding

from ._helpers import (
    CONFIG_MAX_BYTES,
    find_line_numbers,
    is_loopback_url,
    iter_mcp_servers,
    loads_jsonc,
    make_finding,
    read_text_capped,
)
from .mcp_config import _find_mcp_configs

RULE = "AAK-MCP-BROWSER-ATTACH-001"

_BROWSER_WORDS = frozenset({
    "playwright", "puppeteer", "chrome", "chromium", "browser", "browsers", "cdp", "selenium", "devtools", "stagehand",
})
_WORD_RE = re.compile(r"[a-z0-9]+")
_CDP_FLAGS = frozenset({"--cdp-endpoint", "--browserUrl", "--browser-url", "--wsEndpoint", "--ws-endpoint", "--cdp-url", "--cdpUrl"})
_ATTACH_FLAGS = frozenset({"--autoConnect", "--auto-connect", "--extension"})
_DIR_FLAGS = frozenset({"--user-data-dir", "--userDataDir"})
_CHROME_ARG_FLAGS = frozenset({"--chromeArg", "--chrome-arg"})
_REAL_PROFILE_RE = re.compile(
    r"Library/Application Support/(?:Google/Chrome|Chromium|BraveSoftware|Microsoft Edge)"
    r"|\.config/(?:google-chrome|chromium|BraveSoftware|microsoft-edge)"
    r"|AppData[/\\]+(?:Local|Roaming)[/\\]+(?:Google[/\\]+Chrome|Chromium|BraveSoftware|Microsoft[/\\]+Edge)"
    r"|\.mozilla/firefox",
    re.I,
)
_COOKIE_FLAG_RE = re.compile(r"cookie", re.I)
_INLINE_CDP_RE = re.compile(r"connectOverCDP|cdpUrl", re.I)
_CDP_ENV_RE = re.compile(r"CDP_(?:URL|ENDPOINT)|BROWSER_URL|WS_ENDPOINT", re.I)
_LOCAL_NAMES = ("host.docker.internal", "gateway.docker.internal")
_CONTAINER_COMMANDS = frozenset({"docker", "podman", "nerdctl"})


def _is_browser_server(name: str, command: str, args: list[str]) -> bool:
    launch = [a for a in args if not a.startswith(("/", ".", "~", "-"))]
    return bool(_BROWSER_WORDS & set(_WORD_RE.findall(" ".join([name, command, *launch]).lower())))


def _is_local(endpoint: str) -> bool:
    """An endpoint on this machine, which is the user's own browser. A hosted one is not."""
    return is_loopback_url(endpoint) or any(name in endpoint for name in _LOCAL_NAMES) or endpoint.isdigit()


def _arg_reasons(args: list[str], command: str, browser: bool) -> list[str]:
    reasons: list[str] = []
    for index, arg in enumerate(args):
        flag, _, inline = arg.partition("=")
        value = inline or (args[index + 1] if index + 1 < len(args) else "")
        if flag in _CDP_FLAGS and _is_local(value):
            reasons.append(f"attaches over CDP with `{flag}` to a browser on this machine")
        elif flag == "--remote-debugging-port":
            reasons.append("opens `--remote-debugging-port`, which anything on this machine can attach to")
        elif flag in _ATTACH_FLAGS and browser:
            reasons.append(f"attaches to the user's running browser with `{flag}`")
        elif flag in _DIR_FLAGS and _REAL_PROFILE_RE.search(value):
            reasons.append(f"points `{flag}` at the user's real browser profile")
        elif browser and _COOKIE_FLAG_RE.search(flag) and flag.startswith("-"):
            reasons.append(f"imports cookies with `{flag}`")
        elif browser and flag == "--storage-state" and _COOKIE_FLAG_RE.search(value):
            reasons.append("imports cookies with `--storage-state`")
        elif browser and command not in _CONTAINER_COMMANDS and (
            flag == "--no-sandbox" or (flag in _CHROME_ARG_FLAGS and value == "--no-sandbox")
        ):
            reasons.append("turns off the renderer sandbox with `--no-sandbox`")
        elif _INLINE_CDP_RE.search(arg) and not flag.startswith("--"):
            reasons.append("names a CDP attach in its arguments")
    return reasons


def _env_reasons(env: object, command: str, browser: bool) -> list[str]:
    if not isinstance(env, dict):
        return []
    reasons: list[str] = []
    for key, value in env.items():
        text = str(value)
        name = str(key)
        if _CDP_ENV_RE.search(name) and _is_local(text):
            reasons.append(f"attaches over CDP through `{name}` to a browser on this machine")
        elif browser and "USER_DATA_DIR" in name.upper() and _REAL_PROFILE_RE.search(text):
            reasons.append(f"points `{name}` at the user's real browser profile")
        elif browser and "NO_SANDBOX" in name.upper() and text.lower() not in ("0", "false", "") \
                and command not in _CONTAINER_COMMANDS:
            reasons.append(f"turns off the renderer sandbox with `{name}`")
    return reasons


def _server_reasons(name: str, server: dict[str, Any]) -> list[str]:
    raw_args = server.get("args")
    args = [str(a) for a in raw_args] if isinstance(raw_args, list) else []
    command = Path(str(server.get("command") or "")).name
    browser = _is_browser_server(name, command, args)
    reasons = _arg_reasons(args, command, browser) + _env_reasons(server.get("env"), command, browser)
    return list(dict.fromkeys(reasons))


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Report browser-automation MCP servers that can reach the user's own browser.

    Args:
        project_root: The root directory of the project.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned: set[str] = set()
    for path in _find_mcp_configs(project_root):
        if path.suffix.lower() != ".json":
            continue
        try:
            raw = read_text_capped(path, CONFIG_MAX_BYTES, errors="replace")
            data = loads_jsonc(raw, path)
        except (json.JSONDecodeError, OSError):
            continue
        rel = path.relative_to(project_root).as_posix()
        scanned.add(rel)
        hits = [(str(name), reasons) for name, server in iter_mcp_servers(data) if (reasons := _server_reasons(str(name), server))]
        lines = find_line_numbers(raw, [name for name, _ in hits])
        for name, reasons in hits:
            findings.append(make_finding(RULE, rel, f"Server {name!r}: {'; '.join(reasons)}", lines.get(name)))
    return findings, scanned


__all__ = ["RULE", "scan"]
