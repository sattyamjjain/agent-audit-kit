"""AAK-TOOL-NEAR-DUPLICATE-001: two configured servers offer tools with nearly the same name.

A `flight_search_pro` beside `flight_search` wins by description, because selection is a model
reading text the other server's author wrote. The rule reads tool names where a project has them on
disk: the pin file and any MCP config whose servers carry a `tools` list.

What the rule reads, and where it stops, is in the registry's limitations.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterator

from agent_audit_kit.models import Finding

from ._helpers import CONFIG_MAX_BYTES, iter_mcp_servers, loads_json, loads_jsonc, make_finding, read_text_capped
from .mcp_config import _find_mcp_configs

RULE = "AAK-TOOL-NEAR-DUPLICATE-001"

PIN_FILE = ".agent-audit-kit/tool-pins.json"
_WORD_RE = re.compile(r"[vV]\d+|[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
_FLOURISH_WORDS = frozenset({
    "pro", "plus", "premium", "new", "official", "enhanced", "advanced", "ultra", "best", "fast", "secure", "verified",
    "better", "improved", "real", "true", "v2", "v3", "2", "3",
})
# One edit apart reads as a typo only in a name long enough to have one, and only up to here,
# since each name is compared through as many keys as it has characters.
_MIN_EDIT_LENGTH = 8
_MAX_EDIT_LENGTH = 64
# How many near pairs one file names.
_MAX_FINDINGS = 200


def _stem(name: str) -> str:
    """The name without flourishes: `flight_search_pro` and `FlightSearch` are `flightsearch`."""
    words = [word.lower() for word in _WORD_RE.findall(name)]
    while len(words) > 1 and words[-1] in _FLOURISH_WORDS:
        words.pop()
    while len(words) > 1 and words[0] in _FLOURISH_WORDS:
        words.pop(0)
    return "".join(words)


def _edit_keys(stem: str) -> Iterator[str]:
    if _MIN_EDIT_LENGTH <= len(stem) <= _MAX_EDIT_LENGTH:
        yield stem  # the longer of two names, less one character, is the shorter
        for index in range(len(stem)):
            yield stem[:index] + stem[index + 1:]


def _config_tools(project_root: Path, scanned: set[str]) -> Iterator[tuple[str, str, str]]:
    """`(file, server, tool name)` for every tool a config lists."""
    for path in _find_mcp_configs(project_root):
        if path.suffix.lower() != ".json":
            continue
        try:
            data = loads_jsonc(read_text_capped(path, CONFIG_MAX_BYTES, errors="replace"), path)
        except (json.JSONDecodeError, OSError):
            continue
        rel = path.relative_to(project_root).as_posix()
        scanned.add(rel)
        for server_name, server in iter_mcp_servers(data):
            tools = server.get("tools")
            for tool in tools if isinstance(tools, list) else ():
                name = tool.get("name") if isinstance(tool, dict) else None
                if isinstance(name, str) and name:
                    yield rel, str(server_name), name


def _pinned_tools(project_root: Path, scanned: set[str]) -> Iterator[tuple[str, str, str]]:
    path = project_root / PIN_FILE
    if not path.is_file():
        return
    try:
        data = loads_json(read_text_capped(path, CONFIG_MAX_BYTES, errors="replace"), path)
    except (json.JSONDecodeError, OSError):
        return
    scanned.add(PIN_FILE)
    for key in data if isinstance(data, dict) else ():
        server, slash, name = str(key).rpartition("/")
        if slash and name:
            yield PIN_FILE, server, name


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Report tools on different servers whose names are nearly the same.

    Args:
        project_root: The root directory of the project.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    scanned: set[str] = set()
    tools = sorted(set(_config_tools(project_root, scanned)) | set(_pinned_tools(project_root, scanned)))
    # A key maps to the first tool seen under it for each name, so a thousand tools with one
    # stem cost one comparison each and one finding between them.
    by_stem: dict[str, tuple[str, str, str]] = {}
    by_edit: dict[str, tuple[str, str, str]] = {}
    findings: list[Finding] = []
    reported: set[tuple[str, str]] = set()

    def report(first: tuple[str, str, str], other: tuple[str, str, str], how: str) -> None:
        pair = (first[2], other[2])
        if pair in reported or len(findings) >= _MAX_FINDINGS:
            return
        reported.add(pair)
        findings.append(make_finding(
            RULE, other[0],
            f"`{first[2]}` on server {first[1]!r} and `{other[2]}` on server {other[1]!r} {how}: the model picks "
            f"between them by description, which each server's author writes",
        ))

    for entry in tools:
        _file, server, name = entry
        stem = _stem(name)
        if len(stem) < 3:
            continue
        seen = by_stem.setdefault(stem, entry)
        if seen[1] != server and seen[2] != name:
            report(seen, entry, "differ only in a flourish or in how they are written")
        for key in _edit_keys(stem):
            near = by_edit.setdefault(key, entry)
            near_stem = _stem(near[2])
            if near[1] != server and near_stem != stem and not _is_plural_pair(stem, near_stem):
                report(near, entry, "are one character apart")
                break
    return findings, scanned


def _is_plural_pair(a: str, b: str) -> bool:
    return a + "s" == b or b + "s" == a


__all__ = ["RULE", "scan"]
