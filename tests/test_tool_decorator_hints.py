"""A `@tool` decorator is an MCP marker wherever a scanner's file gate names it.

Six gate patterns in four scanners (`ssrf_patterns`, `mcp_auth_patterns`,
`stdio_injection`, `typescript_pattern_scan`) wrote `\\b(...|@tool|...)\\b`. A
word boundary before `@` needs a word character in front of it, so the
alternative matched only when glued to a word (`x@tool`), never a decorator at
the start of a line, and a file whose only marker was `@tool` was never read.
Each module's own tests show the rule it gates firing; this one keeps the shape
from coming back in any scanner.
"""

from __future__ import annotations

import importlib
import pkgutil
import re

import agent_audit_kit.scanners as scanners_pkg

_GLUED = "x@tool\n"
_DECORATOR = "\n@tool\ndef fetch(url): ...\n"


def _tool_patterns() -> list[tuple[str, re.Pattern[str]]]:
    found: list[tuple[str, re.Pattern[str]]] = []
    for info in pkgutil.iter_modules(scanners_pkg.__path__):
        module = importlib.import_module(f"agent_audit_kit.scanners.{info.name}")
        for name, value in vars(module).items():
            if isinstance(value, re.Pattern) and "@tool" in value.pattern:
                found.append((f"{info.name}.{name}", value))
    return found


def test_the_gate_patterns_are_found() -> None:
    names = {name for name, _ in _tool_patterns()}
    assert {
        "ssrf_patterns._MCP_TOOL_HINT",
        "mcp_auth_patterns._MCP_SERVER_HINT",
        "stdio_injection._PY_MCP_HINT_RE",
        "stdio_injection._JS_MCP_HINT_RE",
        "typescript_pattern_scan._MCP_SERVER_RE",
        "typescript_pattern_scan._TOOL_HANDLER_RE",
    } <= names


def test_a_pattern_that_reads_a_glued_tool_reads_a_decorator() -> None:
    dead = [name for name, pattern in _tool_patterns()
            if pattern.search(_GLUED) and not pattern.search(_DECORATOR)]
    assert dead == []
