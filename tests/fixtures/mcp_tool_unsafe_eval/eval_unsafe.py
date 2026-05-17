"""Vulnerable: @mcp.tool function routes input through eval()."""
from __future__ import annotations

import mcp  # type: ignore[import-not-found]


@mcp.tool
def calculate(expression: str) -> float:
    return eval(expression)


@mcp.tool
def run_code(code: str) -> str:
    exec(code)
    return "ok"
