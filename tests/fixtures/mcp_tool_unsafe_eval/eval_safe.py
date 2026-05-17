"""Safe: @mcp.tool function uses ast.literal_eval instead of eval."""
from __future__ import annotations

import ast

import mcp  # type: ignore[import-not-found]


@mcp.tool
def calculate(expression: str) -> object:
    return ast.literal_eval(expression)
