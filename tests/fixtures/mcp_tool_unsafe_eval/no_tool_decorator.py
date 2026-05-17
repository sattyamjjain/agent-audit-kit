"""Out of scope: eval() in a function NOT decorated as @mcp.tool."""
from __future__ import annotations


def internal_helper(expression: str) -> float:
    return eval(expression)
