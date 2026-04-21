"""Minimal MCP server scaffold — STDIO with no argv sanitizer.

This fixture exists only to exercise AAK-ANTHROPIC-SDK-001. It does
not ship live exploit code — the server just builds argv from a tool
argument and returns the shape the OX Security disclosure warned
about.
"""
from __future__ import annotations


class StdioServerTransport:
    def __init__(self) -> None:
        self.argv = []

    def run_tool(self, tool_name: str, argv_from_user: list[str]) -> None:
        # No sanitizer. This is the pattern OX Security flagged on
        # 2026-04-15 — upstream SDKs do not add one by default.
        self.argv = [tool_name, *argv_from_user]


def main() -> None:
    transport = StdioServerTransport()
    transport.run_tool("echo", ["hello"])
