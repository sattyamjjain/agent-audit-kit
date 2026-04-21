"""Sanitized variant — uses shlex.quote on argv; should NOT fire."""
from __future__ import annotations

import shlex


class StdioServerTransport:
    def __init__(self) -> None:
        self.argv = []

    def run_tool(self, tool_name: str, argv_from_user: list[str]) -> None:
        self.argv = [tool_name, *(shlex.quote(a) for a in argv_from_user)]


def main() -> None:
    transport = StdioServerTransport()
    transport.run_tool("echo", ["hello"])
