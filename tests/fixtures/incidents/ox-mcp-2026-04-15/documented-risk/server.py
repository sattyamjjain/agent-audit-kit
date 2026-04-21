"""Risk-accepted variant — scanner reads .agent-audit-kit.yml and suppresses."""
from __future__ import annotations


class StdioServerTransport:
    def __init__(self) -> None:
        self.bound = True


def main() -> None:
    StdioServerTransport()
