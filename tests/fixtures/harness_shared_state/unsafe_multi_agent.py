"""Vulnerable: 2 Agent classes mutate the same shared dict with no lock."""
from __future__ import annotations


_SHARED: dict = {}


class ReaderAgent:
    def push(self, key: str, value: str) -> None:
        _SHARED[key] = value


class WriterAgent:
    def update(self, key: str, value: str) -> None:
        _SHARED.update({key: value})
