"""Vulnerable: ToolNode([...]) positional list — silent coercion in 1.0.11."""
from __future__ import annotations

from langgraph.prebuilt import ToolNode


def search(q: str) -> str:
    return q


def lookup(k: str) -> str:
    return k


tools = [search, lookup]
node = ToolNode(tools)  # positional Name list
node2 = ToolNode([search, lookup])  # positional List literal
