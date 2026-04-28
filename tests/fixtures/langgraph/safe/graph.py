"""Safe: ToolNode(tools=[...]) keyword form."""
from __future__ import annotations

from langgraph.prebuilt import ToolNode


def search(q: str) -> str:
    return q


def lookup(k: str) -> str:
    return k


node = ToolNode(tools=[search, lookup])
node_by_name = ToolNode(tools_by_name={"search": search, "lookup": lookup})
