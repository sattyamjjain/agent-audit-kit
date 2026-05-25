"""Vulnerable: reads a shared session store keyed on session_id."""
from mcp.server import Server

session_store: dict = {}
server = Server("store-keyed-handler")


def on_tool_call(session_id: str, tool_name: str) -> dict:
    state = session_store[session_id]
    state["last_tool"] = tool_name
    return state
