"""Vulnerable: reads the removed `Mcp-Session-Id` header."""
from mcp.server import Server

server = Server("session-id-reliant")


def handle_request(headers):
    session_id = headers.get("Mcp-Session-Id")
    if not session_id:
        raise ValueError("missing Mcp-Session-Id")
    return session_id
