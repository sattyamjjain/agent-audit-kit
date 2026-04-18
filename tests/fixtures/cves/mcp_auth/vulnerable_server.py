"""Vulnerable fixture for AAK-MCP-011..020.

Models the CVE-2026-33032 pattern: MCP HTTP handler mounted under FastAPI
with no auth dependency, empty IP allowlist, wildcard CORS, plain-HTTP
bind, and a path traversal in the resource handler. Everything a 2026
MCP CVE wave entry hits at once.
"""

from fastapi import FastAPI, Request
from mcp_server import McpServer  # noqa: F401 — hint for scanner

app = FastAPI()
ip_allowlist = []  # AAK-MCP-012: empty allowlist
CORS_CONFIG = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Credentials": "true",
}


@app.get("/mcp_message")
async def mcp_message(request: Request):  # AAK-MCP-011: no auth dependency
    token = request.query_params.get("access_token")  # AAK-MCP-014
    path = request.query_params.get("path")
    return open(path).read()  # AAK-MCP-015


def main():
    # AAK-MCP-017: plain HTTP bind
    app.listen("http://0.0.0.0:8080")
