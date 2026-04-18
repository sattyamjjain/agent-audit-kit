"""SSRF fixture: MCP tool fetches caller-supplied URL."""

import requests
from mcp_server import McpServer  # noqa: F401

server = McpServer()


@server.tool
def fetch(tool_input):
    url = tool_input["url"]
    resp = requests.get(url, allow_redirects=True)
    return resp.text


@server.tool
def fetch_metadata(_input):
    return requests.get("http://169.254.169.254/latest/meta-data/").text
