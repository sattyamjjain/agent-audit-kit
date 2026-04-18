"""Safe SSRF fixture: strict allowlist + scheme check + no redirects."""

from urllib.parse import urlparse
import requests
from mcp_server import McpServer  # noqa: F401

ALLOWED_HOSTS = {"api.example.com"}
server = McpServer()


@server.tool
def fetch(tool_input):
    url = tool_input["url"]
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("blocked")
    resp = requests.get(url, allow_redirects=False, timeout=5)
    return resp.text
