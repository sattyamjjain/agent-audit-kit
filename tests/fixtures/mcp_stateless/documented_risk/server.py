"""Would fire 001 + 002 but the project opts out via .agent-audit-kit.yml."""
from mcp.server import Server

server = Server("opt-out")


def handle(headers):
    sid = headers.get("Mcp-Session-Id")
    return {"method": "tasks/list", "sid": sid}
