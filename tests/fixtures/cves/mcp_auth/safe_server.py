"""Safe counterpart: all 2026 MCP auth-wave rules should stay quiet."""

from fastapi import FastAPI, Depends, Request
from mcp_server import McpServer  # noqa: F401
from slowapi import Limiter

limiter = Limiter(key_func=lambda req: req.client.host)


async def require_auth(request: Request) -> None:
    if not request.headers.get("Authorization"):
        raise Exception("unauth")


app = FastAPI()
ip_allowlist = ["10.0.1.0/24", "10.0.2.0/24"]  # non-empty


@app.get("/mcp", dependencies=[Depends(require_auth)])
@limiter.limit("60/minute")
async def mcp_handler(request: Request):
    return {"ok": True}


def main():
    app.listen("https://0.0.0.0:8443")
