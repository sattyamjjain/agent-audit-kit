"""Fixture A with the Host allow-list on the mounted MCP app only. It covers /mcp, not the
management routes on the outer app: still reported.
"""

import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

mcp = FastMCP("jupyter")
mcp_app = mcp.streamable_http_app()
mcp_app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])
state = {"runtime_url": None, "document_url": None, "kernel": None}


@mcp.tool()
def run_cell(code: str) -> str:
    return f"ran {len(code)} characters against {state['runtime_url']}"


async def connect(request: Request) -> JSONResponse:
    body = await request.json()
    state["runtime_url"] = body["runtime_url"]
    state["document_url"] = body["document_url"]
    state["kernel"] = "started"
    return JSONResponse({"success": True})


async def stop(request: Request) -> JSONResponse:
    state["kernel"] = None
    return JSONResponse({"success": True})


async def healthz(request: Request) -> JSONResponse:
    return JSONResponse({"kernel": state["kernel"]})


app = Starlette(
    routes=[
        Route("/api/connect", connect, methods=["PUT"]),
        Route("/api/stop", stop, methods=["DELETE"]),
        Route("/api/healthz", healthz),
        Mount("/mcp", app=mcp_app),
    ],
)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=4040)
