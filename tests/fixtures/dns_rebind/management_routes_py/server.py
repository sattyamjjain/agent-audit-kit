"""A Jupyter MCP server in the shape of jupyter-mcp-server before 1.0.3 (CVE-2026-77359).

The MCP endpoint is FastMCP's own app, mounted at /mcp: on a loopback host, with `mcp`
1.23.0 or later, the SDK checks the Host of each request to it. The management routes
beside it change what the server connects to and stop its kernel, and nothing checks
the Host or Origin of a request to them.
"""

import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

mcp = FastMCP("jupyter")
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
        Mount("/mcp", app=mcp.streamable_http_app()),
    ],
)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=4040)
