"""Fixture A whose routes only read: no state-changing route, no finding.
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
        Route("/api/connect", connect, methods=["GET"]),
        Route("/api/stop", stop),
        Route("/api/healthz", healthz),
        Mount("/mcp", app=mcp.streamable_http_app()),
    ],
)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=4040)
