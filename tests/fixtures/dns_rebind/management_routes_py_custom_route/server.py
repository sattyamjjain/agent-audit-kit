"""FastMCP custom routes, the way jupyter-mcp-server 1.0.2 registered its management routes.

A custom route is served by the same app as the MCP endpoint, but the SDK's Host check
runs inside the MCP transport, so it never sees a request to these.
"""

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

mcp = FastMCP("jupyter", host="127.0.0.1", port=4040)
state = {"runtime_url": None, "document_url": None, "kernel": None}


@mcp.custom_route("/api/connect", ["PUT"])
async def connect(request: Request) -> JSONResponse:
    body = await request.json()
    state["runtime_url"] = body["runtime_url"]
    state["document_url"] = body["document_url"]
    return JSONResponse({"success": True})


@mcp.custom_route("/api/stop", methods=["DELETE"])
async def stop(request: Request) -> JSONResponse:
    state["kernel"] = None
    return JSONResponse({"success": True})


@mcp.custom_route("/api/healthz", ["GET"])
async def healthz(request: Request) -> JSONResponse:
    return JSONResponse({"kernel": state["kernel"]})


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
