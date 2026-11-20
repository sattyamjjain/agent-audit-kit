"""A management route on a FastMCP server, with nothing to check who sent the request."""

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

mcp = FastMCP("notebook", host="127.0.0.1")
state = {"runtime_url": None}


@mcp.custom_route("/api/connect", ["PUT"])
async def connect(request: Request) -> JSONResponse:
    state["runtime_url"] = (await request.json())["runtime_url"]
    return JSONResponse({"success": True})


@mcp.custom_route("/api/healthz", ["GET"])
async def healthz(request: Request) -> JSONResponse:
    return JSONResponse({"runtime": state["runtime_url"]})


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
