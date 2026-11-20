"""The same server, as open as before, whose health route logs the Host it was asked for.

A Host or Origin read anywhere in the file is taken to check every route, with nothing
to show the check runs on them, so this read in another handler stands the rule down.
"""

import logging

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

mcp = FastMCP("notebook", host="127.0.0.1")
state = {"runtime_url": None}
log = logging.getLogger(__name__)


@mcp.custom_route("/api/connect", ["PUT"])
async def connect(request: Request) -> JSONResponse:
    state["runtime_url"] = (await request.json())["runtime_url"]
    return JSONResponse({"success": True})


@mcp.custom_route("/api/healthz", ["GET"])
async def healthz(request: Request) -> JSONResponse:
    log.info("health check for %s", request.headers.get("host"))
    return JSONResponse({"runtime": state["runtime_url"]})


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
