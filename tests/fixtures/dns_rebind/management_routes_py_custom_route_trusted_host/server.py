"""The custom-route server with a Host allow-list on the app `streamable_http_app()`
returns, which is the app that serves the custom routes too. No finding.
"""

import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.middleware.trustedhost import TrustedHostMiddleware
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
    app = mcp.streamable_http_app()
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])
    uvicorn.run(app, host="127.0.0.1", port=4040)
