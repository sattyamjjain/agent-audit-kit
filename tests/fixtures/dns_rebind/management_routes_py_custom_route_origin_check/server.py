"""The custom-route server with the check jupyter-mcp-server 1.0.3 added: a middleware on
the app that serves the routes reads each request's Host and Origin. No finding.
"""

from urllib.parse import urlsplit

import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.middleware.base import BaseHTTPMiddleware
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


LOCAL = {"localhost", "127.0.0.1", "::1"}


class LocalOnly(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if request.url.hostname not in LOCAL:
            return JSONResponse({"error": "Invalid Host header"}, status_code=421)
        origin = request.headers.get("origin")
        if origin and urlsplit(origin).hostname not in LOCAL:
            return JSONResponse({"error": "Invalid Origin header"}, status_code=403)
        return await call_next(request)


if __name__ == "__main__":
    app = mcp.streamable_http_app()
    app.add_middleware(LocalOnly)
    uvicorn.run(app, host="127.0.0.1", port=4040)
