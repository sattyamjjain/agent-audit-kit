from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP

app = FastAPI()
mcp = FastMCP("demo")


@app.post("/mcp")
async def mcp_endpoint(request: dict) -> dict:
    return {"ok": True, "server": mcp.name}

# TODO: add rate_limit middleware
