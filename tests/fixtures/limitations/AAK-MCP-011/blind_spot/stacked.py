from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP

app = FastAPI()
mcp = FastMCP("demo")


def audited(fn):
    return fn


@app.post("/mcp")
@audited
async def mcp_endpoint(request: dict) -> dict:
    return {"ok": True, "server": mcp.name}
