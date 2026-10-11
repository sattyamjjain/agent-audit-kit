from fastapi import Body, FastAPI
from mcp.server.fastmcp import FastMCP

app = FastAPI()
mcp = FastMCP("demo")


@app.post("/mcp")
async def mcp_endpoint(request: dict = Body(...)) -> dict:
    return {"ok": True, "server": mcp.name}
