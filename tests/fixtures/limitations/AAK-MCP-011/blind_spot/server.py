from fastapi import APIRouter, FastAPI
from mcp.server.fastmcp import FastMCP

app = FastAPI()
router = APIRouter()
mcp = FastMCP("demo")


@router.post("/mcp")
async def mcp_endpoint(request: dict) -> dict:
    return {"ok": True, "server": mcp.name}


app.include_router(router)
