from fastapi import APIRouter

router = APIRouter()


@router.post("/mcp_message")
async def mcp_message(request: dict) -> dict:
    return {"ok": True}
